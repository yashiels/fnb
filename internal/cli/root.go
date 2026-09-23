package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/yashiels/fnb/internal/config"
	"github.com/yashiels/fnb/internal/exitcode"
	"github.com/yashiels/fnb/internal/output"
	"github.com/yashiels/fnb/internal/secure"
	"github.com/yashiels/fnb/internal/session"
)

var Version = "dev"

type globalFlags struct {
	json      bool
	plain     bool
	noInput   bool
	configDir string
	verbose   bool
}

type application struct {
	flags       globalFlags
	stdin       io.Reader
	stdout      io.Writer
	stderr      io.Writer
	clock       session.Clock
	isTTY       func() bool
	lockTimeout time.Duration
	lifetime    time.Duration
}

func Execute(args []string, stdout, stderr io.Writer) int {
	app := &application{
		stdin:       os.Stdin,
		stdout:      stdout,
		stderr:      stderr,
		isTTY:       stdinIsTTY,
		lockTimeout: 30 * time.Second,
	}
	root := app.rootCommand()
	return execute(app, root, args)
}

func execute(app *application, root *cobra.Command, args []string) int {
	root.SetArgs(args)
	root.SetOut(app.stdout)
	root.SetErr(app.stderr)
	err := root.Execute()
	if err == nil {
		return exitcode.ExitOK
	}
	var coded *exitcode.Error
	if !errors.As(err, &coded) {
		err = exitcode.Wrap(exitcode.ExitGeneral, "internal_error", err.Error(), err)
	}
	app.report(err)
	return exitcode.Code(err)
}

func (app *application) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "fnb",
		Short:         "Read-only FNB Online Banking CLI",
		Version:       Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          exactArgs(0),
		RunE: func(command *cobra.Command, args []string) error {
			return command.Help()
		},
		PersistentPreRunE: func(command *cobra.Command, args []string) error {
			if app.flags.json && app.flags.plain {
				return exitcode.Usagef("--json and --plain are mutually exclusive")
			}
			return nil
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")
	root.SetFlagErrorFunc(func(command *cobra.Command, err error) error {
		return exitcode.Wrap(exitcode.ExitUsage, "usage", err.Error(), err)
	})
	flags := root.PersistentFlags()
	flags.BoolVar(&app.flags.json, "json", false, "output JSON")
	flags.BoolVar(&app.flags.plain, "plain", false, "output stable tab-separated lines")
	flags.BoolVar(&app.flags.noInput, "no-input", false, "never prompt for input")
	flags.StringVar(&app.flags.configDir, "config-dir", "", "override the config directory")
	flags.BoolVar(&app.flags.verbose, "verbose", false, "write verbose diagnostics to stderr")
	root.AddCommand(app.authCommand(), app.accountsCommand(), app.transactionsCommand(), app.stubCommand("doctor"))
	return root
}

func (app *application) authCommand() *cobra.Command {
	auth := app.groupCommand("auth", "Manage authentication")
	login := app.authLoginCommand()
	approve := app.stubCommand("approve")
	approve.Flags().Duration("wait", 120*time.Second, "maximum time to wait for approval")
	status := app.authStatusCommand()
	logout := app.authLogoutCommand()
	clearLockout := app.authClearLockoutCommand()
	importCookies := app.stubCommand("import-cookies")
	importCookies.Flags().String("from-browser", "", "browser to import cookies from")
	importCookies.Flags().String("profile", "", "dedicated browser profile")
	importCookies.Flags().String("file", "", "cookie file path or - for stdin")
	auth.AddCommand(login, approve, status, logout, clearLockout, importCookies)
	return auth
}

func (app *application) authLoginCommand() *cobra.Command {
	command := &cobra.Command{Use: "login", Args: exactArgs(0)}
	command.RunE = func(command *cobra.Command, args []string) error {
		_, attempts, _, release, err := app.openAuthState(command.Context())
		if err != nil {
			return err
		}
		defer release()
		manager := session.LoginManager{Attempts: attempts, Clock: app.clock}
		if err := manager.Preflight(); err != nil {
			return err
		}
		return exitcode.New(exitcode.ExitGeneral, "not_implemented", command.CommandPath()+" is not implemented")
	}
	return command
}

func (app *application) authStatusCommand() *cobra.Command {
	command := &cobra.Command{Use: "status", Args: exactArgs(0)}
	command.RunE = func(command *cobra.Command, args []string) error {
		resolved, attempts, sessions, release, err := app.openAuthState(command.Context())
		if err != nil {
			return err
		}
		defer release()
		attempt, found, err := attempts.LoadAttempt()
		if err != nil {
			return err
		}
		savedSession, present, err := sessions.LoadSession()
		if err != nil {
			return err
		}
		return app.writeAuthStatus(resolved.Identity, attempt, found, savedSession, present)
	}
	return command
}

func (app *application) authLogoutCommand() *cobra.Command {
	command := &cobra.Command{Use: "logout", Args: exactArgs(0)}
	command.RunE = func(command *cobra.Command, args []string) error {
		_, _, sessions, release, err := app.openAuthState(command.Context())
		if err != nil {
			return err
		}
		defer release()
		if err := sessions.DeleteSession(); err != nil {
			return err
		}
		message := struct {
			Status       string `json:"status"`
			ServerLogoff string `json:"serverLogoff"`
		}{Status: "ok", ServerLogoff: "not_implemented_until_m0"}
		if output.Resolve(app.flags.json, app.flags.plain, app.stdout) == output.JSON {
			return output.WriteJSON(app.stdout, message)
		}
		return output.WritePlain(app.stdout, [][]string{{"status", "ok"}, {"serverLogoff", "not_implemented_until_m0"}})
	}
	return command
}

func (app *application) authClearLockoutCommand() *cobra.Command {
	command := &cobra.Command{Use: "clear-lockout", Args: exactArgs(0)}
	command.RunE = func(command *cobra.Command, args []string) error {
		_, attempts, _, release, err := app.openAuthState(command.Context())
		if err != nil {
			return err
		}
		defer release()
		interactive := !app.flags.noInput && app.isTTY != nil && app.isTTY()
		confirm := func() (bool, error) {
			if _, err := fmt.Fprint(app.stderr, "Type yes to clear the login lockout: "); err != nil {
				return false, err
			}
			value, err := bufio.NewReader(app.stdin).ReadString('\n')
			if err != nil && !errors.Is(err, io.EOF) {
				return false, err
			}
			return strings.TrimSpace(value) == "yes", nil
		}
		if err := session.ClearLockout(attempts, confirm, interactive); err != nil {
			return err
		}
		if output.Resolve(app.flags.json, app.flags.plain, app.stdout) == output.JSON {
			return output.WriteJSON(app.stdout, map[string]string{"status": "ok"})
		}
		return output.WritePlain(app.stdout, [][]string{{"status", "ok"}})
	}
	return command
}

func (app *application) openAuthState(ctx context.Context) (*config.Config, *session.Attempts, *session.Store, func(), error) {
	resolved, root, release, err := app.openLockedConfig(ctx)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return resolved, session.NewAttempts(root), session.NewStore(root, app.effectiveLifetime(), app.clock), release, nil
}

func (app *application) openLockedConfig(ctx context.Context) (*config.Config, *os.Root, func(), error) {
	resolved, err := config.Resolve(app.flags.configDir)
	if err != nil {
		return nil, nil, nil, app.configurationError(err)
	}
	root, err := config.OpenDir(resolved.Dir)
	if err != nil {
		return nil, nil, nil, app.configurationError(err)
	}
	lock, err := session.AcquireLock(ctx, root, app.clock, app.effectiveLockTimeout())
	if err != nil {
		root.Close()
		return nil, nil, nil, err
	}
	release := func() {
		_ = lock.Close()
		_ = root.Close()
	}
	return resolved, root, release, nil
}

func (app *application) configurationError(err error) error {
	var coded *exitcode.Error
	if errors.As(err, &coded) {
		return err
	}
	var unsafeDirectory *secure.UnsafeDirectoryError
	if errors.As(err, &unsafeDirectory) {
		return exitcode.Wrap(exitcode.ExitUsage, "unsafe_output_dir", err.Error(), err)
	}
	return exitcode.Wrap(exitcode.ExitAuthentication, "configuration", err.Error(), err)
}

func (app *application) writeAuthStatus(identity string, attempt session.Attempt, attemptPresent bool, savedSession session.Session, sessionPresent bool) error {
	now := time.Now()
	if app.clock != nil {
		now = app.clock.Now()
	}
	type status struct {
		Identity          string `json:"identity"`
		AttemptState      string `json:"attemptState"`
		AttemptReason     string `json:"attemptReason,omitempty"`
		AttemptAt         string `json:"attemptAt,omitempty"`
		RateNextAllowedAt string `json:"rateNextAllowedAt,omitempty"`
		Session           string `json:"session"`
		SessionAgeSeconds *int64 `json:"sessionAgeSeconds,omitempty"`
		ApprovalPending   bool   `json:"approvalPending,omitempty"`
	}
	result := status{Identity: identity + " (declared, unverified)", AttemptState: "none", Session: "absent"}
	if attemptPresent {
		result.AttemptState = string(attempt.State)
		result.AttemptReason = attempt.Reason
		result.AttemptAt = attempt.At.Format(time.RFC3339)
		if attempt.LastCredentialLoginAt != nil {
			result.RateNextAllowedAt = attempt.LastCredentialLoginAt.Add(session.CredentialInterval).Format(time.RFC3339)
		}
	}
	if sessionPresent {
		result.Session = "present"
		age := int64(now.Sub(savedSession.CreatedAt).Seconds())
		if age < 0 {
			age = 0
		}
		result.SessionAgeSeconds = &age
		result.ApprovalPending = savedSession.ApprovalPending
	}
	if output.Resolve(app.flags.json, app.flags.plain, app.stdout) == output.JSON {
		return output.WriteJSON(app.stdout, result)
	}
	rows := [][]string{{"identity", result.Identity}, {"attemptState", result.AttemptState}}
	if result.AttemptReason != "" {
		rows = append(rows, []string{"attemptReason", result.AttemptReason})
	}
	if result.AttemptAt != "" {
		rows = append(rows, []string{"attemptAt", result.AttemptAt})
	}
	if result.RateNextAllowedAt != "" {
		rows = append(rows, []string{"rateNextAllowedAt", result.RateNextAllowedAt})
	}
	rows = append(rows, []string{"session", result.Session})
	if sessionPresent {
		rows = append(rows, []string{"sessionAgeSeconds", fmt.Sprint(*result.SessionAgeSeconds)})
	}
	return output.WritePlain(app.stdout, rows)
}

func (app *application) effectiveLockTimeout() time.Duration {
	if app.lockTimeout <= 0 {
		return 30 * time.Second
	}
	return app.lockTimeout
}

func (app *application) effectiveLifetime() time.Duration {
	return app.lifetime
}

func stdinIsTTY() bool {
	return output.IsTTY(os.Stdin)
}

func (app *application) accountsCommand() *cobra.Command {
	accounts := app.groupCommand("accounts", "Read accounts")
	list := app.stubCommand("list")
	list.Flags().Bool("show-account-numbers", false, "include full account numbers in JSON output")
	balance := app.stubCommandWithArgs("balance <accountId>", 1)
	accounts.AddCommand(list, balance)
	return accounts
}

func (app *application) groupCommand(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  exactArgs(0),
		RunE: func(command *cobra.Command, args []string) error {
			return command.Help()
		},
	}
}

func (app *application) transactionsCommand() *cobra.Command {
	transactions := app.stubCommandWithArgs("transactions <accountId>", 1)
	transactions.Flags().String("from", "", "inclusive start date in YYYY-MM-DD")
	transactions.Flags().String("to", "", "inclusive end date in YYYY-MM-DD")
	transactions.Flags().String("state", "", "transaction state: posted or pending")
	transactions.Flags().String("partial-out", "", "write incomplete results to a new file")
	transactions.Flags().Bool("overwrite", false, "replace an existing partial output file")
	return transactions
}

func (app *application) stubCommand(use string) *cobra.Command {
	return app.stubCommandWithArgs(use, 0)
}

func (app *application) stubCommandWithArgs(use string, count int) *cobra.Command {
	command := &cobra.Command{Use: use, Args: exactArgs(count)}
	command.RunE = func(command *cobra.Command, args []string) error {
		_, _, release, err := app.openLockedConfig(command.Context())
		if err != nil {
			return err
		}
		defer release()
		return exitcode.New(exitcode.ExitGeneral, "not_implemented", command.CommandPath()+" is not implemented")
	}
	return command
}

func exactArgs(count int) cobra.PositionalArgs {
	return func(command *cobra.Command, args []string) error {
		if count == 0 && len(args) > 0 && command.HasSubCommands() {
			return exitcode.Usagef("unknown command %q for %q", args[0], command.CommandPath())
		}
		if len(args) != count {
			return exitcode.Usagef("%s accepts %d argument(s), received %d", command.CommandPath(), count, len(args))
		}
		return nil
	}
}

func (app *application) report(err error) {
	fmt.Fprintln(app.stderr, "fnb: "+err.Error())
	if !app.flags.json {
		return
	}
	payload := struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}{}
	payload.Error.Code = exitcode.Slug(err)
	payload.Error.Message = err.Error()
	encoder := json.NewEncoder(app.stdout)
	_ = encoder.Encode(payload)
}
