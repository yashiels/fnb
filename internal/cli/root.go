package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/yashiels/fnb/internal/config"
	"github.com/yashiels/fnb/internal/exitcode"
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
	flags  globalFlags
	stdout io.Writer
	stderr io.Writer
}

func Execute(args []string, stdout, stderr io.Writer) int {
	app := &application{stdout: stdout, stderr: stderr}
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
	login := app.stubCommand("login")
	approve := app.stubCommand("approve")
	approve.Flags().Duration("wait", 120*time.Second, "maximum time to wait for approval")
	status := app.stubCommand("status")
	logout := app.stubCommand("logout")
	clearLockout := app.stubCommand("clear-lockout")
	importCookies := app.stubCommand("import-cookies")
	importCookies.Flags().String("from-browser", "", "browser to import cookies from")
	importCookies.Flags().String("profile", "", "dedicated browser profile")
	importCookies.Flags().String("file", "", "cookie file path or - for stdin")
	auth.AddCommand(login, approve, status, logout, clearLockout, importCookies)
	return auth
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
		if _, err := config.Resolve(app.flags.configDir); err != nil {
			return exitcode.Wrap(exitcode.ExitAuthentication, "configuration", err.Error(), err)
		}
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
