package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/yashiels/fnb/internal/exitcode"
	"github.com/yashiels/fnb/internal/session"
)

func TestVersionOutput(t *testing.T) {
	previous := Version
	Version = "0.0.0"
	t.Cleanup(func() { Version = previous })
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute([]string{"--version"}, &stdout, &stderr)
	if code != exitcode.ExitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != Version+"\n" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestAccountsListMissingUsername(t *testing.T) {
	t.Setenv("FNB_USERNAME", "")
	directory := t.TempDir()
	code, stdout, stderr := runCLI("--json", "--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "FNB_USERNAME") {
		t.Fatalf("stderr = %q", stderr)
	}
	if !strings.Contains(stdout, `"code":"configuration"`) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestAccountsListMissingIdentity(t *testing.T) {
	t.Setenv("FNB_USERNAME", "secondary-user")
	directory := t.TempDir()
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "identity") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestConfigDirectorySymlink(t *testing.T) {
	t.Setenv("FNB_USERNAME", "secondary-user")
	parent := t.TempDir()
	realDirectory := filepath.Join(parent, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(realDirectory, link); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI("--json", "--config-dir", link, "accounts", "list")
	if code != exitcode.ExitUsage {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"code":"unsafe_output_dir"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "symlink") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestConfigDirectoryGroupWritable(t *testing.T) {
	t.Setenv("FNB_USERNAME", "secondary-user")
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI("--json", "--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitUsage {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"code":"unsafe_output_dir"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(stderr, "group/world-writable") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestJSONAndPlainAreMutuallyExclusive(t *testing.T) {
	code, stdout, stderr := runCLI("--json", "--plain")
	if code != exitcode.ExitUsage {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "mutually exclusive") {
		t.Fatalf("stderr = %q", stderr)
	}
	if !strings.Contains(stdout, `"code":"usage"`) {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestUnknownFlagIsUsageError(t *testing.T) {
	code, _, stderr := runCLI("--unknown")
	if code != exitcode.ExitUsage {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestWrongArgumentCountIsUsageError(t *testing.T) {
	code, _, stderr := runCLI("accounts", "balance")
	if code != exitcode.ExitUsage {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
}

func TestUnknownCommandIsUsageError(t *testing.T) {
	cases := []struct {
		args    []string
		unknown string
	}{
		{[]string{"bogus"}, "bogus"},
		{[]string{"accounts", "bogus"}, "bogus"},
		{[]string{"auth", "bogus", "extra"}, "bogus"},
	}
	for _, testCase := range cases {
		code, _, stderr := runCLI(testCase.args...)
		if code != exitcode.ExitUsage {
			t.Fatalf("args %v: code = %d, stderr = %q", testCase.args, code, stderr)
		}
		if !strings.Contains(stderr, "unknown command \""+testCase.unknown+"\"") {
			t.Fatalf("args %v: stderr = %q", testCase.args, stderr)
		}
	}
}

func TestUncodedCommandErrorIsGeneralError(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := &application{stdout: &stdout, stderr: &stderr}
	root := app.rootCommand()
	root.AddCommand(&cobra.Command{
		Use: "uncoded",
		RunE: func(command *cobra.Command, args []string) error {
			return errors.New("plain failure")
		},
	})
	code := execute(app, root, []string{"uncoded"})
	if code != exitcode.ExitGeneral {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestConfigurationErrorPreservesCodedError(t *testing.T) {
	app := &application{}
	want := exitcode.New(exitcode.ExitRateLimit, "synthetic", "synthetic")
	if got := app.configurationError(want); got != want {
		t.Fatalf("error = %v", got)
	}
}

func TestValidConfigReachesStub(t *testing.T) {
	t.Setenv("FNB_USERNAME", "")
	directory := t.TempDir()
	config := "username = \"secondary-user\"\nidentity = \"view-only-secondary\"\n"
	if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "balance", "opaque-id")
	if code != exitcode.ExitGeneral {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "not implemented") {
		t.Fatalf("stderr = %q", stderr)
	}
}

type cliClock struct {
	now time.Time
}

func (clock *cliClock) Now() time.Time {
	return clock.now
}

func (clock *cliClock) Sleep(_ context.Context, duration time.Duration) error {
	clock.now = clock.now.Add(duration)
	return nil
}

func TestAuthStatusReportsAttemptRateAndSession(t *testing.T) {
	directory := configuredDirectory(t)
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	attempts := session.NewAttempts(root)
	last := now.Add(-5 * time.Minute)
	if err := attempts.SaveAttempt(session.Attempt{State: session.AttemptOK, At: last, LastCredentialLoginAt: &last}); err != nil {
		t.Fatal(err)
	}
	store := session.NewStore(root, time.Hour, &cliClock{now: now})
	if err := store.SaveSession(session.Session{CreatedAt: now.Add(-10 * time.Minute), Cookies: []session.Cookie{{Name: "session", Value: "synthetic", Secure: true}}}); err != nil {
		t.Fatal(err)
	}
	root.Close()
	code, stdout, stderr := runConfiguredApp(directory, &cliClock{now: now}, strings.NewReader(""), false, "auth", "status")
	if code != exitcode.ExitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	for _, fragment := range []string{
		`"identity": "view-only-secondary (declared, unverified)"`,
		`"attemptState": "ok"`,
		`"rateNextAllowedAt": "2026-09-23T12:10:00Z"`,
		`"session": "present"`,
		`"sessionAgeSeconds": 600`,
	} {
		if !strings.Contains(stdout, fragment) {
			t.Fatalf("stdout = %q, missing %q", stdout, fragment)
		}
	}
}

func TestAuthLoginRunsBlockedAndRatePreflightWithoutWriting(t *testing.T) {
	for _, testCase := range []struct {
		name  string
		state session.AttemptState
		slug  string
	}{
		{"blocked", session.AttemptBlocked, "login_blocked"},
		{"in flight", session.AttemptInFlight, "login_blocked"},
		{"rate", session.AttemptOK, "rate_limited"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := configuredDirectory(t)
			now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			last := now.Add(-time.Minute)
			attempt := session.Attempt{State: testCase.state, Reason: "synthetic", At: last, LastCredentialLoginAt: &last}
			if err := session.NewAttempts(root).SaveAttempt(attempt); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(filepath.Join(directory, session.AttemptFileName))
			if err != nil {
				t.Fatal(err)
			}
			root.Close()
			code, stdout, stderr := runConfiguredApp(directory, &cliClock{now: now}, strings.NewReader(""), false, "--json", "auth", "login")
			if (testCase.slug == "rate_limited" && code != exitcode.ExitRateLimit) || (testCase.slug == "login_blocked" && code != exitcode.ExitAuthentication) {
				t.Fatalf("code = %d, stderr = %q", code, stderr)
			}
			if !strings.Contains(stdout, `"code":"`+testCase.slug+`"`) {
				t.Fatalf("stdout = %q", stdout)
			}
			after, err := os.ReadFile(filepath.Join(directory, session.AttemptFileName))
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("auth login preflight changed attempt state")
			}
		})
	}
}

func TestAuthLoginWithoutGuardStateRemainsNotImplementedAndDoesNotWrite(t *testing.T) {
	directory := configuredDirectory(t)
	code, _, stderr := runConfiguredApp(directory, &cliClock{now: time.Unix(1000, 0)}, strings.NewReader(""), false, "auth", "login")
	if code != exitcode.ExitGeneral || !strings.Contains(stderr, "not implemented") {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(directory, session.AttemptFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("attempt state exists: %v", err)
	}
}

func TestAuthClearLockoutRefusesNoInputAndNoTTY(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
		tty  bool
	}{
		{"no input", []string{"--no-input", "auth", "clear-lockout"}, true},
		{"no tty", []string{"auth", "clear-lockout"}, false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			directory := configuredDirectory(t)
			code, stdout, _ := runConfiguredApp(directory, &cliClock{now: time.Unix(1000, 0)}, strings.NewReader("yes\n"), testCase.tty, append([]string{"--json"}, testCase.args...)...)
			if code != exitcode.ExitUsage || !strings.Contains(stdout, `"code":"interactive_required"`) {
				t.Fatalf("code = %d, stdout = %q", code, stdout)
			}
		})
	}
}

func TestAuthClearLockoutRequiresTypedYes(t *testing.T) {
	directory := configuredDirectory(t)
	now := time.Unix(1000, 0)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.NewAttempts(root).SaveAttempt(session.Attempt{State: session.AttemptBlocked, Reason: "synthetic", At: now}); err != nil {
		t.Fatal(err)
	}
	root.Close()
	code, stdout, stderr := runConfiguredApp(directory, &cliClock{now: now}, strings.NewReader("yes\n"), true, "auth", "clear-lockout")
	if code != exitcode.ExitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"status": "ok"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	root, err = os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	attempt, found, err := session.NewAttempts(root).LoadAttempt()
	if err != nil || !found || attempt.State != session.AttemptOK {
		t.Fatalf("attempt = %#v, found = %v, err = %v", attempt, found, err)
	}
}

func TestAuthLogoutDeletesOnlyLocalSession(t *testing.T) {
	directory := configuredDirectory(t)
	now := time.Unix(1000, 0)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.NewStore(root, time.Hour, &cliClock{now: now}).SaveSession(session.Session{CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	root.Close()
	code, stdout, stderr := runConfiguredApp(directory, &cliClock{now: now}, strings.NewReader(""), false, "auth", "logout")
	if code != exitcode.ExitOK {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stdout, `"serverLogoff": "not_implemented_until_m0"`) {
		t.Fatalf("stdout = %q", stdout)
	}
	if _, err := os.Stat(filepath.Join(directory, session.SessionFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("session still exists: %v", err)
	}
}

func TestPendingM2aAuthCommandsTakeLockAndRemainNotImplemented(t *testing.T) {
	for _, args := range [][]string{{"auth", "approve"}, {"auth", "import-cookies"}} {
		directory := configuredDirectory(t)
		code, _, stderr := runConfiguredApp(directory, &cliClock{now: time.Unix(1000, 0)}, strings.NewReader(""), false, args...)
		if code != exitcode.ExitGeneral || !strings.Contains(stderr, "not implemented") {
			t.Fatalf("args = %v, code = %d, stderr = %q", args, code, stderr)
		}
		info, err := os.Stat(filepath.Join(directory, "lock"))
		if err != nil || !info.Mode().IsRegular() {
			t.Fatalf("args = %v, lock info = %v, err = %v", args, info, err)
		}
	}
}

func TestConfigUsingCommandsReturnLockContention(t *testing.T) {
	directory := configuredDirectory(t)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	holder, err := session.AcquireLock(context.Background(), root, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	for _, args := range [][]string{{"accounts", "list"}, {"transactions", "x"}, {"doctor"}} {
		clock := &cliClock{now: time.Unix(1000, 0)}
		code, stdout, stderr := runConfiguredAppWithTimeout(directory, clock, 200*time.Millisecond, strings.NewReader(""), false, append([]string{"--json"}, args...)...)
		if code != exitcode.ExitRateLimit {
			t.Fatalf("args = %v, code = %d, stderr = %q", args, code, stderr)
		}
		if !strings.Contains(stdout, `"code":"lock_contention"`) {
			t.Fatalf("args = %v, stdout = %q", args, stdout)
		}
	}
}

func configuredDirectory(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	config := "username = \"secondary-user\"\nidentity = \"view-only-secondary\"\n"
	if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}

func runConfiguredApp(directory string, clock session.Clock, stdin io.Reader, tty bool, args ...string) (int, string, string) {
	return runConfiguredAppWithTimeout(directory, clock, time.Second, stdin, tty, args...)
}

func runConfiguredAppWithTimeout(directory string, clock session.Clock, lockTimeout time.Duration, stdin io.Reader, tty bool, args ...string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	app := &application{
		stdin:       stdin,
		stdout:      &stdout,
		stderr:      &stderr,
		clock:       clock,
		isTTY:       func() bool { return tty },
		lockTimeout: lockTimeout,
		lifetime:    time.Hour,
	}
	root := app.rootCommand()
	fullArgs := append([]string{"--config-dir", directory}, args...)
	code := execute(app, root, fullArgs)
	return code, stdout.String(), stderr.String()
}

func runCLI(args ...string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
