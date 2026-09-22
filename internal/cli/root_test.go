package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/yashiels/fnb/internal/exitcode"
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
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "FNB_USERNAME") {
		t.Fatalf("stderr = %q", stderr)
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
	code, _, stderr := runCLI("--config-dir", link, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
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
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
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

func runCLI(args ...string) (int, string, string) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Execute(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
