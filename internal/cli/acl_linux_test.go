//go:build linux

package cli

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/yashiels/fnb/internal/exitcode"
)

func TestConfigDirectoryWithAccessACLEntry(t *testing.T) {
	testLinuxACL(t, "-m", "u:nobody:r-x")
}

func TestConfigDirectoryWithDefaultACLEntry(t *testing.T) {
	testLinuxACL(t, "-d", "-m", "u:nobody:r-x")
}

func testLinuxACL(t *testing.T, arguments ...string) {
	if _, err := exec.LookPath("setfacl"); err != nil {
		t.Skip("setfacl is unavailable")
	}
	directory := t.TempDir()
	arguments = append(arguments, directory)
	if output, err := exec.Command("setfacl", arguments...).CombinedOutput(); err != nil {
		t.Skipf("setfacl unavailable: %v: %s", err, output)
	}
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "ACL") {
		t.Fatalf("stderr = %q", stderr)
	}
}
