//go:build darwin

package cli

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/yashiels/fnb/internal/exitcode"
)

func TestConfigDirectoryWithACLEntry(t *testing.T) {
	directory := t.TempDir()
	command := exec.Command("chmod", "+a", "everyone allow add_file,delete_child,file_inherit", directory)
	if output, err := command.CombinedOutput(); err != nil {
		t.Skipf("chmod ACL unavailable: %v: %s", err, output)
	}
	code, _, stderr := runCLI("--config-dir", directory, "accounts", "list")
	if code != exitcode.ExitAuthentication {
		t.Fatalf("code = %d, stderr = %q", code, stderr)
	}
	if !strings.Contains(stderr, "ACL") {
		t.Fatalf("stderr = %q", stderr)
	}
}
