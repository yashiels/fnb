package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenDirCreatesMode0700(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "fnb")
	root, err := OpenDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	root.Close()
	info, err := os.Stat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("mode = %04o", info.Mode().Perm())
	}
}

func TestCredentialCommandReturnsPasswordWithoutShellInterpretation(t *testing.T) {
	directory := t.TempDir()
	tests := []struct {
		name     string
		argument string
	}{
		{name: "password", argument: "hunter2"},
		{name: "literal", argument: "$HOME"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := "username = \"user\"\nidentity = \"view-only-secondary\"\ncredential_command = [\"/bin/echo\", \"" + test.argument + "\"]\n"
			if err := os.WriteFile(filepath.Join(directory, "config.toml"), []byte(config), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("FNB_USERNAME", "")
			t.Setenv("FNB_PASSWORD", "")
			resolved, err := Resolve(directory)
			if err != nil {
				t.Fatal(err)
			}
			password, err := resolved.Password()
			if err != nil {
				t.Fatal(err)
			}
			if password != test.argument {
				t.Fatalf("password = %q", password)
			}
		})
	}
}

func TestPasswordEnvironmentTakesPrecedence(t *testing.T) {
	t.Setenv("FNB_PASSWORD", "from-env")
	config := &Config{CredentialCommand: []string{"/bin/echo", "from-command"}}
	password, err := config.Password()
	if err != nil {
		t.Fatal(err)
	}
	if password != "from-env" {
		t.Fatalf("password = %q", password)
	}
}
