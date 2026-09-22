package secure

import (
	"strings"
	"testing"
)

func TestScrubbedEnvExcludesFNBVariables(t *testing.T) {
	t.Setenv("FNB_USERNAME", "user")
	t.Setenv("FNB_PASSWORD", "password")
	t.Setenv("FNB_OTP", "123456")
	for _, entry := range ScrubbedEnv() {
		if strings.HasPrefix(entry, "FNB_") {
			t.Fatalf("unexpected environment entry %q", entry)
		}
	}
}

func TestCommandUsesScrubbedEnvironment(t *testing.T) {
	t.Setenv("FNB_PASSWORD", "secret")
	command, err := Command([]string{"/usr/bin/env"})
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "FNB_") {
		t.Fatalf("output contains FNB variable: %q", output)
	}
}
