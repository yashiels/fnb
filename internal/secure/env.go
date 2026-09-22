package secure

import (
	"os"
	"os/exec"
	"strings"
)

var allowedEnvironmentKeys = []string{"HOME", "PATH", "TMPDIR", "LANG", "USER"}

func ScrubbedEnv() []string {
	env := make([]string, 0, len(allowedEnvironmentKeys))
	for _, key := range allowedEnvironmentKeys {
		if value, ok := os.LookupEnv(key); ok && !strings.HasPrefix(key, "FNB_") {
			env = append(env, key+"="+value)
		}
	}
	return env
}

func Command(argv []string) (*exec.Cmd, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, &ArgumentError{Message: "credential_command must contain at least one argument"}
	}
	command := exec.Command(argv[0], argv[1:]...)
	command.Env = ScrubbedEnv()
	return command, nil
}

type ArgumentError struct {
	Message string
}

func (e *ArgumentError) Error() string {
	return e.Message
}
