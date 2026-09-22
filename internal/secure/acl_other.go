//go:build !darwin && !linux

package secure

import (
	"fmt"
	"os"
	"runtime"
)

func aclViolation(directory *os.File) (string, error) {
	return "", fmt.Errorf("ACL inspection is unsupported on %s", runtime.GOOS)
}
