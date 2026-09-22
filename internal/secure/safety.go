package secure

import (
	"fmt"
	"os"
	"syscall"
)

func CheckRoot(root *os.Root) error {
	info, err := root.Stat(".")
	if err != nil {
		return &UnsafeDirectoryError{Reason: "cannot inspect directory: " + err.Error()}
	}
	if !info.IsDir() {
		return &UnsafeDirectoryError{Reason: "path is not a directory"}
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return &UnsafeDirectoryError{Reason: "cannot determine directory owner"}
	}
	if stat.Uid != uint32(os.Getuid()) {
		return &UnsafeDirectoryError{Reason: "directory is not owned by the current user"}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return &UnsafeDirectoryError{Reason: fmt.Sprintf("directory mode %04o is group/world-writable", info.Mode().Perm())}
	}
	directory, err := root.Open(".")
	if err != nil {
		return &UnsafeDirectoryError{Reason: "cannot pin directory for ACL inspection: " + err.Error()}
	}
	defer directory.Close()
	if reason, err := aclViolation(directory); err != nil {
		return &UnsafeDirectoryError{Reason: "cannot inspect directory ACL: " + err.Error()}
	} else if reason != "" {
		return &UnsafeDirectoryError{Reason: reason}
	}
	return nil
}
