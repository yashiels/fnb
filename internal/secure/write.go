package secure

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type Policy int

const (
	NoOverwrite Policy = iota
	Overwrite
)

type UnsafeDirectoryError struct {
	Reason string
}

func (e *UnsafeDirectoryError) Error() string {
	return "unsafe directory: " + e.Reason
}

type FileHandle interface {
	Chmod(os.FileMode) error
	Write([]byte) (int, error)
	Sync() error
	Close() error
}

type WriteOperations interface {
	CheckDirectory() error
	OpenTemp(string) (FileHandle, error)
	Lstat(string) (os.FileInfo, error)
	Link(string, string) error
	Rename(string, string) error
	Remove(string) error
	SyncDirectory() error
}

type rootOperations struct {
	root         *os.Root
	beforeRename func()
}

func WriteFile(dir *os.Root, name string, data []byte, policy Policy) error {
	if dir == nil {
		return errors.New("directory root is required")
	}
	if name == "" || name == "." || filepath.Base(name) != name {
		return fmt.Errorf("invalid file name %q", name)
	}
	return writeFile(rootOperations{root: dir}, name, data, policy, randomTempName)
}

func WriteFileWithOperations(operations WriteOperations, name string, data []byte, policy Policy) error {
	if operations == nil {
		return errors.New("write operations are required")
	}
	if name == "" || name == "." || filepath.Base(name) != name {
		return fmt.Errorf("invalid file name %q", name)
	}
	return writeFile(operations, name, data, policy, randomTempName)
}

func writeFile(operations WriteOperations, name string, data []byte, policy Policy, tempName func(string) (string, error)) error {
	if policy != NoOverwrite && policy != Overwrite {
		return fmt.Errorf("invalid overwrite policy %d", policy)
	}
	if err := operations.CheckDirectory(); err != nil {
		return err
	}
	temporary, err := tempName(name)
	if err != nil {
		return err
	}
	file, err := operations.OpenTemp(temporary)
	if err != nil {
		return err
	}
	temporaryExists := true
	fileOpen := true
	defer func() {
		if fileOpen {
			_ = file.Close()
		}
		if temporaryExists {
			_ = operations.Remove(temporary)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return err
	}
	if err := writeAll(file, data); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		fileOpen = false
		return err
	}
	fileOpen = false
	if policy == NoOverwrite {
		if err := operations.Link(temporary, name); err != nil {
			return err
		}
		if err := operations.Remove(temporary); err != nil {
			return err
		}
		temporaryExists = false
	} else {
		if err := validateOverwriteTarget(operations, name); err != nil {
			return err
		}
		if err := operations.Rename(temporary, name); err != nil {
			return err
		}
		temporaryExists = false
	}
	return operations.SyncDirectory()
}

func writeAll(file FileHandle, data []byte) error {
	written := 0
	for written < len(data) {
		n, err := file.Write(data[written:])
		written += n
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

func validateOverwriteTarget(operations WriteOperations, name string) error {
	info, err := operations.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to overwrite non-regular file %q", name)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) {
		return fmt.Errorf("refusing to overwrite file not owned by current user %q", name)
	}
	return nil
}

func randomTempName(name string) (string, error) {
	bytes := make([]byte, 12)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "." + name + ".tmp-" + hex.EncodeToString(bytes), nil
}

func (operations rootOperations) CheckDirectory() error {
	return CheckRoot(operations.root)
}

func (operations rootOperations) OpenTemp(name string) (FileHandle, error) {
	return operations.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
}

func (operations rootOperations) Lstat(name string) (os.FileInfo, error) {
	return operations.root.Lstat(name)
}

func (operations rootOperations) Link(oldName, newName string) error {
	return operations.root.Link(oldName, newName)
}

func (operations rootOperations) Rename(oldName, newName string) error {
	if operations.beforeRename != nil {
		operations.beforeRename()
	}
	return operations.root.Rename(oldName, newName)
}

func (operations rootOperations) Remove(name string) error {
	return operations.root.Remove(name)
}

func (operations rootOperations) SyncDirectory() error {
	directory, err := operations.root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
