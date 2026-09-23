package secure

import (
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestWriteFileCreatesReadableMode0600UnderRestrictiveUmask(t *testing.T) {
	directory := t.TempDir()
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	previous := syscall.Umask(0o777)
	defer syscall.Umask(previous)
	if err := WriteFile(root, "session.json", []byte("secret"), NoOverwrite); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(directory, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %04o", info.Mode().Perm())
	}
	content, err := os.ReadFile(filepath.Join(directory, "session.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "secret" {
		t.Fatalf("content = %q", content)
	}
}

func TestNoOverwritePreservesExistingTarget(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "session.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := WriteFile(root, "session.json", []byte("replacement"), NoOverwrite); err == nil {
		t.Fatal("expected error")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "original" {
		t.Fatalf("content = %q", content)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestSymlinkTargetIsNeverFollowed(t *testing.T) {
	for _, policy := range []Policy{NoOverwrite, Overwrite} {
		t.Run(policyName(policy), func(t *testing.T) {
			directory := t.TempDir()
			outside := filepath.Join(t.TempDir(), "outside")
			if err := os.WriteFile(outside, []byte("protected"), 0o600); err != nil {
				t.Fatal(err)
			}
			before := sha256.Sum256([]byte("protected"))
			if err := os.Symlink(outside, filepath.Join(directory, "session.json")); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if err := WriteFile(root, "session.json", []byte("replacement"), policy); err == nil {
				t.Fatal("expected error")
			}
			content, err := os.ReadFile(outside)
			if err != nil {
				t.Fatal(err)
			}
			after := sha256.Sum256(content)
			if before != after {
				t.Fatalf("outside content changed to %q", content)
			}
			assertNoTemporaryFiles(t, directory)
		})
	}
}

func TestGroupWritableParentIsRefusedWithoutTemporaryFile(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	err = WriteFile(root, "session.json", []byte("secret"), NoOverwrite)
	if err == nil || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("error = %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries = %v", entries)
	}
}

func TestWriteFileOperationOrder(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		want   []string
	}{
		{
			name:   "no overwrite",
			policy: NoOverwrite,
			want:   []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "link", "remove", "syncDirectory"},
		},
		{
			name:   "overwrite",
			policy: Overwrite,
			want:   []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "lstat", "rename", "syncDirectory"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &recordingOperations{}
			err := writeFile(recorder, "session.json", []byte("secret"), test.policy, fixedTempName)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(recorder.calls, test.want) {
				t.Fatalf("calls = %v, want %v", recorder.calls, test.want)
			}
			if recorder.temporaryExists {
				t.Fatal("temporary file remains")
			}
		})
	}
}

func TestWriteFileFaultsStopAndRemoveTemporaryFile(t *testing.T) {
	tests := []struct {
		name   string
		policy Policy
		step   string
		want   []string
	}{
		{name: "no overwrite checkDirectory", policy: NoOverwrite, step: "checkDirectory", want: []string{"checkDirectory"}},
		{name: "no overwrite openTemp", policy: NoOverwrite, step: "openTemp", want: []string{"checkDirectory", "openTemp"}},
		{name: "no overwrite chmod", policy: NoOverwrite, step: "chmod", want: []string{"checkDirectory", "openTemp", "chmod", "close", "remove"}},
		{name: "no overwrite write", policy: NoOverwrite, step: "write", want: []string{"checkDirectory", "openTemp", "chmod", "write", "close", "remove"}},
		{name: "no overwrite sync", policy: NoOverwrite, step: "sync", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "remove"}},
		{name: "no overwrite close", policy: NoOverwrite, step: "close", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "remove"}},
		{name: "no overwrite link", policy: NoOverwrite, step: "link", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "link", "remove"}},
		{name: "no overwrite remove", policy: NoOverwrite, step: "remove", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "link", "remove", "remove"}},
		{name: "no overwrite syncDirectory", policy: NoOverwrite, step: "syncDirectory", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "link", "remove", "syncDirectory"}},
		{name: "overwrite checkDirectory", policy: Overwrite, step: "checkDirectory", want: []string{"checkDirectory"}},
		{name: "overwrite openTemp", policy: Overwrite, step: "openTemp", want: []string{"checkDirectory", "openTemp"}},
		{name: "overwrite chmod", policy: Overwrite, step: "chmod", want: []string{"checkDirectory", "openTemp", "chmod", "close", "remove"}},
		{name: "overwrite write", policy: Overwrite, step: "write", want: []string{"checkDirectory", "openTemp", "chmod", "write", "close", "remove"}},
		{name: "overwrite sync", policy: Overwrite, step: "sync", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "remove"}},
		{name: "overwrite close", policy: Overwrite, step: "close", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "remove"}},
		{name: "overwrite lstat", policy: Overwrite, step: "lstat", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "lstat", "remove"}},
		{name: "overwrite rename", policy: Overwrite, step: "rename", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "lstat", "rename", "remove"}},
		{name: "overwrite syncDirectory", policy: Overwrite, step: "syncDirectory", want: []string{"checkDirectory", "openTemp", "chmod", "write", "sync", "close", "lstat", "rename", "syncDirectory"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := &recordingOperations{failAt: test.step}
			err := writeFile(recorder, "session.json", []byte("secret"), test.policy, fixedTempName)
			if err == nil {
				t.Fatal("expected error")
			}
			if !reflect.DeepEqual(recorder.calls, test.want) {
				t.Fatalf("calls = %v, want %v", recorder.calls, test.want)
			}
			if recorder.temporaryExists {
				t.Fatal("temporary file remains")
			}
		})
	}
}

func TestOverwriteSwapToSymlinkReplacesEntryWithoutFollowingIt(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "session.json")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(t.TempDir(), "sentinel")
	sentinelContent := []byte("protected")
	if err := os.WriteFile(sentinel, sentinelContent, 0o600); err != nil {
		t.Fatal(err)
	}
	before := sha256.Sum256(sentinelContent)
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	var hookErr error
	operations := rootOperations{
		root: root,
		beforeRename: func() {
			if err := os.Remove(target); err != nil {
				hookErr = err
				return
			}
			hookErr = os.Symlink(sentinel, target)
		},
	}
	if err := writeFile(operations, "session.json", []byte("replacement"), Overwrite, randomTempName); err != nil {
		t.Fatal(err)
	}
	if hookErr != nil {
		t.Fatal(hookErr)
	}
	sentinelAfter, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatal(err)
	}
	if before != sha256.Sum256(sentinelAfter) {
		t.Fatalf("sentinel content changed to %q", sentinelAfter)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() {
		t.Fatalf("target mode = %v", info.Mode())
	}
	content, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != "replacement" {
		t.Fatalf("content = %q", content)
	}
	assertNoTemporaryFiles(t, directory)
}

func TestPinnedRootSurvivesPathReplacement(t *testing.T) {
	parent := t.TempDir()
	directory := filepath.Join(parent, "original")
	moved := filepath.Join(parent, "moved")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := os.Rename(directory, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), directory); err != nil {
		t.Fatal(err)
	}
	if err := WriteFile(root, "session.json", []byte("secret"), NoOverwrite); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(moved, "session.json")); err != nil {
		t.Fatal(err)
	}
}

type recordingOperations struct {
	calls           []string
	failAt          string
	failed          bool
	temporaryExists bool
}

type recordingFile struct {
	operations *recordingOperations
}

func (operations *recordingOperations) CheckDirectory() error {
	return operations.record("checkDirectory")
}

func (operations *recordingOperations) OpenTemp(string) (FileHandle, error) {
	if err := operations.record("openTemp"); err != nil {
		return nil, err
	}
	operations.temporaryExists = true
	return &recordingFile{operations: operations}, nil
}

func (operations *recordingOperations) Lstat(string) (os.FileInfo, error) {
	if err := operations.record("lstat"); err != nil {
		return nil, err
	}
	return nil, os.ErrNotExist
}

func (operations *recordingOperations) Link(string, string) error {
	return operations.record("link")
}

func (operations *recordingOperations) Rename(string, string) error {
	if err := operations.record("rename"); err != nil {
		return err
	}
	operations.temporaryExists = false
	return nil
}

func (operations *recordingOperations) Remove(string) error {
	if err := operations.record("remove"); err != nil {
		return err
	}
	operations.temporaryExists = false
	return nil
}

func (operations *recordingOperations) SyncDirectory() error {
	return operations.record("syncDirectory")
}

func (operations *recordingOperations) record(step string) error {
	operations.calls = append(operations.calls, step)
	if operations.failAt == step && !operations.failed {
		operations.failed = true
		return errors.New("injected " + step + " failure")
	}
	return nil
}

func (file *recordingFile) Chmod(mode os.FileMode) error {
	if mode != 0o600 {
		return errors.New("unexpected mode")
	}
	return file.operations.record("chmod")
}

func (file *recordingFile) Write(data []byte) (int, error) {
	if err := file.operations.record("write"); err != nil {
		return 0, err
	}
	return len(data), nil
}

func (file *recordingFile) Sync() error {
	return file.operations.record("sync")
}

func (file *recordingFile) Close() error {
	return file.operations.record("close")
}

func fixedTempName(string) (string, error) {
	return ".session.json.tmp-fixed", nil
}

func assertNoTemporaryFiles(t *testing.T, directory string) {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("temporary file remains: %s", entry.Name())
		}
	}
}

func policyName(policy Policy) string {
	if policy == NoOverwrite {
		return "no-overwrite"
	}
	return "overwrite"
}
