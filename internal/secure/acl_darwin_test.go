//go:build darwin

package secure

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestACLViolationFallbackTreatsOnlyENOATTRAsAbsent(t *testing.T) {
	primaryErr := errors.New("primary inspection failed")
	tests := []struct {
		name    string
		err     error
		wantErr bool
	}{
		{name: "absent", err: unix.ENOATTR},
		{name: "unsupported", err: unix.ENOTSUP, wantErr: true},
		{name: "permission", err: unix.EPERM, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := aclViolationWith(
				func() (bool, error) { return false, primaryErr },
				func() (int, error) { return 0, test.err },
			)
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v", err)
			}
			if test.wantErr && !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}
		})
	}
}
