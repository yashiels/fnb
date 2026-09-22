//go:build linux

package secure

import (
	"errors"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadXattrTreatsOnlyENODATAAsAbsent(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		present bool
		wantErr bool
	}{
		{name: "absent", err: unix.ENODATA},
		{name: "unsupported", err: unix.ENOTSUP, wantErr: true},
		{name: "permission", err: unix.EPERM, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, present, err := readXattrWith(func([]byte) (int, error) {
				return 0, test.err
			})
			if present != test.present {
				t.Fatalf("present = %v", present)
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("error = %v", err)
			}
			if test.wantErr && !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}
		})
	}
}
