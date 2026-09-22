//go:build linux

package secure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	aclUserObject  = 0x01
	aclUser        = 0x02
	aclGroupObject = 0x04
	aclGroup       = 0x08
	aclMask        = 0x10
	aclOther       = 0x20
)

func aclViolation(directory *os.File) (string, error) {
	defaultACL, present, err := readXattr(directory, "system.posix_acl_default")
	if err != nil {
		return "", err
	}
	if present && len(defaultACL) > 0 {
		return "directory has default ACL entries granting other principals access", nil
	}
	accessACL, present, err := readXattr(directory, "system.posix_acl_access")
	if err != nil {
		return "", err
	}
	if !present {
		return "", nil
	}
	equivalent, err := accessACLEquivalentToMode(accessACL)
	if err != nil {
		return "", err
	}
	if !equivalent {
		return "directory has ACL entries granting other principals access", nil
	}
	return "", nil
}

func readXattr(file *os.File, name string) ([]byte, bool, error) {
	return readXattrWith(func(value []byte) (int, error) {
		return unix.Fgetxattr(int(file.Fd()), name, value)
	})
}

func readXattrWith(get func([]byte) (int, error)) ([]byte, bool, error) {
	size, err := get(nil)
	if errors.Is(err, unix.ENODATA) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	value := make([]byte, size)
	read, err := get(value)
	if err != nil {
		return nil, false, err
	}
	return value[:read], true, nil
}

func accessACLEquivalentToMode(value []byte) (bool, error) {
	if len(value) < 4 || (len(value)-4)%8 != 0 {
		return false, fmt.Errorf("malformed POSIX ACL")
	}
	if binary.LittleEndian.Uint32(value[:4]) != 2 {
		return false, fmt.Errorf("unsupported POSIX ACL version")
	}
	seen := map[uint16]int{}
	for offset := 4; offset < len(value); offset += 8 {
		tag := binary.LittleEndian.Uint16(value[offset : offset+2])
		seen[tag]++
		if tag == aclUser || tag == aclGroup {
			return false, nil
		}
	}
	return seen[aclUserObject] == 1 && seen[aclGroupObject] == 1 && seen[aclOther] == 1 && seen[aclMask] <= 1, nil
}
