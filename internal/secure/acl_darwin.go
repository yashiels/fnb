//go:build darwin

package secure

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	attributeBitmapCount       = 5
	attributeExtendedSecurity  = 0x00400000
	fileSecurityNoACL          = 0xffffffff
	fileSecurityHeaderSize     = 44
	fileSecurityEntryCount     = 36
	attributeReferencePosition = 4
)

type attributeList struct {
	BitmapCount uint16
	Reserved    uint16
	Common      uint32
	Volume      uint32
	Directory   uint32
	File        uint32
	Fork        uint32
}

func aclViolation(directory *os.File) (string, error) {
	return aclViolationWith(
		func() (bool, error) {
			return extendedSecurityHasACL(directory)
		},
		func() (int, error) {
			return unix.Fgetxattr(int(directory.Fd()), "com.apple.system.Security", nil)
		},
	)
}

func aclViolationWith(extendedSecurity func() (bool, error), fallback func() (int, error)) (string, error) {
	hasACL, err := extendedSecurity()
	if err == nil {
		if hasACL {
			return "directory has ACL entries granting other principals access", nil
		}
		return "", nil
	}
	size, err := fallback()
	if errors.Is(err, unix.ENOATTR) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if size > 0 {
		return "directory has ACL entries granting other principals access", nil
	}
	return "", nil
}

func extendedSecurityHasACL(directory *os.File) (bool, error) {
	attributes := attributeList{BitmapCount: attributeBitmapCount, Common: attributeExtendedSecurity}
	buffer := make([]byte, 8192)
	_, _, errno := unix.Syscall6(
		unix.SYS_FGETATTRLIST,
		directory.Fd(),
		uintptr(unsafe.Pointer(&attributes)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		0,
		0,
	)
	if errno != 0 {
		return false, errno
	}
	total := int(binary.LittleEndian.Uint32(buffer[:4]))
	if total < attributeReferencePosition+8 || total > len(buffer) {
		return false, fmt.Errorf("malformed extended security attributes")
	}
	reference := buffer[attributeReferencePosition : attributeReferencePosition+8]
	offset := int(int32(binary.LittleEndian.Uint32(reference[:4]))) + attributeReferencePosition
	length := int(binary.LittleEndian.Uint32(reference[4:]))
	if length == 0 {
		return false, nil
	}
	if offset < attributeReferencePosition+8 || offset+length > total || length < fileSecurityHeaderSize {
		return false, fmt.Errorf("malformed extended security ACL")
	}
	entryCount := binary.LittleEndian.Uint32(buffer[offset+fileSecurityEntryCount : offset+fileSecurityEntryCount+4])
	return entryCount != fileSecurityNoACL && entryCount > 0, nil
}
