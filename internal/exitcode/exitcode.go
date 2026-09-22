package exitcode

import (
	"errors"
	"fmt"
)

const (
	ExitOK              = 0
	ExitGeneral         = 1
	ExitUsage           = 2
	ExitAuthentication  = 3
	ExitAccount         = 4
	ExitRateLimit       = 5
	ExitNetwork         = 6
	ExitData            = 7
	ExitApprovalPending = 8
	ExitApprovalExpired = 9
)

type Error struct {
	Exit    int
	Code    string
	Message string
	Cause   error
}

func (e *Error) Error() string {
	return e.Message
}

func (e *Error) Unwrap() error {
	return e.Cause
}

func New(exit int, code, message string) *Error {
	return &Error{Exit: exit, Code: code, Message: message}
}

func Wrap(exit int, code, message string, cause error) *Error {
	return &Error{Exit: exit, Code: code, Message: message, Cause: cause}
}

func Code(err error) int {
	var coded *Error
	if errors.As(err, &coded) {
		return coded.Exit
	}
	return ExitGeneral
}

func Slug(err error) string {
	var coded *Error
	if errors.As(err, &coded) && coded.Code != "" {
		return coded.Code
	}
	return "internal_error"
}

func Usagef(format string, args ...any) *Error {
	return New(ExitUsage, "usage", fmt.Sprintf(format, args...))
}
