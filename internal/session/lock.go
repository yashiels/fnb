package session

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"

	"github.com/yashiels/fnb/internal/exitcode"
)

type Lock struct {
	file *os.File
}

func AcquireLock(ctx context.Context, root *os.Root, clock Clock, timeout time.Duration) (*Lock, error) {
	clock = normalizeClock(clock)
	file, err := root.OpenFile("lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock: %w", err)
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return nil, fmt.Errorf("secure lock: %w", err)
	}
	deadline := clock.Now().Add(timeout)
	for {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return &Lock{file: file}, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			file.Close()
			return nil, fmt.Errorf("acquire lock: %w", err)
		}
		remaining := deadline.Sub(clock.Now())
		if remaining <= 0 {
			file.Close()
			return nil, exitcode.New(exitcode.ExitRateLimit, "lock_contention", "another fnb command holds the config lock")
		}
		wait := 100 * time.Millisecond
		if remaining < wait {
			wait = remaining
		}
		if err := clock.Sleep(ctx, wait); err != nil {
			file.Close()
			return nil, err
		}
	}
}

func (lock *Lock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
