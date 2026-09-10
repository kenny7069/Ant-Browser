//go:build !windows

package proxy

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type secureRuntimeSweepLock struct {
	file *os.File
}

func secureRuntimeAcquireSweepLock(path string) (*secureRuntimeSweepLock, error) {
	if path == "" {
		return nil, fmt.Errorf("empty secure proxy registry lock path")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|secureRuntimeNoFollowFlag, secureRuntimeFileMode)
	if err != nil {
		return nil, err
	}
	if err := secureRuntimeApplyPermissions(path, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire secure proxy registry lock: %w", err)
	}
	return &secureRuntimeSweepLock{file: file}, nil
}

func (lock *secureRuntimeSweepLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	unlockErr := unix.Flock(int(lock.file.Fd()), unix.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if unlockErr != nil {
		return fmt.Errorf("release secure proxy registry lock: %w", unlockErr)
	}
	if closeErr != nil && !errors.Is(closeErr, os.ErrClosed) {
		return closeErr
	}
	return nil
}
