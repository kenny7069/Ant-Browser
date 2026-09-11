//go:build windows

package proxy

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type secureRuntimeSweepLock struct {
	file *os.File
}

func secureRuntimeAcquireSweepLock(path string) (*secureRuntimeSweepLock, error) {
	if path == "" {
		return nil, fmt.Errorf("empty secure proxy registry lock path")
	}
	// Open the exact lock file without following a reparse point. Its DACL is
	// explicitly reset below even when it existed from an earlier launch.
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("create secure proxy registry lock wrapper")
	}
	if err := secureRuntimeApplyPermissions(path, false); err != nil {
		_ = file.Close()
		return nil, err
	}
	var overlapped windows.Overlapped
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("acquire secure proxy registry lock: %w", err)
	}
	return &secureRuntimeSweepLock{file: file}, nil
}

func (lock *secureRuntimeSweepLock) Close() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	var overlapped windows.Overlapped
	unlockErr := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, 1, 0, &overlapped)
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
