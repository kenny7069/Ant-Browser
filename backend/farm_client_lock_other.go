//go:build windows

package backend

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

// Windows fallback uses an exclusive create. A stale lock file is conservatively
// treated as an active instance; the normal process lifecycle removes it.
type FarmClientInstanceLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func AcquireFarmClientInstanceLock(stateRoot string) (*FarmClientInstanceLock, error) {
	return acquireFarmClientFileLock(filepath.Join(stateRoot, ".ant-farm-client.lock"))
}

func acquireFarmClientFileLock(path string) (*FarmClientInstanceLock, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: acquire instance lock: %v", ErrFarmClientAlreadyRun, err)
	}
	lock := &FarmClientInstanceLock{file: file}
	if err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, ^uint32(0), ^uint32(0), &lock.overlapped); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: acquire instance lock: %v", ErrFarmClientAlreadyRun, err)
	}
	return lock, nil
}

func (lock *FarmClientInstanceLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := windows.UnlockFileEx(windows.Handle(lock.file.Fd()), 0, ^uint32(0), ^uint32(0), &lock.overlapped)
	closeErr := lock.file.Close()
	lock.file = nil
	if err == nil {
		err = closeErr
	}
	return err
}
