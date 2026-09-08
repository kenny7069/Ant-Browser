//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package backend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// FarmClientInstanceLock is an advisory process lock scoped to one state root.
// The lock file is intentionally retained after release; the kernel lock, not
// file existence, is the source of truth and therefore survives crashes.
type FarmClientInstanceLock struct {
	file *os.File
}

func AcquireFarmClientInstanceLock(stateRoot string) (*FarmClientInstanceLock, error) {
	path := filepath.Join(stateRoot, ".ant-farm-client.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("%w: open instance lock: %v", ErrFarmClientAlreadyRun, err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrFarmClientAlreadyRun
		}
		return nil, fmt.Errorf("%w: acquire instance lock: %v", ErrFarmClientAlreadyRun, err)
	}
	return &FarmClientInstanceLock{file: file}, nil
}

func (lock *FarmClientInstanceLock) Release() error {
	if lock == nil || lock.file == nil {
		return nil
	}
	err := syscall.Flock(int(lock.file.Fd()), syscall.LOCK_UN)
	closeErr := lock.file.Close()
	lock.file = nil
	if err != nil {
		return err
	}
	return closeErr
}
