//go:build !windows

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func createFarmClientUpdateDirectoryPlatform(path string) (bool, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return false, err
	}
	return true, nil
}

func secureFarmClientUpdateDirectoryPlatform(path string, _ bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		return ErrFarmClientUpdateUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrFarmClientUpdateUnavailable
	}
	return nil
}

func secureFarmClientUpdateFilePlatform(path string) error {
	if err := os.Chmod(path, 0o700); err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return ErrFarmClientUpdateUnavailable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return ErrFarmClientUpdateUnavailable
	}
	return nil
}

func syncFarmClientUpdateDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("%w: sync update directory", ErrFarmClientUpdateApply)
	}
	return nil
}

// writeFarmClientUpdateState publishes one complete state snapshot.  The
// temporary file is synced before rename and the containing directory is
// synced afterwards, so recovery observes either the old or the new record.
func writeFarmClientUpdateState(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := secureFarmClientUpdateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".state-*")
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return ErrFarmClientUpdateApply
	}
	if _, err := temporary.Write(value); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return ErrFarmClientUpdateApply
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return ErrFarmClientUpdateApply
	}
	return syncFarmClientUpdateDirectory(directory)
}
