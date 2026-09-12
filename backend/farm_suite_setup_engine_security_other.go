//go:build !windows

package backend

import (
	"fmt"
	"os"
)

func secureSuiteSetupPath(path string, directory bool) error {
	mode := os.FileMode(0o600)
	if directory {
		mode = 0o700
	}
	if err := os.Chmod(path, mode); err != nil {
		return err
	}
	return validateSuiteSetupPathSecurity(path, directory)
}

func validateSuiteSetupPathSecurity(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("invalid owner-only path type")
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if info.Mode().Perm() != want {
		return fmt.Errorf("owner-only mode is %o, want %o", info.Mode().Perm(), want)
	}
	return nil
}

func replaceSuiteSetupFile(oldPath, newPath string) error {
	if err := os.Rename(oldPath, newPath); err != nil {
		return err
	}
	return validateSuiteSetupPathSecurity(newPath, false)
}

func syncSuiteSetupDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
