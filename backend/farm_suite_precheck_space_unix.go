//go:build !windows

package backend

import (
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"syscall"
)

func suitePrecheckResolvedPath(path string) (string, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return "", nil, ErrSuiteCanonicalPrecheck
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, ErrSuiteCanonicalPrecheck
	}
	return resolved, info, nil
}

func suitePrecheckAvailableSpace(path string) (string, uint64, error) {
	var filesystem syscall.Statfs_t
	if err := syscall.Statfs(path, &filesystem); err != nil || filesystem.Bsize == 0 {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	var file syscall.Stat_t
	if err := syscall.Stat(path, &file); err != nil {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	high, available := bits.Mul64(uint64(filesystem.Bavail), uint64(filesystem.Bsize))
	if high != 0 {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	return fmt.Sprintf("device-%d", file.Dev), available, nil
}
