//go:build !windows

package backend

import (
	"fmt"
	"math/bits"
	"syscall"
)

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
