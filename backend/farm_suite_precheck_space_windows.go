//go:build windows

package backend

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func suitePrecheckResolvedPath(path string) (string, os.FileInfo, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !suitePrecheckWindowsResolvedPathMatches(resolved, path) {
		return "", nil, ErrSuiteCanonicalPrecheck
	}
	volume := filepath.VolumeName(path)
	if volume == "" {
		return "", nil, ErrSuiteCanonicalPrecheck
	}
	current := volume + string(filepath.Separator)
	remainder := strings.TrimPrefix(path, current)
	for _, segment := range strings.Split(remainder, string(filepath.Separator)) {
		if segment == "" {
			continue
		}
		current = filepath.Join(current, segment)
		if err := rejectSuiteSetupWindowsReparsePoint(current); err != nil {
			return "", nil, ErrSuiteCanonicalPrecheck
		}
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, ErrSuiteCanonicalPrecheck
	}
	return resolved, info, nil
}

func suitePrecheckAvailableSpace(path string) (string, uint64, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	volumeBuffer := make([]uint16, 32768)
	if err := windows.GetVolumePathName(pathPointer, &volumeBuffer[0], uint32(len(volumeBuffer))); err != nil {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	volume := windows.UTF16ToString(volumeBuffer)
	if volume == "" {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	volumePointer, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(volumePointer, &available, nil, nil); err != nil {
		return "", 0, ErrSuiteCanonicalPrecheckCapacity
	}
	return strings.ToLower(volume), available, nil
}
