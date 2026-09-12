//go:build windows

package backend

import (
	"strings"

	"golang.org/x/sys/windows"
)

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
