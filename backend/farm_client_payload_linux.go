//go:build linux

package backend

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func openFarmClientPinnedPayload(updateRoot, executablePath string, slot FarmClientUpdateSlot) (*farmClientPinnedPayload, error) {
	relative, err := filepath.Rel(updateRoot, executablePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, ErrFarmClientUpdateIntegrity
	}
	parts := strings.Split(filepath.ToSlash(relative), "/")
	rootFD, err := unix.Open(updateRoot, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrFarmClientUpdateIntegrity
	}
	fds := []int{rootFD}
	closeFDs := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	if !farmClientSecureUnixObject(rootFD, true) {
		closeFDs()
		return nil, ErrFarmClientUpdateIntegrity
	}
	parent := rootFD
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." || component == ".." {
			closeFDs()
			return nil, ErrFarmClientUpdateIntegrity
		}
		fd, openErr := unix.Openat(parent, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr != nil || !farmClientSecureUnixObject(fd, true) {
			if openErr == nil {
				_ = unix.Close(fd)
			}
			closeFDs()
			return nil, ErrFarmClientUpdateIntegrity
		}
		fds = append(fds, fd)
		parent = fd
	}
	entry := parts[len(parts)-1]
	fd, err := unix.Openat(parent, entry, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil || !farmClientSecureUnixObject(fd, false) {
		if err == nil {
			_ = unix.Close(fd)
		}
		closeFDs()
		return nil, ErrFarmClientUpdateIntegrity
	}
	file := os.NewFile(uintptr(fd), executablePath)
	if file == nil || verifyFarmClientPinnedFile(file, slot.SHA256, slot.Size) != nil {
		if file != nil {
			_ = file.Close()
		} else {
			_ = unix.Close(fd)
		}
		closeFDs()
		return nil, ErrFarmClientUpdateIntegrity
	}
	if _, statErr := os.Stat("/proc/self/fd"); statErr != nil {
		_ = file.Close()
		closeFDs()
		return nil, errors.Join(ErrFarmClientUpdateApply, statErr)
	}
	return &farmClientPinnedPayload{
		path:       "/proc/self/fd/3",
		extraFiles: []*os.File{file},
		close: func() {
			_ = file.Close()
			closeFDs()
		},
	}, nil
}

func farmClientSecureUnixObject(fd int, directory bool) bool {
	if fd < 0 {
		return false
	}
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	mode := stat.Mode
	if directory {
		return mode&unix.S_IFMT == unix.S_IFDIR && mode&0o077 == 0
	}
	return mode&unix.S_IFMT == unix.S_IFREG && stat.Nlink == 1 && mode&(unix.S_ISUID|unix.S_ISGID|0o022) == 0
}
