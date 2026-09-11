//go:build darwin

package backend

import (
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
	// Walk one component at a time from the pinned root. O_NOFOLLOW on every
	// openat is equivalent to NOFOLLOW_ANY for this bounded relative walk and
	// works on all supported macOS filesystem implementations.
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NOFOLLOW
	// updateRoot is the already-validated trust anchor. Do not let Darwin's
	// O_NOFOLLOW_ANY reject immutable system aliases in its absolute prefix
	// (notably /var -> /private/var); every attacker-controlled descendant is
	// still opened relative to this pinned fd with O_NOFOLLOW_ANY.
	rootFD, err := unix.Open(updateRoot, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, ErrFarmClientUpdateIntegrity
	}
	fds := []int{rootFD}
	closeFDs := func() {
		for _, fd := range fds {
			_ = unix.Close(fd)
		}
	}
	if !farmClientSecureDarwinObject(rootFD, true) {
		closeFDs()
		return nil, ErrFarmClientUpdateIntegrity
	}
	parent := rootFD
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." || component == ".." {
			closeFDs()
			return nil, ErrFarmClientUpdateIntegrity
		}
		fd, openErr := unix.Openat(parent, component, flags|unix.O_DIRECTORY, 0)
		if openErr != nil || !farmClientSecureDarwinObject(fd, true) {
			if openErr == nil {
				_ = unix.Close(fd)
			}
			closeFDs()
			return nil, ErrFarmClientUpdateIntegrity
		}
		fds = append(fds, fd)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], flags, 0)
	if err != nil || !farmClientSecureDarwinObject(fd, false) {
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
	var pinned unix.Stat_t
	var current unix.Stat_t
	if unix.Fstat(fd, &pinned) != nil || unix.Fstatat(parent, parts[len(parts)-1], &current, unix.AT_SYMLINK_NOFOLLOW) != nil ||
		pinned.Dev != current.Dev || pinned.Ino != current.Ino || pinned.Size != current.Size || pinned.Ctim != current.Ctim {
		_ = file.Close()
		closeFDs()
		return nil, ErrFarmClientUpdateIntegrity
	}
	return &farmClientPinnedPayload{path: executablePath, close: func() {
		_ = file.Close()
		closeFDs()
	}}, nil
}

func farmClientSecureDarwinObject(fd int, directory bool) bool {
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
