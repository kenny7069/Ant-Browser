//go:build !windows

package proxy

import (
	"fmt"
	"golang.org/x/sys/unix"
	"os"
)

const secureRuntimeNoFollowFlag = unix.O_NOFOLLOW

func secureRuntimeCreateDirectory(path string) error {
	if err := os.Mkdir(path, secureRuntimeDirMode); err != nil {
		return err
	}
	if err := secureRuntimeApplyPermissions(path, true); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func secureRuntimeCreateExclusiveFile(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|secureRuntimeNoFollowFlag, secureRuntimeFileMode)
	if err != nil {
		return nil, err
	}
	if err := secureRuntimeApplyPermissions(path, false); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func secureRuntimeApplyPermissions(path string, directory bool) error {
	mode := os.FileMode(secureRuntimeFileMode)
	if directory {
		mode = secureRuntimeDirMode
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod secure proxy runtime path: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat secure proxy runtime path: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("invalid secure proxy runtime path")
	}
	if info.Mode().Perm() != mode.Perm() {
		return fmt.Errorf("secure proxy runtime permissions are %04o, want %04o", info.Mode().Perm(), mode.Perm())
	}
	return nil
}

func secureRuntimeRename(oldPath string, newPath string) error {
	return os.Rename(oldPath, newPath)
}

func secureRuntimeCheckOwnerAndMode(path string, infoMode os.FileMode, directory bool) error {
	want := os.FileMode(secureRuntimeFileMode)
	if directory {
		want = secureRuntimeDirMode
	}
	if infoMode.Perm() != want.Perm() {
		return fmt.Errorf("%w: secure proxy path permissions are %04o, want %04o", ErrSecureRuntimeAuth, infoMode.Perm(), want.Perm())
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return fmt.Errorf("inspect secure proxy path owner: %w", err)
	}
	if uint32(os.Getuid()) != stat.Uid {
		return fmt.Errorf("%w: secure proxy path is not owned by current user", ErrSecureRuntimeAuth)
	}
	return nil
}
