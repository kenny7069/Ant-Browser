//go:build !windows

package backend

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

func writeSuiteApplicationRecoverableFile(path string, expected []byte) error {
	if len(expected) == 0 {
		return ErrSuiteCanonicalApplicationInit
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	created := err == nil
	if errors.Is(err, os.ErrExist) {
		file, err = os.OpenFile(path, os.O_RDWR, 0)
	}
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !os.SameFile(info, pathInfo) {
		return ErrSuiteCanonicalApplicationInit
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil || (!created && len(raw) == 0) || len(raw) > len(expected) || int64(len(raw)) != info.Size() || !bytes.Equal(raw, expected[:len(raw)]) {
		return ErrSuiteCanonicalApplicationInit
	}
	if len(raw) < len(expected) {
		if _, err := file.Seek(int64(len(raw)), io.SeekStart); err != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		written, err := file.Write(expected[len(raw):])
		if err != nil || written != len(expected)-len(raw) {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	final, err := file.Stat()
	pathFinal, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || final.Size() != int64(len(expected)) || !os.SameFile(info, final) || !os.SameFile(final, pathFinal) || file.Sync() != nil || syncSuiteSetupDirectory(filepath.Dir(path)) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func openSuiteApplicationDatabaseFence(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	stat, ok := info.Sys().(*syscall.Stat_t)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || !os.SameFile(info, pathInfo) {
		file.Close()
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func openSuiteApplicationDataDirectory(path string) (*os.File, error) {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	if validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !info.IsDir() || !os.SameFile(info, pathInfo) {
		file.Close()
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func openSuiteApplicationRootFence(path string) (*os.File, error) {
	if validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	info, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !info.IsDir() || !os.SameFile(info, pathInfo) {
		file.Close()
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func publishSuiteApplicationFileNoReplace(staging, final string, validate func() error) error {
	stagingInfo, err := os.Lstat(staging)
	if err != nil || !stagingInfo.Mode().IsRegular() || stagingInfo.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(staging, false) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if _, err := os.Lstat(final); err == nil || !os.IsNotExist(err) {
		return ErrSuiteCanonicalApplicationInit
	}
	file, err := os.Open(staging)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	handleInfo, err := file.Stat()
	if err != nil || !os.SameFile(stagingInfo, handleInfo) || validate == nil || validate() != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if err := os.Link(staging, final); err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	finalInfo, err := os.Lstat(final)
	if err != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(final, false) != nil || syncSuiteSetupDirectory(filepath.Dir(final)) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}
