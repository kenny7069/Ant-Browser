//go:build !windows

package backend

import (
	"io"
	"os"
	"syscall"
)

func openSuiteTransportReceiptHandle(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil && !create {
		file, err = os.Open(path)
	}
	if err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	return file, nil
}

func writeSuiteTransportReceiptHandle(file *os.File, expected os.FileInfo, raw []byte, recovery *suiteTransportReceiptRecoveryEvidence) error {
	if file == nil || expected == nil || len(raw) == 0 || len(raw) > suiteTransportReceiptMaxBytes {
		return ErrSuiteTransportReceipt
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return ErrSuiteTransportReceipt
	}
	if verifySuiteTransportReceiptRecoveryBytes(file, opened, recovery) != nil {
		return ErrSuiteTransportReceipt
	}
	if file.Chmod(0o600) != nil {
		return ErrSuiteTransportReceipt
	}
	writable := file
	if opened.Mode().Perm()&0o200 == 0 {
		writable, err = os.OpenFile(file.Name(), os.O_RDWR, 0)
		if err != nil {
			return ErrSuiteTransportReceipt
		}
		defer writable.Close()
		writableInfo, statErr := writable.Stat()
		if statErr != nil || !os.SameFile(opened, writableInfo) || verifySuiteTransportReceiptRecoveryBytes(writable, writableInfo, recovery) != nil {
			return ErrSuiteTransportReceipt
		}
	}
	if writable.Truncate(0) != nil {
		return ErrSuiteTransportReceipt
	}
	if _, err := writable.Seek(0, io.SeekStart); err != nil {
		return ErrSuiteTransportReceipt
	}
	written, err := writable.Write(raw)
	if err != nil || written != len(raw) || writable.Sync() != nil {
		return ErrSuiteTransportReceipt
	}
	final, err := file.Stat()
	if err != nil || !final.Mode().IsRegular() || final.Mode().Perm() != 0o600 || final.Size() != int64(len(raw)) || !os.SameFile(opened, final) {
		return ErrSuiteTransportReceipt
	}
	return nil
}

func validateSuiteTransportRecoveryCandidate(path string, info os.FileInfo) error {
	if info == nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrSuiteTransportReceipt
	}
	if info.Size() != 0 {
		if validateSuiteSetupPathSecurity(path, false) != nil {
			return ErrSuiteTransportReceipt
		}
		return nil
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	permissions := info.Mode().Perm()
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || (permissions != 0o400 && permissions != 0o600) {
		return ErrSuiteTransportReceipt
	}
	return nil
}
