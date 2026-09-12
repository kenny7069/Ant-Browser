//go:build !windows

package backend

import (
	"io"
	"os"
)

func openSuiteTransportReceiptHandle(path string, create bool) (*os.File, error) {
	flags := os.O_RDWR
	if create {
		flags |= os.O_CREATE | os.O_EXCL
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	return file, nil
}

func writeSuiteTransportReceiptHandle(file *os.File, expected os.FileInfo, raw []byte) error {
	if file == nil || expected == nil || len(raw) == 0 || len(raw) > suiteTransportReceiptMaxBytes {
		return ErrSuiteTransportReceipt
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) {
		return ErrSuiteTransportReceipt
	}
	if file.Chmod(0o600) != nil || file.Truncate(0) != nil {
		return ErrSuiteTransportReceipt
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return ErrSuiteTransportReceipt
	}
	written, err := file.Write(raw)
	if err != nil || written != len(raw) || file.Sync() != nil {
		return ErrSuiteTransportReceipt
	}
	final, err := file.Stat()
	if err != nil || !final.Mode().IsRegular() || final.Mode().Perm() != 0o600 || final.Size() != int64(len(raw)) || !os.SameFile(opened, final) {
		return ErrSuiteTransportReceipt
	}
	return nil
}
