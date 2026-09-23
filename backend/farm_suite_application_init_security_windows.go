//go:build windows

package backend

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openSuiteApplicationSecureFile(path string, create bool) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	disposition := uint32(windows.OPEN_EXISTING)
	var security *windows.SecurityAttributes
	var descriptor *windows.SECURITY_DESCRIPTOR
	if create {
		disposition = windows.CREATE_NEW
		descriptor, err = suiteSetupWindowsSecurityDescriptor(false)
		if err != nil {
			return nil, ErrSuiteCanonicalApplicationInit
		}
		security = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, security, disposition, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrSuiteCanonicalApplicationInit
	}
	var identity windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &identity) != nil || identity.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 || validateSuiteTransportWindowsHandleSecurity(handle) != nil {
		file.Close()
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func writeSuiteApplicationRecoverableFile(path string, expected []byte) error {
	if len(expected) == 0 {
		return ErrSuiteCanonicalApplicationInit
	}
	file, err := openSuiteApplicationSecureFile(path, true)
	created := err == nil
	if errors.Is(err, windows.ERROR_FILE_EXISTS) || errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		file, err = openSuiteApplicationSecureFile(path, false)
	}
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	opened, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(opened, pathInfo) {
		return ErrSuiteCanonicalApplicationInit
	}
	raw, err := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	if err != nil || (!created && len(raw) == 0) || len(raw) > len(expected) || int64(len(raw)) != opened.Size() || !bytes.Equal(raw, expected[:len(raw)]) {
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
	if err != nil || pathErr != nil || final.Size() != int64(len(expected)) || !os.SameFile(opened, final) || !os.SameFile(final, pathFinal) || validateSuiteTransportWindowsHandleSecurity(windows.Handle(file.Fd())) != nil || file.Sync() != nil || syncSuiteSetupDirectory(filepath.Dir(path)) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func openSuiteApplicationDatabaseFence(path string, create bool) (*os.File, error) {
	return openSuiteApplicationSecureFile(path, create)
}

func openSuiteApplicationDataDirectory(path string) (*os.File, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	descriptor, err := suiteSetupWindowsSecurityDescriptor(true)
	if err != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	security := &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	err = windows.CreateDirectory(pointer, security)
	runtime.KeepAlive(descriptor)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	handle, _, err := openSuiteApplicationDirectoryHandle(path)
	if err != nil || validateSuiteSetupPathSecurity(path, true) != nil {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return nil, ErrSuiteCanonicalApplicationInit
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func openSuiteApplicationRootFence(path string) (*os.File, error) {
	handle, _, err := openSuiteApplicationDirectoryHandle(path)
	if err != nil || validateSuiteSetupPathSecurity(path, true) != nil {
		if handle != 0 {
			windows.CloseHandle(handle)
		}
		return nil, ErrSuiteCanonicalApplicationInit
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		windows.CloseHandle(handle)
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return file, nil
}

func openSuiteApplicationDirectoryHandle(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var identity windows.ByHandleFileInformation
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, identity, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, identity, err
	}
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil || identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || identity.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		windows.CloseHandle(handle)
		return 0, identity, ErrSuiteCanonicalApplicationInit
	}
	return handle, identity, nil
}

// A same-volume hard link is the no-clobber publication primitive on Windows:
// os.Link maps to CreateHardLink and fails when final already exists.
func publishSuiteApplicationFileNoReplace(staging, final string, validate func() error) error {
	handle, identity, err := openSuiteApplicationPublishHandle(staging)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer windows.CloseHandle(handle)
	if validate == nil || validate() != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if _, err := os.Lstat(final); err == nil || !os.IsNotExist(err) {
		return ErrSuiteCanonicalApplicationInit
	}
	if err := os.Link(staging, final); err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	finalHandle, finalIdentity, err := openSuiteApplicationPublishHandle(final)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer windows.CloseHandle(finalHandle)
	if identity.VolumeSerialNumber != finalIdentity.VolumeSerialNumber || identity.FileIndexHigh != finalIdentity.FileIndexHigh || identity.FileIndexLow != finalIdentity.FileIndexLow || validateSuiteSetupPathSecurity(final, false) != nil || syncSuiteSetupDirectory(filepath.Dir(final)) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func openSuiteApplicationPublishHandle(path string) (windows.Handle, windows.ByHandleFileInformation, error) {
	var identity windows.ByHandleFileInformation
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, identity, err
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_READ|windows.READ_CONTROL, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return 0, identity, err
	}
	if err := windows.GetFileInformationByHandle(handle, &identity); err != nil || identity.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		windows.CloseHandle(handle)
		return 0, identity, ErrSuiteCanonicalApplicationInit
	}
	if validateSuiteTransportWindowsHandleSecurity(handle) != nil {
		windows.CloseHandle(handle)
		return 0, identity, ErrSuiteCanonicalApplicationInit
	}
	return handle, identity, nil
}
