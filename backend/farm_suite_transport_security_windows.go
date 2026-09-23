//go:build windows

package backend

import (
	"io"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openSuiteTransportReceiptHandle(path string, create bool) (*os.File, error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	disposition := uint32(windows.OPEN_EXISTING)
	var security *windows.SecurityAttributes
	var descriptor *windows.SECURITY_DESCRIPTOR
	if create {
		disposition = windows.CREATE_NEW
		descriptor, err = suiteSetupWindowsSecurityDescriptor(false)
		if err != nil {
			return nil, ErrSuiteTransportReceipt
		}
		security = &windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
	}
	handle, err := windows.CreateFile(pathPointer,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, security, disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	runtime.KeepAlive(descriptor)
	if err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrSuiteTransportReceipt
	}
	return file, nil
}

func validateSuiteTransportRecoveryCandidate(path string, info os.FileInfo) error {
	if info == nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteTransportReceipt
	}
	return nil
}

func writeSuiteTransportReceiptHandle(file *os.File, expected os.FileInfo, raw []byte, recovery *suiteTransportReceiptRecoveryEvidence) error {
	if file == nil || expected == nil || len(raw) == 0 || len(raw) > suiteTransportReceiptMaxBytes {
		return ErrSuiteTransportReceipt
	}
	handle := windows.Handle(file.Fd())
	var information windows.ByHandleFileInformation
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(expected, opened) || windows.GetFileInformationByHandle(handle, &information) != nil || information.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return ErrSuiteTransportReceipt
	}
	if verifySuiteTransportReceiptRecoveryBytes(file, opened, recovery) != nil {
		return ErrSuiteTransportReceipt
	}
	descriptor, err := suiteSetupWindowsSecurityDescriptor(false)
	if err != nil {
		return ErrSuiteTransportReceipt
	}
	owner, _, ownerErr := descriptor.Owner()
	dacl, defaulted, daclErr := descriptor.DACL()
	if ownerErr != nil || daclErr != nil || dacl == nil || defaulted {
		return ErrSuiteTransportReceipt
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return ErrSuiteTransportReceipt
	}
	runtime.KeepAlive(descriptor)
	if validateSuiteTransportWindowsHandleSecurity(handle) != nil || file.Truncate(0) != nil {
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
	if err != nil || !final.Mode().IsRegular() || final.Size() != int64(len(raw)) || !os.SameFile(opened, final) || validateSuiteTransportWindowsHandleSecurity(handle) != nil {
		return ErrSuiteTransportReceipt
	}
	return nil
}

func validateSuiteTransportWindowsHandleSecurity(handle windows.Handle) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ErrSuiteTransportReceipt
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrSuiteTransportReceipt
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return ErrSuiteTransportReceipt
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrSuiteTransportReceipt
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return ErrSuiteTransportReceipt
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		return ErrSuiteTransportReceipt
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	fullControl := ace.Mask == windows.GENERIC_ALL || ace.Mask == suiteSetupWindowsFileAllAccess
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != uint8(windows.NO_INHERITANCE) || !fullControl || !windows.EqualSid(aceSID, user.User.Sid) {
		return ErrSuiteTransportReceipt
	}
	return nil
}
