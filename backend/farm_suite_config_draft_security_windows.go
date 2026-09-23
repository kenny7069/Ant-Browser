//go:build windows

package backend

import (
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

func secureSuiteConfigDraftApplicationRootHandle(path string, expected os.FileInfo) (result os.FileInfo, resultErr error) {
	pathPointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	handle, err := windows.CreateFile(pathPointer,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	directory := os.NewFile(uintptr(handle), path)
	if directory == nil {
		_ = windows.CloseHandle(handle)
		return nil, ErrSuiteCanonicalConfigDraft
	}
	defer func() {
		if err := directory.Close(); resultErr == nil && err != nil {
			result, resultErr = nil, ErrSuiteCanonicalConfigDraft
		}
	}()
	var handleInfo windows.ByHandleFileInformation
	opened, err := directory.Stat()
	if err != nil || windows.GetFileInformationByHandle(handle, &handleInfo) != nil || expected == nil || !opened.IsDir() || !os.SameFile(expected, opened) || handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	descriptor, err := suiteSetupWindowsSecurityDescriptor(true)
	if err != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	owner, _, ownerErr := descriptor.Owner()
	dacl, defaulted, daclErr := descriptor.DACL()
	if ownerErr != nil || daclErr != nil || dacl == nil || defaulted {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	if err := windows.SetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	runtime.KeepAlive(descriptor)
	if validateSuiteConfigDraftWindowsHandleSecurity(handle) != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	secured, err := directory.Stat()
	if err != nil || !secured.IsDir() || !os.SameFile(opened, secured) {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(secured, pathInfo) || rejectSuiteSetupWindowsReparsePoint(path) != nil || validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	return secured, nil
}

func validateSuiteConfigDraftWindowsHandleSecurity(handle windows.Handle) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return ErrSuiteCanonicalConfigDraft
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return ErrSuiteCanonicalConfigDraft
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrSuiteCanonicalConfigDraft
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return ErrSuiteCanonicalConfigDraft
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		return ErrSuiteCanonicalConfigDraft
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	fullControl := ace.Mask == windows.GENERIC_ALL || ace.Mask == suiteSetupWindowsFileAllAccess
	wantFlags := uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != wantFlags || !fullControl || !windows.EqualSid(aceSID, user.User.Sid) {
		return ErrSuiteCanonicalConfigDraft
	}
	return nil
}
