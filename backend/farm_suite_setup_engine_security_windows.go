//go:build windows

package backend

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const suiteSetupWindowsFileAllAccess = windows.ACCESS_MASK(0x1f01ff)

func suiteSetupWindowsSecurityDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, fmt.Errorf("resolve current Windows user: %w", err)
	}
	sid := user.User.Sid.String()
	sddl := "O:" + sid + "G:" + sid + "D:P(A;;FA;;;" + sid + ")"
	if directory {
		sddl = "O:" + sid + "G:" + sid + "D:P(A;OICI;FA;;;" + sid + ")"
	}
	return windows.SecurityDescriptorFromString(sddl)
}

func secureSuiteSetupPath(path string, directory bool) error {
	if err := rejectSuiteSetupWindowsReparsePoint(path); err != nil {
		return err
	}
	descriptor, err := suiteSetupWindowsSecurityDescriptor(directory)
	if err != nil {
		return err
	}
	owner, _, ownerErr := descriptor.Owner()
	dacl, defaulted, daclErr := descriptor.DACL()
	if ownerErr != nil || daclErr != nil || dacl == nil || defaulted {
		return fmt.Errorf("build owner-only Windows DACL")
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return fmt.Errorf("apply owner-only Windows DACL: %w", err)
	}
	runtime.KeepAlive(descriptor)
	return validateSuiteSetupPathSecurity(path, directory)
}

func validateSuiteSetupPathSecurity(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (directory && !info.IsDir()) || (!directory && !info.Mode().IsRegular()) {
		return fmt.Errorf("invalid owner-only Windows path type")
	}
	if err := rejectSuiteSetupWindowsReparsePoint(path); err != nil {
		return err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return fmt.Errorf("resolve current Windows user: %w", err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect owner-only Windows DACL: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, user.User.Sid) {
		return fmt.Errorf("Windows path owner is not current user")
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("Windows DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return fmt.Errorf("Windows DACL is not owner-only")
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		return fmt.Errorf("inspect Windows owner ACE: %w", err)
	}
	wantFlags := uint8(windows.NO_INHERITANCE)
	if directory {
		wantFlags = uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	fullControl := ace.Mask == windows.GENERIC_ALL || ace.Mask == suiteSetupWindowsFileAllAccess
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != wantFlags ||
		!fullControl || !windows.EqualSid(aceSID, user.User.Sid) {
		return fmt.Errorf("Windows DACL entry is not current-user-only full control")
	}
	return nil
}

func rejectSuiteSetupWindowsReparsePoint(path string) error {
	attributes, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("Windows path is a reparse point")
	}
	return nil
}

func replaceSuiteSetupFile(oldPath, newPath string) error {
	from, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return err
	}
	to, err := windows.UTF16PtrFromString(newPath)
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return validateSuiteSetupPathSecurity(newPath, false)
}

func syncSuiteSetupDirectory(string) error { return nil }
