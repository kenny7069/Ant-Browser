//go:build windows

package proxy

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const secureRuntimeNoFollowFlag = 0

func secureRuntimeOwnerSecurityAttributes() (*windows.SecurityAttributes, error) {
	// The protected DACL contains one ACE for the current token user only. The
	// descriptor is supplied at CreateFile/CreateDirectory time as well as
	// applied after creation, so Windows file modes are never used as a proxy
	// for access control.
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;OW)")
	if err != nil {
		return nil, fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func secureRuntimeCreateDirectory(path string) error {
	attributes, err := secureRuntimeOwnerSecurityAttributes()
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(path), attributes); err != nil {
		return err
	}
	if err := secureRuntimeApplyPermissions(path, true); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func secureRuntimeCreateExclusiveFile(path string) (*os.File, error) {
	attributes, err := secureRuntimeOwnerSecurityAttributes()
	if err != nil {
		return nil, err
	}
	handle, err := windows.CreateFile(
		windows.StringToUTF16Ptr(path),
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		attributes,
		windows.CREATE_NEW,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("create os file wrapper")
	}
	if err := secureRuntimeApplyPermissions(path, false); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, err
	}
	return file, nil
}

func secureRuntimeApplyPermissions(path string, directory bool) error {
	// Build the ACE from the current token SID rather than relying on an
	// inherited ACL or on os.FileMode, which has no owner-only meaning on
	// Windows.
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("get current Windows token user: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE
	}
	entries := []windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL,
		AccessMode:        windows.SET_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_USER,
			TrusteeValue: windows.TrusteeValueFromSID(tokenUser.User.Sid),
		},
	}}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("build owner-only Windows DACL: %w", err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("apply owner-only Windows DACL: %w", err)
	}
	return nil
}

func secureRuntimeRename(oldPath string, newPath string) error {
	return windows.Rename(oldPath, newPath)
}
