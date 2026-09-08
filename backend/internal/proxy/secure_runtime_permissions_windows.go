//go:build windows

package proxy

import (
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const secureRuntimeNoFollowFlag = 0

// FILE_ALL_ACCESS is the access mask produced when Windows resolves the FA
// SDDL right. ACLFromEntries may preserve GENERIC_ALL instead, so inspection
// accepts either equivalent full-control representation while still requiring
// exactly one ACE for the current user.
const secureRuntimeWindowsFileAllAccess windows.ACCESS_MASK = 0x001f01ff

func secureRuntimeOwnerSecurityAttributes(directory bool) (*windows.SecurityAttributes, error) {
	// The protected DACL contains one ACE for the current token user only. The
	// descriptor is supplied at CreateFile/CreateDirectory time as well as
	// applied after creation, so Windows file modes are never used as a proxy
	// for access control.
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, fmt.Errorf("get current Windows token user: %w", err)
	}
	sid := tokenUser.User.Sid.String()
	if sid == "" {
		return nil, fmt.Errorf("format current Windows token SID")
	}
	// Administrators running with an elevated token can otherwise create an
	// object whose owner is the BUILTIN\Administrators group even though its
	// only DACL ACE names the token user. Pin the owner in the create-time
	// descriptor as well as the protected owner-only DACL so the immediately
	// following authenticity check observes the same SID on every Windows
	// token type.
	sddl := fmt.Sprintf("O:%sD:P(A;;FA;;;%s)", sid, sid)
	if directory {
		sddl = fmt.Sprintf("O:%sD:P(A;OICI;FA;;;%s)", sid, sid)
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build owner-only security descriptor: %w", err)
	}
	return &windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}, nil
}

func secureRuntimeCreateDirectory(path string) error {
	attributes, err := secureRuntimeOwnerSecurityAttributes(true)
	if err != nil {
		return err
	}
	if err := windows.CreateDirectory(windows.StringToUTF16Ptr(path), attributes); err != nil {
		return err
	}
	if err := secureRuntimeRejectReparsePoint(path); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := secureRuntimeApplyPermissions(path, true); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func secureRuntimeCreateExclusiveFile(path string) (*os.File, error) {
	attributes, err := secureRuntimeOwnerSecurityAttributes(false)
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
	if err := secureRuntimeRejectReparsePoint(path); err != nil {
		return err
	}
	// Reuse the exact protected SDDL shape supplied at create time. Building an
	// inheritable GENERIC_ALL entry through SetEntriesInAcl can canonicalize it
	// into separate effective and inherit-only ACEs on a directory. Both entries
	// name the owner, but the secure runtime contract deliberately requires one
	// physical owner ACE so inspection stays narrow and deterministic.
	attributes, err := secureRuntimeOwnerSecurityAttributes(directory)
	if err != nil {
		return err
	}
	acl, _, err := attributes.SecurityDescriptor.DACL()
	if err != nil || acl == nil {
		if err != nil {
			return fmt.Errorf("extract owner-only Windows DACL: %w", err)
		}
		return fmt.Errorf("extract owner-only Windows DACL: missing DACL")
	}
	err = windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
	runtime.KeepAlive(attributes)
	if err != nil {
		return fmt.Errorf("apply owner-only Windows DACL: %w", err)
	}
	return nil
}

func secureRuntimeRename(oldPath string, newPath string) error {
	return windows.Rename(oldPath, newPath)
}

func secureRuntimeRejectReparsePoint(path string) error {
	attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(path))
	if err != nil {
		return fmt.Errorf("inspect secure proxy Windows path attributes: %w", err)
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: secure proxy Windows path is a reparse point", ErrSecureRuntimePath)
	}
	return nil
}

func secureRuntimeCheckOwnerAndMode(path string, infoMode os.FileMode, directory bool) error {
	if infoMode&os.ModeSymlink != 0 || (directory && !infoMode.IsDir()) || (!directory && !infoMode.IsRegular()) {
		return fmt.Errorf("%w: invalid secure proxy path", ErrSecureRuntimeAuth)
	}
	if err := secureRuntimeRejectReparsePoint(path); err != nil {
		return err
	}
	tokenUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("inspect secure proxy Windows token user: %w", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect secure proxy Windows DACL: %w", err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, tokenUser.User.Sid) {
		if err != nil {
			return fmt.Errorf("inspect secure proxy Windows owner: %w", err)
		}
		return fmt.Errorf("%w: secure proxy Windows path is not owned by current user", ErrSecureRuntimeAuth)
	}
	control, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("inspect secure proxy Windows DACL control: %w", err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("%w: secure proxy Windows DACL is inheritable", ErrSecureRuntimeAuth)
	}
	acl, _, err := sd.DACL()
	if err != nil || acl == nil {
		if err != nil {
			return fmt.Errorf("inspect secure proxy Windows DACL entries: %w", err)
		}
		return fmt.Errorf("%w: secure proxy Windows DACL is missing", ErrSecureRuntimeAuth)
	}
	if acl.AceCount != 1 {
		return fmt.Errorf("%w: secure proxy Windows DACL must contain one owner entry (got %d)", ErrSecureRuntimeAuth, acl.AceCount)
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(acl, 0, &ace); err != nil || ace == nil {
		if err != nil {
			return fmt.Errorf("inspect secure proxy Windows owner ACE: %w", err)
		}
		return fmt.Errorf("%w: missing secure proxy Windows owner ACE", ErrSecureRuntimeAuth)
	}
	wantFlags := uint8(windows.NO_INHERITANCE)
	if directory {
		wantFlags = uint8(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags != wantFlags || !secureRuntimeWindowsOwnerFullControlMask(ace.Mask) || !windows.EqualSid(aceSID, tokenUser.User.Sid) {
		return fmt.Errorf("%w: secure proxy Windows DACL is not owner-only", ErrSecureRuntimeAuth)
	}
	return nil
}

func secureRuntimeWindowsOwnerFullControlMask(mask windows.ACCESS_MASK) bool {
	return mask == windows.GENERIC_ALL || mask == secureRuntimeWindowsFileAllAccess
}
