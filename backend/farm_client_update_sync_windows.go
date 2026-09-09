//go:build windows

package backend

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"unsafe"
)

func farmClientUpdateWindowsSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return nil, ErrFarmClientUpdateUnavailable
	}
	sddl := "O:" + user.User.Sid.String() + "G:" + user.User.Sid.String() + "D:P" +
		"(A;OICI;FA;;;" + user.User.Sid.String() + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	return windows.SecurityDescriptorFromString(sddl)
}

func createFarmClientUpdateDirectoryPlatform(path string) (bool, error) {
	descriptor, err := farmClientUpdateWindowsSecurityDescriptor()
	if err != nil {
		return false, err
	}
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	if err := windows.CreateDirectory(pointer, &attributes); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func secureFarmClientUpdateDirectoryPlatform(path string, created bool) error {
	if !created {
		handle, err := openFarmClientWindowsObject(path, true)
		if err != nil {
			return ErrFarmClientUpdateUnavailable
		}
		defer windows.CloseHandle(handle)
		if !farmClientSecureWindowsHandle(handle, true) {
			return ErrFarmClientUpdateUnavailable
		}
		return nil
	}
	if err := setFarmClientUpdateWindowsACL(path); err != nil {
		return err
	}
	handle, err := openFarmClientWindowsObject(path, true)
	if err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	defer windows.CloseHandle(handle)
	if !farmClientSecureWindowsHandle(handle, true) {
		return ErrFarmClientUpdateUnavailable
	}
	return nil
}

func secureFarmClientUpdateFilePlatform(path string) error {
	if err := setFarmClientUpdateWindowsACL(path); err != nil {
		return err
	}
	handle, err := openFarmClientWindowsObject(path, false)
	if err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	defer windows.CloseHandle(handle)
	if !farmClientSecureWindowsHandle(handle, false) {
		return ErrFarmClientUpdateUnavailable
	}
	return nil
}

func secureFarmClientStagedFilePlatform(path string) error {
	return secureFarmClientUpdateFilePlatform(path)
}

func setFarmClientUpdateWindowsACL(path string) error {
	descriptor, err := farmClientUpdateWindowsSecurityDescriptor()
	if err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	owner, _, ownerErr := descriptor.Owner()
	dacl, defaulted, daclErr := descriptor.DACL()
	if ownerErr != nil || daclErr != nil || dacl == nil || defaulted {
		return ErrFarmClientUpdateUnavailable
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil); err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	return nil
}

// NTFS does not provide the POSIX directory-fsync contract.  Every state
// publication instead uses MoveFileEx with WRITE_THROUGH below.
func syncFarmClientUpdateDirectory(string) error { return nil }

func writeFarmClientUpdateState(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := secureFarmClientUpdateDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".state-*")
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return ErrFarmClientUpdateApply
	}
	if _, err := temporary.Write(value); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return ErrFarmClientUpdateApply
	}
	if err := setFarmClientUpdateWindowsACL(temporaryPath); err != nil {
		return err
	}
	from, err := windows.UTF16PtrFromString(temporaryPath)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	to, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	if err := windows.MoveFileEx(from, to, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return ErrFarmClientUpdateApply
	}
	return nil
}
