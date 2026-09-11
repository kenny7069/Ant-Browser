//go:build windows

package backend

import (
	"testing"

	"golang.org/x/sys/windows"
)

func assertFarmClientStagedFileSecurity(t *testing.T, path string) {
	t.Helper()
	handle, err := openFarmClientWindowsObject(path, false)
	if err != nil {
		t.Fatalf("open staged update security: %v", err)
	}
	defer windows.CloseHandle(handle)
	if !farmClientSecureWindowsHandle(handle, false) {
		descriptor, descriptorErr := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
		if descriptorErr != nil {
			t.Fatalf("staged update ACL inspection failed: %v", descriptorErr)
		}
		control, _, controlErr := descriptor.Control()
		dacl, defaulted, daclErr := descriptor.DACL()
		aceCount := uint16(0)
		if dacl != nil {
			aceCount = dacl.AceCount
		}
		t.Fatalf("staged update does not have an explicit protected per-user ACL: sddl=%q control=%#x control_err=%v dacl_defaulted=%v dacl_err=%v ace_count=%d", descriptor.String(), control, controlErr, defaulted, daclErr, aceCount)
	}
}
