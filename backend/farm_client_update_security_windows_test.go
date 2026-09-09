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
		t.Fatal("staged update does not have an explicit protected per-user ACL")
	}
}
