//go:build windows

package backend

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openFarmClientPinnedPayload(updateRoot, executablePath string, slot FarmClientUpdateSlot) (*farmClientPinnedPayload, error) {
	relative, err := filepath.Rel(updateRoot, executablePath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, ErrFarmClientUpdateIntegrity
	}
	handles := make([]windows.Handle, 0, 4)
	closeHandles := func() {
		for _, handle := range handles {
			_ = windows.CloseHandle(handle)
		}
	}
	paths := []string{updateRoot}
	current := updateRoot
	parts := strings.Split(relative, string(filepath.Separator))
	for _, component := range parts[:len(parts)-1] {
		if component == "" || component == "." || component == ".." {
			closeHandles()
			return nil, ErrFarmClientUpdateIntegrity
		}
		current = filepath.Join(current, component)
		paths = append(paths, current)
	}
	for _, path := range paths {
		handle, openErr := openFarmClientWindowsObject(path, true)
		if openErr != nil || !farmClientSecureWindowsHandle(handle, true) {
			if openErr == nil {
				_ = windows.CloseHandle(handle)
			}
			closeHandles()
			return nil, ErrFarmClientUpdateIntegrity
		}
		handles = append(handles, handle)
	}
	executableHandle, err := openFarmClientWindowsObject(executablePath, false)
	if err != nil || !farmClientSecureWindowsHandle(executableHandle, false) {
		if err == nil {
			_ = windows.CloseHandle(executableHandle)
		}
		closeHandles()
		return nil, ErrFarmClientUpdateIntegrity
	}
	file := os.NewFile(uintptr(executableHandle), executablePath)
	if file == nil || verifyFarmClientPinnedFile(file, slot.SHA256, slot.Size) != nil {
		if file != nil {
			_ = file.Close()
		} else {
			_ = windows.CloseHandle(executableHandle)
		}
		closeHandles()
		return nil, ErrFarmClientUpdateIntegrity
	}
	return &farmClientPinnedPayload{path: executablePath, close: func() {
		_ = file.Close()
		closeHandles()
	}}, nil
}

func openFarmClientWindowsObject(path string, directory bool) (windows.Handle, error) {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	access := uint32(windows.GENERIC_READ | windows.READ_CONTROL | windows.SYNCHRONIZE)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
		access = windows.FILE_READ_ATTRIBUTES | windows.READ_CONTROL | windows.SYNCHRONIZE
	} else {
		access |= windows.FILE_EXECUTE
	}
	return windows.CreateFile(pointer, access, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, flags, 0)
}

func farmClientSecureWindowsHandle(handle windows.Handle, directory bool) bool {
	if handle == 0 || handle == windows.InvalidHandle {
		return false
	}
	var info windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if directory != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) || (!directory && info.NumberOfLinks != 1) {
		return false
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return false
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || !owner.Equals(user.User.Sid) {
		return false
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, present, err := descriptor.DACL()
	if err != nil || !present || dacl == nil || dacl.AceCount != 3 {
		return false
	}
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	seen := map[string]bool{}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERITED_ACE != 0 {
			return false
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(user.User.Sid):
			seen["user"] = true
		case sid.Equals(system):
			seen["system"] = true
		case sid.Equals(admins):
			seen["admins"] = true
		default:
			return false
		}
	}
	return seen["user"] && seen["system"] && seen["admins"]
}
