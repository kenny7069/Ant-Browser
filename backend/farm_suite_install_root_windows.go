//go:build windows

package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const suiteTrustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"

type suiteWindowsACEMask struct {
	Header windows.ACE_HEADER
	Mask   windows.ACCESS_MASK
}

func validateCanonicalSuiteInstallRoot(h SuiteOwnershipHandoff) error {
	elevated, err := suiteWindowsCurrentTokenElevated()
	if err != nil || elevated {
		return fmt.Errorf("%w: activation requires a non-elevated user token", ErrSuiteServiceActivation)
	}
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	want := filepath.Join(programFiles, "Ant Browser Suite", "versions", filepath.Base(h.SuiteBinaryRoot))
	if !strings.EqualFold(filepath.Clean(h.SuiteBinaryRoot), filepath.Clean(want)) {
		return fmt.Errorf("%w: noncanonical Program Files root", ErrSuiteServiceActivation)
	}
	paths := []string{
		programFiles,
		filepath.Join(programFiles, "Ant Browser Suite"),
		filepath.Join(programFiles, "Ant Browser Suite", "versions"),
		h.SuiteBinaryRoot,
		filepath.Join(h.SuiteBinaryRoot, "release-manifest.json"),
		filepath.Join(h.SuiteBinaryRoot, "release-manifest.envelope.json"),
		filepath.Join(h.SuiteBinaryRoot, "ant-farm-client.exe"),
	}
	manifestPath := filepath.Join(h.SuiteBinaryRoot, "release-manifest.json")
	manifestInfo, err := os.Lstat(manifestPath)
	if err != nil || !manifestInfo.Mode().IsRegular() || manifestInfo.Size() <= 0 || manifestInfo.Size() > maxSuiteReleaseManifestBytes {
		return ErrSuiteServiceActivation
	}
	manifestRaw, err := os.ReadFile(manifestPath)
	if err != nil || int64(len(manifestRaw)) != manifestInfo.Size() {
		return ErrSuiteServiceActivation
	}
	manifest, err := ParseSuiteReleaseManifest(manifestRaw)
	manifestHash := sha256.Sum256(manifestRaw)
	if err != nil || hex.EncodeToString(manifestHash[:]) != h.ManifestSHA256 || manifest.Target != h.ReleaseTarget || manifest.Target != (SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}) || manifest.Version != filepath.Base(h.SuiteBinaryRoot) {
		return ErrSuiteServiceActivation
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		path, pathErr := safeSuiteReleaseEntryPath(h.SuiteBinaryRoot, entry.Path)
		if pathErr != nil {
			return ErrSuiteServiceActivation
		}
		entryInfo, entryErr := os.Lstat(path)
		if entryErr != nil || !entryInfo.Mode().IsRegular() || entryInfo.Size() != entry.Size {
			return ErrSuiteServiceActivation
		}
		entryDigest, digestErr := streamSuiteInstalledEntryDigest(path, entry.Size)
		if digestErr != nil || entryDigest != entry.SHA256 {
			return ErrSuiteServiceActivation
		}
		for current := path; ; current = filepath.Dir(current) {
			if !seen[current] {
				paths = append(paths, current)
				seen[current] = true
			}
			if strings.EqualFold(current, h.SuiteBinaryRoot) {
				break
			}
			if !suitePathWithin(current, h.SuiteBinaryRoot) {
				return ErrSuiteServiceActivation
			}
		}
	}
	if err := validateInstalledSuiteTree(h.SuiteBinaryRoot, manifest); err != nil {
		return ErrSuiteServiceActivation
	}
	for _, path := range paths {
		if err := validateSuiteWindowsImmutablePath(path); err != nil {
			return err
		}
	}
	return nil
}

func suiteWindowsCurrentTokenElevated() (bool, error) {
	var elevated uint32
	var returned uint32
	err := windows.GetTokenInformation(windows.GetCurrentProcessToken(), windows.TokenElevation, (*byte)(unsafe.Pointer(&elevated)), uint32(unsafe.Sizeof(elevated)), &returned)
	if err != nil || returned != uint32(unsafe.Sizeof(elevated)) {
		return false, ErrSuiteServiceActivation
	}
	return elevated != 0, nil
}

func validateSuiteWindowsImmutablePath(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	directory := info.IsDir()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(pointer, windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	defer windows.CloseHandle(handle)
	var fileInfo windows.ByHandleFileInformation
	if windows.GetFileInformationByHandle(handle, &fileInfo) != nil || fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || directory != (fileInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) {
		return fmt.Errorf("%w: immutable path is reparse or wrong type", ErrSuiteServiceActivation)
	}
	descriptor, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	policy, err := suiteWindowsDACLPolicy(descriptor)
	if err != nil || validateSuiteInstallDACLPolicy(policy) != nil {
		return ErrSuiteServiceActivation
	}
	accesses := []uint32{
		windows.FILE_WRITE_DATA, windows.FILE_APPEND_DATA, windows.FILE_WRITE_EA, windows.FILE_WRITE_ATTRIBUTES,
		windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER,
	}
	if directory {
		accesses = append(accesses, 0x00000040)
	}
	for _, access := range accesses {
		probe, probeErr := windows.CreateFile(pointer, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
		if probeErr == nil {
			windows.CloseHandle(probe)
			return fmt.Errorf("%w: current token has dangerous immutable-tree access", ErrSuiteServiceActivation)
		}
		if !errors.Is(probeErr, windows.ERROR_ACCESS_DENIED) {
			return fmt.Errorf("%w: immutable-tree access probe indeterminate", ErrSuiteServiceActivation)
		}
	}
	return nil
}

func suiteWindowsDACLPolicy(descriptor *windows.SECURITY_DESCRIPTOR) (suiteInstallDACLPolicy, error) {
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return suiteInstallDACLPolicy{}, ErrSuiteServiceActivation
	}
	trusted, err := suiteWindowsTrustedSIDs()
	if err != nil {
		return suiteInstallDACLPolicy{}, err
	}
	policy := suiteInstallDACLPolicy{TrustedOwner: suiteWindowsSIDTrusted(owner, trusted)}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return policy, ErrSuiteServiceActivation
	}
	policy.DACLPresent = true
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil {
			return policy, ErrSuiteServiceActivation
		}
		if err := validateSuiteInstallACEHeaderMaskSize(ace.Header.AceSize); err != nil {
			return policy, err
		}
		header := (*suiteWindowsACEMask)(unsafe.Pointer(ace))
		allowed, objectACE, unknownAllowed := classifySuiteInstallACEType(header.Header.AceType)
		entry := suiteInstallACEPolicy{Allowed: allowed, UnknownAllowType: unknownAllowed, ObjectACE: objectACE, Mask: uint32(header.Mask), InheritOnly: header.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0}
		if allowed && !objectACE {
			if ace.Header.AceSize < 16 {
				return policy, ErrSuiteServiceActivation
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
			sidHeader := (*[2]byte)(unsafe.Pointer(sid))
			sidLength, layoutErr := validateSuiteInstallAllowedSIDLayout(ace.Header.AceSize, sidHeader[0], sidHeader[1])
			if layoutErr != nil || !sid.IsValid() || windows.GetLengthSid(sid) != uint32(sidLength) {
				return policy, ErrSuiteServiceActivation
			}
			entry.TrustedPrincipal = suiteWindowsSIDTrusted(sid, trusted)
			creatorOwner, _ := windows.CreateWellKnownSid(windows.WinCreatorOwnerSid)
			entry.CreatorOwner = creatorOwner != nil && sid.Equals(creatorOwner)
		}
		policy.ACEs = append(policy.ACEs, entry)
	}
	return policy, nil
}

func suiteWindowsTrustedSIDs() ([]*windows.SID, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	installer, err := windows.StringToSid(suiteTrustedInstallerSID)
	if err != nil {
		return nil, err
	}
	return []*windows.SID{system, admins, installer}, nil
}

func suiteWindowsSIDTrusted(sid *windows.SID, trusted []*windows.SID) bool {
	for _, candidate := range trusted {
		if sid != nil && candidate != nil && sid.Equals(candidate) {
			return true
		}
	}
	return false
}
