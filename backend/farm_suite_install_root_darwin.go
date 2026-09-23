//go:build darwin

package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// suiteDarwinInstallBase is the macOS counterpart of
// %ProgramFiles%\Ant Browser Suite: created by the root pkg installer, never
// writable by the Agent user, so a user-level process cannot swap a verified
// binary between validation and spawn.
const suiteDarwinInstallBase = "/Library/Application Support/Ant Browser Suite"

type suiteDarwinInstallValidator struct {
	base     string
	chainTop string // production: "/" (every ancestor must be root-owned)
	euid     func() int
	owner    uint32
	policy   suiteDarwinSigningPolicy
	codesign suiteDarwinCodesignRunner
	hasACL   func(string) (bool, error)
}

func productionSuiteDarwinInstallValidator() suiteDarwinInstallValidator {
	return suiteDarwinInstallValidator{
		base: suiteDarwinInstallBase, chainTop: "/", euid: os.Geteuid, owner: 0,
		policy: currentSuiteDarwinSigningPolicy(), codesign: runSuiteDarwinCodesign,
		hasACL: suiteDarwinHasExtendedACL,
	}
}

func validateCanonicalSuiteInstallRoot(h SuiteOwnershipHandoff) error {
	return productionSuiteDarwinInstallValidator().validate(h)
}

func (v suiteDarwinInstallValidator) validate(h SuiteOwnershipHandoff) error {
	if v.hasACL == nil {
		return ErrSuiteServiceActivation
	}
	if v.euid == nil || v.euid() == 0 {
		return fmt.Errorf("%w: activation must run as the Agent user, not root", ErrSuiteServiceActivation)
	}
	root := filepath.Clean(h.SuiteBinaryRoot)
	if root != filepath.Join(v.base, "versions", filepath.Base(root)) {
		return fmt.Errorf("%w: noncanonical macOS Suite root", ErrSuiteServiceActivation)
	}
	manifestPath := filepath.Join(root, "release-manifest.json")
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
	if err != nil || hex.EncodeToString(manifestHash[:]) != h.ManifestSHA256 || manifest.Target != h.ReleaseTarget ||
		manifest.Target != (SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}) || manifest.Version != filepath.Base(root) {
		return ErrSuiteServiceActivation
	}
	// Ownership first: hashing bytes a user could still rewrite proves nothing.
	if v.chainTop == "" || !suitePathWithin(root, v.chainTop) {
		return ErrSuiteServiceActivation
	}
	for current := filepath.Dir(root); ; current = filepath.Dir(current) {
		if err := v.immutable(current, false); err != nil {
			return err
		}
		if current == filepath.Clean(v.chainTop) || current == filepath.Dir(current) {
			break
		}
	}
	if err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return ErrSuiteServiceActivation
		}
		return v.immutable(path, entry.Type()&fs.ModeSymlink != 0)
	}); err != nil {
		return err
	}
	if err := validateInstalledSuiteEntries(root, manifest); err != nil {
		return ErrSuiteServiceActivation
	}
	if err := validateInstalledSuiteTree(root, manifest); err != nil {
		return ErrSuiteServiceActivation
	}
	if err := verifySuiteDarwinCodeSignatures(root, manifest, v.policy, v.codesign); err != nil {
		return fmt.Errorf("%w: %v", ErrSuiteServiceActivation, err)
	}
	return nil
}

// immutable requires root ownership, no extended ACL, no group/other write
// bit, and that the running user cannot write the object.
func (v suiteDarwinInstallValidator) immutable(path string, symlink bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return ErrSuiteServiceActivation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != v.owner {
		return fmt.Errorf("%w: macOS install path is not root-owned", ErrSuiteServiceActivation)
	}
	if (info.Mode()&os.ModeSymlink != 0) != symlink {
		return fmt.Errorf("%w: unexpected macOS install path type", ErrSuiteServiceActivation)
	}
	// access(2) cannot see ACL grants such as writesecurity, delete or
	// chown, which let a user later give itself write access: no ACL at all.
	if hasACL, err := v.hasACL(path); err != nil || hasACL {
		return fmt.Errorf("%w: macOS install path carries an extended ACL", ErrSuiteServiceActivation)
	}
	if symlink {
		// A link cannot be rewritten in place; replacing it needs write
		// access to its directory, which is checked like every directory.
		return nil
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w: macOS install path is group/other writable", ErrSuiteServiceActivation)
	}
	accessErr := unix.Faccessat(unix.AT_FDCWD, path, unix.W_OK, unix.AT_EACCESS)
	if accessErr == nil {
		return fmt.Errorf("%w: current user can modify the macOS install tree", ErrSuiteServiceActivation)
	}
	if !errors.Is(accessErr, unix.EACCES) && !errors.Is(accessErr, unix.EPERM) && !errors.Is(accessErr, unix.EROFS) {
		return fmt.Errorf("%w: macOS install write probe indeterminate", ErrSuiteServiceActivation)
	}
	return nil
}
