package backend

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var (
	ErrSuiteCanonicalPrecheck         = errors.New("suite canonical precheck failed")
	ErrSuiteCanonicalPrecheckExisting = errors.New("existing Ant application footprint blocks precheck")
	ErrSuiteCanonicalPrecheckCapacity = errors.New("suite precheck payload capacity unavailable")
)

type SuiteCanonicalPrecheckResult struct {
	Stage               SetupStage `json:"stage"`
	RequestUID          string     `json:"request_uid"`
	ManifestSHA256      string     `json:"manifest_sha256"`
	PayloadMinimumBytes uint64     `json:"payload_minimum_bytes"`
	VolumeCount         int        `json:"volume_count"`
}

type suitePrecheckInstanceLock interface{ Release() error }

type suiteCanonicalPrecheckDependencies struct {
	ProbeRoot       func(string) error
	AvailableSpace  func(string) (string, uint64, error)
	AcquireInstance func(string) (suitePrecheckInstanceLock, error)
	SecureInstance  func(string) error
	ValidateSource  func(string, SuiteSetupPlan) (SuiteReleaseManifest, string, error)
	SaveCheckpoint  func(string, SetupCheckpoint) error
	AfterProbes     func() error
}

func RunSuiteCanonicalPrecheck(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, suiteSourceRoot string) (SuiteCanonicalPrecheckResult, error) {
	return runSuiteCanonicalPrecheckWithDependencies(ctx, bootstrap, roots, release, suiteSourceRoot, suiteCanonicalPrecheckDependencies{
		ProbeRoot:       probeSuitePrecheckOwnerRoot,
		AvailableSpace:  suitePrecheckAvailableSpace,
		AcquireInstance: func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:  func(path string) error { return secureSuiteSetupPath(path, false) },
		ValidateSource:  validateInstalledSuiteRelease,
		SaveCheckpoint:  SaveSetupCheckpoint,
	})
}

func runSuiteCanonicalPrecheckWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, suiteSourceRoot string, deps suiteCanonicalPrecheckDependencies) (SuiteCanonicalPrecheckResult, error) {
	if ctx == nil || deps.ProbeRoot == nil || deps.AvailableSpace == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.ValidateSource == nil || deps.SaveCheckpoint == nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	rawStatePath := bootstrap.StatePath
	if err := validateSuiteSetupInputs(&bootstrap, roots); err != nil || rawStatePath != filepath.Join(roots.AgentState, "setup.json") || validateSuitePrecheckRootLayout(roots, suiteSourceRoot) != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	if err := ctx.Err(); err != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	lock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	defer lock.release()

	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || (checkpoint != nil && (checkpoint.Stage != SetupPrecheck || checkpoint.RequestUID != preparation.RequestUID)) {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	if err := inspectSuitePrecheckFootprint(roots, bootstrap, preparation.RequestUID); err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	if err := SaveSuiteSetupPlan(roots, *expectedPlan); err != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	if err := inspectSuitePrecheckFootprint(roots, bootstrap, preparation.RequestUID); err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	manifest, manifestDigest, err := deps.ValidateSource(suiteSourceRoot, *plan)
	if err != nil || manifestDigest != plan.ManifestSHA256 {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	if err := requireEmptySuiteBrowserData(roots.BrowserData); err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	defer instanceLock.Release()
	if err := deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")); err != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	for _, root := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		if err := ctx.Err(); err != nil {
			return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
		}
		if err := validateSuiteSetupPathSecurity(root, true); err != nil || deps.ProbeRoot(root) != nil {
			return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
		}
	}
	payloadBytes, err := suitePrecheckPayloadBytes(manifest)
	if err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	volumes := map[string]uint64{}
	for _, root := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		volume, available, err := deps.AvailableSpace(root)
		if err != nil || volume == "" {
			return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheckCapacity
		}
		if prior, exists := volumes[volume]; !exists || available < prior {
			volumes[volume] = available
		}
	}
	for _, available := range volumes {
		if available < payloadBytes {
			return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheckCapacity
		}
	}
	if deps.AfterProbes != nil {
		if err := deps.AfterProbes(); err != nil {
			return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
		}
	}
	if err := ctx.Err(); err != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	confirmedPreparation, confirmedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil || *confirmedPreparation != *preparation || *confirmedPlan != *expectedPlan {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	confirmedManifest, confirmedDigest, err := deps.ValidateSource(suiteSourceRoot, *expectedPlan)
	if err != nil || confirmedDigest != manifestDigest || confirmedManifest.Validate() != nil || inspectSuitePrecheckFootprint(roots, bootstrap, preparation.RequestUID) != nil {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	confirmedCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || (checkpoint == nil && confirmedCheckpoint != nil) || (checkpoint != nil && (confirmedCheckpoint == nil || *confirmedCheckpoint != *checkpoint)) {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: preparation.RequestUID}
	if err := deps.SaveCheckpoint(bootstrap.StatePath, next); err != nil {
		return SuiteCanonicalPrecheckResult{}, err
	}
	written, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || written == nil || *written != next {
		return SuiteCanonicalPrecheckResult{}, ErrSuiteCanonicalPrecheck
	}
	return SuiteCanonicalPrecheckResult{Stage: SetupPrecheck, RequestUID: preparation.RequestUID, ManifestSHA256: manifestDigest, PayloadMinimumBytes: payloadBytes, VolumeCount: len(volumes)}, nil
}

func loadSuitePrecheckProofChain(bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease) (*SetupPreparationCheckpoint, *SuiteSetupPlan, error) {
	if !release.verified || release.manifest.Validate() != nil || release.manifest.Target != (SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}) {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	preparation, err := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
	if err != nil || preparation == nil || preparation.Stage != SetupBootstrapDrafted {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	digest, err := bootstrapConfigDigest(bootstrap)
	if err != nil || digest != preparation.BootstrapSHA256 {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	draft, exists, err := loadBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName))
	if err != nil || !exists || draft == nil || *draft != bootstrap {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	expected, err := NewSuiteSetupPlan(*preparation, release)
	if err != nil {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	existing, err := LoadSuiteSetupPlan(roots)
	if err != nil {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	if existing != nil && *existing != expected {
		return nil, nil, ErrSuiteCanonicalPrecheck
	}
	return preparation, &expected, nil
}

func validateSuitePrecheckRootLayout(roots SuiteUserRoots, source string) error {
	if source == "" || strings.TrimSpace(source) != source || filepath.Clean(source) != source {
		return ErrSuiteCanonicalPrecheck
	}
	for _, root := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		if root == "" || strings.TrimSpace(root) != root || filepath.Clean(root) != root {
			return ErrSuiteCanonicalPrecheck
		}
	}
	if !filepath.IsAbs(source) || source == "." {
		return ErrSuiteCanonicalPrecheck
	}
	mutable := []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs}
	allPaths := append(append([]string{}, mutable...), source)
	resolved := make([]string, len(allPaths))
	identities := make([]os.FileInfo, len(allPaths))
	for index, path := range allPaths {
		resolvedPath, info, err := suitePrecheckResolvedPath(path)
		if err != nil || info == nil || !info.IsDir() {
			return ErrSuiteCanonicalPrecheck
		}
		resolved[index], identities[index] = resolvedPath, info
	}
	for left := range resolved {
		for right := left + 1; right < len(resolved); right++ {
			leftContainsRight, leftErr := suitePrecheckIdentityContains(resolved[left], identities[left], resolved[right])
			rightContainsLeft, rightErr := suitePrecheckIdentityContains(resolved[right], identities[right], resolved[left])
			if leftErr != nil || rightErr != nil || os.SameFile(identities[left], identities[right]) || leftContainsRight || rightContainsLeft {
				return ErrSuiteCanonicalPrecheck
			}
		}
	}
	for left := range mutable {
		for right := left + 1; right < len(mutable); right++ {
			if suitePrecheckPathContains(mutable[left], mutable[right]) || suitePrecheckPathContains(mutable[right], mutable[left]) {
				return ErrSuiteCanonicalPrecheck
			}
		}
		if suitePrecheckPathContains(mutable[left], source) || suitePrecheckPathContains(source, mutable[left]) {
			return ErrSuiteCanonicalPrecheck
		}
	}
	return nil
}

// inspectSuitePrecheckFootprint keeps PRECHECK expand-only. Preparation evidence,
// its locks, and a same-request PRECHECK checkpoint are the complete set of
// mutable artifacts accepted here; any application, enrollment, service, log,
// or browser artifact means this is not a fresh canonical setup.
func inspectSuitePrecheckFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID string) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || (checkpoint != nil && (checkpoint.RequestUID != requestUID || checkpoint.Stage != SetupPrecheck)) {
		return ErrSuiteCanonicalPrecheck
	}
	allowed := map[string]map[string]struct{}{
		roots.Config: {
			suiteBootstrapDraftName: {},
		},
		roots.BrowserData: {},
		roots.Logs:        {},
		roots.AgentState: {
			suitePreparationStateName:                   {},
			suiteSetupLockName:                          {},
			suiteSetupPlanName:                          {},
			suiteSetupPlanName + ".lock":                {},
			".ant-farm-client.lock":                     {},
			filepath.Base(bootstrap.StatePath):          {},
			filepath.Base(bootstrap.StatePath) + ".bak": {},
		},
	}
	for root, names := range allowed {
		if err := validateSuiteSetupPathSecurity(root, true); err != nil {
			return ErrSuiteCanonicalPrecheck
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalPrecheck
		}
		for _, entry := range entries {
			if _, ok := names[entry.Name()]; !ok {
				return ErrSuiteCanonicalPrecheckExisting
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalPrecheck
			}
		}
	}
	return nil
}

func suitePrecheckPathContains(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && (relative == "." || (relative != ".." && !filepath.IsAbs(relative) && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func suitePrecheckIdentityContains(root string, rootInfo os.FileInfo, candidate string) (bool, error) {
	if suitePrecheckPathContains(root, candidate) {
		return true, nil
	}
	for current := candidate; ; {
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		info, err := os.Stat(parent)
		if err != nil {
			return false, err
		}
		if os.SameFile(rootInfo, info) {
			return true, nil
		}
		current = parent
	}
}

func requireEmptySuiteBrowserData(path string) error {
	if err := validateSuiteSetupPathSecurity(path, true); err != nil {
		return ErrSuiteCanonicalPrecheck
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return ErrSuiteCanonicalPrecheck
	}
	if len(entries) != 0 {
		return ErrSuiteCanonicalPrecheckExisting
	}
	return nil
}

func suitePrecheckPayloadBytes(manifest SuiteReleaseManifest) (uint64, error) {
	var total uint64
	for _, entry := range manifest.Entries {
		if entry.Size < 0 || uint64(entry.Size) > ^uint64(0)-total {
			return 0, ErrSuiteCanonicalPrecheckCapacity
		}
		total += uint64(entry.Size)
	}
	return total, nil
}

func probeSuitePrecheckOwnerRoot(root string) (resultErr error) {
	if err := validateSuiteSetupPathSecurity(root, true); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(root, ".suite-precheck-probe-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	finalPath := temporaryPath + ".committed"
	defer func() {
		for _, path := range []string{temporaryPath, finalPath} {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) && resultErr == nil {
				resultErr = err
			}
		}
		if err := syncSuiteSetupDirectory(root); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	if err := secureSuiteSetupPath(temporaryPath, false); err != nil {
		_ = temporary.Close()
		return err
	}
	payload := []byte("suite-precheck-v1\n")
	if _, err := temporary.Write(payload); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceSuiteSetupFile(temporaryPath, finalPath); err != nil {
		return err
	}
	raw, exists, err := readOwnerFile(finalPath)
	if err != nil || !exists || !bytes.Equal(raw, payload) {
		return ErrSuiteCanonicalPrecheck
	}
	if err := os.Remove(finalPath); err != nil {
		return err
	}
	return syncSuiteSetupDirectory(root)
}
