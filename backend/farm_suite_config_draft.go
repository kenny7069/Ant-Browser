package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type SuiteCanonicalConfigDraftResult struct {
	Stage           SetupStage `json:"stage"`
	RequestUID      string     `json:"request_uid"`
	ManifestSHA256  string     `json:"manifest_sha256"`
	SetupStageID    string     `json:"setup_stage_id"`
	DraftPath       string     `json:"draft_path"`
	ApplicationRoot string     `json:"application_root"`
}

type suiteCanonicalConfigDraftDependencies struct {
	ValidateInstall   func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance   func(string) (suitePrecheckInstanceLock, error)
	SecureInstance    func(string) error
	EnsureApplication func(string, bool) (os.FileInfo, error)
	SaveDraft         func(SuiteUserRoots, BootstrapConfig, SuiteClientConfigDraft) error
	SaveCheckpoint    func(string, SetupCheckpoint) error
	AfterValidate     func() error
}

type suiteConfigDraftApplicationRootOperations struct {
	Mkdir      func(string, os.FileMode) error
	Lstat      func(string) (os.FileInfo, error)
	Secure     func(string, bool) error
	SyncParent func(string) error
	ReadDir    func(string) ([]os.DirEntry, error)
	Remove     func(string) error
	Resolve    func(string) (string, os.FileInfo, error)
}

func defaultSuiteConfigDraftApplicationRootOperations() suiteConfigDraftApplicationRootOperations {
	return suiteConfigDraftApplicationRootOperations{
		Mkdir: os.Mkdir, Lstat: os.Lstat, Secure: secureSuiteSetupPath,
		SyncParent: syncSuiteSetupDirectory, ReadDir: os.ReadDir, Remove: os.Remove,
		Resolve: suitePrecheckResolvedPath,
	}
}

func RunSuiteCanonicalConfigDraft(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalConfigDraftResult, error) {
	return runSuiteCanonicalConfigDraftWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalConfigDraftDependencies{
		ValidateInstall:   validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
		SaveDraft:         saveSuiteClientConfigDraft,
		SaveCheckpoint:    SaveSetupCheckpoint,
	})
}

func runSuiteCanonicalConfigDraftWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalConfigDraftDependencies) (SuiteCanonicalConfigDraftResult, error) {
	if ctx == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || deps.SaveDraft == nil || deps.SaveCheckpoint == nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	rawStatePath := bootstrap.StatePath
	if err := validateSuiteSetupInputs(&bootstrap, roots); err != nil || rawStatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || filepath.Clean(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteCanonicalConfigDraftResult{}, err
	}
	defer setupLock.release()
	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || (checkpoint.Stage != SetupStaged && checkpoint.Stage != SetupConfigDrafted) {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	installedEvidence, err := deps.ValidateInstall(installedSuiteRoot, *plan, release.manifest.Version)
	if err != nil || installedEvidence.RootInfo == nil || !installedEvidence.RootInfo.IsDir() || installedEvidence.CanonicalRoot == "" {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	expectedReceipt := SuiteStageReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version, InstalledSuiteRoot: installedEvidence.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind}
	receipt, err := LoadSuiteStageReceipt(roots)
	if err != nil || receipt == nil || *receipt != expectedReceipt {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	applicationRoot := filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir)
	draft := SuiteClientConfigDraft{
		SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID,
		BootstrapSHA256: preparation.BootstrapSHA256, ManifestSHA256: plan.ManifestSHA256,
		Target: plan.Target, Version: release.manifest.Version, SuiteBinaryRoot: installedEvidence.CanonicalRoot,
		ServerOrigin: bootstrap.ServerURL, NodeName: bootstrap.NodeName,
		ClientConfigPath: filepath.Join(roots.Config, SuiteClientConfigName), AgentStateRoot: roots.AgentState,
		ApplicationRoot: applicationRoot, AntConfigPath: filepath.Join(applicationRoot, "config.yaml"), LogPath: filepath.Join(roots.Logs, suiteConfigDraftLogName),
	}
	if draft.validate(bootstrap, roots) != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	tempName, err := suiteConfigDraftTempName(draft, bootstrap, roots)
	if err != nil || inspectSuiteConfigDraftFootprint(roots, bootstrap, preparation.RequestUID, tempName) != nil || cleanupSuiteConfigDraftTemp(roots, tempName) != nil || inspectSuiteConfigDraftFootprint(roots, bootstrap, preparation.RequestUID, "") != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	existingDraft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || (existingDraft != nil && *existingDraft != draft) || (checkpoint.Stage == SetupConfigDrafted && existingDraft == nil) {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	applicationInfo, err := deps.EnsureApplication(applicationRoot, checkpoint.Stage == SetupStaged)
	if err != nil || applicationInfo == nil || !applicationInfo.IsDir() {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	if deps.AfterValidate != nil && deps.AfterValidate() != nil {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	if err := revalidateSuiteConfigDraftEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, applicationInfo, *preparation, *plan, *checkpoint, expectedReceipt, draft, false, deps); err != nil {
		return SuiteCanonicalConfigDraftResult{}, err
	}
	if err := deps.SaveDraft(roots, bootstrap, draft); err != nil {
		return SuiteCanonicalConfigDraftResult{}, err
	}
	if err := revalidateSuiteConfigDraftEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, applicationInfo, *preparation, *plan, *checkpoint, expectedReceipt, draft, true, deps); err != nil {
		return SuiteCanonicalConfigDraftResult{}, err
	}
	next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupConfigDrafted, RequestUID: preparation.RequestUID}
	if err := deps.SaveCheckpoint(bootstrap.StatePath, next); err != nil {
		return SuiteCanonicalConfigDraftResult{}, err
	}
	written, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || written == nil || *written != next {
		return SuiteCanonicalConfigDraftResult{}, ErrSuiteCanonicalConfigDraft
	}
	return SuiteCanonicalConfigDraftResult{Stage: SetupConfigDrafted, RequestUID: preparation.RequestUID, ManifestSHA256: plan.ManifestSHA256, SetupStageID: plan.StageID, DraftPath: filepath.Join(roots.Config, SuiteClientConfigDraftName), ApplicationRoot: applicationRoot}, nil
}

func revalidateSuiteConfigDraftEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, layout *suitePrecheckRootLayoutSnapshot, installedEvidence suiteStageInstallEvidence, applicationInfo os.FileInfo, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, checkpoint SetupCheckpoint, receipt SuiteStageReceipt, draft SuiteClientConfigDraft, requireDraft bool, deps suiteCanonicalConfigDraftDependencies) error {
	if ctx.Err() != nil || layout.revalidate(roots, installedSuiteRoot) != nil || inspectSuiteConfigDraftFootprint(roots, bootstrap, preparation.RequestUID, "") != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedPreparation, confirmedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil || confirmedPreparation == nil || confirmedPlan == nil || *confirmedPreparation != preparation || *confirmedPlan != plan {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || confirmedCheckpoint == nil || *confirmedCheckpoint != checkpoint {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedReceipt, err := LoadSuiteStageReceipt(roots)
	if err != nil || confirmedReceipt == nil || *confirmedReceipt != receipt {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedInstall, err := deps.ValidateInstall(installedSuiteRoot, plan, release.manifest.Version)
	if err != nil || confirmedInstall.RootInfo == nil || confirmedInstall.CanonicalRoot != installedEvidence.CanonicalRoot || !os.SameFile(installedEvidence.RootInfo, confirmedInstall.RootInfo) {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedApplication, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	if err != nil || confirmedApplication == nil || !os.SameFile(applicationInfo, confirmedApplication) {
		return ErrSuiteCanonicalConfigDraft
	}
	confirmedDraft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || (confirmedDraft != nil && *confirmedDraft != draft) || (requireDraft && confirmedDraft == nil) {
		return ErrSuiteCanonicalConfigDraft
	}
	return nil
}

func ensureSuiteConfigDraftApplicationRoot(path string, allowCreate bool) (os.FileInfo, error) {
	return ensureSuiteConfigDraftApplicationRootWithOperations(path, allowCreate, defaultSuiteConfigDraftApplicationRootOperations())
}

func ensureSuiteConfigDraftApplicationRootWithOperations(path string, allowCreate bool, operations suiteConfigDraftApplicationRootOperations) (os.FileInfo, error) {
	if operations.Mkdir == nil || operations.Lstat == nil || operations.Secure == nil || operations.SyncParent == nil || operations.ReadDir == nil || operations.Remove == nil || operations.Resolve == nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	info, err := operations.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !allowCreate || operations.Mkdir(path, 0o700) != nil {
			return nil, ErrSuiteCanonicalConfigDraft
		}
		createdInfo, createdErr := operations.Lstat(path)
		if createdErr != nil || createdInfo.Mode()&os.ModeSymlink != 0 || !createdInfo.IsDir() {
			return nil, ErrSuiteCanonicalConfigDraft
		}
		if operations.Secure(path, true) != nil || operations.SyncParent(filepath.Dir(path)) != nil {
			_ = cleanupNewSuiteConfigDraftApplicationRoot(path, createdInfo, operations)
			return nil, ErrSuiteCanonicalConfigDraft
		}
		info, err = operations.Lstat(path)
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	_, resolvedInfo, err := operations.Resolve(path)
	if err != nil || resolvedInfo == nil || !os.SameFile(info, resolvedInfo) {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	entries, err := operations.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	return resolvedInfo, nil
}

func cleanupNewSuiteConfigDraftApplicationRoot(path string, createdInfo os.FileInfo, operations suiteConfigDraftApplicationRootOperations) error {
	current, err := operations.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.IsDir() || !os.SameFile(createdInfo, current) {
		return ErrSuiteCanonicalConfigDraft
	}
	_, resolved, err := operations.Resolve(path)
	if err != nil || resolved == nil || !os.SameFile(createdInfo, resolved) {
		return ErrSuiteCanonicalConfigDraft
	}
	entries, err := operations.ReadDir(path)
	if err != nil || len(entries) != 0 {
		return ErrSuiteCanonicalConfigDraft
	}
	final, err := operations.Lstat(path)
	if err != nil || final.Mode()&os.ModeSymlink != 0 || !final.IsDir() || !os.SameFile(createdInfo, final) {
		return ErrSuiteCanonicalConfigDraft
	}
	if err := operations.Remove(path); err != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	if err := operations.SyncParent(filepath.Dir(path)); err != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	return nil
}

func inspectSuiteConfigDraftFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID, allowedTempName string) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != requestUID || (checkpoint.Stage != SetupStaged && checkpoint.Stage != SetupConfigDrafted) {
		return ErrSuiteCanonicalConfigDraft
	}
	allowedFiles := map[string]map[string]struct{}{
		roots.Config:     {suiteBootstrapDraftName: {}, SuiteClientConfigDraftName: {}},
		roots.AgentState: {suitePreparationStateName: {}, suiteSetupLockName: {}, suiteSetupPlanName: {}, suiteSetupPlanName + ".lock": {}, ".ant-farm-client.lock": {}, filepath.Base(bootstrap.StatePath): {}, filepath.Base(bootstrap.StatePath) + ".bak": {}, SuiteStageReceiptName: {}},
		roots.Logs:       {},
	}
	if allowedTempName != "" {
		allowedFiles[roots.Config][allowedTempName] = struct{}{}
	}
	for root, names := range allowedFiles {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalConfigDraft
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalConfigDraft
		}
		for _, entry := range entries {
			if _, ok := names[entry.Name()]; !ok {
				return ErrSuiteCanonicalConfigDraft
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalConfigDraft
			}
		}
	}
	if validateSuiteSetupPathSecurity(roots.BrowserData, true) != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	entries, err := os.ReadDir(roots.BrowserData)
	if err != nil {
		return ErrSuiteCanonicalConfigDraft
	}
	for _, entry := range entries {
		if entry.Name() != suiteConfigDraftApplicationDir || !entry.IsDir() {
			return ErrSuiteCanonicalConfigDraft
		}
		if _, err := ensureSuiteConfigDraftApplicationRoot(filepath.Join(roots.BrowserData, entry.Name()), false); err != nil {
			return ErrSuiteCanonicalConfigDraft
		}
	}
	return nil
}
