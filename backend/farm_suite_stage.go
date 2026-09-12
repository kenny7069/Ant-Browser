package backend

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

type SuiteCanonicalStageResult struct {
	Stage          SetupStage `json:"stage"`
	RequestUID     string     `json:"request_uid"`
	ManifestSHA256 string     `json:"manifest_sha256"`
	SetupStageID   string     `json:"setup_stage_id"`
	Version        string     `json:"version"`
}

type suiteStageInstallEvidence struct {
	CanonicalRoot string
	RootInfo      os.FileInfo
}

type suiteCanonicalStageDependencies struct {
	ValidateInstall func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance func(string) (suitePrecheckInstanceLock, error)
	SecureInstance  func(string) error
	SaveReceipt     func(SuiteUserRoots, SuiteStageReceipt) error
	SaveCheckpoint  func(string, SetupCheckpoint) error
	AfterValidate   func() error
}

func RunSuiteCanonicalStage(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalStageResult, error) {
	return runSuiteCanonicalStageWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalStageDependencies{
		ValidateInstall: validateSuiteStagePlatformInstall,
		AcquireInstance: func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:  func(path string) error { return secureSuiteSetupPath(path, false) },
		SaveReceipt:     saveSuiteStageReceipt,
		SaveCheckpoint:  SaveSetupCheckpoint,
	})
}

func runSuiteCanonicalStageWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalStageDependencies) (SuiteCanonicalStageResult, error) {
	if ctx == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.SaveReceipt == nil || deps.SaveCheckpoint == nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	rawStatePath := bootstrap.StatePath
	if err := validateSuiteSetupInputs(&bootstrap, roots); err != nil || rawStatePath != filepath.Join(roots.AgentState, "setup.json") ||
		installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) || filepath.Clean(installedSuiteRoot) != installedSuiteRoot {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	if err := ctx.Err(); err != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteCanonicalStageResult{}, err
	}
	defer setupLock.release()

	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || (checkpoint.Stage != SetupPrecheck && checkpoint.Stage != SetupStaged) {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	installedEvidence, err := deps.ValidateInstall(installedSuiteRoot, *plan, release.manifest.Version)
	if err != nil || installedEvidence.RootInfo == nil || !installedEvidence.RootInfo.IsDir() || installedEvidence.CanonicalRoot == "" {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	expectedReceipt := SuiteStageReceipt{
		SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID,
		ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version,
		InstalledSuiteRoot: installedEvidence.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind,
	}
	if expectedReceipt.validate() != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	tempName, err := suiteStageReceiptTempName(expectedReceipt)
	if err != nil || inspectSuiteStageFootprint(roots, bootstrap, preparation.RequestUID, tempName) != nil || cleanupSuiteStageReceiptTemp(roots, tempName) != nil || inspectSuiteStageFootprint(roots, bootstrap, preparation.RequestUID, "") != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	receipt, err := LoadSuiteStageReceipt(roots)
	if err != nil || (receipt != nil && *receipt != expectedReceipt) || (checkpoint.Stage == SetupStaged && receipt == nil) {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	if deps.AfterValidate != nil && deps.AfterValidate() != nil {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	if err := revalidateSuiteStageEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, *preparation, *plan, *checkpoint, deps); err != nil {
		return SuiteCanonicalStageResult{}, err
	}
	if err := deps.SaveReceipt(roots, expectedReceipt); err != nil {
		return SuiteCanonicalStageResult{}, err
	}
	if err := revalidateSuiteStageEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, *preparation, *plan, *checkpoint, deps); err != nil {
		return SuiteCanonicalStageResult{}, err
	}
	writtenReceipt, err := LoadSuiteStageReceipt(roots)
	if err != nil || writtenReceipt == nil || *writtenReceipt != expectedReceipt {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: preparation.RequestUID}
	if err := deps.SaveCheckpoint(bootstrap.StatePath, next); err != nil {
		return SuiteCanonicalStageResult{}, err
	}
	writtenCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || writtenCheckpoint == nil || *writtenCheckpoint != next {
		return SuiteCanonicalStageResult{}, ErrSuiteCanonicalStage
	}
	return SuiteCanonicalStageResult{Stage: SetupStaged, RequestUID: preparation.RequestUID, ManifestSHA256: plan.ManifestSHA256, SetupStageID: plan.StageID, Version: release.manifest.Version}, nil
}

func revalidateSuiteStageEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, layout *suitePrecheckRootLayoutSnapshot, installedEvidence suiteStageInstallEvidence, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, checkpoint SetupCheckpoint, deps suiteCanonicalStageDependencies) error {
	if ctx.Err() != nil || layout.revalidate(roots, installedSuiteRoot) != nil || inspectSuiteStageFootprint(roots, bootstrap, preparation.RequestUID, "") != nil {
		return ErrSuiteCanonicalStage
	}
	confirmedPreparation, confirmedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil || confirmedPreparation == nil || confirmedPlan == nil || *confirmedPreparation != preparation || *confirmedPlan != plan {
		return ErrSuiteCanonicalStage
	}
	confirmedCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || confirmedCheckpoint == nil || *confirmedCheckpoint != checkpoint {
		return ErrSuiteCanonicalStage
	}
	confirmedEvidence, err := deps.ValidateInstall(installedSuiteRoot, plan, release.manifest.Version)
	if err != nil || confirmedEvidence.RootInfo == nil || confirmedEvidence.CanonicalRoot != installedEvidence.CanonicalRoot || !os.SameFile(installedEvidence.RootInfo, confirmedEvidence.RootInfo) {
		return ErrSuiteCanonicalStage
	}
	return nil
}

func inspectSuiteStageFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID, allowedTempName string) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != requestUID || (checkpoint.Stage != SetupPrecheck && checkpoint.Stage != SetupStaged) {
		return ErrSuiteCanonicalStage
	}
	allowed := map[string]map[string]struct{}{
		roots.Config:      {suiteBootstrapDraftName: {}},
		roots.BrowserData: {},
		roots.Logs:        {},
		roots.AgentState: {
			suitePreparationStateName: {}, suiteSetupLockName: {}, suiteSetupPlanName: {}, suiteSetupPlanName + ".lock": {},
			".ant-farm-client.lock": {}, filepath.Base(bootstrap.StatePath): {}, filepath.Base(bootstrap.StatePath) + ".bak": {}, SuiteStageReceiptName: {},
		},
	}
	if allowedTempName != "" {
		allowed[roots.AgentState][allowedTempName] = struct{}{}
	}
	for root, names := range allowed {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalStage
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalStage
		}
		for _, entry := range entries {
			if _, allowed := names[entry.Name()]; !allowed {
				return ErrSuiteCanonicalStage
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalStage
			}
		}
	}
	return nil
}
