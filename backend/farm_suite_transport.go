package backend

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type SuiteCanonicalTransportResult struct {
	Stage           SetupStage `json:"stage"`
	RequestUID      string     `json:"request_uid"`
	ManifestSHA256  string     `json:"manifest_sha256"`
	SetupStageID    string     `json:"setup_stage_id"`
	DiscoverySHA256 string     `json:"discovery_sha256"`
	DeploymentUID   string     `json:"deployment_uid"`
}

type suiteCanonicalTransportDependencies struct {
	CurrentSuiteVersion string
	Fetch               func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error)
	ValidateInstall     func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance     func(string) (suitePrecheckInstanceLock, error)
	SecureInstance      func(string) error
	EnsureApplication   func(string, bool) (os.FileInfo, error)
	SaveReceipt         func(SuiteUserRoots, BootstrapConfig, SuiteTransportReceipt) error
	SaveCheckpoint      func(string, SetupCheckpoint) error
	AfterFetch          func() error
}

func suiteCanonicalTransportProductionDependencies() suiteCanonicalTransportDependencies {
	return suiteCanonicalTransportDependencies{
		CurrentSuiteVersion: FarmClientVersion,
		Fetch:               FetchSuiteBootstrapDiscovery, ValidateInstall: validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot, SaveReceipt: saveSuiteTransportReceipt,
		SaveCheckpoint: SaveSetupCheckpoint,
	}
}

func RunSuiteCanonicalTransport(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalTransportResult, error) {
	return runSuiteCanonicalTransportWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalTransportProductionDependencies())
}

func runSuiteCanonicalTransportWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalTransportDependencies) (SuiteCanonicalTransportResult, error) {
	if ctx == nil || !validSuiteReleaseSemver(deps.CurrentSuiteVersion) || deps.CurrentSuiteVersion != release.manifest.Version || deps.Fetch == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || deps.SaveReceipt == nil || deps.SaveCheckpoint == nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	rawStatePath := bootstrap.StatePath
	if validateSuiteSetupInputs(&bootstrap, roots) != nil || rawStatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || filepath.Clean(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	defer setupLock.release()
	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || (checkpoint.Stage != SetupConfigDrafted && checkpoint.Stage != SetupTransportVerified) {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	installedEvidence, err := deps.ValidateInstall(installedSuiteRoot, *plan, release.manifest.Version)
	if err != nil || installedEvidence.RootInfo == nil || !installedEvidence.RootInfo.IsDir() || installedEvidence.CanonicalRoot == "" {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	stageReceipt := SuiteStageReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version, InstalledSuiteRoot: installedEvidence.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind}
	loadedStageReceipt, err := LoadSuiteStageReceipt(roots)
	if err != nil || loadedStageReceipt == nil || *loadedStageReceipt != stageReceipt {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	draft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || draft == nil || !suiteTransportDraftMatchesChain(*draft, bootstrap, roots, *preparation, *plan, installedEvidence.CanonicalRoot, release.manifest.Version) {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	applicationInfo, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	if err != nil || applicationInfo == nil || !applicationInfo.IsDir() {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	if err := revalidateSuiteTransportLocalEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, applicationInfo, *preparation, *plan, *checkpoint, stageReceipt, *draft, nil, false, deps); err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	discovery, err := deps.Fetch(ctx, bootstrap)
	if err != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	if deps.AfterFetch != nil && deps.AfterFetch() != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	receipt, err := newSuiteTransportReceipt(*preparation, *plan, *draft, bootstrap, roots, release.manifest.Version, discovery)
	if err != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	if inspectSuiteTransportFootprint(roots, bootstrap, preparation.RequestUID) != nil {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	existingState, err := inspectSuiteTransportReceiptState(roots, bootstrap, checkpoint.Stage)
	if err != nil || (existingState.Receipt != nil && !reflect.DeepEqual(*existingState.Receipt, receipt)) || (checkpoint.Stage == SetupTransportVerified && existingState.Receipt == nil) {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	if err := revalidateSuiteTransportLocalEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, applicationInfo, *preparation, *plan, *checkpoint, stageReceipt, *draft, &receipt, false, deps); err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	if err := deps.SaveReceipt(roots, bootstrap, receipt); err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	if err := revalidateSuiteTransportLocalEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installedEvidence, applicationInfo, *preparation, *plan, *checkpoint, stageReceipt, *draft, &receipt, true, deps); err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupTransportVerified, RequestUID: preparation.RequestUID}
	if err := deps.SaveCheckpoint(bootstrap.StatePath, next); err != nil {
		return SuiteCanonicalTransportResult{}, err
	}
	written, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || written == nil || *written != next {
		return SuiteCanonicalTransportResult{}, ErrSuiteCanonicalTransport
	}
	return SuiteCanonicalTransportResult{Stage: SetupTransportVerified, RequestUID: preparation.RequestUID, ManifestSHA256: plan.ManifestSHA256, SetupStageID: plan.StageID, DiscoverySHA256: receipt.DiscoverySHA256, DeploymentUID: receipt.DeploymentUID}, nil
}

func suiteTransportDraftMatchesChain(draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, installedRoot, version string) bool {
	return draft.validate(bootstrap, roots) == nil && draft.RequestUID == preparation.RequestUID && draft.SetupStageID == plan.StageID && draft.BootstrapSHA256 == preparation.BootstrapSHA256 && draft.ManifestSHA256 == plan.ManifestSHA256 && draft.Target == plan.Target && draft.Version == version && draft.SuiteBinaryRoot == installedRoot
}

func revalidateSuiteTransportLocalEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, layout *suitePrecheckRootLayoutSnapshot, installedEvidence suiteStageInstallEvidence, applicationInfo os.FileInfo, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, checkpoint SetupCheckpoint, stageReceipt SuiteStageReceipt, draft SuiteClientConfigDraft, expectedReceipt *SuiteTransportReceipt, requireReceipt bool, deps suiteCanonicalTransportDependencies) error {
	if ctx.Err() != nil || layout.revalidate(roots, installedSuiteRoot) != nil || inspectSuiteTransportFootprint(roots, bootstrap, preparation.RequestUID) != nil {
		return ErrSuiteCanonicalTransport
	}
	confirmedPreparation, confirmedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil || confirmedPreparation == nil || confirmedPlan == nil || *confirmedPreparation != preparation || *confirmedPlan != plan {
		return ErrSuiteCanonicalTransport
	}
	confirmedCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || confirmedCheckpoint == nil || *confirmedCheckpoint != checkpoint {
		return ErrSuiteCanonicalTransport
	}
	confirmedStage, err := LoadSuiteStageReceipt(roots)
	if err != nil || confirmedStage == nil || *confirmedStage != stageReceipt {
		return ErrSuiteCanonicalTransport
	}
	confirmedDraft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || confirmedDraft == nil || *confirmedDraft != draft || !suiteTransportDraftMatchesChain(*confirmedDraft, bootstrap, roots, preparation, plan, installedEvidence.CanonicalRoot, release.manifest.Version) {
		return ErrSuiteCanonicalTransport
	}
	confirmedInstall, err := deps.ValidateInstall(installedSuiteRoot, plan, release.manifest.Version)
	if err != nil || confirmedInstall.RootInfo == nil || confirmedInstall.CanonicalRoot != installedEvidence.CanonicalRoot || !os.SameFile(installedEvidence.RootInfo, confirmedInstall.RootInfo) {
		return ErrSuiteCanonicalTransport
	}
	confirmedApplication, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	if err != nil || confirmedApplication == nil || !os.SameFile(applicationInfo, confirmedApplication) {
		return ErrSuiteCanonicalTransport
	}
	confirmedState, err := inspectSuiteTransportReceiptState(roots, bootstrap, checkpoint.Stage)
	if err != nil || (confirmedState.Receipt != nil && expectedReceipt != nil && !reflect.DeepEqual(*confirmedState.Receipt, *expectedReceipt)) || (requireReceipt && confirmedState.Receipt == nil) {
		return ErrSuiteCanonicalTransport
	}
	return nil
}

func inspectSuiteTransportFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID string) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != requestUID || (checkpoint.Stage != SetupConfigDrafted && checkpoint.Stage != SetupTransportVerified) {
		return ErrSuiteCanonicalTransport
	}
	allowed := map[string]map[string]struct{}{
		roots.Config:     {suiteBootstrapDraftName: {}, SuiteClientConfigDraftName: {}},
		roots.AgentState: {suitePreparationStateName: {}, suiteSetupLockName: {}, suiteSetupPlanName: {}, suiteSetupPlanName + ".lock": {}, ".ant-farm-client.lock": {}, filepath.Base(bootstrap.StatePath): {}, filepath.Base(bootstrap.StatePath) + ".bak": {}, SuiteStageReceiptName: {}, SuiteTransportReceiptName: {}},
		roots.Logs:       {},
	}
	for root, names := range allowed {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalTransport
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalTransport
		}
		for _, entry := range entries {
			_, permitted := names[entry.Name()]
			if !permitted {
				return ErrSuiteCanonicalTransport
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return ErrSuiteCanonicalTransport
			}
			if root == roots.AgentState && entry.Name() == SuiteTransportReceiptName && checkpoint.Stage == SetupConfigDrafted {
				if validateSuiteTransportRecoveryCandidate(path, info) != nil {
					return ErrSuiteCanonicalTransport
				}
			} else if validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalTransport
			}
		}
	}
	if validateSuiteSetupPathSecurity(roots.BrowserData, true) != nil {
		return ErrSuiteCanonicalTransport
	}
	entries, err := os.ReadDir(roots.BrowserData)
	if err != nil || len(entries) != 1 || entries[0].Name() != suiteConfigDraftApplicationDir || !entries[0].IsDir() {
		return ErrSuiteCanonicalTransport
	}
	if _, err := ensureSuiteConfigDraftApplicationRoot(filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir), false); err != nil {
		return ErrSuiteCanonicalTransport
	}
	return nil
}
