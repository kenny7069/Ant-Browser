package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

var ErrSuiteCanonicalIdentity = errors.New("suite canonical identity failed")

type SuiteCanonicalIdentityResult struct {
	Stage           SetupStage `json:"stage"`
	RequestUID      string     `json:"request_uid"`
	ManifestSHA256  string     `json:"manifest_sha256"`
	SetupStageID    string     `json:"setup_stage_id"`
	DiscoverySHA256 string     `json:"discovery_sha256"`
	IdentityRef     string     `json:"identity_ref"`
	PublicKeySHA256 string     `json:"public_key_sha256"`
}

type suiteCanonicalIdentityDependencies struct {
	NewStore          func(string) (FarmClientIdentityStore, error)
	Random            io.Reader
	ValidateInstall   func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance   func(string) (suitePrecheckInstanceLock, error)
	SecureInstance    func(string) error
	EnsureApplication func(string, bool) (os.FileInfo, error)
	SaveReceipt       func(SuiteUserRoots, SuiteIdentityReceipt) error
	SaveCheckpoint    func(string, SetupCheckpoint) error
	AfterIdentitySave func() error
	AfterReceiptSave  func() error
}

func suiteCanonicalIdentityProductionDependencies() suiteCanonicalIdentityDependencies {
	return suiteCanonicalIdentityDependencies{
		NewStore: NewFarmClientIdentityStore, Random: rand.Reader,
		ValidateInstall:   validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
		SaveReceipt:       saveSuiteIdentityReceipt, SaveCheckpoint: SaveSetupCheckpoint,
	}
}

func RunSuiteCanonicalIdentity(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalIdentityResult, error) {
	return runSuiteCanonicalIdentityWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalIdentityProductionDependencies())
}

func runSuiteCanonicalIdentityWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalIdentityDependencies) (SuiteCanonicalIdentityResult, error) {
	if ctx == nil || deps.NewStore == nil || deps.Random == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || deps.SaveReceipt == nil || deps.SaveCheckpoint == nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	if validateSuiteSetupInputs(&bootstrap, roots) != nil || bootstrap.StatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) || filepath.Clean(installedSuiteRoot) != installedSuiteRoot {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteCanonicalIdentityResult{}, err
	}
	defer setupLock.release()
	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || (checkpoint.Stage != SetupTransportVerified && checkpoint.Stage != SetupIdentityReady) {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	installed, err := deps.ValidateInstall(installedSuiteRoot, *plan, release.manifest.Version)
	if err != nil || installed.RootInfo == nil || !installed.RootInfo.IsDir() || installed.CanonicalRoot == "" {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	stage := SuiteStageReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version, InstalledSuiteRoot: installed.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind}
	loadedStage, err := LoadSuiteStageReceipt(roots)
	if err != nil || loadedStage == nil || *loadedStage != stage {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	draft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || draft == nil || !suiteTransportDraftMatchesChain(*draft, bootstrap, roots, *preparation, *plan, installed.CanonicalRoot, release.manifest.Version) {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	applicationInfo, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	if err != nil || applicationInfo == nil || !applicationInfo.IsDir() {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	transport, err := LoadSuiteTransportReceipt(roots, bootstrap)
	if err != nil || transport == nil || !suiteIdentityTransportMatchesChain(*transport, *preparation, *plan, *draft, bootstrap, roots, release.manifest.Version) {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	ref, err := suiteBootstrapEnrollmentIdentityRef(transport.DeploymentUID, preparation.RequestUID)
	if err != nil || inspectSuiteIdentityFootprint(roots, bootstrap, preparation.RequestUID, ref) != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	store, err := deps.NewStore(roots.AgentState)
	if err != nil || store == nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	key, err := loadOrCreateSuiteCanonicalIdentity(store, ref, deps.Random, deps.AfterIdentitySave)
	if err != nil {
		return SuiteCanonicalIdentityResult{}, err
	}
	defer clearBytes(key)
	public := farmClientIdentityPublicKey(key)
	if len(public) != ed25519.PublicKeySize {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	publicDigest := sha256.Sum256(public)
	clearBytes(public)
	draftDigest, err := suiteConfigDraftCanonicalDigest(*draft, bootstrap, roots)
	if err != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	receipt := SuiteIdentityReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, BootstrapSHA256: preparation.BootstrapSHA256, ManifestSHA256: plan.ManifestSHA256, ConfigDraftSHA256: draftDigest, DiscoverySHA256: transport.DiscoverySHA256, DeploymentUID: transport.DeploymentUID, IdentityRef: string(ref), PublicKeySHA256: hex.EncodeToString(publicDigest[:]), StoreKind: suiteIdentityStoreKind}
	if receipt.validate() != nil || revalidateSuiteIdentityEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installed, applicationInfo, *preparation, *plan, *checkpoint, stage, *draft, *transport, receipt, store, ref, false, deps) != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	existing, err := LoadSuiteIdentityReceipt(roots)
	if err != nil && checkpoint.Stage == SetupTransportVerified {
		_, raw, recoveryErr := readSuiteTransportReceiptRecoveryCandidate(roots, filepath.Join(roots.AgentState, SuiteIdentityReceiptName))
		if recoveryErr != nil || len(raw) > suiteIdentityReceiptMaxBytes || json.Valid(raw) {
			return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
		}
		existing = nil
		err = nil
	}
	if err != nil || (existing != nil && *existing != receipt) || (checkpoint.Stage == SetupIdentityReady && existing == nil) {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	if err := deps.SaveReceipt(roots, receipt); err != nil {
		return SuiteCanonicalIdentityResult{}, err
	}
	if deps.AfterReceiptSave != nil && deps.AfterReceiptSave() != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	if revalidateSuiteIdentityEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, installed, applicationInfo, *preparation, *plan, *checkpoint, stage, *draft, *transport, receipt, store, ref, true, deps) != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupIdentityReady, RequestUID: preparation.RequestUID}
	if deps.SaveCheckpoint(bootstrap.StatePath, next) != nil {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	written, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || written == nil || *written != next {
		return SuiteCanonicalIdentityResult{}, ErrSuiteCanonicalIdentity
	}
	return SuiteCanonicalIdentityResult{Stage: SetupIdentityReady, RequestUID: preparation.RequestUID, ManifestSHA256: plan.ManifestSHA256, SetupStageID: plan.StageID, DiscoverySHA256: transport.DiscoverySHA256, IdentityRef: string(ref), PublicKeySHA256: receipt.PublicKeySHA256}, nil
}

func loadOrCreateSuiteCanonicalIdentity(store FarmClientIdentityStore, ref FarmClientIdentityKeyRef, random io.Reader, afterSave func() error) (ed25519.PrivateKey, error) {
	key, err := store.Load(ref)
	if errors.Is(err, ErrFarmClientIdentityKeyNotFound) {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(random, seed); err != nil {
			clearBytes(seed)
			return nil, ErrSuiteCanonicalIdentity
		}
		if err := store.Save(ref, seed); err != nil {
			clearBytes(seed)
			return nil, ErrSuiteCanonicalIdentity
		}
		clearBytes(seed)
		if afterSave != nil && afterSave() != nil {
			return nil, ErrSuiteCanonicalIdentity
		}
		key, err = store.Load(ref)
	}
	if err != nil || len(key) != ed25519.PrivateKeySize {
		if key != nil {
			clearBytes(key)
		}
		return nil, ErrSuiteCanonicalIdentity
	}
	normalized, seed, err := normalizeFarmClientIdentityKey(key)
	clearBytes(key)
	clearBytes(seed)
	if err != nil || len(normalized) != ed25519.PrivateKeySize {
		return nil, ErrSuiteCanonicalIdentity
	}
	return normalized, nil
}

func suiteIdentityTransportMatchesChain(receipt SuiteTransportReceipt, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots, version string) bool {
	digest, err := suiteConfigDraftCanonicalDigest(draft, bootstrap, roots)
	return err == nil && receipt.validate(bootstrap) == nil && receipt.RequestUID == preparation.RequestUID && receipt.SetupStageID == plan.StageID && receipt.BootstrapSHA256 == preparation.BootstrapSHA256 && receipt.ManifestSHA256 == plan.ManifestSHA256 && receipt.ConfigDraftSHA256 == digest && receipt.Target == plan.Target && receipt.Version == version
}

func revalidateSuiteIdentityEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, installed suiteStageInstallEvidence, application os.FileInfo, preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, checkpoint SetupCheckpoint, stage SuiteStageReceipt, draft SuiteClientConfigDraft, transport SuiteTransportReceipt, receipt SuiteIdentityReceipt, store FarmClientIdentityStore, ref FarmClientIdentityKeyRef, requireReceipt bool, deps suiteCanonicalIdentityDependencies) error {
	if ctx.Err() != nil || layout.revalidate(roots, installedRoot) != nil || inspectSuiteIdentityFootprint(roots, bootstrap, preparation.RequestUID, ref) != nil {
		return ErrSuiteCanonicalIdentity
	}
	confirmedPreparation, confirmedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil || confirmedPreparation == nil || confirmedPlan == nil || *confirmedPreparation != preparation || *confirmedPlan != plan {
		return ErrSuiteCanonicalIdentity
	}
	confirmedCheckpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || confirmedCheckpoint == nil || *confirmedCheckpoint != checkpoint {
		return ErrSuiteCanonicalIdentity
	}
	confirmedStage, stageErr := LoadSuiteStageReceipt(roots)
	confirmedDraft, draftErr := LoadSuiteClientConfigDraft(roots, bootstrap)
	confirmedTransport, transportErr := LoadSuiteTransportReceipt(roots, bootstrap)
	confirmedInstall, installErr := deps.ValidateInstall(installedRoot, plan, release.manifest.Version)
	confirmedApplication, appErr := deps.EnsureApplication(draft.ApplicationRoot, false)
	if stageErr != nil || confirmedStage == nil || *confirmedStage != stage || draftErr != nil || confirmedDraft == nil || *confirmedDraft != draft || transportErr != nil || confirmedTransport == nil || !reflect.DeepEqual(*confirmedTransport, transport) || !suiteIdentityTransportMatchesChain(*confirmedTransport, preparation, plan, draft, bootstrap, roots, release.manifest.Version) || installErr != nil || confirmedInstall.RootInfo == nil || confirmedInstall.CanonicalRoot != installed.CanonicalRoot || !os.SameFile(installed.RootInfo, confirmedInstall.RootInfo) || appErr != nil || confirmedApplication == nil || !os.SameFile(application, confirmedApplication) {
		return ErrSuiteCanonicalIdentity
	}
	key, err := store.Load(ref)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		if key != nil {
			clearBytes(key)
		}
		return ErrSuiteCanonicalIdentity
	}
	public := farmClientIdentityPublicKey(key)
	clearBytes(key)
	digest := sha256.Sum256(public)
	clearBytes(public)
	if hex.EncodeToString(digest[:]) != receipt.PublicKeySHA256 {
		return ErrSuiteCanonicalIdentity
	}
	confirmedReceipt, err := LoadSuiteIdentityReceipt(roots)
	if err != nil && !requireReceipt {
		_, raw, recoveryErr := readSuiteTransportReceiptRecoveryCandidate(roots, filepath.Join(roots.AgentState, SuiteIdentityReceiptName))
		if recoveryErr != nil || len(raw) > suiteIdentityReceiptMaxBytes || json.Valid(raw) {
			return ErrSuiteCanonicalIdentity
		}
	} else if err != nil || (confirmedReceipt != nil && *confirmedReceipt != receipt) || (requireReceipt && confirmedReceipt == nil) {
		return ErrSuiteCanonicalIdentity
	}
	return nil
}

func inspectSuiteIdentityFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID string, ref FarmClientIdentityKeyRef) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != requestUID || (checkpoint.Stage != SetupTransportVerified && checkpoint.Stage != SetupIdentityReady) {
		return ErrSuiteCanonicalIdentity
	}
	allowed := map[string]map[string]bool{
		roots.Config:     {suiteBootstrapDraftName: true, SuiteClientConfigDraftName: true},
		roots.AgentState: {suitePreparationStateName: true, suiteSetupLockName: true, suiteSetupPlanName: true, suiteSetupPlanName + ".lock": true, ".ant-farm-client.lock": true, filepath.Base(bootstrap.StatePath): true, filepath.Base(bootstrap.StatePath) + ".bak": true, SuiteStageReceiptName: true, SuiteTransportReceiptName: true, SuiteIdentityReceiptName: true, farmClientIdentityStoreDir: true},
		roots.Logs:       {},
	}
	for root, names := range allowed {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalIdentity
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalIdentity
		}
		for _, entry := range entries {
			if !names[entry.Name()] {
				return ErrSuiteCanonicalIdentity
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrSuiteCanonicalIdentity
			}
			if root == roots.AgentState && entry.Name() == farmClientIdentityStoreDir {
				if !info.IsDir() || validateSuiteIdentityStoreDirectory(path, roots.AgentState, ref) != nil {
					return ErrSuiteCanonicalIdentity
				}
			} else if !info.Mode().IsRegular() {
				return ErrSuiteCanonicalIdentity
			} else if root == roots.AgentState && entry.Name() == SuiteIdentityReceiptName && checkpoint.Stage == SetupTransportVerified {
				if validateSuiteTransportRecoveryCandidate(path, info) != nil {
					return ErrSuiteCanonicalIdentity
				}
			} else if validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalIdentity
			}
		}
	}
	entries, err := os.ReadDir(roots.BrowserData)
	if err != nil || len(entries) != 1 || entries[0].Name() != suiteConfigDraftApplicationDir || !entries[0].IsDir() {
		return ErrSuiteCanonicalIdentity
	}
	_, err = ensureSuiteConfigDraftApplicationRoot(filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir), false)
	return err
}

func validateSuiteIdentityStoreDirectory(path, root string, ref FarmClientIdentityKeyRef) error {
	info, err := os.Lstat(path)
	_, resolvedInfo, resolveErr := suitePrecheckResolvedPath(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(path, true) != nil || resolveErr != nil || resolvedInfo == nil || !os.SameFile(info, resolvedInfo) {
		return ErrSuiteCanonicalIdentity
	}
	expected, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		return ErrSuiteCanonicalIdentity
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(expected) {
		return ErrSuiteCanonicalIdentity
	}
	child, err := os.Lstat(expected)
	_, resolvedChild, childResolveErr := suitePrecheckResolvedPath(expected)
	finalInfo, finalErr := os.Lstat(path)
	finalChild, finalChildErr := os.Lstat(expected)
	finalEntries, entriesErr := os.ReadDir(path)
	if err != nil || !child.Mode().IsRegular() || child.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(expected, false) != nil || childResolveErr != nil || resolvedChild == nil || !os.SameFile(child, resolvedChild) || finalErr != nil || !os.SameFile(info, finalInfo) || finalChildErr != nil || !os.SameFile(child, finalChild) || validateSuiteSetupPathSecurity(expected, false) != nil || entriesErr != nil || len(finalEntries) != 1 || finalEntries[0].Name() != filepath.Base(expected) {
		return ErrSuiteCanonicalIdentity
	}
	return nil
}
