package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
)

var ErrSuiteCanonicalEnrollmentACK = errors.New("suite canonical enrollment acknowledgment failed")

type suiteCanonicalEnrollmentACKDependencies struct {
	CurrentSuiteVersion string
	Fetch               func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error)
	NewStore            func(string) (FarmClientIdentityStore, error)
	Client              *http.Client
	ValidateInstall     func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance     func(string) (suitePrecheckInstanceLock, error)
	SecureInstance      func(string) error
	EnsureApplication   func(string, bool) (os.FileInfo, error)
	AfterFetch          func() error
	AfterResponse       func() error
	BeforeFinalReadback func() error
}

func suiteCanonicalEnrollmentACKProductionDependencies() suiteCanonicalEnrollmentACKDependencies {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		MaxResponseHeaderBytes: maxSuiteBootstrapHeaderBytes, ResponseHeaderTimeout: 10 * time.Second,
		DisableCompression: true,
	}
	return suiteCanonicalEnrollmentACKDependencies{
		CurrentSuiteVersion: FarmClientVersion, Fetch: FetchSuiteBootstrapDiscovery,
		NewStore: NewFarmClientIdentityStore, Client: &http.Client{Transport: transport},
		ValidateInstall:   validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
	}
}

// RunSuiteCanonicalEnrollmentACK records only the server acknowledgment. It
// deliberately leaves the canonical setup checkpoint at IDENTITY_READY; a
// later slice must durably write the client config before advancing enrollment.
func RunSuiteCanonicalEnrollmentACK(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot, enrollmentCode string) (SuiteBootstrapEnrollmentResult, error) {
	deps := suiteCanonicalEnrollmentACKProductionDependencies()
	if transport, ok := deps.Client.Transport.(*http.Transport); ok {
		defer transport.CloseIdleConnections()
	}
	return runSuiteCanonicalEnrollmentACKWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, enrollmentCode, deps)
}

type suiteCanonicalEnrollmentEvidence struct {
	preparation SetupPreparationCheckpoint
	plan        SuiteSetupPlan
	checkpoint  SetupCheckpoint
	stage       SuiteStageReceipt
	draft       SuiteClientConfigDraft
	transport   SuiteTransportReceipt
	identity    SuiteIdentityReceipt
	installed   suiteStageInstallEvidence
	application os.FileInfo
	ref         FarmClientIdentityKeyRef
}

func runSuiteCanonicalEnrollmentACKWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot, enrollmentCode string, deps suiteCanonicalEnrollmentACKDependencies) (SuiteBootstrapEnrollmentResult, error) {
	if ctx == nil || deps.Fetch == nil || deps.NewStore == nil || deps.Client == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || !validSuiteReleaseSemver(deps.CurrentSuiteVersion) || deps.CurrentSuiteVersion != release.manifest.Version {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	if validateSuiteSetupInputs(&bootstrap, roots) != nil || bootstrap.StatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) || filepath.Clean(installedSuiteRoot) != installedSuiteRoot {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	budget, cancel := context.WithTimeout(ctx, suiteBootstrapEnrollmentTimeout)
	defer cancel()
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	defer setupLock.release()
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	attemptLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteBootstrapEnrollmentLockName))
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	defer attemptLock.release()
	evidence, err := loadSuiteCanonicalEnrollmentEvidence(budget, bootstrap, roots, release, installedSuiteRoot, deps)
	if err != nil || layout.revalidate(roots, installedSuiteRoot) != nil || inspectSuiteCanonicalEnrollmentFootprint(roots, bootstrap, evidence.preparation.RequestUID, evidence.ref) != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	store, err := deps.NewStore(roots.AgentState)
	if err != nil || store == nil || verifySuiteCanonicalEnrollmentKey(store, evidence.ref, evidence.identity.PublicKeySHA256) != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	if err := revalidateSuiteCanonicalEnrollmentEvidence(budget, bootstrap, roots, release, installedSuiteRoot, layout, evidence, store, deps); err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	discovery, err := deps.Fetch(budget, bootstrap)
	if err != nil || !reflect.DeepEqual(discovery, evidence.transport.discovery()) {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	if deps.AfterFetch != nil && deps.AfterFetch() != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	if err := revalidateSuiteCanonicalEnrollmentEvidence(budget, bootstrap, roots, release, installedSuiteRoot, layout, evidence, store, deps); err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	priorAttempt, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	result, err := enrollSuiteBootstrapWithDependencies(budget, roots, evidence.preparation.RequestUID, bootstrap.NodeName, deps.CurrentSuiteVersion, enrollmentCode, discovery, suiteBootstrapEnrollmentDependencies{
		IdentityStore: store, Client: deps.Client, RequireExistingIdentity: true, AttemptLockHeld: true,
		AfterResponse: deps.AfterResponse,
		RevalidateIdentity: func() error {
			return revalidateSuiteCanonicalEnrollmentEvidence(budget, bootstrap, roots, release, installedSuiteRoot, layout, evidence, store, deps)
		},
	})
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	if deps.BeforeFinalReadback != nil && deps.BeforeFinalReadback() != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	if err := revalidateSuiteCanonicalEnrollmentEvidence(budget, bootstrap, roots, release, installedSuiteRoot, layout, evidence, store, deps); err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	if !validateSuiteCanonicalEnrollmentAttempt(roots, evidence, discovery, bootstrap.NodeName, deps.CurrentSuiteVersion, enrollmentCode, store, priorAttempt, result) {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteCanonicalEnrollmentACK
	}
	return result, nil
}

func validateSuiteCanonicalEnrollmentAttempt(roots SuiteUserRoots, evidence suiteCanonicalEnrollmentEvidence, discovery SuiteBootstrapDiscovery, nodeName, suiteVersion, enrollmentCode string, store FarmClientIdentityStore, prior *SuiteBootstrapEnrollmentAttempt, result SuiteBootstrapEnrollmentResult) bool {
	final, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil || final == nil || final.Stage != SuiteBootstrapAcknowledged || suiteBootstrapEnrollmentResultFromAttempt(*final) != result {
		return false
	}
	if prior != nil && prior.Stage == SuiteBootstrapAcknowledged && enrollmentCode == "" {
		discoveryRaw, discoveryErr := json.Marshal(discovery)
		metadataRaw, metadataErr := json.Marshal(suiteBootstrapEnrollmentMetadata{NodeName: strings.TrimSpace(nodeName), SuiteVersion: suiteVersion})
		return discoveryErr == nil && metadataErr == nil && *final == *prior &&
			final.PreparationRequestUID == evidence.preparation.RequestUID && final.DeploymentUID == discovery.DeploymentUID &&
			final.DiscoverySHA256 == suiteBootstrapSHA256(discoveryRaw) && final.MetadataSHA256 == suiteBootstrapSHA256(metadataRaw) &&
			final.IdentityRef == string(evidence.ref) && final.PublicKeySHA256 == evidence.identity.PublicKeySHA256 &&
			final.IdempotencySHA256 == suiteBootstrapSHA256([]byte(suiteBootstrapEnrollmentIdempotencyKey(evidence.preparation.RequestUID))) &&
			final.ControlEndpoint == discovery.ControlEndpoint
	}
	if enrollmentCode == "" {
		return false
	}
	key, err := store.Load(evidence.ref)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clearBytes(key)
		return false
	}
	public := farmClientIdentityPublicKey(key)
	clearBytes(key)
	defer clearBytes(public)
	discoveryRaw, err := json.Marshal(discovery)
	if err != nil {
		return false
	}
	metadata := suiteBootstrapEnrollmentMetadata{NodeName: strings.TrimSpace(nodeName), SuiteVersion: suiteVersion}
	metadataRaw, err := json.Marshal(metadata)
	if err != nil {
		return false
	}
	requestUID, err := canonicalSuiteBootstrapRequestUID(evidence.preparation.RequestUID)
	if err != nil {
		return false
	}
	codeRaw, err := decodeSuiteBootstrapEnrollmentCode(enrollmentCode)
	if err != nil {
		return false
	}
	codeDigest := suiteBootstrapSHA256(codeRaw)
	clearBytes(codeRaw)
	idempotencyKey := suiteBootstrapEnrollmentIdempotencyKey(requestUID)
	requestRaw, err := json.Marshal(suiteBootstrapEnrollmentRequest{RequestUID: requestUID, EnrollmentCode: enrollmentCode, DevicePublicKeyEd25519Base64: base64.StdEncoding.EncodeToString(public), Metadata: metadata})
	if err != nil {
		return false
	}
	expected := SuiteBootstrapEnrollmentAttempt{
		SchemaVersion: suiteBootstrapEnrollmentSchema, Stage: SuiteBootstrapAcknowledged,
		PreparationRequestUID: requestUID, DeploymentUID: discovery.DeploymentUID,
		DiscoverySHA256: suiteBootstrapSHA256(discoveryRaw), MetadataSHA256: suiteBootstrapSHA256(metadataRaw),
		IdentityRef: string(evidence.ref), PublicKeySHA256: evidence.identity.PublicKeySHA256,
		EnrollmentCodeSHA256: codeDigest, RequestSHA256: suiteBootstrapSHA256(requestRaw),
		IdempotencySHA256: suiteBootstrapSHA256([]byte(idempotencyKey)), NodeUID: result.NodeUID,
		EnrollmentState: result.EnrollmentState, ControlEndpoint: result.ControlEndpoint,
	}
	return *final == expected && (prior == nil || sameSuiteBootstrapEnrollmentBinding(*prior, expected))
}

func loadSuiteCanonicalEnrollmentEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, deps suiteCanonicalEnrollmentACKDependencies) (suiteCanonicalEnrollmentEvidence, error) {
	var out suiteCanonicalEnrollmentEvidence
	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return out, err
	}
	plan, err := LoadSuiteSetupPlan(roots)
	if err != nil || plan == nil || *plan != *expectedPlan {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || checkpoint.Stage != SetupIdentityReady {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	installed, err := deps.ValidateInstall(installedRoot, *plan, release.manifest.Version)
	if err != nil || installed.RootInfo == nil || !installed.RootInfo.IsDir() || installed.CanonicalRoot == "" {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	stage := SuiteStageReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version, InstalledSuiteRoot: installed.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind}
	loadedStage, err := LoadSuiteStageReceipt(roots)
	if err != nil || loadedStage == nil || *loadedStage != stage {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	draft, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || draft == nil || !suiteTransportDraftMatchesChain(*draft, bootstrap, roots, *preparation, *plan, installed.CanonicalRoot, release.manifest.Version) {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	application, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	if err != nil || application == nil || !application.IsDir() {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	transport, err := LoadSuiteTransportReceipt(roots, bootstrap)
	if err != nil || transport == nil || !suiteIdentityTransportMatchesChain(*transport, *preparation, *plan, *draft, bootstrap, roots, release.manifest.Version) {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	identity, err := LoadSuiteIdentityReceipt(roots)
	if err != nil || identity == nil {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	ref, err := suiteBootstrapEnrollmentIdentityRef(transport.DeploymentUID, preparation.RequestUID)
	if err != nil {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	draftDigest, err := suiteConfigDraftCanonicalDigest(*draft, bootstrap, roots)
	if err != nil || identity.RequestUID != preparation.RequestUID || identity.SetupStageID != plan.StageID || identity.BootstrapSHA256 != preparation.BootstrapSHA256 || identity.ManifestSHA256 != plan.ManifestSHA256 || identity.ConfigDraftSHA256 != draftDigest || identity.DiscoverySHA256 != transport.DiscoverySHA256 || identity.DeploymentUID != transport.DeploymentUID || identity.IdentityRef != string(ref) || identity.StoreKind != suiteIdentityStoreKind {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	if ctx.Err() != nil {
		return out, ErrSuiteCanonicalEnrollmentACK
	}
	return suiteCanonicalEnrollmentEvidence{*preparation, *plan, *checkpoint, stage, *draft, *transport, *identity, installed, application, ref}, nil
}

func revalidateSuiteCanonicalEnrollmentEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, expected suiteCanonicalEnrollmentEvidence, store FarmClientIdentityStore, deps suiteCanonicalEnrollmentACKDependencies) error {
	if ctx.Err() != nil || layout.revalidate(roots, installedRoot) != nil || inspectSuiteCanonicalEnrollmentFootprint(roots, bootstrap, expected.preparation.RequestUID, expected.ref) != nil {
		return ErrSuiteCanonicalEnrollmentACK
	}
	current, err := loadSuiteCanonicalEnrollmentEvidence(ctx, bootstrap, roots, release, installedRoot, deps)
	if err != nil || current.preparation != expected.preparation || current.plan != expected.plan || current.checkpoint != expected.checkpoint || current.stage != expected.stage || current.draft != expected.draft || !reflect.DeepEqual(current.transport, expected.transport) || current.identity != expected.identity || current.installed.CanonicalRoot != expected.installed.CanonicalRoot || !os.SameFile(current.installed.RootInfo, expected.installed.RootInfo) || !os.SameFile(current.application, expected.application) || verifySuiteCanonicalEnrollmentKey(store, expected.ref, expected.identity.PublicKeySHA256) != nil {
		return ErrSuiteCanonicalEnrollmentACK
	}
	return nil
}

func verifySuiteCanonicalEnrollmentKey(store FarmClientIdentityStore, ref FarmClientIdentityKeyRef, expectedDigest string) error {
	key, err := store.Load(ref)
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clearBytes(key)
		return ErrSuiteCanonicalEnrollmentACK
	}
	public := farmClientIdentityPublicKey(key)
	clearBytes(key)
	digest := sha256.Sum256(public)
	clearBytes(public)
	if hex.EncodeToString(digest[:]) != expectedDigest {
		return ErrSuiteCanonicalEnrollmentACK
	}
	return nil
}

func inspectSuiteCanonicalEnrollmentFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, requestUID string, ref FarmClientIdentityKeyRef) error {
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupIdentityReady || checkpoint.RequestUID != requestUID {
		return ErrSuiteCanonicalEnrollmentACK
	}
	allowed := map[string]map[string]bool{
		roots.Config:     {suiteBootstrapDraftName: true, SuiteClientConfigDraftName: true},
		roots.AgentState: {suitePreparationStateName: true, suiteSetupLockName: true, suiteSetupPlanName: true, suiteSetupPlanName + ".lock": true, ".ant-farm-client.lock": true, filepath.Base(bootstrap.StatePath): true, filepath.Base(bootstrap.StatePath) + ".bak": true, SuiteStageReceiptName: true, SuiteTransportReceiptName: true, SuiteIdentityReceiptName: true, farmClientIdentityStoreDir: true, SuiteBootstrapEnrollmentAttemptName: true, SuiteBootstrapEnrollmentAttemptName + ".bak": true, suiteBootstrapEnrollmentLockName: true},
		roots.Logs:       {},
	}
	for root, names := range allowed {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalEnrollmentACK
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalEnrollmentACK
		}
		for _, entry := range entries {
			if !names[entry.Name()] {
				return ErrSuiteCanonicalEnrollmentACK
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrSuiteCanonicalEnrollmentACK
			}
			if root == roots.AgentState && entry.Name() == farmClientIdentityStoreDir {
				if !info.IsDir() || validateSuiteIdentityStoreDirectory(path, roots.AgentState, ref, false) != nil {
					return ErrSuiteCanonicalEnrollmentACK
				}
			} else if !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalEnrollmentACK
			}
		}
	}
	entries, err := os.ReadDir(roots.BrowserData)
	if err != nil || len(entries) != 1 || entries[0].Name() != suiteConfigDraftApplicationDir || !entries[0].IsDir() {
		return ErrSuiteCanonicalEnrollmentACK
	}
	_, err = ensureSuiteConfigDraftApplicationRoot(filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir), false)
	return err
}
