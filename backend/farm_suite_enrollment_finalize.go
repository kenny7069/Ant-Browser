package backend

import (
	appbrowser "ant-chrome/backend/internal/browser"
	appconfig "ant-chrome/backend/internal/config"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrSuiteCanonicalEnrollmentFinalize = errors.New("suite canonical enrollment finalization failed")

const (
	suiteFinalClientConfigStagingPrefix = ".client-yaml-"
	suiteFinalShutdownTimeoutMS         = 30000
	suiteFinalHeartbeatIntervalMS       = 5000
	suiteFinalReconnectMinBackoffMS     = 1000
	suiteFinalReconnectMaxBackoffMS     = 30000
	suiteFinalUpdateCheckIntervalMS     = 900000
	suiteFinalUpdateHealthTimeoutMS     = 90000
	suiteFinalUpdateProbationMS         = 60000
)

type SuiteCanonicalEnrollmentFinalizeResult struct {
	Stage              SetupStage `json:"stage"`
	RequestUID         string     `json:"request_uid"`
	ClientConfigPath   string     `json:"client_config_path"`
	ClientConfigSHA256 string     `json:"client_config_sha256"`
	HandoffState       string     `json:"handoff_state"`
}

type suiteCanonicalEnrollmentFinalizeDependencies struct {
	CurrentGOOS       string
	NewStore          func(string) (FarmClientIdentityStore, error)
	ValidateInstall   func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance   func(string) (suitePrecheckInstanceLock, error)
	SecureInstance    func(string) error
	EnsureApplication func(string, bool) (os.FileInfo, error)
	Readback          func(string, *appconfig.Config, string, appbrowser.Core) error
	SaveCheckpoint    func(string, SetupCheckpoint) error
	FinalizeHandoff   func(SuiteUserRoots, string, string, string) (SuiteOwnershipHandoff, error)
	LoadHandoff       func(SuiteUserRoots) (*SuiteOwnershipHandoff, error)
	AfterConfig       func() error
	AfterHandoff      func() error
	BeforeCheckpoint  func() error
	AfterCheckpoint   func() error
}

type suiteEnrollmentFinalizeEvidence struct {
	canonical suiteCanonicalEnrollmentEvidence
	attempt   SuiteBootstrapEnrollmentAttempt
	init      SuiteApplicationInitState
	appConfig *appconfig.Config
	core      appbrowser.Core
	store     FarmClientIdentityStore
}

func suiteCanonicalEnrollmentFinalizeProductionDependencies() suiteCanonicalEnrollmentFinalizeDependencies {
	return suiteCanonicalEnrollmentFinalizeDependencies{
		CurrentGOOS: runtime.GOOS, NewStore: NewFarmClientIdentityStore,
		ValidateInstall:   validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteApplicationRootIdentity, Readback: readbackSuiteApplication,
		SaveCheckpoint: SaveSetupCheckpoint, FinalizeHandoff: FinalizeSuiteOwnershipHandoff, LoadHandoff: LoadSuiteOwnershipHandoff,
	}
}

// RunSuiteCanonicalEnrollmentFinalize publishes the production client
// configuration and ownership handoff. ENROLLED is the commit marker and is
// written only after every durable artifact has passed a complete readback.
func RunSuiteCanonicalEnrollmentFinalize(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalEnrollmentFinalizeResult, error) {
	return runSuiteCanonicalEnrollmentFinalizeWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalEnrollmentFinalizeProductionDependencies())
}

func runSuiteCanonicalEnrollmentFinalizeWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalEnrollmentFinalizeDependencies) (SuiteCanonicalEnrollmentFinalizeResult, error) {
	if ctx == nil || !suiteCanonicalInstallPlatform(deps.CurrentGOOS) || deps.NewStore == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || deps.Readback == nil || deps.SaveCheckpoint == nil || deps.FinalizeHandoff == nil || deps.LoadHandoff == nil ||
		validateSuiteSetupInputs(&bootstrap, roots) != nil || bootstrap.StatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot || !filepath.IsAbs(installedSuiteRoot) || filepath.Clean(installedSuiteRoot) != installedSuiteRoot {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		if errors.Is(err, ErrSuiteSetupLocked) {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteSetupLocked
		}
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	defer setupLock.release()
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	attemptLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteBootstrapEnrollmentLockName))
	if err != nil {
		if errors.Is(err, ErrSuiteSetupLocked) {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteSetupLocked
		}
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	defer attemptLock.release()

	evidence, err := loadSuiteEnrollmentFinalizeEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, deps)
	if err != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	config, raw, digest, stagingPath, err := buildSuiteFinalClientConfig(bootstrap, roots, evidence)
	if err != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	checkpointStage := evidence.canonical.checkpoint.Stage
	if checkpointStage == SetupIdentityReady {
		_, configErr := os.Lstat(filepath.Join(roots.Config, SuiteClientConfigName))
		_, stagingErr := os.Lstat(stagingPath)
		existingHandoff, handoffErr := deps.LoadHandoff(roots)
		if errors.Is(configErr, os.ErrNotExist) && errors.Is(stagingErr, os.ErrNotExist) && handoffErr == nil && existingHandoff == nil {
			if inspectSuiteApplicationInitFootprint(roots, bootstrap, evidence.canonical.ref, true) != nil {
				return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
			}
		} else if (configErr != nil && !errors.Is(configErr, os.ErrNotExist)) || (stagingErr != nil && !errors.Is(stagingErr, os.ErrNotExist)) || handoffErr != nil || inspectSuiteEnrollmentFinalizeArtifactRoots(roots, bootstrap, stagingPath) != nil {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
		}
	} else if checkpointStage != SetupEnrolled {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if ensureSuiteFinalClientConfig(roots, stagingPath, raw) != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if deps.AfterConfig != nil && deps.AfterConfig() != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if revalidateSuiteEnrollmentFinalizeEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, evidence, config, raw, stagingPath, deps, false) != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	handoff, err := deps.FinalizeHandoff(roots, evidence.canonical.preparation.RequestUID, evidence.canonical.installed.CanonicalRoot, filepath.Join(evidence.canonical.installed.CanonicalRoot, filepath.FromSlash(suiteCurrentReleaseLayout().GUI)))
	if err != nil || handoff.ClientConfigSHA256 != digest || handoff.SetupRequestUID != evidence.canonical.preparation.RequestUID || handoff.ManifestSHA256 != evidence.canonical.plan.ManifestSHA256 || handoff.SetupStageID != evidence.canonical.plan.StageID {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if deps.AfterHandoff != nil && deps.AfterHandoff() != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if revalidateSuiteEnrollmentFinalizeEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, evidence, config, raw, stagingPath, deps, true) != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	if checkpointStage == SetupIdentityReady {
		if deps.BeforeCheckpoint != nil && deps.BeforeCheckpoint() != nil {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
		}
		next := SetupCheckpoint{SchemaVersion: 1, Stage: SetupEnrolled, RequestUID: evidence.canonical.preparation.RequestUID}
		if deps.SaveCheckpoint(bootstrap.StatePath, next) != nil {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
		}
		if deps.AfterCheckpoint != nil && deps.AfterCheckpoint() != nil {
			return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
		}
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	finalEvidence, finalEvidenceErr := loadSuiteEnrollmentFinalizeEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, deps)
	loadedHandoff, handoffErr := deps.LoadHandoff(roots)
	loadedRaw, rawErr := readSuiteFinalClientConfigRaw(filepath.Join(roots.Config, SuiteClientConfigName))
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupEnrolled || checkpoint.RequestUID != evidence.canonical.preparation.RequestUID || finalEvidenceErr != nil || !sameSuiteEnrollmentFinalizeBinding(finalEvidence, evidence, SetupEnrolled) || handoffErr != nil || loadedHandoff == nil || *loadedHandoff != handoff || rawErr != nil || !bytes.Equal(loadedRaw, raw) || verifySuiteFinalClientConfig(filepath.Join(roots.Config, SuiteClientConfigName), config, raw) != nil || deps.Readback(finalEvidence.init.AntConfigPath, finalEvidence.appConfig, finalEvidence.init.DatabasePath, finalEvidence.core) != nil || verifySuiteCanonicalEnrollmentKey(finalEvidence.store, finalEvidence.canonical.ref, finalEvidence.canonical.identity.PublicKeySHA256) != nil {
		return SuiteCanonicalEnrollmentFinalizeResult{}, ErrSuiteCanonicalEnrollmentFinalize
	}
	return SuiteCanonicalEnrollmentFinalizeResult{Stage: SetupEnrolled, RequestUID: checkpoint.RequestUID, ClientConfigPath: filepath.Join(roots.Config, SuiteClientConfigName), ClientConfigSHA256: digest, HandoffState: handoff.HandoffState}, nil
}

func sameSuiteEnrollmentFinalizeBinding(current, expected suiteEnrollmentFinalizeEvidence, checkpointStage SetupStage) bool {
	return current.canonical.preparation == expected.canonical.preparation &&
		current.canonical.plan == expected.canonical.plan &&
		current.canonical.checkpoint == (SetupCheckpoint{SchemaVersion: 1, Stage: checkpointStage, RequestUID: expected.canonical.preparation.RequestUID}) &&
		current.canonical.stage == expected.canonical.stage && current.canonical.draft == expected.canonical.draft &&
		reflect.DeepEqual(current.canonical.transport, expected.canonical.transport) && current.canonical.identity == expected.canonical.identity &&
		current.canonical.installed.CanonicalRoot == expected.canonical.installed.CanonicalRoot && current.canonical.installed.RootInfo != nil && expected.canonical.installed.RootInfo != nil && os.SameFile(current.canonical.installed.RootInfo, expected.canonical.installed.RootInfo) &&
		current.canonical.application != nil && expected.canonical.application != nil && os.SameFile(current.canonical.application, expected.canonical.application) &&
		current.canonical.ref == expected.canonical.ref && current.attempt == expected.attempt && current.init == expected.init && current.core == expected.core && reflect.DeepEqual(current.appConfig, expected.appConfig)
}

func loadSuiteEnrollmentFinalizeEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, deps suiteCanonicalEnrollmentFinalizeDependencies) (suiteEnrollmentFinalizeEvidence, error) {
	var out suiteEnrollmentFinalizeEvidence
	preparation, expectedPlan, err := loadSuitePrecheckProofChain(bootstrap, roots, release)
	if err != nil {
		return out, err
	}
	plan, err := LoadSuiteSetupPlan(roots)
	checkpoint, checkpointErr := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || plan == nil || *plan != *expectedPlan || checkpointErr != nil || checkpoint == nil || checkpoint.RequestUID != preparation.RequestUID || (checkpoint.Stage != SetupIdentityReady && checkpoint.Stage != SetupEnrolled) {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	installed, err := deps.ValidateInstall(installedRoot, *plan, release.manifest.Version)
	if err != nil || installed.RootInfo == nil || !installed.RootInfo.IsDir() || installed.CanonicalRoot == "" || layout.revalidate(roots, installedRoot) != nil {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	stage := SuiteStageReceipt{SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, ManifestSHA256: plan.ManifestSHA256, Target: plan.Target, Version: release.manifest.Version, InstalledSuiteRoot: installed.CanonicalRoot, AdoptionKind: suiteStageAdoptionKind}
	loadedStage, err := LoadSuiteStageReceipt(roots)
	draft, draftErr := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || loadedStage == nil || *loadedStage != stage || draftErr != nil || draft == nil || !suiteTransportDraftMatchesChain(*draft, bootstrap, roots, *preparation, *plan, installed.CanonicalRoot, release.manifest.Version) {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	application, err := deps.EnsureApplication(draft.ApplicationRoot, false)
	transport, transportErr := LoadSuiteTransportReceipt(roots, bootstrap)
	identity, identityErr := LoadSuiteIdentityReceipt(roots)
	if err != nil || application == nil || !application.IsDir() || transportErr != nil || transport == nil || !suiteIdentityTransportMatchesChain(*transport, *preparation, *plan, *draft, bootstrap, roots, release.manifest.Version) || identityErr != nil || identity == nil {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	ref, err := suiteBootstrapEnrollmentIdentityRef(transport.DeploymentUID, preparation.RequestUID)
	draftDigest, digestErr := suiteConfigDraftCanonicalDigest(*draft, bootstrap, roots)
	if err != nil || digestErr != nil || identity.RequestUID != preparation.RequestUID || identity.SetupStageID != plan.StageID || identity.BootstrapSHA256 != preparation.BootstrapSHA256 || identity.ManifestSHA256 != plan.ManifestSHA256 || identity.ConfigDraftSHA256 != draftDigest || identity.DiscoverySHA256 != transport.DiscoverySHA256 || identity.DeploymentUID != transport.DeploymentUID || identity.IdentityRef != string(ref) || identity.StoreKind != suiteIdentityStoreKind {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	store, err := deps.NewStore(roots.AgentState)
	attempt, attemptErr := loadSuiteBootstrapEnrollmentAttempt(roots)
	canonical := suiteCanonicalEnrollmentEvidence{*preparation, *plan, *checkpoint, stage, *draft, *transport, *identity, installed, application, ref}
	if err != nil || store == nil || attemptErr != nil || attempt == nil || attempt.Stage != SuiteBootstrapAcknowledged || !validateSuiteCanonicalEnrollmentAttempt(roots, canonical, transport.discovery(), bootstrap.NodeName, release.manifest.Version, "", store, attempt, suiteBootstrapEnrollmentResultFromAttempt(*attempt)) || verifySuiteCanonicalEnrollmentKey(store, ref, identity.PublicKeySHA256) != nil {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	attemptRaw, _ := json.Marshal(attempt)
	stagingID := suiteBootstrapSHA256([]byte(preparation.RequestUID + "\x00" + plan.ManifestSHA256))
	initialized := SuiteApplicationInitState{SchemaVersion: 1, Stage: SuiteApplicationInitialized, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID, BootstrapSHA256: preparation.BootstrapSHA256, ManifestSHA256: plan.ManifestSHA256, ConfigDraftSHA256: draftDigest, DiscoverySHA256: transport.DiscoverySHA256, IdentityRef: string(ref), PublicKeySHA256: identity.PublicKeySHA256, EnrollmentAttemptSHA256: suiteBootstrapSHA256(attemptRaw), NodeUID: attempt.NodeUID, ApplicationRoot: draft.ApplicationRoot, AntConfigPath: draft.AntConfigPath, DatabasePath: filepath.Join(draft.ApplicationRoot, "data", "app.db"), ChromiumPath: filepath.Join(installed.CanonicalRoot, filepath.FromSlash(suiteCurrentReleaseLayout().Chromium)), ChromiumVersion: release.manifest.CoreVersions["chromium"], StagingConfigPath: filepath.Join(draft.ApplicationRoot, ".suite-init-"+stagingID+"-config.staging"), StagingDatabasePath: filepath.Join(draft.ApplicationRoot, "data", ".suite-init-"+stagingID+"-app.db.staging")}
	loadedInit, initErr := LoadSuiteApplicationInitState(roots)
	if initialized.validate() != nil || initErr != nil || loadedInit == nil || *loadedInit != initialized {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	appConfig := appconfig.DefaultConfig()
	appConfig.Database.Type, appConfig.Database.SQLite.Path = "sqlite", "data/app.db"
	core := appbrowser.Core{CoreId: suiteApplicationCoreID, CoreName: "Chromium " + initialized.ChromiumVersion, CorePath: filepath.Dir(initialized.ChromiumPath), IsDefault: true}
	appConfig.Browser.Cores, appConfig.Browser.DefaultCoreId = []appconfig.BrowserCore{core}, core.CoreId
	if deps.Readback(initialized.AntConfigPath, appConfig, initialized.DatabasePath, core) != nil || ctx.Err() != nil {
		return out, ErrSuiteCanonicalEnrollmentFinalize
	}
	return suiteEnrollmentFinalizeEvidence{canonical: canonical, attempt: *attempt, init: initialized, appConfig: appConfig, core: core, store: store}, nil
}

func buildSuiteFinalClientConfig(bootstrap BootstrapConfig, roots SuiteUserRoots, evidence suiteEnrollmentFinalizeEvidence) (FarmClientConfig, []byte, string, string, error) {
	origin, err := canonicalSuiteBootstrapOrigin(bootstrap.ServerURL, "https")
	if err != nil {
		return FarmClientConfig{}, nil, "", "", err
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.Host == "" {
		return FarmClientConfig{}, nil, "", "", ErrSuiteCanonicalEnrollmentFinalize
	}
	providerDigest := sha256.Sum256([]byte("ant-suite-provider-instance-v1\x00" + evidence.attempt.NodeUID))
	config := FarmClientConfig{
		ApplicationRoot: evidence.canonical.draft.ApplicationRoot, StateRoot: roots.AgentState,
		AntConfigPath: evidence.init.AntConfigPath, ControlURL: evidence.attempt.ControlEndpoint,
		EnrollmentURL: evidence.canonical.transport.EnrollmentEndpoint, PairingURL: origin + "/api/farm/pair",
		NodeName:           evidence.canonical.draft.NodeName,
		Identity:           FarmClientIdentityConfig{NodeUID: evidence.attempt.NodeUID, PrivateKeyRef: evidence.attempt.IdentityRef},
		ProviderInstanceID: "ant-farm-client-" + hex.EncodeToString(providerDigest[:]), FencingEpoch: 1,
		ShutdownTimeoutMs: suiteFinalShutdownTimeoutMS, HeartbeatIntervalMs: suiteFinalHeartbeatIntervalMS,
		ReconnectMinBackoffMs: suiteFinalReconnectMinBackoffMS, ReconnectMaxBackoffMs: suiteFinalReconnectMaxBackoffMS,
		LogFile: evidence.canonical.draft.LogPath,
	}
	if update := evidence.canonical.transport.Update; update != nil {
		config.UpdateManifestURL, config.UpdatePublicKey, config.UpdateChannel = update.ManifestURL, update.PublicKeyEd25519Base64, update.Channel
		config.UpdateCheckIntervalMs, config.UpdateHealthTimeoutMs, config.UpdateProbationMs = suiteFinalUpdateCheckIntervalMS, suiteFinalUpdateHealthTimeoutMS, suiteFinalUpdateProbationMS
	}
	validated := config
	if validated.ValidateFarmClientConfig() != nil {
		return FarmClientConfig{}, nil, "", "", ErrSuiteCanonicalEnrollmentFinalize
	}
	raw, err := yaml.Marshal(config)
	if err != nil || len(raw) == 0 || len(raw) > maxSuiteClientConfigBytes {
		return FarmClientConfig{}, nil, "", "", ErrSuiteCanonicalEnrollmentFinalize
	}
	digest := sha256.Sum256(raw)
	staging := filepath.Join(roots.Config, suiteFinalClientConfigStagingPrefix+hex.EncodeToString(digest[:16])+".staging")
	return config, raw, hex.EncodeToString(digest[:]), staging, nil
}

func ensureSuiteFinalClientConfig(roots SuiteUserRoots, stagingPath string, expected []byte) error {
	finalPath := filepath.Join(roots.Config, SuiteClientConfigName)
	if raw, err := readSuiteFinalClientConfigRaw(finalPath); err == nil {
		if !bytes.Equal(raw, expected) || verifySuiteFinalClientConfig(finalPath, FarmClientConfig{}, expected) != nil {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
		return cleanupSuiteFinalConfigStaging(stagingPath, expected)
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if raw, err := readSuiteFinalClientConfigRaw(stagingPath); err == nil {
		if !bytes.Equal(raw, expected) {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
	} else if errors.Is(err, os.ErrNotExist) {
		file, createErr := os.OpenFile(stagingPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil || secureSuiteSetupPath(stagingPath, false) != nil {
			if file != nil {
				_ = file.Close()
			}
			return ErrSuiteCanonicalEnrollmentFinalize
		}
		if _, writeErr := file.Write(expected); writeErr != nil || file.Sync() != nil || file.Close() != nil || syncSuiteSetupDirectory(roots.Config) != nil {
			_ = file.Close()
			return ErrSuiteCanonicalEnrollmentFinalize
		}
	} else {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if raw, err := readSuiteFinalClientConfigRaw(stagingPath); err != nil || !bytes.Equal(raw, expected) {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if err := publishSuiteApplicationFileNoReplace(stagingPath, finalPath, func() error {
		raw, err := readSuiteFinalClientConfigRaw(stagingPath)
		if err != nil || !bytes.Equal(raw, expected) {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
		return nil
	}); err != nil {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if raw, err := readSuiteFinalClientConfigRaw(finalPath); err != nil || !bytes.Equal(raw, expected) {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	return cleanupSuiteFinalConfigStaging(stagingPath, expected)
}

func cleanupSuiteFinalConfigStaging(path string, expected []byte) error {
	raw, err := readSuiteFinalClientConfigRaw(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !bytes.Equal(raw, expected) || os.Remove(path) != nil || syncSuiteSetupDirectory(filepath.Dir(path)) != nil {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	return nil
}

func readSuiteFinalClientConfigRaw(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxSuiteClientConfigBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteCanonicalEnrollmentFinalize
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteCanonicalEnrollmentFinalize
	}
	defer file.Close()
	handleInfo, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, maxSuiteClientConfigBytes+1))
	finalInfo, finalErr := os.Lstat(path)
	if statErr != nil || readErr != nil || finalErr != nil || len(raw) == 0 || len(raw) > maxSuiteClientConfigBytes || int64(len(raw)) != handleInfo.Size() || !os.SameFile(info, handleInfo) || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteCanonicalEnrollmentFinalize
	}
	return raw, nil
}

func verifySuiteFinalClientConfig(path string, expected FarmClientConfig, expectedRaw []byte) error {
	raw, err := readSuiteFinalClientConfigRaw(path)
	if err != nil || !bytes.Equal(raw, expectedRaw) {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	loaded, err := LoadFarmClientConfig(path)
	if err != nil || loaded.ValidateFarmClientConfig() != nil {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if expected != (FarmClientConfig{}) {
		validated := expected
		if validated.ValidateFarmClientConfig() != nil || loaded != validated {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
	}
	identity := loaded.identityConfig()
	if identity.PrivateKey != "" || identity.PrivateKeyEnv != "" || identity.PrivateKeyRef == "" {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	return nil
}

func revalidateSuiteEnrollmentFinalizeEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, expected suiteEnrollmentFinalizeEvidence, config FarmClientConfig, raw []byte, stagingPath string, deps suiteCanonicalEnrollmentFinalizeDependencies, requireHandoff bool) error {
	current, err := loadSuiteEnrollmentFinalizeEvidence(ctx, bootstrap, roots, release, installedRoot, layout, deps)
	if err != nil || current.canonical.preparation != expected.canonical.preparation || current.canonical.plan != expected.canonical.plan || current.canonical.checkpoint != expected.canonical.checkpoint || current.canonical.stage != expected.canonical.stage || current.canonical.draft != expected.canonical.draft || !reflect.DeepEqual(current.canonical.transport, expected.canonical.transport) || current.canonical.identity != expected.canonical.identity || current.attempt != expected.attempt || current.init != expected.init || current.canonical.installed.CanonicalRoot != expected.canonical.installed.CanonicalRoot || !os.SameFile(current.canonical.installed.RootInfo, expected.canonical.installed.RootInfo) || !os.SameFile(current.canonical.application, expected.canonical.application) || verifySuiteFinalClientConfig(filepath.Join(roots.Config, SuiteClientConfigName), config, raw) != nil || cleanupSuiteFinalConfigStaging(stagingPath, raw) != nil || inspectSuiteEnrollmentFinalizeArtifactRoots(roots, bootstrap, stagingPath) != nil {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	if requireHandoff {
		handoff, err := deps.LoadHandoff(roots)
		if err != nil || handoff == nil || handoff.ClientConfigSHA256 != suiteBootstrapSHA256(raw) || handoff.SetupRequestUID != expected.canonical.preparation.RequestUID || handoff.ManifestSHA256 != expected.canonical.plan.ManifestSHA256 || handoff.SetupStageID != expected.canonical.plan.StageID {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
	} else if handoff, err := deps.LoadHandoff(roots); err != nil {
		return ErrSuiteCanonicalEnrollmentFinalize
	} else if handoff != nil && (handoff.ClientConfigSHA256 != suiteBootstrapSHA256(raw) || handoff.SetupRequestUID != expected.canonical.preparation.RequestUID || handoff.ManifestSHA256 != expected.canonical.plan.ManifestSHA256 || handoff.SetupStageID != expected.canonical.plan.StageID) {
		return ErrSuiteCanonicalEnrollmentFinalize
	}
	return nil
}

func inspectSuiteEnrollmentFinalizeArtifactRoots(roots SuiteUserRoots, bootstrap BootstrapConfig, stagingPath string) error {
	allowedAgent := map[string]bool{
		suitePreparationStateName: true, suiteSetupLockName: true, suiteSetupPlanName: true, suiteSetupPlanName + ".lock": true,
		".ant-farm-client.lock": true, filepath.Base(bootstrap.StatePath): true, filepath.Base(bootstrap.StatePath) + ".bak": true,
		SuiteStageReceiptName: true, SuiteTransportReceiptName: true, SuiteIdentityReceiptName: true, farmClientIdentityStoreDir: true,
		SuiteBootstrapEnrollmentAttemptName: true, SuiteBootstrapEnrollmentAttemptName + ".bak": true, suiteBootstrapEnrollmentLockName: true,
		SuiteApplicationInitStateName: true, suiteApplicationInitBackupName: true, SuiteOwnershipHandoffName: true, SuiteOwnershipHandoffName + ".lock": true,
	}
	allowed := map[string]map[string]bool{
		roots.Config:     {suiteBootstrapDraftName: true, SuiteClientConfigDraftName: true, SuiteClientConfigName: true, filepath.Base(stagingPath): true},
		roots.AgentState: allowedAgent,
		roots.Logs:       {},
	}
	for root, names := range allowed {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return ErrSuiteCanonicalEnrollmentFinalize
		}
		for _, entry := range entries {
			if !names[entry.Name()] {
				return ErrSuiteCanonicalEnrollmentFinalize
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrSuiteCanonicalEnrollmentFinalize
			}
			if root == roots.AgentState && entry.Name() == farmClientIdentityStoreDir {
				if !info.IsDir() {
					return ErrSuiteCanonicalEnrollmentFinalize
				}
			} else if !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalEnrollmentFinalize
			}
		}
	}
	return nil
}
