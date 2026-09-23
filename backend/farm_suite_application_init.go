package backend

import (
	appbrowser "ant-chrome/backend/internal/browser"
	appconfig "ant-chrome/backend/internal/config"
	appdatabase "ant-chrome/backend/internal/database"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"gopkg.in/yaml.v3"
)

var ErrSuiteCanonicalApplicationInit = errors.New("suite canonical application initialization failed")

const suiteApplicationCoreID = "suite-chromium"
const suiteApplicationConfigSchema = 3

type SuiteCanonicalApplicationInitResult struct {
	Stage           string `json:"stage"`
	RequestUID      string `json:"request_uid"`
	ApplicationRoot string `json:"application_root"`
	AntConfigPath   string `json:"ant_config_path"`
	DatabasePath    string `json:"database_path"`
}

type suiteCanonicalApplicationInitDependencies struct {
	NewStore          func(string) (FarmClientIdentityStore, error)
	ValidateInstall   func(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error)
	AcquireInstance   func(string) (suitePrecheckInstanceLock, error)
	SecureInstance    func(string) error
	EnsureApplication func(string, bool) (os.FileInfo, error)
	SaveState         func(SuiteUserRoots, SuiteApplicationInitState) error
	WriteConfig       func(string, *appconfig.Config) error
	InitializeDB      func(context.Context, string, appbrowser.Core) error
	Readback          func(string, *appconfig.Config, string, appbrowser.Core) error
	AfterPlanned      func() error
	AfterConfig       func() error
	AfterDatabase     func() error
}

func suiteCanonicalApplicationInitProductionDependencies() suiteCanonicalApplicationInitDependencies {
	return suiteCanonicalApplicationInitDependencies{
		NewStore: NewFarmClientIdentityStore, ValidateInstall: validateSuiteStagePlatformInstall,
		AcquireInstance:   func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) },
		SecureInstance:    func(path string) error { return secureSuiteSetupPath(path, false) },
		EnsureApplication: ensureSuiteApplicationRootIdentity, SaveState: saveSuiteApplicationInitState,
		WriteConfig: writeSuiteApplicationConfig, InitializeDB: initializeSuiteApplicationDatabase, Readback: readbackSuiteApplication,
	}
}

func RunSuiteCanonicalApplicationInit(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string) (SuiteCanonicalApplicationInitResult, error) {
	return runSuiteCanonicalApplicationInitWithDependencies(ctx, bootstrap, roots, release, installedSuiteRoot, suiteCanonicalApplicationInitProductionDependencies())
}

func runSuiteCanonicalApplicationInitWithDependencies(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedSuiteRoot string, deps suiteCanonicalApplicationInitDependencies) (SuiteCanonicalApplicationInitResult, error) {
	if ctx == nil || deps.NewStore == nil || deps.ValidateInstall == nil || deps.AcquireInstance == nil || deps.SecureInstance == nil || deps.EnsureApplication == nil || deps.SaveState == nil || deps.WriteConfig == nil || deps.InitializeDB == nil || deps.Readback == nil ||
		validateSuiteSetupInputs(&bootstrap, roots) != nil || bootstrap.StatePath != filepath.Join(roots.AgentState, "setup.json") || installedSuiteRoot == "" || !filepath.IsAbs(installedSuiteRoot) || filepath.Clean(installedSuiteRoot) != installedSuiteRoot || strings.TrimSpace(installedSuiteRoot) != installedSuiteRoot {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	layout, err := captureSuitePrecheckRootLayout(roots, installedSuiteRoot)
	if err != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	setupLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		if errors.Is(err, ErrSuiteSetupLocked) {
			return SuiteCanonicalApplicationInitResult{}, ErrSuiteSetupLocked
		}
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	defer setupLock.release()
	instanceLock, err := deps.AcquireInstance(roots.AgentState)
	if err != nil || instanceLock == nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	defer instanceLock.Release()
	if deps.SecureInstance(filepath.Join(roots.AgentState, ".ant-farm-client.lock")) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	attemptLock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, suiteBootstrapEnrollmentLockName))
	if err != nil {
		if errors.Is(err, ErrSuiteSetupLocked) {
			return SuiteCanonicalApplicationInitResult{}, ErrSuiteSetupLocked
		}
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	defer attemptLock.release()
	checkpointSnapshot, err := captureSuiteApplicationEvidenceSnapshot([]string{bootstrap.StatePath, bootstrap.StatePath + ".bak"})
	if err != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}

	evidence, store, attempt, planned, desiredConfig, core, err := loadSuiteApplicationInitEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, deps)
	if err != nil || validateSuiteApplicationEvidenceSnapshot(checkpointSnapshot) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	applicationFence, err := openSuiteApplicationRootFence(planned.ApplicationRoot)
	if err != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	defer applicationFence.Close()
	revalidate := func() error {
		if validateSuiteApplicationEvidenceSnapshot(checkpointSnapshot) != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		return revalidateSuiteApplicationInitEvidence(ctx, bootstrap, roots, release, installedSuiteRoot, layout, evidence, store, attempt, planned, deps)
	}
	existing, err := LoadSuiteApplicationInitState(roots)
	if err != nil || (existing != nil && *existing != planned && !sameSuiteApplicationInitBinding(*existing, planned)) {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if inspectSuiteApplicationInitFootprint(roots, bootstrap, evidence.ref, existing != nil) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if existing == nil {
		entries, readErr := os.ReadDir(planned.ApplicationRoot)
		if readErr != nil || len(entries) != 0 {
			return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
		}
		if deps.SaveState(roots, planned) != nil {
			return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
		}
		existing = &planned
	} else if existing.Stage == SuiteApplicationInitPlanned && deps.SaveState(roots, planned) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if deps.AfterPlanned != nil && deps.AfterPlanned() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if revalidate() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if existing.Stage == SuiteApplicationInitialized {
		if deps.Readback(planned.AntConfigPath, desiredConfig, planned.DatabasePath, core) != nil || revalidate() != nil {
			return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
		}
		return suiteApplicationInitResult(planned, SuiteApplicationInitialized), nil
	}
	if ensureSuiteApplicationConfigPublished(planned, desiredConfig, deps.WriteConfig) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if deps.AfterConfig != nil && deps.AfterConfig() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if revalidate() != nil || ensureSuiteApplicationDatabasePublished(ctx, planned, desiredConfig, core, deps) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if deps.AfterDatabase != nil && deps.AfterDatabase() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if revalidate() != nil || deps.Readback(planned.AntConfigPath, desiredConfig, planned.DatabasePath, core) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	if revalidate() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	initialized := planned
	initialized.Stage = SuiteApplicationInitialized
	if deps.SaveState(roots, initialized) != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	written, err := LoadSuiteApplicationInitState(roots)
	if err != nil || written == nil || *written != initialized || revalidate() != nil {
		return SuiteCanonicalApplicationInitResult{}, ErrSuiteCanonicalApplicationInit
	}
	return suiteApplicationInitResult(initialized, initialized.Stage), nil
}

func loadSuiteApplicationInitEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, deps suiteCanonicalApplicationInitDependencies) (suiteCanonicalEnrollmentEvidence, FarmClientIdentityStore, SuiteBootstrapEnrollmentAttempt, SuiteApplicationInitState, *appconfig.Config, appbrowser.Core, error) {
	var emptyEvidence suiteCanonicalEnrollmentEvidence
	evidence, err := loadSuiteCanonicalEnrollmentEvidence(ctx, bootstrap, roots, release, installedRoot, suiteCanonicalEnrollmentACKDependencies{ValidateInstall: deps.ValidateInstall, EnsureApplication: deps.EnsureApplication})
	if err != nil || layout.revalidate(roots, installedRoot) != nil {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	store, err := deps.NewStore(roots.AgentState)
	if err != nil || store == nil || verifySuiteCanonicalEnrollmentKey(store, evidence.ref, evidence.identity.PublicKeySHA256) != nil {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	attempt, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil || attempt == nil || attempt.Stage != SuiteBootstrapAcknowledged || !validateSuiteCanonicalEnrollmentAttempt(roots, evidence, evidence.transport.discovery(), bootstrap.NodeName, release.manifest.Version, "", store, attempt, suiteBootstrapEnrollmentResultFromAttempt(*attempt)) {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	chromiumVersion, ok := release.manifest.CoreVersions["chromium"]
	if !ok || strings.TrimSpace(chromiumVersion) != chromiumVersion || chromiumVersion == "" || release.manifest.ConfigSchema != suiteApplicationConfigSchema {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	chromeRelative := suiteCurrentReleaseLayout().Chromium
	covered := 0
	for _, entry := range release.manifest.Entries {
		if entry.Path == chromeRelative && entry.Executable && entry.Role == "binary" {
			covered++
		}
	}
	if covered != 1 {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	chromePath := filepath.Join(evidence.installed.CanonicalRoot, filepath.FromSlash(chromeRelative))
	chromeInfo, err := os.Lstat(chromePath)
	if err != nil || !chromeInfo.Mode().IsRegular() || chromeInfo.Mode()&os.ModeSymlink != 0 {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	attemptRaw, _ := json.Marshal(attempt)
	draftDigest, err := suiteConfigDraftCanonicalDigest(evidence.draft, bootstrap, roots)
	if err != nil {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	stagingID := suiteBootstrapSHA256([]byte(evidence.preparation.RequestUID + "\x00" + evidence.plan.ManifestSHA256))
	planned := SuiteApplicationInitState{SchemaVersion: 1, Stage: SuiteApplicationInitPlanned, RequestUID: evidence.preparation.RequestUID, SetupStageID: evidence.plan.StageID, BootstrapSHA256: evidence.preparation.BootstrapSHA256, ManifestSHA256: evidence.plan.ManifestSHA256, ConfigDraftSHA256: draftDigest, DiscoverySHA256: evidence.transport.DiscoverySHA256, IdentityRef: string(evidence.ref), PublicKeySHA256: evidence.identity.PublicKeySHA256, EnrollmentAttemptSHA256: suiteBootstrapSHA256(attemptRaw), NodeUID: attempt.NodeUID, ApplicationRoot: evidence.draft.ApplicationRoot, AntConfigPath: evidence.draft.AntConfigPath, DatabasePath: filepath.Join(evidence.draft.ApplicationRoot, "data", "app.db"), ChromiumPath: chromePath, ChromiumVersion: chromiumVersion, StagingConfigPath: filepath.Join(evidence.draft.ApplicationRoot, ".suite-init-"+stagingID+"-config.staging"), StagingDatabasePath: filepath.Join(evidence.draft.ApplicationRoot, "data", ".suite-init-"+stagingID+"-app.db.staging")}
	if planned.validate() != nil {
		return emptyEvidence, nil, SuiteBootstrapEnrollmentAttempt{}, SuiteApplicationInitState{}, nil, appbrowser.Core{}, ErrSuiteCanonicalApplicationInit
	}
	core := appbrowser.Core{CoreId: suiteApplicationCoreID, CoreName: "Chromium " + chromiumVersion, CorePath: filepath.Dir(chromePath), IsDefault: true}
	config := appconfig.DefaultConfig()
	config.Database.Type, config.Database.SQLite.Path = "sqlite", "data/app.db"
	config.Browser.Cores = []appconfig.BrowserCore{core}
	config.Browser.DefaultCoreId = core.CoreId
	return evidence, store, *attempt, planned, config, core, nil
}

func revalidateSuiteApplicationInitEvidence(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, release VerifiedSuiteRelease, installedRoot string, layout *suitePrecheckRootLayoutSnapshot, expected suiteCanonicalEnrollmentEvidence, store FarmClientIdentityStore, attempt SuiteBootstrapEnrollmentAttempt, planned SuiteApplicationInitState, deps suiteCanonicalApplicationInitDependencies) error {
	current, currentStore, currentAttempt, currentPlanned, _, _, err := loadSuiteApplicationInitEvidence(ctx, bootstrap, roots, release, installedRoot, layout, deps)
	journal, journalErr := LoadSuiteApplicationInitState(roots)
	if err != nil || journalErr != nil || journal == nil || !sameSuiteApplicationInitBinding(*journal, planned) || currentStore == nil || current.preparation != expected.preparation || current.plan != expected.plan || current.checkpoint != expected.checkpoint || current.stage != expected.stage || current.draft != expected.draft || !reflect.DeepEqual(current.transport, expected.transport) || current.identity != expected.identity || currentAttempt != attempt || currentPlanned != planned || !os.SameFile(current.application, expected.application) || verifySuiteCanonicalEnrollmentKey(store, expected.ref, expected.identity.PublicKeySHA256) != nil || inspectSuiteApplicationInitFootprint(roots, bootstrap, expected.ref, true) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func ensureSuiteApplicationRootIdentity(path string, _ bool) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	_, resolved, resolveErr := suitePrecheckResolvedPath(path)
	final, finalErr := os.Lstat(path)
	if err != nil || resolveErr != nil || resolved == nil || finalErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, resolved) || !os.SameFile(info, final) || validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalApplicationInit
	}
	return info, nil
}

func sameSuiteApplicationInitBinding(existing, planned SuiteApplicationInitState) bool {
	existing.Stage = planned.Stage
	return existing == planned
}

func suiteApplicationInitResult(state SuiteApplicationInitState, stage string) SuiteCanonicalApplicationInitResult {
	return SuiteCanonicalApplicationInitResult{Stage: stage, RequestUID: state.RequestUID, ApplicationRoot: state.ApplicationRoot, AntConfigPath: state.AntConfigPath, DatabasePath: state.DatabasePath}
}

func ensureSuiteApplicationConfig(path string, desired *appconfig.Config, write func(string, *appconfig.Config) error) error {
	expected, err := yaml.Marshal(desired)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if write == nil {
			return ErrSuiteCanonicalApplicationInit
		}
		return write(path, desired)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	handleInfo, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	finalInfo, finalErr := os.Lstat(path)
	var loaded appconfig.Config
	if err != nil || statErr != nil || readErr != nil || finalErr != nil || !os.SameFile(info, handleInfo) || !os.SameFile(handleInfo, finalInfo) || !reflect.DeepEqual(raw, expected) || yaml.Unmarshal(raw, &loaded) != nil || !reflect.DeepEqual(&loaded, desired) {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func ensureSuiteApplicationConfigPublished(state SuiteApplicationInitState, desired *appconfig.Config, write func(string, *appconfig.Config) error) error {
	if err := ensureSuiteApplicationConfig(state.AntConfigPath, desired, nil); err == nil {
		stagingInfo, stagingErr := os.Lstat(state.StagingConfigPath)
		finalInfo, finalErr := os.Lstat(state.AntConfigPath)
		if stagingErr != nil || finalErr != nil || !os.SameFile(stagingInfo, finalInfo) || ensureSuiteApplicationConfig(state.StagingConfigPath, desired, nil) != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		return nil
	} else if _, statErr := os.Lstat(state.AntConfigPath); !errors.Is(statErr, os.ErrNotExist) {
		return ErrSuiteCanonicalApplicationInit
	}
	if err := write(state.StagingConfigPath, desired); err != nil {
		return err
	}
	if err := ensureSuiteApplicationConfig(state.StagingConfigPath, desired, nil); err != nil {
		return err
	}
	if err := publishSuiteApplicationFileNoReplace(state.StagingConfigPath, state.AntConfigPath, func() error {
		return ensureSuiteApplicationConfig(state.StagingConfigPath, desired, nil)
	}); err != nil {
		return err
	}
	return ensureSuiteApplicationConfig(state.AntConfigPath, desired, nil)
}

func ensureSuiteApplicationDatabasePublished(ctx context.Context, state SuiteApplicationInitState, config *appconfig.Config, core appbrowser.Core, deps suiteCanonicalApplicationInitDependencies) error {
	if _, err := os.Lstat(state.DatabasePath); err == nil {
		if err := deps.Readback(state.AntConfigPath, config, state.DatabasePath, core); err != nil {
			return err
		}
		stagingInfo, stagingErr := os.Lstat(state.StagingDatabasePath)
		finalInfo, finalErr := os.Lstat(state.DatabasePath)
		if stagingErr != nil || finalErr != nil || !os.SameFile(stagingInfo, finalInfo) || deps.Readback(state.AntConfigPath, config, state.StagingDatabasePath, core) != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrSuiteCanonicalApplicationInit
	}
	if err := deps.InitializeDB(ctx, state.StagingDatabasePath, core); err != nil {
		return err
	}
	if err := deps.Readback(state.AntConfigPath, config, state.StagingDatabasePath, core); err != nil {
		return err
	}
	if err := publishSuiteApplicationFileNoReplace(state.StagingDatabasePath, state.DatabasePath, func() error {
		return deps.Readback(state.AntConfigPath, config, state.StagingDatabasePath, core)
	}); err != nil {
		return err
	}
	if err := deps.Readback(state.AntConfigPath, config, state.DatabasePath, core); err != nil {
		return err
	}
	return nil
}

func writeSuiteApplicationConfig(path string, config *appconfig.Config) error {
	raw, err := yaml.Marshal(config)
	if err != nil {
		return err
	}
	return writeSuiteApplicationRecoverableFile(path, raw)
}

func initializeSuiteApplicationDatabase(ctx context.Context, path string, core appbrowser.Core) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	dataRoot := filepath.Dir(path)
	dataFence, err := openSuiteApplicationDataDirectory(dataRoot)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer dataFence.Close()
	_, statErr := os.Lstat(path)
	create := errors.Is(statErr, os.ErrNotExist)
	if statErr != nil && !create {
		return ErrSuiteCanonicalApplicationInit
	}
	databaseFence, err := openSuiteApplicationDatabaseFence(path, create)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer databaseFence.Close()
	info, err := databaseFence.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, pathInfo) || validateSuiteSetupPathSecurity(path, false) != nil || (!create && info.Size() > 0 && validateSuiteApplicationPartialDatabase(path) != nil) {
		return ErrSuiteCanonicalApplicationInit
	}
	if create && (databaseFence.Sync() != nil || syncSuiteSetupDirectory(dataRoot) != nil) {
		return ErrSuiteCanonicalApplicationInit
	}
	db, err := appdatabase.NewDB(path)
	if err != nil {
		return err
	}
	defer func() {
		if db != nil {
			_ = db.Close()
		}
	}()
	if _, err := db.GetConn().ExecContext(ctx, "PRAGMA synchronous=FULL"); err != nil {
		return err
	}
	if err := db.Migrate(); err != nil {
		return err
	}
	dao := appbrowser.NewSQLiteCoreDAO(db.GetConn())
	cores, err := dao.List()
	if err != nil || (len(cores) != 0 && (len(cores) != 1 || cores[0] != core)) {
		return ErrSuiteCanonicalApplicationInit
	}
	if len(cores) == 0 && dao.Upsert(core) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	var busy, logFrames, checkpointed int
	if err := db.GetConn().QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointed); err != nil || busy != 0 || logFrames != 0 || checkpointed != 0 {
		return ErrSuiteCanonicalApplicationInit
	}
	if err := db.Close(); err != nil {
		return err
	}
	db = nil
	for _, suffix := range []string{"", "-wal", "-shm"} {
		candidate := path + suffix
		if _, err := os.Lstat(candidate); err == nil {
			if secureSuiteSetupPath(candidate, false) != nil {
				return ErrSuiteCanonicalApplicationInit
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	err = file.Sync()
	closeErr := file.Close()
	if err != nil || closeErr != nil || syncSuiteSetupDirectory(dataRoot) != nil || syncSuiteSetupDirectory(filepath.Dir(dataRoot)) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func readbackSuiteApplication(configPath string, expected *appconfig.Config, databasePath string, core appbrowser.Core) (resultErr error) {
	snapshot, err := captureSuiteApplicationDatabaseSnapshot(databasePath)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer func() {
		if validateSuiteApplicationDatabaseSnapshot(databasePath, snapshot) != nil {
			resultErr = ErrSuiteCanonicalApplicationInit
		}
	}()
	if err := ensureSuiteApplicationConfig(configPath, expected, nil); err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	db, err := sql.Open("sqlite", suiteApplicationSQLiteReadOnlyURI(databasePath))
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if _, err := db.Exec("PRAGMA query_only=ON"); err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if validateSuiteApplicationSQLiteHeader(databasePath) != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return ErrSuiteCanonicalApplicationInit
	}
	rows, err := db.Query("PRAGMA foreign_key_check")
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if rows.Next() || rows.Close() != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	list, err := db.Query("PRAGMA database_list")
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	mainCount := 0
	for list.Next() {
		var sequence int
		var name, file string
		if list.Scan(&sequence, &name, &file) != nil || (name != "main" && (name != "temp" || file != "")) {
			list.Close()
			return ErrSuiteCanonicalApplicationInit
		}
		if name == "main" {
			listed, listedErr := os.Lstat(filepath.Clean(filepath.FromSlash(file)))
			if file == "" || !filepath.IsAbs(filepath.FromSlash(file)) || listedErr != nil || !os.SameFile(snapshot.Info, listed) {
				list.Close()
				return ErrSuiteCanonicalApplicationInit
			}
			mainCount++
		}
	}
	if list.Close() != nil || mainCount != 1 {
		return ErrSuiteCanonicalApplicationInit
	}
	actualSchema, err := inspectSuiteApplicationDatabaseSchema(db)
	expectedSchema, err2 := canonicalSuiteApplicationDatabaseSchema()
	if err != nil || err2 != nil || !reflect.DeepEqual(actualSchema, expectedSchema) {
		return ErrSuiteCanonicalApplicationInit
	}
	cores, err := appbrowser.NewSQLiteCoreDAO(db).List()
	if err != nil || len(cores) != 1 || cores[0] != core {
		return ErrSuiteCanonicalApplicationInit
	}
	for table := range actualSchema.Columns {
		if table == "schema_migrations" || table == "browser_cores" {
			continue
		}
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteSuiteSQLiteIdentifier(table)).Scan(&count); err != nil || count != 0 {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	return nil
}

type suiteApplicationDatabaseSnapshot struct {
	Info os.FileInfo
	Size int64
	Hash [sha256.Size]byte
}

type suiteApplicationEvidenceFileSnapshot struct {
	Path   string
	Exists bool
	Info   os.FileInfo
	Size   int64
	Hash   [sha256.Size]byte
}

func captureSuiteApplicationEvidenceSnapshot(paths []string) ([]suiteApplicationEvidenceFileSnapshot, error) {
	result := make([]suiteApplicationEvidenceFileSnapshot, 0, len(paths))
	for _, path := range paths {
		entry := suiteApplicationEvidenceFileSnapshot{Path: path}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			result = append(result, entry)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(path, false) != nil {
			return nil, ErrSuiteCanonicalApplicationInit
		}
		file, err := os.Open(path)
		if err != nil {
			return nil, ErrSuiteCanonicalApplicationInit
		}
		handleInfo, statErr := file.Stat()
		hasher := sha256.New()
		written, readErr := io.Copy(hasher, file)
		closeErr := file.Close()
		finalInfo, finalErr := os.Lstat(path)
		if statErr != nil || readErr != nil || closeErr != nil || finalErr != nil || written != handleInfo.Size() || !os.SameFile(info, handleInfo) || !os.SameFile(handleInfo, finalInfo) {
			return nil, ErrSuiteCanonicalApplicationInit
		}
		entry.Exists, entry.Info, entry.Size = true, handleInfo, handleInfo.Size()
		copy(entry.Hash[:], hasher.Sum(nil))
		result = append(result, entry)
	}
	return result, nil
}

func validateSuiteApplicationEvidenceSnapshot(expected []suiteApplicationEvidenceFileSnapshot) error {
	paths := make([]string, len(expected))
	for index := range expected {
		paths[index] = expected[index].Path
	}
	current, err := captureSuiteApplicationEvidenceSnapshot(paths)
	if err != nil || len(current) != len(expected) {
		return ErrSuiteCanonicalApplicationInit
	}
	for index := range expected {
		if current[index].Exists != expected[index].Exists || current[index].Exists && (!os.SameFile(current[index].Info, expected[index].Info) || current[index].Size != expected[index].Size || current[index].Hash != expected[index].Hash) {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	return nil
}

func suiteApplicationSQLiteReadOnlyURI(path string) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	return u.String() + "?mode=ro&immutable=1"
}

func suiteApplicationSQLiteRecoveryURI(path string) string {
	u := &url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	return u.String() + "?mode=ro&immutable=1"
}

func captureSuiteApplicationDatabaseSnapshot(path string) (suiteApplicationDatabaseSnapshot, error) {
	var snapshot suiteApplicationDatabaseSnapshot
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(path, false) != nil {
		return snapshot, ErrSuiteCanonicalApplicationInit
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(path + suffix); !errors.Is(err, os.ErrNotExist) {
			return snapshot, ErrSuiteCanonicalApplicationInit
		}
	}
	file, err := os.Open(path)
	if err != nil {
		return snapshot, ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	handleInfo, err := file.Stat()
	hasher := sha256.New()
	written, readErr := io.Copy(hasher, file)
	finalInfo, finalErr := os.Lstat(path)
	if err != nil || readErr != nil || finalErr != nil || written != handleInfo.Size() || !os.SameFile(info, handleInfo) || !os.SameFile(handleInfo, finalInfo) {
		return snapshot, ErrSuiteCanonicalApplicationInit
	}
	copy(snapshot.Hash[:], hasher.Sum(nil))
	snapshot.Info, snapshot.Size = handleInfo, handleInfo.Size()
	return snapshot, nil
}

func validateSuiteApplicationDatabaseSnapshot(path string, expected suiteApplicationDatabaseSnapshot) error {
	current, err := captureSuiteApplicationDatabaseSnapshot(path)
	if err != nil || expected.Info == nil || !os.SameFile(expected.Info, current.Info) || expected.Size != current.Size || expected.Hash != current.Hash {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

func validateSuiteApplicationSQLiteHeader(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer file.Close()
	header := make([]byte, 20)
	if read, err := io.ReadFull(file, header); err != nil || read != len(header) || string(header[:16]) != "SQLite format 3\x00" || header[18] != 2 || header[19] != 2 {
		return ErrSuiteCanonicalApplicationInit
	}
	return nil
}

type suiteApplicationColumn struct {
	Name       string
	Type       string
	NotNull    int
	DefaultSQL sql.NullString
	PrimaryKey int
}

type suiteApplicationDatabaseSchema struct {
	Versions     []int
	Descriptions map[int]string
	Columns      map[string][]suiteApplicationColumn
	Objects      map[string]string
}

func canonicalSuiteApplicationDatabaseSchema() (suiteApplicationDatabaseSchema, error) {
	db, err := appdatabase.NewDB(":memory:")
	if err != nil {
		return suiteApplicationDatabaseSchema{}, err
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		return suiteApplicationDatabaseSchema{}, err
	}
	return inspectSuiteApplicationDatabaseSchema(db.GetConn())
}

func inspectSuiteApplicationDatabaseSchema(db *sql.DB) (suiteApplicationDatabaseSchema, error) {
	result := suiteApplicationDatabaseSchema{Descriptions: map[int]string{}, Columns: map[string][]suiteApplicationColumn{}, Objects: map[string]string{}}
	type objectRow struct{ kind, name, definition string }
	var objects []objectRow
	rows, err := db.Query("SELECT type,name,COALESCE(sql,'') FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%' ORDER BY type,name")
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var kind, name, definition string
		if err := rows.Scan(&kind, &name, &definition); err != nil {
			rows.Close()
			return result, err
		}
		objects = append(objects, objectRow{kind, name, definition})
	}
	if err := rows.Close(); err != nil {
		return result, err
	}
	for _, object := range objects {
		kind, name, definition := object.kind, object.name, object.definition
		if kind == "table" {
			columnRows, err := db.Query("PRAGMA table_info(" + quoteSuiteSQLiteIdentifier(name) + ")")
			if err != nil {
				return result, err
			}
			for columnRows.Next() {
				var cid int
				var column suiteApplicationColumn
				if err := columnRows.Scan(&cid, &column.Name, &column.Type, &column.NotNull, &column.DefaultSQL, &column.PrimaryKey); err != nil {
					columnRows.Close()
					return result, err
				}
				result.Columns[name] = append(result.Columns[name], column)
			}
			if err := columnRows.Close(); err != nil {
				return result, err
			}
		} else {
			result.Objects[kind+"\x00"+name] = definition
		}
	}
	if _, ok := result.Columns["schema_migrations"]; ok {
		versionRows, err := db.Query("SELECT version,desc FROM schema_migrations ORDER BY version")
		if err != nil {
			return result, err
		}
		for versionRows.Next() {
			var version int
			var description string
			if err := versionRows.Scan(&version, &description); err != nil {
				versionRows.Close()
				return result, err
			}
			result.Versions = append(result.Versions, version)
			result.Descriptions[version] = description
		}
		if err := versionRows.Close(); err != nil {
			return result, err
		}
	}
	return result, nil
}

func quoteSuiteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func validateSuiteApplicationPartialDatabase(path string) (resultErr error) {
	snapshot, err := captureSuiteApplicationEvidenceSnapshot([]string{path, path + "-wal", path + "-shm"})
	if err != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	defer func() {
		if validateSuiteApplicationEvidenceSnapshot(snapshot) != nil {
			resultErr = ErrSuiteCanonicalApplicationInit
		}
	}()
	for _, entry := range snapshot[1:] {
		if entry.Exists {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	db, err := sql.Open("sqlite", suiteApplicationSQLiteRecoveryURI(path))
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil || integrity != "ok" {
		return ErrSuiteCanonicalApplicationInit
	}
	foreignKeys, err := db.Query("PRAGMA foreign_key_check")
	if err != nil || foreignKeys.Next() || foreignKeys.Close() != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	actual, err := inspectSuiteApplicationDatabaseSchema(db)
	expected, expectedErr := canonicalSuiteApplicationDatabaseSchema()
	if err != nil || expectedErr != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	if len(actual.Versions) > len(expected.Versions) {
		return ErrSuiteCanonicalApplicationInit
	}
	for index, version := range actual.Versions {
		if version != index+1 || version != expected.Versions[index] || actual.Descriptions[version] != expected.Descriptions[version] {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	for table, columns := range actual.Columns {
		expectedColumns, ok := expected.Columns[table]
		if !ok || len(columns) > len(expectedColumns) || !reflect.DeepEqual(columns, expectedColumns[:len(columns)]) || table == "schema_migrations" && !reflect.DeepEqual(columns, expectedColumns) {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	for object, definition := range actual.Objects {
		if expectedDefinition, ok := expected.Objects[object]; !ok || definition != expectedDefinition {
			return ErrSuiteCanonicalApplicationInit
		}
	}
	for table := range actual.Columns {
		if table != "schema_migrations" {
			var count int
			if err := db.QueryRow("SELECT COUNT(*) FROM " + quoteSuiteSQLiteIdentifier(table)).Scan(&count); err != nil || count != 0 {
				return ErrSuiteCanonicalApplicationInit
			}
		}
	}
	return nil
}

func inspectSuiteApplicationInitFootprint(roots SuiteUserRoots, bootstrap BootstrapConfig, ref FarmClientIdentityKeyRef, allowApplication bool) error {
	state, stateErr := LoadSuiteApplicationInitState(roots)
	if stateErr != nil {
		return ErrSuiteCanonicalApplicationInit
	}
	allowedState := map[string]bool{suitePreparationStateName: true, suiteSetupLockName: true, suiteSetupPlanName: true, suiteSetupPlanName + ".lock": true, ".ant-farm-client.lock": true, filepath.Base(bootstrap.StatePath): true, filepath.Base(bootstrap.StatePath) + ".bak": true, SuiteStageReceiptName: true, SuiteTransportReceiptName: true, SuiteIdentityReceiptName: true, farmClientIdentityStoreDir: true, SuiteBootstrapEnrollmentAttemptName: true, SuiteBootstrapEnrollmentAttemptName + ".bak": true, suiteBootstrapEnrollmentLockName: true, SuiteApplicationInitStateName: true, suiteApplicationInitNextName: true, suiteApplicationInitBackupName: true}
	for root, allowed := range map[string]map[string]bool{roots.Config: {suiteBootstrapDraftName: true, SuiteClientConfigDraftName: true}, roots.AgentState: allowedState, roots.Logs: {}} {
		if validateSuiteSetupPathSecurity(root, true) != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, entry := range entries {
			if !allowed[entry.Name()] {
				return ErrSuiteCanonicalApplicationInit
			}
			path := filepath.Join(root, entry.Name())
			info, err := os.Lstat(path)
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return ErrSuiteCanonicalApplicationInit
			}
			if root == roots.AgentState && entry.Name() == farmClientIdentityStoreDir {
				if !info.IsDir() || validateSuiteIdentityStoreDirectory(path, roots.AgentState, ref, false) != nil {
					return ErrSuiteCanonicalApplicationInit
				}
			} else if !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
				return ErrSuiteCanonicalApplicationInit
			}
		}
	}
	applicationEntries, err := os.ReadDir(filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir))
	if err != nil {
		return err
	}
	if !allowApplication && len(applicationEntries) != 0 {
		return ErrSuiteCanonicalApplicationInit
	}
	for _, entry := range applicationEntries {
		stagingConfigName := ""
		if state != nil {
			stagingConfigName = filepath.Base(state.StagingConfigPath)
		}
		if entry.Name() != "config.yaml" && entry.Name() != "data" && entry.Name() != stagingConfigName {
			return ErrSuiteCanonicalApplicationInit
		}
		path := filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir, entry.Name())
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || (entry.Name() == "data") != info.IsDir() || validateSuiteSetupPathSecurity(path, entry.Name() == "data") != nil {
			return ErrSuiteCanonicalApplicationInit
		}
		if entry.Name() == "data" {
			children, err := os.ReadDir(path)
			if err != nil {
				return err
			}
			for _, child := range children {
				stagingDBName := ""
				if state != nil {
					stagingDBName = filepath.Base(state.StagingDatabasePath)
				}
				if child.Name() != "app.db" && child.Name() != "app.db-wal" && child.Name() != "app.db-shm" && child.Name() != stagingDBName && child.Name() != stagingDBName+"-wal" && child.Name() != stagingDBName+"-shm" {
					return ErrSuiteCanonicalApplicationInit
				}
				childPath := filepath.Join(path, child.Name())
				if info, err := os.Lstat(childPath); err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || validateSuiteSetupPathSecurity(childPath, false) != nil {
					return ErrSuiteCanonicalApplicationInit
				}
			}
		}
	}
	return nil
}
