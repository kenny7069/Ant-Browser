package backend

import (
	appbrowser "ant-chrome/backend/internal/browser"
	appconfig "ant-chrome/backend/internal/config"
	appdatabase "ant-chrome/backend/internal/database"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"gopkg.in/yaml.v3"
)

func newSuiteApplicationInitFixture(t *testing.T) suiteIdentityFixture {
	t.Helper()
	fixture := newSuiteEnrollmentACKFixture(t)
	ackDeps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x61), ackDeps); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestSuiteCanonicalApplicationInitRecoversOwnedPartialStagingDatabase(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	deps.AfterPlanned = func() error { return errors.New("planned") }
	_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil {
		t.Fatal(err)
	}
	if err := ensureOwnerDirectory(filepath.Dir(state.StagingDatabasePath)); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(state.StagingDatabasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	db, err := appdatabase.NewDB(state.StagingDatabasePath)
	if err != nil || db.Migrate() != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConn().Exec("DELETE FROM schema_migrations WHERE version > 10"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConn().Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	deps.AfterPlanned = nil
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatalf("partial recovery failed: %v", err)
	}
}

func TestSuiteCanonicalApplicationInitRejectsStagingSchemaDriftAndFinalClobber(t *testing.T) {
	t.Run("extra staging schema", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		deps.AfterPlanned = func() error { return errors.New("planned") }
		_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		state, _ := LoadSuiteApplicationInitState(fixture.roots)
		if err := ensureOwnerDirectory(filepath.Dir(state.StagingDatabasePath)); err != nil {
			t.Fatal(err)
		}
		file, _ := os.OpenFile(state.StagingDatabasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		_ = file.Close()
		db, err := appdatabase.NewDB(state.StagingDatabasePath)
		if err != nil || db.Migrate() != nil {
			t.Fatal(err)
		}
		_, _ = db.GetConn().Exec("CREATE TABLE foreign_data(value TEXT)")
		_, _ = db.GetConn().Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = db.Close()
		deps.AfterPlanned = nil
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
		db, _ = appdatabase.NewDB(state.StagingDatabasePath)
		defer db.Close()
		var count int
		if err := db.GetConn().QueryRow("SELECT COUNT(*) FROM foreign_data").Scan(&count); err != nil {
			t.Fatal("foreign schema was overwritten")
		}
	})
	t.Run("existing final database", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		deps.AfterPlanned = func() error { return errors.New("planned") }
		_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		state, _ := LoadSuiteApplicationInitState(fixture.roots)
		if err := ensureOwnerDirectory(filepath.Dir(state.DatabasePath)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(state.DatabasePath, []byte("user database"), 0o600); err != nil {
			t.Fatal(err)
		}
		deps.AfterPlanned = nil
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
		if raw, _ := os.ReadFile(state.DatabasePath); string(raw) != "user database" {
			t.Fatal("existing final database was clobbered")
		}
	})
}

func TestSuiteCanonicalApplicationInitStateCommitUnknownRecovers(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	original := deps.SaveState
	failed := false
	deps.SaveState = func(roots SuiteUserRoots, state SuiteApplicationInitState) error {
		if err := original(roots, state); err != nil {
			return err
		}
		if state.Stage == SuiteApplicationInitialized && !failed {
			failed = true
			return errors.New("commit unknown")
		}
		return nil
	}
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
		t.Fatal("commit unknown reported success")
	}
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatalf("commit unknown recovery failed: %v", err)
	}
}

func TestSuiteCanonicalApplicationInitReadbackIsPhysicallyReadOnly(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatal(err)
	}
	state, _ := LoadSuiteApplicationInitState(fixture.roots)
	before, err := os.ReadFile(state.DatabasePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := deps.Readback(state.AntConfigPath, appConfigForSuiteState(t, fixture, deps), state.DatabasePath, appCoreForSuiteState(t, fixture, deps)); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(state.DatabasePath)
	if !bytes.Equal(before, after) {
		t.Fatal("readback changed database bytes")
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if _, err := os.Lstat(state.DatabasePath + suffix); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("readback created sidecar %s", suffix)
		}
	}
}

func TestSuiteCanonicalApplicationInitRecoversJournalAndConfigPrefixes(t *testing.T) {
	t.Run("journal next prefix", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		original := deps.SaveState
		first := true
		deps.SaveState = func(roots SuiteUserRoots, state SuiteApplicationInitState) error {
			if first {
				first = false
				raw, _ := json.Marshal(state)
				raw = append(raw, '\n')
				return os.WriteFile(filepath.Join(roots.AgentState, suiteApplicationInitNextName), raw[:len(raw)/2], 0o600)
			}
			return original(roots, state)
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("partial journal reported success")
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
			t.Fatalf("journal recovery failed: %v", err)
		}
	})
	t.Run("config prefix", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		original := deps.WriteConfig
		first := true
		deps.WriteConfig = func(path string, config *appconfig.Config) error {
			if first {
				first = false
				raw, _ := yaml.Marshal(config)
				return os.WriteFile(path, raw[:len(raw)/2], 0o600)
			}
			return original(path, config)
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("partial config reported success")
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
			t.Fatalf("config recovery failed: %v", err)
		}
	})
}

func appConfigForSuiteState(t *testing.T, fixture suiteIdentityFixture, deps suiteCanonicalApplicationInitDependencies) *appconfig.Config {
	t.Helper()
	_, _, _, _, config, _, err := loadSuiteApplicationInitEvidence(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, mustSuiteLayout(t, fixture), deps)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func appCoreForSuiteState(t *testing.T, fixture suiteIdentityFixture, deps suiteCanonicalApplicationInitDependencies) appbrowser.Core {
	t.Helper()
	_, _, _, _, _, core, err := loadSuiteApplicationInitEvidence(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, mustSuiteLayout(t, fixture), deps)
	if err != nil {
		t.Fatal(err)
	}
	return core
}

func mustSuiteLayout(t *testing.T, fixture suiteIdentityFixture) *suitePrecheckRootLayoutSnapshot {
	t.Helper()
	layout, err := captureSuitePrecheckRootLayout(fixture.roots, fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	return layout
}

func suiteApplicationInitTestDependencies(fixture suiteIdentityFixture) suiteCanonicalApplicationInitDependencies {
	stage := suiteStageTestDependencies()
	return suiteCanonicalApplicationInitDependencies{
		NewStore:        func(string) (FarmClientIdentityStore, error) { return fixture.store, nil },
		ValidateInstall: stage.ValidateInstall,
		AcquireInstance: func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:  func(string) error { return nil }, EnsureApplication: ensureSuiteApplicationRootIdentity,
		SaveState: saveSuiteApplicationInitState, WriteConfig: writeSuiteApplicationConfig,
		InitializeDB: initializeSuiteApplicationDatabase, Readback: readbackSuiteApplication,
	}
}

func TestSuiteCanonicalApplicationInitCreatesCanonicalConfigDatabaseAndCore(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	for run := 0; run < 2; run++ {
		result, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		if err != nil || result.Stage != SuiteApplicationInitialized || result.RequestUID != fixture.preparation.RequestUID {
			t.Fatalf("run=%d result=%+v err=%v", run, result, err)
		}
	}
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil || state.Stage != SuiteApplicationInitialized {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupIdentityReady {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
	assertSuiteApplicationInitNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalApplicationInitRetainsProvenanceAndRecoversMissingPrimaryState(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatal(err)
	}
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil || state.Stage != SuiteApplicationInitialized {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	for _, pair := range [][2]string{{state.StagingConfigPath, state.AntConfigPath}, {state.StagingDatabasePath, state.DatabasePath}} {
		left, leftErr := os.Lstat(pair[0])
		right, rightErr := os.Lstat(pair[1])
		if leftErr != nil || rightErr != nil || !os.SameFile(left, right) {
			t.Fatalf("publication lost provenance: %v %v", leftErr, rightErr)
		}
	}
	backup, err := readSuiteApplicationInitStateFile(filepath.Join(fixture.roots.AgentState, suiteApplicationInitBackupName), fixture.roots.AgentState, mustSuiteApplicationStateRoot(t, fixture.roots.AgentState))
	if err != nil || backup == nil || backup.Stage != SuiteApplicationInitPlanned {
		t.Fatalf("backup=%+v err=%v", backup, err)
	}
	if err := os.Remove(filepath.Join(fixture.roots.AgentState, SuiteApplicationInitStateName)); err != nil {
		t.Fatal(err)
	}
	if recovered, err := LoadSuiteApplicationInitState(fixture.roots); err != nil || recovered == nil || recovered.Stage != SuiteApplicationInitPlanned {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}

func mustSuiteApplicationStateRoot(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := captureSuiteConfigDraftRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestSuiteCanonicalApplicationInitPreservesUnownedConfigAndDatabase(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{{"empty config", nil}, {"different config", []byte("foreign: true\n")}} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteApplicationInitFixture(t)
			deps := suiteApplicationInitTestDependencies(fixture)
			deps.AfterPlanned = func() error { return errors.New("stop") }
			_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
			state, _ := LoadSuiteApplicationInitState(fixture.roots)
			if err := os.WriteFile(state.StagingConfigPath, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			deps.AfterPlanned = nil
			if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
				t.Fatalf("err=%v", err)
			}
			if raw, _ := os.ReadFile(state.StagingConfigPath); !bytes.Equal(raw, test.raw) {
				t.Fatal("foreign config was modified")
			}
		})
	}
	t.Run("staging user row", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		deps.AfterPlanned = func() error { return errors.New("stop") }
		_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		state, _ := LoadSuiteApplicationInitState(fixture.roots)
		if err := ensureOwnerDirectory(filepath.Dir(state.StagingDatabasePath)); err != nil {
			t.Fatal(err)
		}
		seed, err := os.OpenFile(state.StagingDatabasePath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_ = seed.Close()
		db, err := appdatabase.NewDB(state.StagingDatabasePath)
		if err != nil || db.Migrate() != nil {
			t.Fatal(err)
		}
		if _, err := db.GetConn().Exec("INSERT INTO browser_bookmarks(name,url) VALUES('keep','https://example.invalid')"); err != nil {
			t.Fatal(err)
		}
		_, _ = db.GetConn().Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		_ = db.Close()
		before, _ := os.ReadFile(state.StagingDatabasePath)
		deps.AfterPlanned = nil
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
		after, _ := os.ReadFile(state.StagingDatabasePath)
		if !bytes.Equal(before, after) {
			t.Fatal("staging database with user data was modified")
		}
	})
}

func TestSuiteCanonicalApplicationInitRejectsCheckpointByteDriftAndManifestDrift(t *testing.T) {
	t.Run("checkpoint bytes", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		deps.AfterConfig = func() error {
			raw, err := os.ReadFile(fixture.bootstrap.StatePath)
			if err != nil {
				return err
			}
			return os.WriteFile(fixture.bootstrap.StatePath, append(raw, ' '), 0o600)
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
	})
	for _, mutate := range []func(*VerifiedSuiteRelease){
		func(release *VerifiedSuiteRelease) { release.manifest.ConfigSchema++ },
		func(release *VerifiedSuiteRelease) {
			for index := range release.manifest.Entries {
				if release.manifest.Entries[index].Path == "runtime/chrome/chrome.exe" {
					release.manifest.Entries[index].Role = "data"
				}
			}
		},
	} {
		fixture := newSuiteApplicationInitFixture(t)
		mutate(&fixture.release)
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteApplicationInitTestDependencies(fixture)); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("manifest drift err=%v", err)
		}
	}
}

func TestSuiteCanonicalApplicationInitPlansBeforeMutationAndRecoversConfigFault(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	firstPlan := true
	deps.AfterPlanned = func() error {
		if !firstPlan {
			return nil
		}
		firstPlan = false
		state, err := LoadSuiteApplicationInitState(fixture.roots)
		entries, readErr := os.ReadDir(filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir))
		if err != nil || state == nil || state.Stage != SuiteApplicationInitPlanned || readErr != nil || len(entries) != 0 {
			t.Fatalf("state=%+v err=%v entries=%v readErr=%v", state, err, entries, readErr)
		}
		return nil
	}
	deps.AfterConfig = func() error { return errors.New("crash after config") }
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
		t.Fatal("config crash reported success")
	}
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil || state.Stage != SuiteApplicationInitPlanned {
		t.Fatalf("state=%+v err=%v", state, err)
	}
	deps.AfterConfig = nil
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatalf("recovery failed: %v", err)
	}
}

func TestSuiteCanonicalApplicationInitRejectsNoACKAndUnknownFreshFootprint(t *testing.T) {
	t.Run("no acknowledgment", func(t *testing.T) {
		fixture := newSuiteEnrollmentACKFixture(t)
		deps := suiteApplicationInitTestDependencies(fixture)
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("unknown application file", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		unknown := filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir, "user-data")
		if err := os.WriteFile(unknown, []byte("keep"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteApplicationInitTestDependencies(fixture)); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
			t.Fatalf("err=%v", err)
		}
		if raw, _ := os.ReadFile(unknown); string(raw) != "keep" {
			t.Fatal("unknown data was modified")
		}
		if state, _ := LoadSuiteApplicationInitState(fixture.roots); state != nil {
			t.Fatal("journal created for non-fresh application")
		}
	})
}

func TestSuiteCanonicalApplicationInitReadbackMissingConfigFailsClosed(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	deps.AfterDatabase = func() error {
		return os.Remove(filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml"))
	}
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalApplicationInit) {
		t.Fatalf("err=%v", err)
	}
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil || state.Stage != SuiteApplicationInitPlanned {
		t.Fatalf("state=%+v err=%v", state, err)
	}
}

func TestSuiteApplicationInitStateStrictAndMonotonic(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	deps.AfterPlanned = func() error { return errors.New("stop") }
	_, _ = runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	state, err := LoadSuiteApplicationInitState(fixture.roots)
	if err != nil || state == nil {
		t.Fatal(err)
	}
	changed := *state
	changed.NodeUID = "other"
	if err := saveSuiteApplicationInitState(fixture.roots, changed); !errors.Is(err, ErrSuiteApplicationInitState) {
		t.Fatalf("binding drift err=%v", err)
	}
	path := filepath.Join(fixture.roots.AgentState, SuiteApplicationInitStateName)
	raw, _ := os.ReadFile(path)
	if err := os.WriteFile(path, append(raw[:len(raw)-2], []byte(",\"secret\":true}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteApplicationInitState(fixture.roots); !errors.Is(err, ErrSuiteApplicationInitState) {
		t.Fatalf("unknown field err=%v", err)
	}
}

func TestSuiteApplicationInitStateRejectsDuplicateAndOversize(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate", []byte(`{"schema_version":1,"schema_version":1}`)},
		{"oversize", bytes.Repeat([]byte{'x'}, suiteApplicationInitMaxBytes+1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteApplicationInitFixture(t)
			path := filepath.Join(fixture.roots.AgentState, SuiteApplicationInitStateName)
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSuiteApplicationInitState(fixture.roots); !errors.Is(err, ErrSuiteApplicationInitState) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestSuiteCanonicalApplicationInitHundredCallers(t *testing.T) {
	fixture := newSuiteApplicationInitFixture(t)
	deps := suiteApplicationInitTestDependencies(fixture)
	var wait sync.WaitGroup
	errorsOut := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
			errorsOut <- err
		}()
	}
	wait.Wait()
	close(errorsOut)
	wins := 0
	for err := range errorsOut {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("unexpected err=%v", err)
		}
	}
	if wins == 0 {
		t.Fatal("no initializer completed")
	}
}

func assertSuiteApplicationInitNoLaterArtifacts(t *testing.T, fixture suiteIdentityFixture) {
	t.Helper()
	for _, path := range []string{filepath.Join(fixture.roots.Config, SuiteClientConfigName), filepath.Join(fixture.roots.AgentState, SuiteOwnershipHandoffName), filepath.Join(fixture.roots.AgentState, SuiteActivationJournalName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact exists: %s", path)
		}
	}
}
