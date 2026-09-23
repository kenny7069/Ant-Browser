package backend

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

func setupEngineFixture(t *testing.T) (SuiteUserRoots, BootstrapConfig) {
	t.Helper()
	base := t.TempDir()
	roots := SuiteUserRoots{
		Config:      filepath.Join(base, "config"),
		BrowserData: filepath.Join(base, "browser-data"),
		AgentState:  filepath.Join(base, "agent-state"),
		Logs:        filepath.Join(base, "logs"),
	}
	config := BootstrapConfig{
		ServerURL: "https://farm.example.test:8443",
		StatePath: filepath.Join(roots.AgentState, "setup.json"),
		NodeName:  "Farm One",
	}
	return roots, config
}

func TestSuiteSetupFreshRunWritesOwnerOnlyTypedDraft(t *testing.T) {
	roots, config := setupEngineFixture(t)
	classification, err := ClassifySuiteSetup(roots, config)
	if err != nil || classification != SuiteSetupFresh {
		t.Fatalf("initial classification = %q, %v", classification, err)
	}
	coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Run()
	if err != nil {
		t.Fatal(err)
	}
	if result.Classification != SuiteSetupFresh || result.Checkpoint.Stage != SetupBootstrapDrafted {
		t.Fatalf("result = %+v", result)
	}
	if _, err := os.Stat(config.StatePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preparation advanced canonical checkpoint: %v", err)
	}
	preparationPath := filepath.Join(roots.AgentState, suitePreparationStateName)
	if _, err := os.Stat(preparationPath); err != nil {
		t.Fatalf("preparation checkpoint: %v", err)
	}
	for _, path := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		info, statErr := os.Stat(path)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("root %q = %v, %v", path, info, statErr)
		}
		if runtime.GOOS != "windows" && info.Mode().Perm() != 0o700 {
			t.Fatalf("root %q mode = %o", path, info.Mode().Perm())
		}
	}
	raw, err := os.ReadFile(result.BootstrapPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"enrollment_code", "private_key", "password", "cookie"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("bootstrap draft contains %q: %s", forbidden, raw)
		}
	}
	draft, exists, err := loadBootstrapDraft(result.BootstrapPath)
	if err != nil || !exists || *draft != config {
		t.Fatalf("draft = %#v, exists=%v, err=%v", draft, exists, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(result.BootstrapPath)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("draft mode = %o", info.Mode().Perm())
		}
	}
	if matches, _ := filepath.Glob(filepath.Join(roots.Config, ".suite-bootstrap-*")); len(matches) != 0 {
		t.Fatalf("temporary drafts remain: %v", matches)
	}
}

func TestSuiteSetupFailureInjectionResumesIdempotently(t *testing.T) {
	for _, failedStage := range []SetupStage{SetupInputValidated, SetupUserRootsReady, SetupBootstrapDrafted} {
		t.Run(string(failedStage), func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			injected := errors.New("injected setup failure")
			coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
			if err != nil {
				t.Fatal(err)
			}
			coordinator.FailAfter = func(stage SetupStage) error {
				if stage == failedStage {
					return injected
				}
				return nil
			}
			first, err := coordinator.Run()
			if !errors.Is(err, injected) || first.Checkpoint.Stage != failedStage {
				t.Fatalf("first run = %+v, %v", first, err)
			}

			resumed, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
			if err != nil {
				t.Fatal(err)
			}
			second, err := resumed.Run()
			if err != nil || second.Classification != SuiteSetupExisting || second.Checkpoint.Stage != SetupBootstrapDrafted {
				t.Fatalf("resumed run = %+v, %v", second, err)
			}
			before, _ := os.ReadFile(second.BootstrapPath)
			third, err := resumed.Run()
			after, _ := os.ReadFile(second.BootstrapPath)
			if err != nil || third.Checkpoint != second.Checkpoint || string(before) != string(after) {
				t.Fatalf("idempotent rerun = %+v, %v", third, err)
			}
		})
	}
}

func TestSuiteSetupConcurrentRunRejectsSecondLockOwner(t *testing.T) {
	roots, config := setupEngineFixture(t)
	first, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	release := make(chan struct{})
	first.FailAfter = func(stage SetupStage) error {
		if stage == SetupInputValidated {
			close(entered)
			<-release
		}
		return nil
	}
	var wg sync.WaitGroup
	wg.Add(1)
	var firstErr error
	go func() {
		defer wg.Done()
		_, firstErr = first.Run()
	}()
	<-entered

	second, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := second.Run(); !errors.Is(err, ErrSuiteSetupLocked) {
		t.Fatalf("concurrent setup error = %v", err)
	}
	close(release)
	wg.Wait()
	if firstErr != nil {
		t.Fatalf("first setup: %v", firstErr)
	}
	lockInfo, err := os.Stat(filepath.Join(roots.AgentState, suiteSetupLockName))
	if err != nil {
		t.Fatalf("persistent setup lock file: %v", err)
	}
	if runtime.GOOS != "windows" && lockInfo.Mode().Perm() != 0o600 {
		t.Fatalf("setup lock mode = %o", lockInfo.Mode().Perm())
	}
	third, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := third.Run(); err != nil {
		t.Fatalf("lock was not released for restart: %v", err)
	}
}

func TestSuiteSetupClassifiesExistingAndCorruptState(t *testing.T) {
	t.Run("existing footprint", func(t *testing.T) {
		roots, config := setupEngineFixture(t)
		if err := os.MkdirAll(roots.BrowserData, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(roots.BrowserData, "profile.db"), []byte("existing"), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := ClassifySuiteSetup(roots, config)
		if err != nil || got != SuiteSetupExisting {
			t.Fatalf("classification = %q, %v", got, err)
		}
		coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
		if err != nil {
			t.Fatal(err)
		}
		result, err := coordinator.Run()
		if result.Classification != SuiteSetupExisting || !errors.Is(err, ErrSuiteSetupExistingState) || !errors.Is(err, ErrSuiteSetupCorrupt) {
			t.Fatalf("existing setup run = %+v, %v", result, err)
		}
		if _, err := os.Stat(config.StatePath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("existing setup was modified: %v", err)
		}
	})

	for _, tc := range []struct {
		name  string
		build func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig)
	}{
		{
			name: "invalid preparation checkpoint",
			build: func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
				if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(roots.AgentState, suitePreparationStateName), []byte("{"), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "secret draft field",
			build: func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
				if err := os.MkdirAll(roots.Config, 0o700); err != nil {
					t.Fatal(err)
				}
				data := `{"server_url":"https://farm.example.test:8443","state_path":"` + config.StatePath + `","node_name":"Farm One","private_key":"secret"}`
				if err := os.WriteFile(filepath.Join(roots.Config, suiteBootstrapDraftName), []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			tc.build(t, roots, config)
			got, err := ClassifySuiteSetup(roots, config)
			if got != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
				t.Fatalf("classification = %q, %v", got, err)
			}
		})
	}
}

func TestSuiteSetupRejectsSymlinkRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires platform privileges")
	}
	roots, config := setupEngineFixture(t)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, roots.Config); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Run(); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("symlink root accepted: %v", err)
	}
}

func TestSuiteSetupRejectsCanonicalStateOutsideAgentStateAndPreparationSymlink(t *testing.T) {
	roots, config := setupEngineFixture(t)
	config.StatePath = filepath.Join(t.TempDir(), "setup.json")
	if _, err := NewSuiteSetupCoordinatorWithRoots(config, roots); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("checkpoint outside agent state accepted: %v", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	roots, config = setupEngineFixture(t)
	if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "preparation.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(roots.AgentState, suitePreparationStateName)); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Run()
	if result.Classification != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
		t.Fatalf("symlink preparation checkpoint accepted: result=%+v err=%v", result, err)
	}
}

func TestSuiteSetupRejectsCanonicalCheckpointSymlinkWithoutReadingIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires platform privileges")
	}
	roots, config := setupEngineFixture(t)
	if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "canonical.json")
	if err := os.WriteFile(target, []byte(`{"private_key":"must-not-be-read"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, config.StatePath); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.Run()
	if result.Classification != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
		t.Fatalf("canonical checkpoint symlink accepted: result=%+v err=%v", result, err)
	}
}

func TestSuiteSetupRejectsUnsafeBootstrapDraftBeforeRead(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows DACL validation is compile-checked and requires a native runner")
	}
	t.Run("symlink", func(t *testing.T) {
		roots, config := setupEngineFixture(t)
		if err := os.MkdirAll(roots.Config, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "draft.json")
		if err := os.WriteFile(target, []byte(`{"private_key":"must-not-be-read"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(roots.Config, suiteBootstrapDraftName)); err != nil {
			t.Fatal(err)
		}
		got, err := ClassifySuiteSetup(roots, config)
		if got != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
			t.Fatalf("symlink draft classification = %q, %v", got, err)
		}
	})
	t.Run("permissive mode", func(t *testing.T) {
		roots, config := setupEngineFixture(t)
		if err := os.MkdirAll(roots.Config, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(roots.Config, suiteBootstrapDraftName)
		if err := os.WriteFile(path, []byte(`{"private_key":"must-not-be-read"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := ClassifySuiteSetup(roots, config)
		if got != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
			t.Fatalf("permissive draft classification = %q, %v", got, err)
		}
	})
}

func TestSuitePreparationCheckpointRejectsCanonicalStage(t *testing.T) {
	roots, config := setupEngineFixture(t)
	digest, err := bootstrapConfigDigest(config)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := SetupPreparationCheckpoint{
		SchemaVersion: 1, Stage: SetupPrecheck,
		RequestUID: "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6", BootstrapSHA256: digest,
	}
	if err := saveSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName), checkpoint); !errors.Is(err, ErrSuiteSetupCorrupt) {
		t.Fatalf("canonical stage accepted as preparation: %v", err)
	}
}

func TestSuiteSetupMigratesAllLegacyPreparationStages(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	for _, stage := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted} {
		t.Run(string(stage), func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			for _, candidate := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted} {
				if setupStageIndex(candidate) > setupStageIndex(stage) {
					break
				}
				if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: candidate, RequestUID: requestUID}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == SetupConfigDrafted {
				if err := writeBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName), config); err != nil {
					t.Fatal(err)
				}
			}
			classification, err := ClassifySuiteSetup(roots, config)
			if err != nil || classification != SuiteSetupExisting {
				t.Fatalf("legacy classification = %q, %v", classification, err)
			}
			coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
			if err != nil {
				t.Fatal(err)
			}
			result, err := coordinator.Run()
			if err != nil || result.Checkpoint.Stage != SetupBootstrapDrafted || result.Checkpoint.RequestUID != requestUID {
				t.Fatalf("migration result = %+v, %v", result, err)
			}
			if _, err := os.Stat(config.StatePath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("legacy canonical primary remains: %v", err)
			}
			archive := legacyArchivePath(config.StatePath, requestUID)
			if _, err := os.Stat(archive); err != nil {
				t.Fatalf("legacy primary was not preserved: %v", err)
			}
			checkpoint, err := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
			if err != nil || checkpoint.RequestUID != requestUID {
				t.Fatalf("preparation checkpoint = %+v, %v", checkpoint, err)
			}
		})
	}
}

func TestSuiteSetupLegacyMigrationRecoversBackupAndJournalRetry(t *testing.T) {
	for name, damaged := range map[string][]byte{"empty primary": {}, "truncated primary": {'{'}, "malformed primary": []byte("not-json")} {
		t.Run(name+" uses backup", func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
				t.Fatal(err)
			}
			requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
			if err := os.WriteFile(config.StatePath, damaged, 0o600); err != nil {
				t.Fatal(err)
			}
			backup, _ := json.Marshal(SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID})
			if err := os.WriteFile(config.StatePath+".bak", backup, 0o600); err != nil {
				t.Fatal(err)
			}
			coordinator, _ := NewSuiteSetupCoordinatorWithRoots(config, roots)
			result, err := coordinator.Run()
			if err != nil || result.Checkpoint.RequestUID != requestUID || result.Checkpoint.Stage != SetupBootstrapDrafted {
				t.Fatalf("backup recovery = %+v, %v", result, err)
			}
			for _, source := range []string{config.StatePath, config.StatePath + ".bak"} {
				if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("legacy source remains: %s: %v", source, err)
				}
			}
		})
	}

	t.Run("journal resumes after partial archival", func(t *testing.T) {
		roots, config := setupEngineFixture(t)
		requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
		if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}); err != nil {
			t.Fatal(err)
		}
		if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: requestUID}); err != nil {
			t.Fatal(err)
		}
		migration, err := inspectLegacySetupMigration(roots, config)
		if err != nil {
			t.Fatal(err)
		}
		marker, _ := json.Marshal(migration)
		if err := writeOwnerAtomic(filepath.Join(roots.AgentState, suiteMigrationStateName), append(marker, '\n')); err != nil {
			t.Fatal(err)
		}
		input := SetupPreparationCheckpoint{SchemaVersion: 1, Stage: SetupInputValidated, RequestUID: requestUID, BootstrapSHA256: migration.BootstrapSHA256}
		if err := saveSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName), input); err != nil {
			t.Fatal(err)
		}
		if err := archiveLegacySetupFile(config.StatePath, legacyArchivePath(config.StatePath, requestUID), migration.primaryRaw); err != nil {
			t.Fatal(err)
		}
		coordinator, _ := NewSuiteSetupCoordinatorWithRoots(config, roots)
		result, err := coordinator.Run()
		if err != nil || result.Checkpoint.Stage != SetupBootstrapDrafted || result.Checkpoint.RequestUID != requestUID {
			t.Fatalf("journal retry = %+v, %v", result, err)
		}
		if _, err := os.Stat(filepath.Join(roots.AgentState, suiteMigrationStateName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("migration marker remains: %v", err)
		}
	})
}

func TestSuiteSetupRejectsInvalidLegacyPreparation(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	for _, tc := range []struct {
		name  string
		build func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig)
	}{
		{"mismatched draft", func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
			for _, stage := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted} {
				if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: requestUID}); err != nil {
					t.Fatal(err)
				}
			}
			other := config
			other.NodeName = "Other Node"
			if err := writeBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName), other); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown secret field", func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
			if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
				t.Fatal(err)
			}
			raw := `{"schema_version":1,"stage":"PRECHECK","request_uid":"` + requestUID + `","private_key":"secret"}`
			if err := os.WriteFile(config.StatePath, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unknown field cannot use backup", func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
			if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
				t.Fatal(err)
			}
			raw := `{"schema_version":1,"stage":"PRECHECK","request_uid":"` + requestUID + `","future_field":true}`
			if err := os.WriteFile(config.StatePath, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			backup, _ := json.Marshal(SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID})
			if err := os.WriteFile(config.StatePath+".bak", backup, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"unsafe mode", func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
			if runtime.GOOS == "windows" {
				t.Skip("native Windows DACL test required")
			}
			if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID})
			if err := os.WriteFile(config.StatePath, raw, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			tc.build(t, roots, config)
			classification, err := ClassifySuiteSetup(roots, config)
			if classification != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
				t.Fatalf("invalid legacy classification = %q, %v", classification, err)
			}
		})
	}
}

func TestSuiteSetupRejectsPreparationAndLegacyInconsistency(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	otherUID := "64473c80-0e26-4d7d-9b17-fd9cc6c959d8"
	for _, tc := range []struct {
		name       string
		stage      SetupStage
		uid        string
		alterInput bool
	}{
		{name: "request uid", stage: SetupInputValidated, uid: otherUID},
		{name: "bootstrap digest", stage: SetupInputValidated, uid: requestUID, alterInput: true},
		{name: "stage", stage: SetupBootstrapDrafted, uid: requestUID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}); err != nil {
				t.Fatal(err)
			}
			digestConfig := config
			if tc.alterInput {
				digestConfig.NodeName = "Other Node"
			}
			digest, err := bootstrapConfigDigest(digestConfig)
			if err != nil {
				t.Fatal(err)
			}
			checkpoint := SetupPreparationCheckpoint{SchemaVersion: 1, Stage: tc.stage, RequestUID: tc.uid, BootstrapSHA256: digest}
			raw, _ := json.Marshal(checkpoint)
			if err := writeOwnerAtomic(filepath.Join(roots.AgentState, suitePreparationStateName), append(raw, '\n')); err != nil {
				t.Fatal(err)
			}
			classification, err := ClassifySuiteSetup(roots, config)
			if classification != SuiteSetupCorrupt || !errors.Is(err, ErrSuiteSetupCorrupt) {
				t.Fatalf("inconsistent coexistence = %q, %v", classification, err)
			}
		})
	}
}

// A canonical run that stopped after preparation (e.g. an untrusted TLS
// Server failed TRANSPORT_VERIFIED) must resume, not be archived as legacy.
func TestSuiteSetupRerunKeepsCanonicalCheckpoint(t *testing.T) {
	for _, stage := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted, SetupTransportVerified} {
		t.Run(string(stage), func(t *testing.T) {
			roots, config := setupEngineFixture(t)
			coordinator, err := NewSuiteSetupCoordinatorWithRoots(config, roots)
			if err != nil {
				t.Fatal(err)
			}
			first, err := coordinator.Run()
			if err != nil || first.Checkpoint.Stage != SetupBootstrapDrafted {
				t.Fatalf("first run = %+v, %v", first, err)
			}
			digest, _ := bootstrapConfigDigest(config)
			plan := SuiteSetupPlan{SchemaVersion: 1, PreparationRequestUID: first.Checkpoint.RequestUID,
				BootstrapSHA256: digest, ManifestSHA256: strings.Repeat("a", 64),
				Target: SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}}
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			if err := SaveSuiteSetupPlan(roots, plan); err != nil {
				t.Fatal(err)
			}
			canonical := SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: first.Checkpoint.RequestUID}
			for _, candidate := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted, SetupTransportVerified} {
				if setupStageIndex(candidate) > setupStageIndex(stage) {
					break
				}
				next := canonical
				next.Stage = candidate
				if err := SaveSetupCheckpoint(config.StatePath, next); err != nil {
					t.Fatal(err)
				}
			}
			second, err := coordinator.Run()
			if err != nil || second.Checkpoint.RequestUID != first.Checkpoint.RequestUID {
				t.Fatalf("rerun = %+v, %v", second, err)
			}
			kept, err := LoadSetupCheckpoint(config.StatePath)
			if err != nil || kept == nil || *kept != canonical {
				t.Fatalf("canonical checkpoint lost: %+v, %v", kept, err)
			}
			if _, err := os.Stat(legacyArchivePath(config.StatePath, first.Checkpoint.RequestUID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("canonical checkpoint was archived as legacy: %v", err)
			}
			// A checkpoint for another request is corruption, not a resume.
			for _, path := range []string{config.StatePath, config.StatePath + ".bak"} {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					t.Fatal(err)
				}
			}
			if err := SaveSetupCheckpoint(config.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"}); err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.Run(); !errors.Is(err, ErrSuiteSetupCorrupt) {
				t.Fatalf("foreign canonical checkpoint accepted: %v", err)
			}
		})
	}
}
