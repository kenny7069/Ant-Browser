package backend

import (
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
	if result.Classification != SuiteSetupFresh || result.Checkpoint.Stage != SetupConfigDrafted {
		t.Fatalf("result = %+v", result)
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
	for _, failedStage := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted} {
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
			if err != nil || second.Classification != SuiteSetupExisting || second.Checkpoint.Stage != SetupConfigDrafted {
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
		if stage == SetupPrecheck {
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
			name: "invalid checkpoint",
			build: func(t *testing.T, roots SuiteUserRoots, config BootstrapConfig) {
				if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(config.StatePath, []byte("{"), 0o600); err != nil {
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
