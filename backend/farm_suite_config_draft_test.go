package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type suiteConfigDraftFixture struct{ suiteStageFixture }

func newSuiteConfigDraftFixture(t *testing.T) suiteConfigDraftFixture {
	t.Helper()
	fixture := newSuiteStageFixture(t)
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
		t.Fatal(err)
	}
	return suiteConfigDraftFixture{suiteStageFixture: fixture}
}

func suiteConfigDraftTestDependencies() suiteCanonicalConfigDraftDependencies {
	stageDeps := suiteStageTestDependencies()
	return suiteCanonicalConfigDraftDependencies{
		ValidateInstall:   stageDeps.ValidateInstall,
		AcquireInstance:   func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:    func(string) error { return nil },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
		SaveDraft:         saveSuiteClientConfigDraft,
		SaveCheckpoint:    SaveSetupCheckpoint,
	}
}

func TestSuiteCanonicalConfigDraftCreatesTypedDraftAndEmptyApplicationRoot(t *testing.T) {
	fixture := newSuiteConfigDraftFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies())
		if err != nil || result.Stage != SetupConfigDrafted || result.RequestUID != fixture.preparation.RequestUID || result.ManifestSHA256 != fixture.plan.ManifestSHA256 || result.SetupStageID != fixture.plan.StageID || result.DraftPath != filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName) || result.ApplicationRoot != filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir) {
			t.Fatalf("attempt=%d result=%+v err=%v", attempt, result, err)
		}
	}
	draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap)
	if err != nil || draft == nil || draft.ServerOrigin != fixture.bootstrap.ServerURL || draft.NodeName != fixture.bootstrap.NodeName || draft.ClientConfigPath != filepath.Join(fixture.roots.Config, SuiteClientConfigName) || draft.AntConfigPath != filepath.Join(draft.ApplicationRoot, "config.yaml") {
		t.Fatalf("draft=%+v err=%v", draft, err)
	}
	raw, err := os.ReadFile(filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"enrollment_code", "private_key", "node_uid", "identity", "credential", "deployment_uid", "control_endpoint", "update_public_key"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("draft contains forbidden %q", forbidden)
		}
	}
	entries, err := os.ReadDir(draft.ApplicationRoot)
	if err != nil || len(entries) != 0 {
		t.Fatalf("application root=%v err=%v", entries, err)
	}
	assertSuiteConfigDraftNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalConfigDraftProductionFailsClosedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires native Program Files fixture")
	}
	fixture := newSuiteConfigDraftFixture(t)
	if _, err := RunSuiteCanonicalConfigDraft(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); !errors.Is(err, ErrSuiteCanonicalConfigDraft) {
		t.Fatalf("error=%v", err)
	}
	assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
}

func TestSuiteCanonicalConfigDraftRequiresExactStagedEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *suiteConfigDraftFixture)
	}{
		{"missing staged", func(t *testing.T, f *suiteConfigDraftFixture) {
			if err := os.Remove(f.bootstrap.StatePath); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt checkpoint", func(t *testing.T, f *suiteConfigDraftFixture) {
			if err := os.WriteFile(f.bootstrap.StatePath, []byte(`{"stage":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"cross request", func(t *testing.T, f *suiteConfigDraftFixture) {
			if err := os.WriteFile(f.bootstrap.StatePath, []byte(`{"schema_version":1,"stage":"STAGED","request_uid":"64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"future checkpoint", func(t *testing.T, f *suiteConfigDraftFixture) {
			if err := SaveSetupCheckpoint(f.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupConfigDrafted, RequestUID: f.preparation.RequestUID}); err != nil {
				t.Fatal(err)
			}
			if err := SaveSetupCheckpoint(f.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupTransportVerified, RequestUID: f.preparation.RequestUID}); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt receipt", func(t *testing.T, f *suiteConfigDraftFixture) {
			if err := os.WriteFile(filepath.Join(f.roots.AgentState, SuiteStageReceiptName), []byte(`{"schema":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"plan drift", func(t *testing.T, f *suiteConfigDraftFixture) {
			plan := f.plan
			plan.ManifestSHA256 = strings.Repeat("b", 64)
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			raw, _ := jsonMarshalSuiteSetupPlan(plan)
			if err := writeOwnerAtomic(filepath.Join(f.roots.AgentState, suiteSetupPlanName), raw); err != nil {
				t.Fatal(err)
			}
		}},
		{"release proof", func(_ *testing.T, f *suiteConfigDraftFixture) { f.release.verified = false }},
		{"bootstrap", func(_ *testing.T, f *suiteConfigDraftFixture) { f.bootstrap.NodeName = "Changed" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			test.mutate(t, &fixture)
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
				t.Fatal("invalid staged evidence accepted")
			}
		})
	}
}

func TestSuiteCanonicalConfigDraftRejectsValidConflictingDraft(t *testing.T) {
	fixture := newSuiteConfigDraftFixture(t)
	conflict := expectedSuiteConfigDraftForTest(fixture)
	conflict.SuiteBinaryRoot = filepath.Join(filepath.Dir(fixture.source), "3.0.1")
	if err := saveSuiteClientConfigDraft(fixture.roots, fixture.bootstrap, conflict); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
		t.Fatal("valid conflicting draft accepted")
	}
	assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
}

func TestSuiteCanonicalConfigDraftCompletedStageRequiresDurableArtifacts(t *testing.T) {
	for _, test := range []struct {
		name   string
		remove func(suiteConfigDraftFixture) string
	}{
		{"draft", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.Config, SuiteClientConfigDraftName)
		}},
		{"application root", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
				t.Fatal(err)
			}
			path := test.remove(fixture)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
				t.Fatal("completed stage recreated missing durable evidence")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("missing evidence was recreated: %v", err)
			}
			assertSuiteConfigDraftCheckpoint(t, fixture, SetupConfigDrafted)
		})
	}
}

func TestSuiteClientConfigDraftClosedOwnerOnlyContract(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate", []byte(`{"schema_version":1,"schema_version":1}`)}, {"unknown", []byte(`{"unknown":true}`)},
		{"secret", []byte(`{"private_key":"secret"}`)}, {"trailing", []byte(`{} {}`)}, {"type", []byte(`[]`)},
		{"oversize", []byte(strings.Repeat("x", suiteConfigDraftMaxBytes+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			path := filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName)
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err == nil || draft != nil {
				t.Fatalf("draft=%+v err=%v", draft, err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		target := filepath.Join(t.TempDir(), "draft")
		_ = os.WriteFile(target, []byte(`{}`), 0o600)
		if err := os.Symlink(target, filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName)); err != nil {
			t.Skip(err)
		}
		if _, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("mode", func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName)
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err == nil {
				t.Fatal("permissive draft accepted")
			}
		})
		t.Run("config root mode", func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(fixture.roots.Config, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err == nil {
				t.Fatal("permissive config root accepted")
			}
		})
	}
	t.Run("config ancestor symlink", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatal(err)
		}
		ancestor := filepath.Dir(fixture.roots.Config)
		moved := ancestor + "-moved"
		if err := os.Rename(ancestor, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, ancestor); err != nil {
			_ = os.Rename(moved, ancestor)
			t.Skip(err)
		}
		if _, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err == nil {
			t.Fatal("redirected config ancestor accepted")
		}
		if err := os.Remove(ancestor); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, ancestor); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("config root replaced during read", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatal(err)
		}
		raw, err := os.ReadFile(filepath.Join(fixture.roots.Config, SuiteClientConfigDraftName))
		if err != nil {
			t.Fatal(err)
		}
		moved := fixture.roots.Config + "-moved"
		dependencies := suiteConfigDraftLoadDependencies{ReadFile: func(string, os.FileInfo) ([]byte, error) {
			if err := os.Rename(fixture.roots.Config, moved); err != nil {
				return nil, err
			}
			if err := os.Mkdir(fixture.roots.Config, 0o700); err != nil {
				return nil, err
			}
			return raw, nil
		}}
		if draft, err := loadSuiteClientConfigDraftWithDependencies(fixture.roots, fixture.bootstrap, dependencies); err == nil || draft != nil {
			t.Fatalf("replacement accepted: draft=%+v err=%v", draft, err)
		}
		if err := os.Remove(fixture.roots.Config); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, fixture.roots.Config); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing draft root replaced before return", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		moved := fixture.roots.Config + "-moved"
		dependencies := suiteConfigDraftLoadDependencies{
			ReadFile: readSuiteConfigDraftFile,
			AfterMissing: func() error {
				if err := os.Rename(fixture.roots.Config, moved); err != nil {
					return err
				}
				return os.Mkdir(fixture.roots.Config, 0o700)
			},
		}
		if draft, err := loadSuiteClientConfigDraftWithDependencies(fixture.roots, fixture.bootstrap, dependencies); err == nil || draft != nil {
			t.Fatalf("missing-path replacement accepted: draft=%+v err=%v", draft, err)
		}
		if err := os.Remove(fixture.roots.Config); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(moved, fixture.roots.Config); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("application symlink", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		target := t.TempDir()
		path := filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir)
		if err := os.Symlink(target, path); err != nil {
			t.Skip(err)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
			t.Fatal("application symlink accepted")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
	})
}

func TestSuiteCanonicalConfigDraftRejectsExistingApplicationAndLaterArtifacts(t *testing.T) {
	for _, test := range []struct {
		name string
		path func(suiteConfigDraftFixture) string
	}{
		{"client yaml", func(f suiteConfigDraftFixture) string { return filepath.Join(f.roots.Config, SuiteClientConfigName) }},
		{"Ant config", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml")
		}},
		{"Ant DB", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "ant.db")
		}},
		{"application data", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "data")
		}},
		{"identity", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		}},
		{"handoff", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName)
		}},
		{"service", func(f suiteConfigDraftFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteActivationJournalName)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			path := test.path(fixture)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("early"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
				t.Fatal("early artifact accepted")
			}
			assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		})
	}
}

func TestSuiteCanonicalConfigDraftFailuresAndCommitUnknownRecover(t *testing.T) {
	t.Run("application secure failure retains exact root and retries", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		applicationRoot := filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir)
		operations := defaultSuiteConfigDraftApplicationRootOperations()
		operations.Secure = func(path string, _ bool) error {
			if runtime.GOOS != "windows" {
				if err := os.Chmod(path, 0o755); err != nil {
					return err
				}
			}
			return errors.New("injected secure failure")
		}
		deps := suiteConfigDraftTestDependencies()
		deps.EnsureApplication = func(path string, allowCreate bool) (os.FileInfo, error) {
			return ensureSuiteConfigDraftApplicationRootWithOperations(path, allowCreate, operations)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("secure failure accepted")
		}
		if info, err := os.Lstat(applicationRoot); err != nil || !info.IsDir() {
			t.Fatalf("new directory was deleted: info=%v err=%v", info, err)
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err != nil || draft != nil {
			t.Fatalf("failure wrote draft=%+v err=%v", draft, err)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatalf("retry after retained directory: %v", err)
		}
	})
	t.Run("application secure failure never deletes replacement", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		applicationRoot := filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir)
		replacement := filepath.Join(t.TempDir(), "replacement")
		if err := os.Mkdir(replacement, 0o700); err != nil {
			t.Fatal(err)
		}
		operations := defaultSuiteConfigDraftApplicationRootOperations()
		operations.Secure = func(path string, _ bool) error {
			if err := os.Remove(path); err != nil {
				return err
			}
			if err := os.Rename(replacement, path); err != nil {
				return err
			}
			return errors.New("injected secure failure after replacement")
		}
		deps := suiteConfigDraftTestDependencies()
		deps.EnsureApplication = func(path string, allowCreate bool) (os.FileInfo, error) {
			return ensureSuiteConfigDraftApplicationRootWithOperations(path, allowCreate, operations)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("secure failure accepted")
		}
		if info, err := os.Lstat(applicationRoot); err != nil || !info.IsDir() {
			t.Fatalf("replacement deleted: info=%v err=%v", info, err)
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err != nil || draft != nil {
			t.Fatalf("failure wrote draft=%+v err=%v", draft, err)
		}
	})
	t.Run("application secure failure never deletes nonempty directory", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		applicationRoot := filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir)
		operations := defaultSuiteConfigDraftApplicationRootOperations()
		operations.Secure = func(path string, _ bool) error {
			if err := os.WriteFile(filepath.Join(path, "foreign"), []byte("keep"), 0o600); err != nil {
				return err
			}
			return errors.New("injected secure failure after foreign write")
		}
		deps := suiteConfigDraftTestDependencies()
		deps.EnsureApplication = func(path string, allowCreate bool) (os.FileInfo, error) {
			return ensureSuiteConfigDraftApplicationRootWithOperations(path, allowCreate, operations)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("secure failure accepted")
		}
		if raw, err := os.ReadFile(filepath.Join(applicationRoot, "foreign")); err != nil || string(raw) != "keep" {
			t.Fatalf("foreign content mutated: %q err=%v", raw, err)
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err != nil || draft != nil {
			t.Fatalf("failure wrote draft=%+v err=%v", draft, err)
		}
	})
	t.Run("application create", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.EnsureApplication = func(string, bool) (os.FileInfo, error) { return nil, errors.New("injected") }
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("failure accepted")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
	})
	t.Run("application create commit unknown", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.EnsureApplication = func(path string, allowCreate bool) (os.FileInfo, error) {
			info, err := ensureSuiteConfigDraftApplicationRoot(path, allowCreate)
			if err != nil {
				return nil, err
			}
			return info, errors.New("injected directory acknowledgement loss")
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("directory commit-unknown reported success")
		}
		if _, err := ensureSuiteConfigDraftApplicationRoot(filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir), false); err != nil {
			t.Fatalf("durable application root: %v", err)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatalf("directory commit-unknown recovery: %v", err)
		}
	})
	t.Run("draft write", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.SaveDraft = func(SuiteUserRoots, BootstrapConfig, SuiteClientConfigDraft) error { return errors.New("injected") }
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("failure accepted")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
	})
	t.Run("checkpoint after draft", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.SaveCheckpoint = func(string, SetupCheckpoint) error { return errors.New("injected") }
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("failure accepted")
		}
		if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err != nil || draft == nil {
			t.Fatalf("draft=%+v err=%v", draft, err)
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("draft commit unknown", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.SaveDraft = func(r SuiteUserRoots, b BootstrapConfig, d SuiteClientConfigDraft) error {
			if err := saveSuiteClientConfigDraft(r, b, d); err != nil {
				return err
			}
			return errors.New("ack lost")
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("unknown reported success")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("evidence drift after draft", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.SaveDraft = func(r SuiteUserRoots, b BootstrapConfig, d SuiteClientConfigDraft) error {
			if err := saveSuiteClientConfigDraft(r, b, d); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(r.AgentState, SuiteStageReceiptName), []byte(`{"bad":true}`), 0o600)
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("post-draft evidence drift accepted")
		}
		if draft, err := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap); err != nil || draft == nil {
			t.Fatalf("draft=%+v err=%v", draft, err)
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
	})
	t.Run("checkpoint commit unknown", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		deps := suiteConfigDraftTestDependencies()
		deps.SaveCheckpoint = func(path string, checkpoint SetupCheckpoint) error {
			if err := SaveSetupCheckpoint(path, checkpoint); err != nil {
				return err
			}
			return errors.New("injected checkpoint acknowledgement loss")
		}
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("checkpoint commit-unknown reported success")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupConfigDrafted)
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
			t.Fatalf("checkpoint commit-unknown recovery: %v", err)
		}
	})
}

func TestSuiteCanonicalConfigDraftRevalidatesAllEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, suiteConfigDraftFixture) error
	}{
		{"installed tree", func(_ *testing.T, f suiteConfigDraftFixture) error {
			return os.WriteFile(filepath.Join(f.source, "evil.dll"), []byte("evil"), 0o600)
		}},
		{"installed new inode", func(t *testing.T, f suiteConfigDraftFixture) error {
			old := f.source + "-old"
			if err := os.Rename(f.source, old); err != nil {
				return err
			}
			return cloneSuitePrecheckTree(t, old, f.source)
		}},
		{"installed ancestor redirect", func(_ *testing.T, f suiteConfigDraftFixture) error {
			parent := filepath.Dir(f.source)
			moved := parent + "-moved"
			if err := os.Rename(parent, moved); err != nil {
				return err
			}
			return os.Symlink(moved, parent)
		}},
		{"application new inode", func(_ *testing.T, f suiteConfigDraftFixture) error {
			app := filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir)
			old := app + "-old"
			if err := os.Rename(app, old); err != nil {
				return err
			}
			return os.Mkdir(app, 0o700)
		}},
		{"receipt", func(_ *testing.T, f suiteConfigDraftFixture) error {
			return os.WriteFile(filepath.Join(f.roots.AgentState, SuiteStageReceiptName), []byte(`{"bad":true}`), 0o600)
		}},
		{"plan", func(_ *testing.T, f suiteConfigDraftFixture) error {
			plan := f.plan
			plan.ManifestSHA256 = strings.Repeat("b", 64)
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			raw, _ := jsonMarshalSuiteSetupPlan(plan)
			return writeOwnerAtomic(filepath.Join(f.roots.AgentState, suiteSetupPlanName), raw)
		}},
		{"draft", func(_ *testing.T, f suiteConfigDraftFixture) error {
			return os.WriteFile(filepath.Join(f.roots.Config, SuiteClientConfigDraftName), []byte(`{"bad":true}`), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteConfigDraftFixture(t)
			deps := suiteConfigDraftTestDependencies()
			deps.AfterValidate = func() error { return test.mutate(t, fixture) }
			if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("drift accepted")
			}
			assertSuiteConfigDraftCheckpoint(t, fixture, SetupStaged)
		})
	}
}

func TestSuiteCanonicalConfigDraftLocksAndConcurrentCallers(t *testing.T) {
	t.Run("active instance", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		lock, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Release()
		deps := suiteConfigDraftTestDependencies()
		deps.AcquireInstance = func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) }
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("active accepted")
		}
	})
	t.Run("setup lock", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("100 callers", func(t *testing.T) {
		fixture := newSuiteConfigDraftFixture(t)
		var wait sync.WaitGroup
		results := make(chan error, 100)
		for i := 0; i < 100; i++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies())
				results <- err
			}()
		}
		wait.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrSuiteSetupLocked) {
				t.Fatalf("err=%v", err)
			}
		}
		if wins == 0 {
			t.Fatal("no winner")
		}
		assertSuiteConfigDraftCheckpoint(t, fixture, SetupConfigDrafted)
	})
}

func TestSuiteConfigDraftExactTempRecoveryDoesNotDeleteForeign(t *testing.T) {
	fixture := newSuiteConfigDraftFixture(t)
	draft := expectedSuiteConfigDraftForTest(fixture)
	name, err := suiteConfigDraftTempName(draft, fixture.bootstrap, fixture.roots)
	if err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(fixture.roots.Config, name)
	if err := os.WriteFile(exact, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(exact); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp remains %v", err)
	}
	fixture = newSuiteConfigDraftFixture(t)
	foreign := filepath.Join(fixture.roots.Config, suiteConfigDraftTempPrefix+"foreign.tmp")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err == nil {
		t.Fatal("foreign accepted")
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "foreign" {
		t.Fatalf("foreign mutated %q %v", raw, err)
	}
}

func expectedSuiteConfigDraftForTest(f suiteConfigDraftFixture) SuiteClientConfigDraft {
	app := filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir)
	return SuiteClientConfigDraft{SchemaVersion: 1, RequestUID: f.preparation.RequestUID, SetupStageID: f.plan.StageID, BootstrapSHA256: f.preparation.BootstrapSHA256, ManifestSHA256: f.plan.ManifestSHA256, Target: f.plan.Target, Version: f.release.manifest.Version, SuiteBinaryRoot: f.source, ServerOrigin: f.bootstrap.ServerURL, NodeName: f.bootstrap.NodeName, ClientConfigPath: filepath.Join(f.roots.Config, SuiteClientConfigName), AgentStateRoot: f.roots.AgentState, ApplicationRoot: app, AntConfigPath: filepath.Join(app, "config.yaml"), LogPath: filepath.Join(f.roots.Logs, suiteConfigDraftLogName)}
}
func assertSuiteConfigDraftCheckpoint(t *testing.T, f suiteConfigDraftFixture, stage SetupStage) {
	t.Helper()
	checkpoint, err := LoadSetupCheckpoint(f.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != stage {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}
func assertSuiteConfigDraftNoLaterArtifacts(t *testing.T, f suiteConfigDraftFixture) {
	t.Helper()
	for _, path := range []string{filepath.Join(f.roots.Config, SuiteClientConfigName), filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml"), filepath.Join(f.roots.AgentState, SuiteBootstrapEnrollmentAttemptName), filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName), filepath.Join(f.roots.AgentState, SuiteActivationJournalName)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact %s: %v", filepath.Base(path), err)
		}
	}
}
