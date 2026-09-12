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

type suiteStageFixture struct {
	suitePrecheckFixture
	preparation SetupPreparationCheckpoint
	plan        SuiteSetupPlan
}

func newSuiteStageFixture(t *testing.T) suiteStageFixture {
	t.Helper()
	fixture := newSuitePrecheckFixture(t)
	if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err != nil {
		t.Fatal(err)
	}
	versionRoot := filepath.Join(filepath.Dir(fixture.source), fixture.release.manifest.Version)
	if err := os.Rename(fixture.source, versionRoot); err != nil {
		t.Fatal(err)
	}
	fixture.source = versionRoot
	preparation, err := loadSetupPreparationCheckpoint(filepath.Join(fixture.roots.AgentState, suitePreparationStateName))
	if err != nil || preparation == nil {
		t.Fatal(err)
	}
	plan, err := LoadSuiteSetupPlan(fixture.roots)
	if err != nil || plan == nil {
		t.Fatal(err)
	}
	return suiteStageFixture{suitePrecheckFixture: fixture, preparation: *preparation, plan: *plan}
}

func suiteStageTestDependencies() suiteCanonicalStageDependencies {
	return suiteCanonicalStageDependencies{
		ValidateInstall: func(root string, plan SuiteSetupPlan, version string) (suiteStageInstallEvidence, error) {
			manifest, digest, err := validateInstalledSuiteRelease(root, plan)
			if err != nil || digest != plan.ManifestSHA256 || manifest.Version != version || manifest.Version != filepath.Base(root) {
				return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
			}
			_, info, err := suitePrecheckResolvedPath(root)
			return suiteStageInstallEvidence{CanonicalRoot: root, RootInfo: info}, err
		},
		AcquireInstance: func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:  func(string) error { return nil },
		SaveReceipt:     saveSuiteStageReceipt,
		SaveCheckpoint:  SaveSetupCheckpoint,
	}
}

func TestSuiteCanonicalStageWritesReceiptThenAdjacentCheckpointIdempotently(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies())
		if err != nil || result.Stage != SetupStaged || result.RequestUID != fixture.preparation.RequestUID || result.ManifestSHA256 != fixture.plan.ManifestSHA256 || result.SetupStageID != fixture.plan.StageID || result.Version != fixture.release.manifest.Version {
			t.Fatalf("attempt=%d result=%+v err=%v", attempt, result, err)
		}
	}
	receipt, err := LoadSuiteStageReceipt(fixture.roots)
	if err != nil || receipt == nil || receipt.AdoptionKind != suiteStageAdoptionKind || receipt.InstalledSuiteRoot != fixture.source {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupStaged || checkpoint.RequestUID != fixture.preparation.RequestUID {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
	assertSuiteStageHasNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalStageProductionFailsClosedOffWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("requires a native admin-installed Program Files fixture")
	}
	fixture := newSuiteStageFixture(t)
	if _, err := RunSuiteCanonicalStage(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); !errors.Is(err, ErrSuiteCanonicalStage) {
		t.Fatalf("unsupported platform error=%v", err)
	}
	assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
}

func TestSuiteCanonicalStageRequiresPrecheckAndExactReceipt(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, suiteStageFixture)
	}{
		{"missing precheck", func(t *testing.T, f suiteStageFixture) {
			if err := os.Remove(f.bootstrap.StatePath); err != nil {
				t.Fatal(err)
			}
		}},
		{"different request", func(t *testing.T, f suiteStageFixture) {
			if err := SaveSetupCheckpoint(f.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: "64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}); err == nil {
				t.Fatal("invalid transition unexpectedly written")
			}
			if err := os.WriteFile(f.bootstrap.StatePath, []byte(`{"schema_version":1,"stage":"PRECHECK","request_uid":"64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"corrupt checkpoint", func(t *testing.T, f suiteStageFixture) {
			if err := os.WriteFile(f.bootstrap.StatePath, []byte(`{"schema_version":1,"stage":`), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"future checkpoint", func(t *testing.T, f suiteStageFixture) {
			if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), f.bootstrap, f.roots, f.release, f.source, suiteStageTestDependencies()); err != nil {
				t.Fatal(err)
			}
			if err := SaveSetupCheckpoint(f.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupConfigDrafted, RequestUID: f.preparation.RequestUID}); err != nil {
				t.Fatal(err)
			}
		}},
		{"conflict receipt", func(t *testing.T, f suiteStageFixture) {
			receipt := SuiteStageReceipt{SchemaVersion: 1, RequestUID: f.preparation.RequestUID, SetupStageID: f.plan.StageID, ManifestSHA256: f.plan.ManifestSHA256, Target: f.plan.Target, Version: f.release.manifest.Version, InstalledSuiteRoot: filepath.Join(filepath.Dir(f.source), "other"), AdoptionKind: suiteStageAdoptionKind}
			if err := saveSuiteStageReceipt(f.roots, receipt); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			test.mutate(t, fixture)
			if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
				t.Fatal("invalid evidence accepted")
			}
		})
	}
	t.Run("staged missing receipt", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(fixture.roots.AgentState, SuiteStageReceiptName)); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
			t.Fatal("missing receipt accepted")
		}
	})
}

func TestSuiteCanonicalStageRejectsProofPlanAndInstalledTreeDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *suiteStageFixture)
	}{
		{"unverified proof", func(_ *testing.T, f *suiteStageFixture) { f.release.verified = false }},
		{"proof target", func(_ *testing.T, f *suiteStageFixture) {
			f.release.manifest.Target.OS = "windows"
			if runtime.GOOS == "windows" {
				f.release.manifest.Target.OS = "linux"
			}
		}},
		{"plan", func(t *testing.T, f *suiteStageFixture) {
			plan := f.plan
			plan.ManifestSHA256 = strings.Repeat("b", 64)
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			raw, err := jsonMarshalSuiteSetupPlan(plan)
			if err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerAtomic(filepath.Join(f.roots.AgentState, suiteSetupPlanName), raw); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing entry", func(t *testing.T, f *suiteStageFixture) {
			if err := os.Remove(filepath.Join(f.source, "AntBrowser.exe")); err != nil {
				t.Fatal(err)
			}
		}},
		{"entry hash and size", func(t *testing.T, f *suiteStageFixture) {
			if err := os.WriteFile(filepath.Join(f.source, "AntBrowser.exe"), []byte("tampered"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest version", func(t *testing.T, f *suiteStageFixture) {
			manifest := f.manifest
			manifest.Version = "3.0.1"
			raw, err := MarshalSuiteReleaseManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.source, "release-manifest.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"manifest target", func(t *testing.T, f *suiteStageFixture) {
			manifest := f.manifest
			manifest.Target.OS = "windows"
			if runtime.GOOS == "windows" {
				manifest.Target.OS = "linux"
			}
			raw, err := MarshalSuiteReleaseManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.source, "release-manifest.json"), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			test.mutate(t, &fixture)
			if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
				t.Fatal("drift accepted")
			}
			assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
		})
	}
}

func TestSuiteStageReceiptClosedOwnerOnlyContract(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate", []byte(`{"schema_version":1,"schema_version":1}`)},
		{"unknown", []byte(`{"schema_version":1,"unknown":true}`)},
		{"trailing", []byte(`{} {}`)},
		{"corrupt", []byte(`{"schema_version":`)},
		{"oversize", []byte(strings.Repeat("x", suiteStageReceiptMaxBytes+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			path := filepath.Join(fixture.roots.AgentState, SuiteStageReceiptName)
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if receipt, err := LoadSuiteStageReceipt(fixture.roots); err == nil || receipt != nil {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		target := filepath.Join(t.TempDir(), "receipt")
		if err := os.WriteFile(target, []byte(`{}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(fixture.roots.AgentState, SuiteStageReceiptName)); err != nil {
			t.Skip(err)
		}
		if _, err := LoadSuiteStageReceipt(fixture.roots); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("wrong mode", func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			receipt := SuiteStageReceipt{SchemaVersion: 1, RequestUID: fixture.preparation.RequestUID, SetupStageID: fixture.plan.StageID, ManifestSHA256: fixture.plan.ManifestSHA256, Target: fixture.plan.Target, Version: fixture.release.manifest.Version, InstalledSuiteRoot: fixture.source, AdoptionKind: suiteStageAdoptionKind}
			if err := saveSuiteStageReceipt(fixture.roots, receipt); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Join(fixture.roots.AgentState, SuiteStageReceiptName), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSuiteStageReceipt(fixture.roots); err == nil {
				t.Fatal("permissive receipt accepted")
			}
		})
	}
}

func TestSuiteCanonicalStageReceiptSurvivesCheckpointFailureAndRetries(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	deps := suiteStageTestDependencies()
	deps.SaveCheckpoint = func(string, SetupCheckpoint) error { return errors.New("injected checkpoint failure") }
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
		t.Fatal("checkpoint failure accepted")
	}
	if receipt, err := LoadSuiteStageReceipt(fixture.roots); err != nil || receipt == nil {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertSuiteStageCheckpoint(t, fixture, SetupStaged)
	t.Run("checkpoint commit unknown", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		deps := suiteStageTestDependencies()
		deps.SaveCheckpoint = func(path string, checkpoint SetupCheckpoint) error {
			if err := SaveSetupCheckpoint(path, checkpoint); err != nil {
				return err
			}
			return errors.New("injected checkpoint acknowledgement loss")
		}
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("checkpoint commit-unknown reported success")
		}
		assertSuiteStageCheckpoint(t, fixture, SetupStaged)
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
			t.Fatalf("checkpoint commit-unknown recovery: %v", err)
		}
	})
}

func TestSuiteCanonicalStageReceiptAndLockSecurityFailuresDoNotAdvance(t *testing.T) {
	t.Run("receipt write", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		deps := suiteStageTestDependencies()
		deps.SaveReceipt = func(SuiteUserRoots, SuiteStageReceipt) error { return errors.New("injected receipt failure") }
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("receipt failure accepted")
		}
		assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
		if receipt, _ := LoadSuiteStageReceipt(fixture.roots); receipt != nil {
			t.Fatalf("failed write left receipt: %+v", receipt)
		}
	})
	t.Run("receipt commit unknown", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		deps := suiteStageTestDependencies()
		deps.SaveReceipt = func(roots SuiteUserRoots, receipt SuiteStageReceipt) error {
			if err := saveSuiteStageReceipt(roots, receipt); err != nil {
				return err
			}
			return errors.New("injected acknowledgement loss")
		}
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("commit-unknown receipt write reported success")
		}
		if receipt, err := LoadSuiteStageReceipt(fixture.roots); err != nil || receipt == nil {
			t.Fatalf("durable receipt=%+v err=%v", receipt, err)
		}
		assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
			t.Fatalf("commit-unknown recovery: %v", err)
		}
	})
	t.Run("instance lock security", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		deps := suiteStageTestDependencies()
		lock := &suitePrecheckTestLock{}
		deps.AcquireInstance = func(string) (suitePrecheckInstanceLock, error) { return lock, nil }
		calls := 0
		deps.SecureInstance = func(path string) error {
			calls++
			if path != filepath.Join(fixture.roots.AgentState, ".ant-farm-client.lock") {
				t.Fatalf("path=%q", path)
			}
			return errors.New("injected DACL failure")
		}
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("lock security failure accepted")
		}
		if calls != 1 || !lock.released {
			t.Fatalf("calls=%d released=%v", calls, lock.released)
		}
		assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
	})
}

func TestSuiteCanonicalStageRequiresThreeStableInstallValidations(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	deps := suiteStageTestDependencies()
	validate := deps.ValidateInstall
	calls := 0
	deps.ValidateInstall = func(root string, plan SuiteSetupPlan, version string) (suiteStageInstallEvidence, error) {
		calls++
		return validate(root, plan, version)
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Fatalf("install validation calls=%d, want 3", calls)
	}
}

func TestSuiteCanonicalStageStagedCorruptReceiptFailsClosed(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fixture.roots.AgentState, SuiteStageReceiptName), []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
		t.Fatal("corrupt durable receipt accepted")
	}
	assertSuiteStageCheckpoint(t, fixture, SetupStaged)
}

func TestSuiteCanonicalStageRevalidatesInstalledRootBeforeReceiptAndCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, suiteStageFixture) error
	}{
		{"tree drift", func(_ *testing.T, f suiteStageFixture) error {
			return os.WriteFile(filepath.Join(f.source, "evil.dll"), []byte("evil"), 0o600)
		}},
		{"ancestor redirect", func(_ *testing.T, f suiteStageFixture) error {
			parent := filepath.Dir(f.source)
			moved := parent + "-moved"
			if err := os.Rename(parent, moved); err != nil {
				return err
			}
			return os.Symlink(moved, parent)
		}},
		{"new inode equal tree", func(t *testing.T, f suiteStageFixture) error {
			old := f.source + "-old"
			if err := os.Rename(f.source, old); err != nil {
				return err
			}
			return cloneSuitePrecheckTree(t, old, f.source)
		}},
		{"plan drift", func(_ *testing.T, f suiteStageFixture) error {
			plan := f.plan
			plan.ManifestSHA256 = strings.Repeat("b", 64)
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			raw, err := jsonMarshalSuiteSetupPlan(plan)
			if err != nil {
				return err
			}
			return writeOwnerAtomic(filepath.Join(f.roots.AgentState, suiteSetupPlanName), raw)
		}},
		{"mutable footprint drift", func(_ *testing.T, f suiteStageFixture) error {
			return os.WriteFile(filepath.Join(f.roots.Config, SuiteClientConfigName), []byte("late"), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			deps := suiteStageTestDependencies()
			deps.AfterValidate = func() error { return test.mutate(t, fixture) }
			if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("post-validation drift accepted")
			}
			assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
			if receipt, _ := LoadSuiteStageReceipt(fixture.roots); receipt != nil {
				t.Fatalf("drift wrote receipt: %+v", receipt)
			}
		})
	}
}

func TestSuiteCanonicalStageRevalidatesTreeAfterReceiptBeforeCheckpoint(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	deps := suiteStageTestDependencies()
	deps.SaveReceipt = func(roots SuiteUserRoots, receipt SuiteStageReceipt) error {
		if err := saveSuiteStageReceipt(roots, receipt); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(fixture.source, "post-receipt-evil.dll"), []byte("evil"), 0o600)
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
		t.Fatal("post-receipt tree drift accepted")
	}
	assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
	if receipt, err := LoadSuiteStageReceipt(fixture.roots); err != nil || receipt == nil {
		t.Fatalf("diagnostic receipt=%+v err=%v", receipt, err)
	}
}

func TestSuiteCanonicalStageLocksAndFootprintFailClosed(t *testing.T) {
	t.Run("active instance", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		lock, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Release()
		deps := suiteStageTestDependencies()
		deps.AcquireInstance = func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) }
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("active instance accepted")
		}
	})
	t.Run("setup lock", func(t *testing.T) {
		fixture := newSuiteStageFixture(t)
		lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("error=%v", err)
		}
	})
	for _, artifact := range []struct {
		name string
		path func(suiteStageFixture) string
	}{
		{"client config", func(f suiteStageFixture) string { return filepath.Join(f.roots.Config, SuiteClientConfigName) }},
		{"handoff", func(f suiteStageFixture) string { return filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName) }},
		{"identity", func(f suiteStageFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		}},
		{"service", func(f suiteStageFixture) string { return filepath.Join(f.roots.AgentState, SuiteActivationJournalName) }},
		{"browser", func(f suiteStageFixture) string { return filepath.Join(f.roots.BrowserData, "Default") }},
	} {
		t.Run(artifact.name, func(t *testing.T) {
			fixture := newSuiteStageFixture(t)
			if err := os.WriteFile(artifact.path(fixture), []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
				t.Fatal("existing footprint accepted")
			}
			assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
		})
	}
}

func TestSuiteCanonicalStageConcurrentCallers(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	var wait sync.WaitGroup
	results := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies())
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if successes == 0 {
		t.Fatal("no stage winner")
	}
	assertSuiteStageCheckpoint(t, fixture, SetupStaged)
}

func TestSuiteStageReceiptTempRecoveryBoundary(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	receipt := SuiteStageReceipt{SchemaVersion: 1, RequestUID: fixture.preparation.RequestUID, SetupStageID: fixture.plan.StageID, ManifestSHA256: fixture.plan.ManifestSHA256, Target: fixture.plan.Target, Version: fixture.release.manifest.Version, InstalledSuiteRoot: fixture.source, AdoptionKind: suiteStageAdoptionKind}
	name, err := suiteStageReceiptTempName(receipt)
	if err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(fixture.roots.AgentState, name)
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale temp remains: %v", err)
	}
}

func TestSuiteStageReceiptTempCleanupRejectsForeignPrefixWithoutDeleting(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	foreign := filepath.Join(fixture.roots.AgentState, suiteStageReceiptTempPrefix+"foreign.tmp")
	if err := os.WriteFile(foreign, []byte("foreign"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteStageTestDependencies()); err == nil {
		t.Fatal("foreign reserved-prefix artifact accepted")
	}
	if raw, err := os.ReadFile(foreign); err != nil || string(raw) != "foreign" {
		t.Fatalf("foreign artifact mutated raw=%q err=%v", raw, err)
	}
	assertSuiteStageCheckpoint(t, fixture, SetupPrecheck)
}

func TestSuiteCanonicalStagePersistsOnlyPlatformCanonicalRoot(t *testing.T) {
	fixture := newSuiteStageFixture(t)
	deps := suiteStageTestDependencies()
	validate := deps.ValidateInstall
	canonical := filepath.Join(filepath.Dir(filepath.Dir(fixture.source)), "Canonical Program Files", fixture.release.manifest.Version)
	deps.ValidateInstall = func(root string, plan SuiteSetupPlan, version string) (suiteStageInstallEvidence, error) {
		evidence, err := validate(root, plan, version)
		evidence.CanonicalRoot = canonical
		return evidence, err
	}
	if _, err := runSuiteCanonicalStageWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatal(err)
	}
	receipt, err := LoadSuiteStageReceipt(fixture.roots)
	if err != nil || receipt == nil || receipt.InstalledSuiteRoot != canonical || receipt.InstalledSuiteRoot == fixture.source {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
}

func assertSuiteStageCheckpoint(t *testing.T, fixture suiteStageFixture, stage SetupStage) {
	t.Helper()
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != stage {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}

func assertSuiteStageHasNoLaterArtifacts(t *testing.T, fixture suiteStageFixture) {
	t.Helper()
	for _, path := range []string{filepath.Join(fixture.roots.Config, SuiteClientConfigName), filepath.Join(fixture.roots.AgentState, SuiteBootstrapEnrollmentAttemptName), filepath.Join(fixture.roots.AgentState, SuiteOwnershipHandoffName), filepath.Join(fixture.roots.AgentState, SuiteActivationJournalName)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact %s: %v", filepath.Base(path), err)
		}
	}
}
