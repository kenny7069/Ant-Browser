package backend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeSuiteServicePlatform struct {
	calls []string
	fail  string
}

type fakeLegacyAutostartManager struct {
	removeCalls int
	statusCalls int
}

func (*fakeLegacyAutostartManager) Install(string, string) error { return nil }
func (f *fakeLegacyAutostartManager) Remove() error {
	f.removeCalls++
	return nil
}
func (f *fakeLegacyAutostartManager) Status() (FarmClientAutostartStatus, error) {
	f.statusCalls++
	return FarmClientAutostartStatus{}, nil
}

func (f *fakeSuiteServicePlatform) call(name string) error {
	f.calls = append(f.calls, name)
	if f.fail == name {
		return errors.New("injected")
	}
	return nil
}
func (f *fakeSuiteServicePlatform) ValidateInstall(SuiteOwnershipHandoff) (string, error) {
	if err := f.call("validate"); err != nil {
		return "", err
	}
	return "task-current-user", nil
}
func (f *fakeSuiteServicePlatform) RegisterDisabled(SuiteOwnershipHandoff, string) error {
	return f.call("register-disabled")
}
func (f *fakeSuiteServicePlatform) Audit(_ SuiteOwnershipHandoff, _ string, enabled bool) error {
	if enabled {
		return f.call("audit-enabled")
	}
	return f.call("audit-disabled")
}
func (f *fakeSuiteServicePlatform) Enable(SuiteOwnershipHandoff, string) error {
	return f.call("enable")
}
func (f *fakeSuiteServicePlatform) Start(SuiteOwnershipHandoff, string) error { return f.call("start") }

func enrolledSuiteFixture(t *testing.T) (SuiteUserRoots, SetupPreparationCheckpoint) {
	t.Helper()
	roots, preparation, binaryRoot, gui := suiteHandoffFixture(t)
	if _, err := FinalizeSuiteOwnershipHandoff(roots, preparation.RequestUID, binaryRoot, gui); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roots.AgentState, "setup.json")
	for _, stage := range []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted, SetupTransportVerified, SetupIdentityReady, SetupEnrolled} {
		if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: preparation.RequestUID}); err != nil {
			t.Fatal(err)
		}
	}
	return roots, preparation
}

func TestSuiteServiceCoordinatorSeparatesDurableTransitions(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
	if err := coordinator.Activate(context.Background(), roots); err != nil {
		t.Fatal(err)
	}
	want := "validate,register-disabled,audit-disabled,validate,enable,validate,audit-enabled,validate,start"
	if strings.Join(platform.calls, ",") != want {
		t.Fatalf("calls=%v", platform.calls)
	}
	j, err := LoadSuiteActivationJournal(roots)
	if err != nil || j.Stage != SuiteActivationCheckpointWritten {
		t.Fatalf("journal=%+v err=%v", j, err)
	}
	cp, err := LoadSetupCheckpoint(filepath.Join(roots.AgentState, "setup.json"))
	if err != nil || cp.Stage != SetupServiceStarted {
		t.Fatalf("checkpoint=%+v err=%v", cp, err)
	}
	platform.calls = nil
	if err := coordinator.Activate(context.Background(), roots); err != nil || len(platform.calls) != 1 {
		t.Fatalf("retry calls=%v err=%v", platform.calls, err)
	}
}

func TestSuiteServiceRequiresExactEnrolledAndMarksUnknownSideEffect(t *testing.T) {
	roots, preparation := enrolledSuiteFixture(t)
	path := filepath.Join(roots.AgentState, "setup.json")
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupServiceStarted, RequestUID: preparation.RequestUID}); err != nil {
		t.Fatal(err)
	}
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupControlAuthenticated, RequestUID: preparation.RequestUID}); err != nil {
		t.Fatal(err)
	}
	p := &fakeSuiteServicePlatform{}
	c := &SuiteServiceCoordinator{Platform: p, ResidentProof: func(context.Context, string) error { return nil }}
	if err := c.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) || len(p.calls) != 0 {
		t.Fatalf("non-enrolled err=%v calls=%v", err, p.calls)
	}
	roots, _ = enrolledSuiteFixture(t)
	p = &fakeSuiteServicePlatform{fail: "register-disabled"}
	c.Platform = p
	if err := c.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("register failure=%v", err)
	}
	j, _ := LoadSuiteActivationJournal(roots)
	if j == nil || j.Stage != SuiteActivationReconcileRequired {
		t.Fatalf("journal=%+v", j)
	}
}

func TestSuiteActivationJournalStrictAndDoctorSecretFree(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteActivationJournalName), []byte(`{"schema_version":1,"private_key":"secret"}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteActivationJournal(roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("unknown field=%v", err)
	}
	report := DoctorSuite(context.Background(), roots)
	if report.Overall == "READY" {
		t.Fatal("doctor reported READY with unknown and failed layers")
	}
	raw := strings.ToLower(strings.TrimSpace(toJSON(report)))
	for _, forbidden := range []string{"private_key", roots.AgentState, `"sid"`, "secret"} {
		if strings.Contains(raw, strings.ToLower(forbidden)) {
			t.Fatalf("doctor leaked %q: %s", forbidden, raw)
		}
	}
}

func toJSON(value any) string { raw, _ := json.Marshal(value); return string(raw) }

func TestRawAutostartRejectsSuiteFootprint(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	canonical := filepath.Join(roots.Config, SuiteClientConfigName)
	if err := rejectRawAutostartForSuiteFootprintAtRoots(canonical, roots); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("bypass=%v", err)
	}
	raw, _ := os.ReadFile(canonical)
	copyPath := filepath.Join(t.TempDir(), "copied.yaml")
	if err := os.WriteFile(copyPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := rejectRawAutostartForSuiteFootprintAtRoots(copyPath, roots); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("copied config bypass=%v", err)
	}
	manager := &fakeLegacyAutostartManager{}
	if err := removeFarmClientAutostartForConfigAtRoots(copyPath, roots, manager); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("guarded removal=%v", err)
	}
	if _, err := farmClientAutostartStatusForConfigAtRoots(copyPath, roots, manager); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("guarded status=%v", err)
	}
	if manager.removeCalls != 0 || manager.statusCalls != 0 {
		t.Fatalf("legacy manager invoked remove=%d status=%d", manager.removeCalls, manager.statusCalls)
	}
	hardlinkPath := filepath.Join(t.TempDir(), "linked.yaml")
	if err := os.Link(canonical, hardlinkPath); err == nil {
		if err := rejectRawAutostartForSuiteFootprintAtRoots(hardlinkPath, roots); !errors.Is(err, ErrFarmClientAutostart) {
			t.Fatalf("hardlink bypass=%v", err)
		}
	}
	_ = os.Remove(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName))
	if err := rejectRawAutostartForSuiteFootprintAtRoots(canonical, roots); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("missing handoff bypass=%v", err)
	}
	if err := writeOwnerAtomic(canonical, []byte("broken: [")); err != nil {
		t.Fatal(err)
	}
	if err := rejectRawAutostartForSuiteFootprintAtRoots(canonical, roots); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("corrupt config bypass=%v", err)
	}
}

func TestSuiteActivationJournalRejectsSkipRollbackAndConcurrentDoubleStart(t *testing.T) {
	roots, preparation := enrolledSuiteFixture(t)
	h := strings.Repeat("a", 64)
	j := SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: preparation.RequestUID, Generation: 1, ClientConfigSHA256: h, ManifestSHA256: h, SetupStageID: "stage", TaskIdentityDigest: h}
	if err := saveSuiteActivationJournal(roots, j); err != nil {
		t.Fatal(err)
	}
	j.Stage = SuiteActivationEnabled
	if err := saveSuiteActivationJournal(roots, j); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("skip=%v", err)
	}
	j.Stage = SuiteActivationRegisterDisabled
	if err := saveSuiteActivationJournal(roots, j); err != nil {
		t.Fatal(err)
	}
	j.Stage = SuiteActivationValidated
	if err := saveSuiteActivationJournal(roots, j); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("rollback=%v", err)
	}

	roots, _ = enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
	var wait sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wait.Add(1)
		go func() { defer wait.Done(); errs <- coordinator.Activate(context.Background(), roots) }()
	}
	wait.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("concurrent activation=%v", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successful contenders=%d", successes)
	}
	starts := 0
	for _, call := range platform.calls {
		if call == "start" {
			starts++
		}
	}
	if starts != 1 {
		t.Fatalf("start calls=%d all=%v", starts, platform.calls)
	}
}

func TestSuiteDoctorRequiresPlatformObservationAndTypedExit(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return errors.New("not resident") }}
	if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("activation=%v", err)
	}
	report := doctorSuiteWithPlatform(context.Background(), roots, platform)
	foundRegistration := false
	for _, layer := range report.Layers {
		if layer.Name == "registration" {
			foundRegistration = true
			if layer.Status != "PASS" || layer.Code != "REGISTRATION_OBSERVED" {
				t.Fatalf("registration=%+v", layer)
			}
		}
	}
	if !foundRegistration || report.Overall == "READY" || SuiteDoctorExitCode(report) == 0 {
		t.Fatalf("report=%+v", report)
	}
	deferred := doctorSuiteWithPlatform(context.Background(), roots, &fakeSuiteServicePlatform{fail: "validate"})
	if deferred.ExitClass != "DEFERRED" || SuiteDoctorExitCode(deferred) != 5 {
		t.Fatalf("deferred=%+v", deferred)
	}
}
