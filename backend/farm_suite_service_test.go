package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type fakeSuiteServicePlatform struct {
	calls        []string
	fail         string
	registration suiteServiceRegistrationState
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
	if err := f.call("register-disabled"); err != nil {
		return err
	}
	f.registration = suiteServiceRegistrationExactDisabled
	return nil
}
func (f *fakeSuiteServicePlatform) InspectRegistration(SuiteOwnershipHandoff, string) (suiteServiceRegistrationState, error) {
	state := f.registration
	if state == "" {
		state = suiteServiceRegistrationAbsent
	}
	if err := f.call("inspect-" + strings.ToLower(string(state))); err != nil {
		return suiteServiceRegistrationDrift, err
	}
	return state, nil
}
func (f *fakeSuiteServicePlatform) Enable(SuiteOwnershipHandoff, string) error {
	if err := f.call("enable"); err != nil {
		return err
	}
	f.registration = suiteServiceRegistrationExactEnabled
	return nil
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
	want := "validate,inspect-absent,register-disabled,inspect-exact_disabled,validate,inspect-exact_disabled,enable,validate,inspect-exact_enabled,start,validate,inspect-exact_enabled,validate,inspect-exact_enabled,validate,inspect-exact_enabled"
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
	if err := coordinator.Activate(context.Background(), roots); err != nil || strings.Join(platform.calls, ",") != "validate,validate,inspect-exact_enabled" {
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

func TestSuiteServiceRecoversDisabledRegistrationAndRejectsDrift(t *testing.T) {
	roots, preparation := enrolledSuiteFixture(t)
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		t.Fatal(err)
	}
	taskHash := sha256.Sum256([]byte("task-current-user"))
	journal := SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: preparation.RequestUID, Generation: 1, ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256, SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskHash[:])}
	if err := saveSuiteActivationJournal(roots, journal); err != nil {
		t.Fatal(err)
	}
	platform := &fakeSuiteServicePlatform{registration: suiteServiceRegistrationExactDisabled}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
	if err := coordinator.Activate(context.Background(), roots); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(platform.calls, ","), "register-disabled") {
		t.Fatalf("recovery re-registered task: %v", platform.calls)
	}

	for _, state := range []suiteServiceRegistrationState{suiteServiceRegistrationDrift, suiteServiceRegistrationExactEnabled} {
		roots, preparation = enrolledSuiteFixture(t)
		handoff, err = LoadSuiteOwnershipHandoff(roots)
		if err != nil || handoff == nil {
			t.Fatal(err)
		}
		journal = SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: preparation.RequestUID, Generation: 1, ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256, SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskHash[:])}
		if err := saveSuiteActivationJournal(roots, journal); err != nil {
			t.Fatal(err)
		}
		platform = &fakeSuiteServicePlatform{registration: state}
		coordinator.Platform = platform
		if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
			t.Fatalf("state=%s err=%v", state, err)
		}
		current, loadErr := LoadSuiteActivationJournal(roots)
		if loadErr != nil || current == nil || current.Stage != SuiteActivationReconcileRequired {
			t.Fatalf("state=%s journal=%+v err=%v", state, current, loadErr)
		}
		if containsSuiteServiceCall(platform.calls, "enable") || containsSuiteServiceCall(platform.calls, "start") {
			t.Fatalf("state=%s unsafe calls=%v", state, platform.calls)
		}
	}
}

func TestSuiteServiceRechecksDisabledBeforeEnableAndEnabledBeforeStart(t *testing.T) {
	for _, test := range []struct {
		name  string
		stage SuiteActivationStage
		state suiteServiceRegistrationState
	}{
		{name: "drift before enable", stage: SuiteActivationTaskAudited, state: suiteServiceRegistrationDrift},
		{name: "disabled before start", stage: SuiteActivationEnabled, state: suiteServiceRegistrationExactDisabled},
	} {
		t.Run(test.name, func(t *testing.T) {
			roots, preparation := enrolledSuiteFixture(t)
			handoff, err := LoadSuiteOwnershipHandoff(roots)
			if err != nil || handoff == nil {
				t.Fatal(err)
			}
			taskHash := sha256.Sum256([]byte("task-current-user"))
			journal := SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: preparation.RequestUID, Generation: 1, ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256, SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskHash[:])}
			for suiteActivationStageIndex(journal.Stage) < suiteActivationStageIndex(test.stage) {
				journal.Stage = []SuiteActivationStage{SuiteActivationValidated, SuiteActivationRegisterDisabled, SuiteActivationTaskAudited, SuiteActivationEnabled}[suiteActivationStageIndex(journal.Stage)+1]
				if err := saveSuiteActivationJournal(roots, journal); err != nil {
					t.Fatal(err)
				}
			}
			platform := &fakeSuiteServicePlatform{registration: test.state}
			coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
			if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
				t.Fatalf("err=%v", err)
			}
			if containsSuiteServiceCall(platform.calls, "enable") || containsSuiteServiceCall(platform.calls, "start") {
				t.Fatalf("unsafe calls=%v", platform.calls)
			}
			current, _ := LoadSuiteActivationJournal(roots)
			if current == nil || current.Stage != SuiteActivationReconcileRequired {
				t.Fatalf("journal=%+v", current)
			}
		})
	}
}

func TestSuiteServiceRecoveryRequiresEnabledEvidenceAtEveryPostEnableStage(t *testing.T) {
	for _, stage := range []SuiteActivationStage{SuiteActivationStartRequested, SuiteActivationResidentProved, SuiteActivationCheckpointWritten} {
		for _, state := range []suiteServiceRegistrationState{suiteServiceRegistrationAbsent, suiteServiceRegistrationDrift} {
			t.Run(string(stage)+"/"+string(state), func(t *testing.T) {
				roots, preparation := enrolledSuiteFixture(t)
				advanceActivationJournalForTest(t, roots, preparation, stage)
				platform := &fakeSuiteServicePlatform{registration: state}
				residentCalls := 0
				coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error {
					residentCalls++
					return nil
				}}
				if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
					t.Fatalf("err=%v", err)
				}
				if residentCalls != 0 {
					t.Fatalf("resident proof ran with registration %s", state)
				}
				journal, err := LoadSuiteActivationJournal(roots)
				if err != nil || journal == nil || journal.Stage != SuiteActivationReconcileRequired {
					t.Fatalf("journal=%+v err=%v", journal, err)
				}
			})
		}
	}
}

func TestSuiteServiceCompletedOutageDoesNotRewriteJournal(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
	if err := coordinator.Activate(context.Background(), roots); err != nil {
		t.Fatal(err)
	}
	coordinator.ResidentProof = func(context.Context, string) error { return errors.New("resident disappeared") }
	if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("completed recovery=%v", err)
	}
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage != SuiteActivationCheckpointWritten {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
}

func TestSuiteServiceResidentProvedOutagePreservesRetryStage(t *testing.T) {
	roots, preparation := enrolledSuiteFixture(t)
	advanceActivationJournalForTest(t, roots, preparation, SuiteActivationResidentProved)
	platform := &fakeSuiteServicePlatform{registration: suiteServiceRegistrationExactEnabled}
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return errors.New("resident disappeared") }}
	if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("resident recovery=%v", err)
	}
	checkpoint, err := LoadSetupCheckpoint(filepath.Join(roots.AgentState, "setup.json"))
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupEnrolled {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage != SuiteActivationResidentProved {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
}

func TestSuiteServiceStartupProofRetriesThenSucceeds(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	proofCalls := 0
	coordinator := &SuiteServiceCoordinator{
		Platform:             platform,
		StartupProofAttempts: 3,
		ResidentProof: func(context.Context, string) error {
			proofCalls++
			if proofCalls <= 2 {
				return errors.New("temporarily unavailable")
			}
			return nil
		},
	}
	if err := coordinator.Activate(context.Background(), roots); err != nil {
		t.Fatal(err)
	}
	if proofCalls != 5 {
		t.Fatalf("proof calls=%d", proofCalls)
	}
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage != SuiteActivationCheckpointWritten {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
}

func TestSuiteServiceStartupProofExhaustionRecoversOnNextCall(t *testing.T) {
	roots, _ := enrolledSuiteFixture(t)
	platform := &fakeSuiteServicePlatform{}
	unavailable := true
	proofCalls := 0
	coordinator := &SuiteServiceCoordinator{
		Platform:             platform,
		StartupProofAttempts: 2,
		ResidentProof: func(context.Context, string) error {
			proofCalls++
			if unavailable {
				return errors.New("temporarily unavailable")
			}
			return nil
		},
	}
	if err := coordinator.Activate(context.Background(), roots); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("first activation=%v", err)
	}
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage != SuiteActivationStartRequested || proofCalls != 2 {
		t.Fatalf("journal=%+v proofCalls=%d err=%v", journal, proofCalls, err)
	}
	unavailable = false
	if err := coordinator.Activate(context.Background(), roots); err != nil {
		t.Fatalf("recovery=%v", err)
	}
	journal, err = LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage != SuiteActivationCheckpointWritten {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
}

func advanceActivationJournalForTest(t *testing.T, roots SuiteUserRoots, preparation SetupPreparationCheckpoint, target SuiteActivationStage) {
	t.Helper()
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		t.Fatal(err)
	}
	taskHash := sha256.Sum256([]byte("task-current-user"))
	journal := SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: preparation.RequestUID, Generation: 1, ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256, SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskHash[:])}
	if err := saveSuiteActivationJournal(roots, journal); err != nil {
		t.Fatal(err)
	}
	stages := []SuiteActivationStage{SuiteActivationValidated, SuiteActivationRegisterDisabled, SuiteActivationTaskAudited, SuiteActivationEnabled, SuiteActivationStartRequested, SuiteActivationResidentProved, SuiteActivationCheckpointWritten}
	for suiteActivationStageIndex(journal.Stage) < suiteActivationStageIndex(target) {
		journal.Stage = stages[suiteActivationStageIndex(journal.Stage)+1]
		if err := saveSuiteActivationJournal(roots, journal); err != nil {
			t.Fatal(err)
		}
	}
}

func containsSuiteServiceCall(calls []string, want string) bool {
	for _, call := range calls {
		if call == want {
			return true
		}
	}
	return false
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
	coordinator := &SuiteServiceCoordinator{Platform: platform, ResidentProof: func(context.Context, string) error { return nil }}
	if err := coordinator.Activate(context.Background(), roots); err != nil {
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
	platform.registration = suiteServiceRegistrationDrift
	drifted := doctorSuiteWithPlatform(context.Background(), roots, platform)
	for _, layer := range drifted.Layers {
		if layer.Name == "registration" && (layer.Status != "FAIL" || layer.Code != "REGISTRATION_AUDIT_FAILED") {
			t.Fatalf("drift registration=%+v", layer)
		}
	}
	deferred := doctorSuiteWithPlatform(context.Background(), roots, &fakeSuiteServicePlatform{fail: "validate"})
	if deferred.ExitClass != "DEFERRED" || SuiteDoctorExitCode(deferred) != 5 {
		t.Fatalf("deferred=%+v", deferred)
	}
}
