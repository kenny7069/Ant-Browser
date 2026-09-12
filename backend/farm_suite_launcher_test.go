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
	"testing"
	"time"
)

func TestClassifySuiteFarmClientLaunchRecognizesCanonicalAlias(t *testing.T) {
	base := t.TempDir()
	roots := SuiteUserRoots{
		Config: filepath.Join(base, "Config"), BrowserData: filepath.Join(base, "BrowserData"),
		AgentState: filepath.Join(base, "AgentState"), Logs: filepath.Join(base, "Logs"),
	}
	canonical := filepath.Join(roots.Config, SuiteClientConfigName)
	alias := strings.ToUpper(canonical)
	isSuite, err := classifySuiteFarmClientLaunch(roots, alias, func(left, right string) bool {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	})
	if err != nil || !isSuite {
		t.Fatalf("canonical alias classified as legacy: suite=%t err=%v", isSuite, err)
	}
}

func TestClassifySuiteFarmClientLaunchRejectsAlternateSuiteFootprint(t *testing.T) {
	base := t.TempDir()
	roots := SuiteUserRoots{
		Config: filepath.Join(base, "config"), BrowserData: filepath.Join(base, "browser-data"),
		AgentState: filepath.Join(base, "agent-state"), Logs: filepath.Join(base, "logs"),
	}
	if err := ensureSuiteOwnerRoots(roots); err != nil {
		t.Fatal(err)
	}
	config := FarmClientConfig{
		ApplicationRoot: filepath.Join(roots.BrowserData, "ant-application"),
		StateRoot:       roots.AgentState,
		ControlURL:      "ws://127.0.0.1:1",
		NodeUID:         "suite-classification-test",
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	canonical := filepath.Join(roots.Config, SuiteClientConfigName)
	if err := os.WriteFile(canonical, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "alternate")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		make func(string) error
	}{
		{name: "copy", make: func(path string) error { return os.WriteFile(path, raw, 0o600) }},
		{name: "hardlink", make: func(path string) error { return os.Link(canonical, path) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			alternate := filepath.Join(outside, test.name+".yaml")
			if err := test.make(alternate); err != nil {
				t.Fatal(err)
			}
			isSuite, err := ClassifySuiteFarmClientLaunch(roots, alternate)
			if isSuite || !errors.Is(err, ErrSuiteLauncherRevalidation) {
				t.Fatalf("alternate Suite config reached legacy classification: suite=%t err=%v", isSuite, err)
			}
			if _, statErr := os.Lstat(filepath.Join(roots.AgentState, "updates", "activation.lock")); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("classification mutated legacy launcher state: %v", statErr)
			}
		})
	}

	legacyRoot := filepath.Join(base, "legacy")
	legacy := FarmClientConfig{ApplicationRoot: legacyRoot, StateRoot: filepath.Join(legacyRoot, "state"), ControlURL: "ws://127.0.0.1:1", NodeUID: "legacy-classification-test"}
	legacyRaw, _ := json.Marshal(legacy)
	legacyPath := filepath.Join(outside, "legacy.yaml")
	if err := os.WriteFile(legacyPath, legacyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if isSuite, err := ClassifySuiteFarmClientLaunch(roots, legacyPath); err != nil || isSuite {
		t.Fatalf("genuine legacy config changed classification: suite=%t err=%v", isSuite, err)
	}
}

func TestSuiteLauncherValidationFailureLeavesStagedActivationUntouched(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+stateRoot+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-mutation-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateRoot, err := farmClientUpdateRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("pending"))
	activation := FarmClientUpdateActivation{Version: 1, Phase: farmClientUpdatePhaseStaged, Pending: &FarmClientUpdateSlot{Version: "1.1.0", Target: "darwin-arm64", SHA256: hex.EncodeToString(digest[:]), Size: 7}}
	if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
		t.Fatal(err)
	}
	launcher, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	called := 0
	validate := func(string, string) error {
		called++
		return ErrSuiteLauncherRevalidation
	}
	if err := runFarmClientLauncherWithValidation(context.Background(), configPath, launcher, nil, nil, validate); !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	if called != 1 {
		t.Fatalf("validator calls=%d, want one before staged rollback", called)
	}
	loaded, err := LoadFarmClientUpdateActivation(stateRoot)
	if err != nil || loaded.Phase != farmClientUpdatePhaseStaged || loaded.Pending == nil || loaded.Pending.SHA256 != activation.Pending.SHA256 {
		t.Fatalf("activation mutated: %#v err=%v", loaded, err)
	}
}

func TestSuiteLauncherStrictWrapperRejectsBeforeLegacyLauncher(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+filepath.Join(root, "state")+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-wrapper-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "launcher")
	if err := os.WriteFile(launcher, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	called := 0
	validate := func(string, string) error {
		called++
		return ErrSuiteLauncherRevalidation
	}
	if err := runSuiteFarmClientLauncher(context.Background(), configPath, launcher, nil, nil, validate); !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	if called != 1 {
		t.Fatalf("strict validator calls=%d, want 1 before legacy launcher", called)
	}
}

func TestSuiteLauncherRevalidatesAfterChildExitBeforeRestart(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+stateRoot+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-boundary-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := 0
	validate := func(string, string) error {
		called++
		if called >= 3 {
			return ErrSuiteLauncherRevalidation
		}
		return nil
	}
	launcher, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = runFarmClientLauncherWithValidation(ctx, configPath, launcher, nil, nil, validate)
	if !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	if called != 3 {
		t.Fatalf("strict validator calls=%d, want entry, spawn, and restart", called)
	}
}

func TestSuiteLauncherProductionValidatorRejectsDurableEvidenceDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, roots SuiteUserRoots, platform *fakeSuiteServicePlatform)
	}{
		{name: "journal stage", mutate: func(t *testing.T, roots SuiteUserRoots, _ *fakeSuiteServicePlatform) {
			mutateSuiteLauncherJournal(t, roots, func(j *SuiteActivationJournal) { j.Stage = SuiteActivationTaskAudited })
		}},
		{name: "journal generation", mutate: func(t *testing.T, roots SuiteUserRoots, _ *fakeSuiteServicePlatform) {
			mutateSuiteLauncherJournal(t, roots, func(j *SuiteActivationJournal) { j.Generation++ })
		}},
		{name: "task digest", mutate: func(t *testing.T, roots SuiteUserRoots, _ *fakeSuiteServicePlatform) {
			mutateSuiteLauncherJournal(t, roots, func(j *SuiteActivationJournal) { j.TaskIdentityDigest = strings.Repeat("0", 64) })
		}},
		{name: "registration", mutate: func(_ *testing.T, _ SuiteUserRoots, platform *fakeSuiteServicePlatform) {
			platform.registration = suiteServiceRegistrationExactDisabled
		}},
		{name: "handoff", mutate: func(t *testing.T, roots SuiteUserRoots, _ *fakeSuiteServicePlatform) {
			if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName), []byte("{}\n")); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "checkpoint", mutate: func(t *testing.T, roots SuiteUserRoots, _ *fakeSuiteServicePlatform) {
			path := filepath.Join(roots.AgentState, "setup.json")
			_ = os.Remove(path + ".bak")
			raw, _ := json.Marshal(SetupCheckpoint{SchemaVersion: 1, Stage: SetupIdentityReady, RequestUID: "8a064666-42a6-4f0c-b023-f12393c25674"})
			if err := writeOwnerAtomic(path, append(raw, '\n')); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			roots, _ := enrolledSuiteFixture(t)
			platform := &fakeSuiteServicePlatform{registration: suiteServiceRegistrationExactEnabled}
			handoff, err := LoadSuiteOwnershipHandoff(roots)
			if err != nil || handoff == nil {
				t.Fatalf("handoff=%+v err=%v", handoff, err)
			}
			taskIdentity, _ := platform.ValidateInstall(*handoff)
			taskDigest := sha256.Sum256([]byte(taskIdentity))
			journal := SuiteActivationJournal{
				SchemaVersion: 1, Stage: SuiteActivationEnabled, RequestUID: handoff.SetupRequestUID, Generation: 1,
				ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256,
				SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskDigest[:]),
			}
			if err := saveSuiteActivationJournal(roots, journal); err != nil {
				t.Fatal(err)
			}
			platform.calls = nil
			configPath := filepath.Join(roots.Config, SuiteClientConfigName)
			launcherPath := filepath.Join(handoff.SuiteBinaryRoot, "ant-farm-client.exe")
			if err := validateSuiteLauncherStartWithPlatform(roots, configPath, launcherPath, platform); err != nil {
				t.Fatalf("valid production fixture rejected: %v", err)
			}
			test.mutate(t, roots, platform)
			if err := validateSuiteLauncherStartWithPlatform(roots, configPath, launcherPath, platform); !errors.Is(err, ErrSuiteLauncherRevalidation) {
				t.Fatalf("drift accepted: %v", err)
			}
		})
	}
}

func mutateSuiteLauncherJournal(t *testing.T, roots SuiteUserRoots, mutate func(*SuiteActivationJournal)) {
	t.Helper()
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil {
		t.Fatalf("journal=%+v err=%v", journal, err)
	}
	mutate(journal)
	raw, err := json.Marshal(journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteActivationJournalName), append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
}
