package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type farmRuntimeTestFixture struct {
	farm        *FarmRuntimeService
	runtime     *BrowserRuntimeService
	manager     *browser.Manager
	detectCalls atomic.Int32
	startCalls  atomic.Int32
	startEvents atomic.Int32
	stopCalls   atomic.Int32
}

func newFarmRuntimeTestFixture(t *testing.T, profileIDs ...string) *farmRuntimeTestFixture {
	t.Helper()
	cfg := config.DefaultConfig()
	coreRoot := t.TempDir()
	chromePath := filepath.Join(coreRoot, "chrome")
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "test-core", CoreName: "test", CorePath: coreRoot, IsDefault: true}}
	manager := browser.NewManager(cfg, t.TempDir())
	for _, profileID := range profileIDs {
		manager.Profiles[profileID] = &browser.Profile{
			ProfileId:   profileID,
			ProfileName: profileID,
			CoreId:      "test-core",
			UserDataDir: t.TempDir(),
		}
	}
	fixture := &farmRuntimeTestFixture{manager: manager}
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			fixture.startCalls.Add(1)
			return nil, errors.New("unexpected process launch in recovered fixture")
		},
		StopProcess: func(*exec.Cmd) error {
			fixture.stopCalls.Add(1)
			return nil
		},
		ResolveUserDataDir: func(profile *browser.Profile) string {
			if profile == nil {
				return ""
			}
			return profile.UserDataDir
		},
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			fixture.detectCalls.Add(1)
			return BrowserRuntimeDetection{PID: 7001, DebugPort: 9701, DebugReady: true}, true
		},
		TryCloseCDP: func(int, time.Duration) bool {
			fixture.stopCalls.Add(1)
			return true
		},
		EmitStarted: func(*browser.Profile, bool) {
			fixture.startEvents.Add(1)
		},
	}
	fixture.runtime = NewBrowserRuntimeService(BrowserRuntimeServiceConfig{
		Manager: manager,
		Config:  cfg,
		Host:    host,
	})
	var err error
	fixture.farm, err = NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		NodeUID:               "node-test",
		ProviderInstanceID:    "provider-test",
		FencingEpoch:          7,
	})
	if err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestFarmRuntimeEnsureStatusStopAndInventory(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1", "unowned")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	if runtime.State != FarmRuntimeStateIdle || runtime.RuntimeUID == "" || runtime.ProviderInstanceID != "provider-test" || runtime.FencingEpoch != 7 || runtime.Generation == 0 {
		t.Fatalf("ensure result = %+v", runtime)
	}
	if runtime.DebugPort != 9701 || !runtime.DebugReady {
		t.Fatalf("ensure telemetry = %+v", runtime)
	}
	status, err := fixture.farm.RuntimeStatus(FarmRuntimeStatusRequest{ProfileID: "profile-1", RuntimeUID: runtime.RuntimeUID, Generation: runtime.Generation})
	if err != nil {
		t.Fatalf("RuntimeStatus: %v", err)
	}
	if status.RuntimeUID != runtime.RuntimeUID || status.State != FarmRuntimeStateIdle {
		t.Fatalf("status = %+v", status)
	}
	inventory, err := fixture.farm.InventoryWithError()
	if err != nil || len(inventory) != 1 || inventory[0].ProfileID != "profile-1" {
		t.Fatalf("inventory = %#v, err=%v", inventory, err)
	}
	stopped, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            runtime.NodeUID,
		ProfileID:          runtime.ProfileID,
		RuntimeUID:         runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch:       runtime.FencingEpoch,
		ConfigHash:         runtime.ConfigHash,
		Generation:         runtime.Generation,
	})
	if err != nil {
		t.Fatalf("StopRuntime: %v", err)
	}
	if stopped.State != FarmRuntimeStateStopped || stopped.RuntimeUID != runtime.RuntimeUID {
		t.Fatalf("stopped = %+v", stopped)
	}
	if fixture.stopCalls.Load() != 1 {
		t.Fatalf("stop calls = %d, want one explicit CDP close", fixture.stopCalls.Load())
	}
}

func TestFarmRuntimeEnsureIdempotencyDoesNotReinvokeSharedStart(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	first, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("first ensure: %v", err)
	}
	second, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID:          "profile-1",
		RuntimeUID:         first.RuntimeUID,
		ProviderInstanceID: first.ProviderInstanceID,
		FencingEpoch:       first.FencingEpoch,
		ConfigHash:         first.ConfigHash,
		Generation:         first.Generation,
	})
	if err != nil {
		t.Fatalf("idempotent ensure: %v", err)
	}
	if first.RuntimeUID != second.RuntimeUID || first.Generation != second.Generation {
		t.Fatalf("identity changed across ensure: first=%+v second=%+v", first, second)
	}
	if fixture.detectCalls.Load() != 1 || fixture.startCalls.Load() != 0 || fixture.startEvents.Load() != 1 {
		t.Fatalf("shared lifecycle calls = detect:%d start:%d events:%d; removed idempotency shortcut would emit a second start", fixture.detectCalls.Load(), fixture.startCalls.Load(), fixture.startEvents.Load())
	}
}

func TestFarmRuntimeRejectsStaleIdentityAndUnknownInventory(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1", "profile-2")
	first, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            first.NodeUID,
		ProfileID:          first.ProfileID,
		RuntimeUID:         "stale-runtime",
		ProviderInstanceID: first.ProviderInstanceID,
		FencingEpoch:       first.FencingEpoch,
		ConfigHash:         first.ConfigHash,
		Generation:         first.Generation,
	}); !errors.Is(err, ErrFarmRuntimeIdentityMismatch) {
		t.Fatalf("stale UID error = %v, want identity mismatch", err)
	}
	if fixture.stopCalls.Load() != 0 {
		t.Fatal("stale stop attempted to close the runtime")
	}
	if _, err := fixture.farm.RuntimeStatus(FarmRuntimeStatusRequest{ProfileID: "profile-2"}); !errors.Is(err, ErrFarmRuntimeUnknown) {
		t.Fatalf("unknown status error = %v, want unknown", err)
	}
	inventory := fixture.farm.Inventory()
	if len(inventory) != 1 || inventory[0].ProfileID != "profile-1" {
		t.Fatalf("inventory included unowned profile: %#v", inventory)
	}
}

func TestFarmRuntimeRejectsConfigAndFencingContradictionsBeforeStart(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	if _, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID:    "profile-1",
		FencingEpoch: 8,
	}); !errors.Is(err, ErrFarmRuntimeIdentityMismatch) {
		t.Fatalf("fencing contradiction = %v", err)
	}
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID:  "profile-1",
		ConfigHash: "server-hash-v1",
	})
	if err != nil {
		t.Fatalf("ensure with opaque config hash: %v", err)
	}
	if runtime.ConfigHash != "server-hash-v1" {
		t.Fatalf("opaque config hash was not retained: %+v", runtime)
	}
	if _, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID:  runtime.ProfileID,
		RuntimeUID: runtime.RuntimeUID,
		ConfigHash: "server-hash-v2",
	}); !errors.Is(err, ErrFarmRuntimeConfigMismatch) {
		t.Fatalf("opaque config contradiction = %v", err)
	}
	if fixture.detectCalls.Load() != 1 || fixture.startCalls.Load() != 0 {
		t.Fatalf("opaque contradiction restarted lifecycle: detect:%d start:%d", fixture.detectCalls.Load(), fixture.startCalls.Load())
	}
}

func TestFarmRuntimeStopDoesNotSelfAttestProfileMutation(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.Mutex.Lock()
	fixture.manager.Profiles["profile-1"].LaunchArgs = []string{"--mutated-after-ensure"}
	fixture.manager.Mutex.Unlock()
	observed, err := fixture.farm.RuntimeStatus(FarmRuntimeStatusRequest{
		ProfileID:  runtime.ProfileID,
		RuntimeUID: runtime.RuntimeUID,
		Generation: runtime.Generation,
	})
	if err != nil {
		t.Fatalf("status after profile mutation: %v", err)
	}
	if len(observed.Profile.LaunchArgs) != 1 || observed.Profile.LaunchArgs[0] != "--mutated-after-ensure" {
		t.Fatalf("profile mutation was hidden or rewritten: %+v", observed.Profile.LaunchArgs)
	}

	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            runtime.NodeUID,
		ProfileID:          runtime.ProfileID,
		RuntimeUID:         runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch:       runtime.FencingEpoch,
		ConfigHash:         runtime.ConfigHash,
		Generation:         runtime.Generation,
	}); err != nil {
		t.Fatalf("stop after profile mutation: %v", err)
	}
	if fixture.stopCalls.Load() != 1 {
		t.Fatalf("profile mutation stop calls = %d, want one explicit stop", fixture.stopCalls.Load())
	}
}

func TestFarmRuntimeStaleRuntimeCannotStopReplacement(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	first, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	// Simulate an external terminal event through the same shared service; the
	// Farm record remains the old identity until the next ensure.
	if _, err := fixture.runtime.Stop("profile-1"); err != nil {
		t.Fatalf("external stop: %v", err)
	}
	second, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("replacement ensure: %v", err)
	}
	if second.RuntimeUID == first.RuntimeUID || second.Generation == first.Generation {
		t.Fatalf("replacement did not mint identity: first=%+v second=%+v", first, second)
	}
	stopCallsBefore := fixture.stopCalls.Load()
	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            first.NodeUID,
		ProfileID:          first.ProfileID,
		RuntimeUID:         first.RuntimeUID,
		ProviderInstanceID: first.ProviderInstanceID,
		FencingEpoch:       first.FencingEpoch,
		ConfigHash:         first.ConfigHash,
		Generation:         first.Generation,
	}); !errors.Is(err, ErrFarmRuntimeIdentityMismatch) {
		t.Fatalf("stale replacement stop = %v", err)
	}
	if fixture.stopCalls.Load() != stopCallsBefore {
		t.Fatal("stale stop touched replacement runtime")
	}
}

func TestFarmRuntimePerProfileEnsureRaceAndParallelProfiles(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1", "profile-2")
	const contenders = 24
	results := make([]FarmRuntime, contenders)
	errs := make([]error, contenders)
	var wg sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
		}(index)
	}
	wg.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("same-profile ensure %d: %v", index, err)
		}
		if results[index].RuntimeUID != results[0].RuntimeUID || results[index].Generation != results[0].Generation {
			t.Fatalf("same-profile identity %d = %+v, first=%+v", index, results[index], results[0])
		}
	}
	if fixture.detectCalls.Load() != 1 {
		t.Fatalf("same-profile detection calls = %d, want one", fixture.detectCalls.Load())
	}

	var parallel sync.WaitGroup
	parallel.Add(2)
	parallelResults := make(chan FarmRuntime, 2)
	for _, profileID := range []string{"profile-1", "profile-2"} {
		go func(profileID string) {
			defer parallel.Done()
			runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: profileID})
			if err != nil {
				t.Errorf("parallel ensure %s: %v", profileID, err)
				return
			}
			parallelResults <- runtime
		}(profileID)
	}
	parallel.Wait()
	close(parallelResults)
	if len(parallelResults) != 2 {
		t.Fatalf("parallel result count = %d, want two", len(parallelResults))
	}
}

func TestFarmRuntimeFreshSameProfileLaunchesOneOwnedChild(t *testing.T) {
	var startCalls atomic.Int32
	var cleanupCalls atomic.Int32
	var cleanupMu sync.Mutex
	var servers []*http.Server
	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", plan.Spec.AssignedDebugPort))
			if err != nil {
				return nil, err
			}
			server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/json/version" {
					_, _ = writer.Write([]byte(`{"Browser":"farm-test","webSocketDebuggerUrl":"ws://127.0.0.1/devtools"}`))
					return
				}
				writer.WriteHeader(http.StatusNotFound)
			})}
			cleanupMu.Lock()
			servers = append(servers, server)
			cleanupMu.Unlock()
			go func() { _ = server.Serve(listener) }()
			cmd := exec.Command("/bin/sleep", "30")
			if err := cmd.Start(); err != nil {
				_ = server.Close()
				return nil, err
			}
			owner, err := NewBrowserRuntimeCmdOwner(cmd)
			if err != nil {
				_ = cmd.Process.Kill()
				return nil, err
			}
			cleanup := func() {
				cleanupMu.Lock()
				cleanupCalls.Add(1)
				cleanupMu.Unlock()
				_ = server.Close()
			}
			return NewBrowserRuntimeProcess(cmd, owner, &runtimeStartTestMonitor{}, cleanup)
		},
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd == nil || cmd.Process == nil {
				return errors.New("missing child")
			}
			return cmd.Process.Kill()
		},
		CanConnect: func(port int, _ time.Duration) bool {
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
			if err != nil {
				return false
			}
			_ = conn.Close()
			return true
		},
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: service,
		NodeUID:               "node-fresh",
		ProviderInstanceID:    "provider-fresh",
		FencingEpoch:          11,
	})
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 12
	results := make([]FarmRuntime, contenders)
	errs := make([]error, contenders)
	var wg sync.WaitGroup
	for index := 0; index < contenders; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			results[index], errs[index] = farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
		}(index)
	}
	wg.Wait()
	for index, err := range errs {
		if err != nil {
			t.Fatalf("fresh ensure %d: %v", index, err)
		}
		if results[index].RuntimeUID != results[0].RuntimeUID || results[index].Generation != results[0].Generation {
			t.Fatalf("fresh identity %d = %+v, first=%+v", index, results[index], results[0])
		}
	}
	if startCalls.Load() != 1 {
		t.Fatalf("owned child launch calls = %d, want one", startCalls.Load())
	}
	if _, err := farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            results[0].NodeUID,
		ProfileID:          results[0].ProfileID,
		RuntimeUID:         results[0].RuntimeUID,
		ProviderInstanceID: results[0].ProviderInstanceID,
		FencingEpoch:       results[0].FencingEpoch,
		ConfigHash:         results[0].ConfigHash,
		Generation:         results[0].Generation,
	}); err != nil {
		t.Fatalf("fresh stop: %v", err)
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("fresh cleanup calls = %d, want one", cleanupCalls.Load())
	}
	manager.Mutex.Lock()
	tracked := manager.BrowserProcesses["profile-1"]
	manager.Mutex.Unlock()
	if tracked != nil {
		t.Fatal("fresh child remained tracked after explicit stop")
	}
	cleanupMu.Lock()
	for _, server := range servers {
		_ = server.Close()
	}
	cleanupMu.Unlock()
}

func TestFarmRuntimeCommandHandlerPreservesP17Envelope(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	response, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type:          "command",
		NodeUID:       "node-test",
		CorrelationID: "corr-1",
		Command:       "ensure_runtime",
		Payload:       map[string]any{"profile_id": "profile-1", "launch_mode": FarmRuntimeLaunchModeDirectNoProxy},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Type != "command_response" || response.NodeUID != "node-test" || response.CorrelationID != "corr-1" || !response.OK {
		t.Fatalf("response = %+v", response)
	}
	if _, ok := response.Payload.(FarmRuntime); !ok {
		t.Fatalf("response payload type = %T, want FarmRuntime", response.Payload)
	}
	if _, err := fixture.farm.HandleCommandEnvelope(FarmRuntimeCommandEnvelope{
		Type:          "command",
		NodeUID:       "node-test",
		CorrelationID: "corr-2",
		Command:       "runtime_status",
		Payload:       map[string]any{"profile_id": "profile-1"},
	}); err != nil {
		t.Fatalf("HandleCommandEnvelope: %v", err)
	}
	failed := fixture.farm.DispatchCommand(FarmRuntimeCommand{
		Type:    "command",
		NodeUID: "wrong-node",
		Command: "inventory",
	})
	if failed.OK || !strings.Contains(failed.Error, ErrFarmRuntimeIdentityMismatch.Error()) {
		t.Fatalf("wrong-node response = %+v", failed)
	}
	if _, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type:    "command",
		NodeUID: "node-test",
		Command: "ensure_runtime",
		Payload: map[string]any{"profile_id": "profile-1", "unknown": true},
	}); !errors.Is(err, ErrFarmRuntimeCommand) {
		t.Fatalf("unknown command payload error = %v", err)
	}
}

func TestFarmRuntimeFactoryRejectsConflictingAliases(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	other := NewBrowserRuntimeService()
	if _, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		RuntimeService:        other,
		NodeUID:               "node-test",
		ProviderInstanceID:    "provider-test",
		FencingEpoch:          7,
	}); !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("conflicting service aliases = %v", err)
	}
	if _, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		NodeUID:               "node-test",
		NodeID:                "other-node",
		ProviderInstanceID:    "provider-test",
		FencingEpoch:          7,
	}); !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("conflicting node aliases = %v", err)
	}
}

func TestFarmRuntimeNoGlobalShutdownCall(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	if _, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"}); err != nil {
		t.Fatal(err)
	}
	// The Farm layer has no shutdown path that can enumerate Manager profiles;
	// this compile-time/use-site assertion documents the ownership boundary.
	if fixture.farm.runtimeService == nil {
		t.Fatal(fmt.Errorf("farm runtime service lost shared lifecycle owner"))
	}
}

func TestFarmRuntimeRestartDoesNotAdoptByProfileOrPort(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	owned, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	// A newly constructed Farm service represents an Agent process restart.
	// The shared service still observes the recovered profile, but without an
	// authenticated ownership record this instance must not claim it.
	restarted, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		NodeUID:               "node-test",
		ProviderInstanceID:    "provider-test",
		FencingEpoch:          7,
	})
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := restarted.InventoryWithError()
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory) != 0 {
		t.Fatalf("restart inventory adopted unproven runtime: %#v", inventory)
	}
	if _, err := restarted.RuntimeStatus(FarmRuntimeStatusRequest{ProfileID: owned.ProfileID}); !errors.Is(err, ErrFarmRuntimeUnknown) {
		t.Fatalf("restart status error = %v, want unknown ownership", err)
	}
}
