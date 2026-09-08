package backend

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func newProvenRestartFixture(t *testing.T, withStore bool) (*FarmRuntimeService, FarmRuntimeHandoffRequest, FarmRuntimeOwnershipStore) {
	t.Helper()
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	pid := os.Getpid()
	port := 19223
	fixture.manager.Mutex.Lock()
	profile := fixture.manager.Profiles["profile-1"]
	profile.Running, profile.DebugReady, profile.Pid, profile.DebugPort = true, true, pid, port
	profile.CreatedAt = "2026-09-08T00:00:00Z"
	fixture.manager.Mutex.Unlock()
	startIdentity, err := defaultProcessStartIdentity(pid)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store, err := NewFileFarmRuntimeOwnershipStore(filepath.Join(t.TempDir(), "ownership.json"), key)
	if err != nil {
		t.Fatal(err)
	}
	identity := FarmRuntimeIdentity{NodeUID: "node-test", ProfileID: "profile-1", RuntimeUID: "runtime-proven", ProviderInstanceID: "provider-test", FencingEpoch: 7, ConfigHash: "config-a", Generation: 9, ControllerID: "controller-old", ControllerGeneration: 4}
	if withStore {
		if err := store.Save([]FarmRuntimeOwnershipProvenance{{Runtime: identity, PID: pid, DebugPort: port, ProcessStartIdentity: startIdentity, LaunchMode: FarmRuntimeLaunchModeDirectNoProxy, ProfileCreatedAt: profile.CreatedAt}}); err != nil {
			t.Fatal(err)
		}
	}
	restartedRuntime := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: fixture.manager, Config: fixture.runtime.config, Host: fixture.runtime.host})
	if !withStore {
		if _, err := restartedRuntime.RestoreProvenRuntimeIdentity("profile-1", identity.Generation, pid, port, profile.CreatedAt); err != nil {
			t.Fatal(err)
		}
	}
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{BrowserRuntimeService: restartedRuntime, NodeUID: "node-test", ProviderInstanceID: "provider-test", FencingEpoch: 7, ControllerID: "controller-new", ControllerGeneration: 5, OwnershipStore: func() FarmRuntimeOwnershipStore {
		if withStore {
			return store
		}
		return nil
	}()})
	if err != nil {
		t.Fatal(err)
	}
	record, ok := farm.currentRecord("profile-1")
	incarnation := ""
	if ok {
		incarnation = record.profileIncarnation
	} else {
		snapshot, snapshotErr := restartedRuntime.RuntimeSnapshot("profile-1")
		if snapshotErr != nil {
			t.Fatal(snapshotErr)
		}
		incarnation = snapshot.ProfileIncarnation
	}
	request := FarmRuntimeHandoffRequest{Provider: "farm", NodeUID: "node-test", ProfileID: "profile-1", RuntimeUID: identity.RuntimeUID, ProviderInstanceID: "provider-test", FencingEpoch: 7, ConfigHash: identity.ConfigHash, Generation: identity.Generation, PID: pid, ProcessStartIdentity: startIdentity, ProfileIncarnation: incarnation, ControllerID: "controller-new", ControllerGeneration: 5, State: "idle", DebugReady: true, LaunchMode: FarmRuntimeLaunchModeDirectNoProxy}
	return farm, request, store
}

func TestHandoffRestoresOnlyAuthenticatedPersistentOwnership(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, true)
	inventory, err := farm.InventoryWithError()
	if err != nil || len(inventory) != 1 || inventory[0].RuntimeUID != request.RuntimeUID || inventory[0].PID != request.PID {
		t.Fatalf("restored inventory = %+v, err=%v", inventory, err)
	}
	if _, err := farm.PrepareAdoptRuntime(request); err != nil {
		t.Fatalf("prepare proven runtime: %v", err)
	}
	if _, err := farm.AdoptRuntime(request); err != nil {
		t.Fatalf("adopt proven runtime: %v", err)
	}
}

func TestHandoffCannotMintOwnershipFromRunningSnapshot(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, false)
	if _, err := farm.PrepareAdoptRuntime(request); !errors.Is(err, ErrFarmRuntimeUnknown) {
		t.Fatalf("prepare unproven error=%v, want unknown", err)
	}
	if _, err := farm.AdoptRuntime(request); !errors.Is(err, ErrFarmRuntimeUnknown) {
		t.Fatalf("adopt unproven error=%v, want unknown", err)
	}
	if _, ok := farm.currentRecord(request.ProfileID); ok {
		t.Fatal("unproven request minted an ownership record")
	}
}

func TestOwnershipStoreRejectsMutation(t *testing.T) {
	_, _, store := newProvenRestartFixture(t, true)
	fileStore := store.(*fileFarmRuntimeOwnershipStore)
	raw, err := os.ReadFile(fileStore.path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(fileStore.path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrFarmRuntimeOwnershipProvenance) {
		t.Fatalf("mutated store error=%v", err)
	}
}

func TestOwnershipStoreWriteFailurePreservesLastAuthority(t *testing.T) {
	_, _, store := newProvenRestartFixture(t, true)
	fileStore := store.(*fileFarmRuntimeOwnershipStore)
	before, err := os.ReadFile(fileStore.path)
	if err != nil {
		t.Fatal(err)
	}
	fileStore.write = func(*os.File, []byte) (int, error) { return 0, errors.New("injected write failure") }
	if err := store.Save(nil); err == nil {
		t.Fatal("injected write failure was ignored")
	}
	after, err := os.ReadFile(fileStore.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed save replaced the last authenticated authority")
	}
}

func TestOwnershipStoreRejectsDuplicateAndOversizeAuthority(t *testing.T) {
	_, request, store := newProvenRestartFixture(t, true)
	fileStore := store.(*fileFarmRuntimeOwnershipStore)
	entry := FarmRuntimeOwnershipProvenance{Runtime: FarmRuntimeIdentity{NodeUID: request.NodeUID, ProfileID: request.ProfileID, RuntimeUID: request.RuntimeUID, ProviderInstanceID: request.ProviderInstanceID, FencingEpoch: request.FencingEpoch, ConfigHash: request.ConfigHash, Generation: request.Generation, ControllerID: request.ControllerID, ControllerGeneration: request.ControllerGeneration}, PID: request.PID, DebugPort: 19223, ProcessStartIdentity: request.ProcessStartIdentity, LaunchMode: request.LaunchMode, ProfileCreatedAt: "2026-09-08T00:00:00Z"}
	if err := store.Save([]FarmRuntimeOwnershipProvenance{entry, entry}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrFarmRuntimeOwnershipProvenance) {
		t.Fatalf("duplicate authority error=%v", err)
	}
	if err := os.WriteFile(fileStore.path, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrFarmRuntimeOwnershipProvenance) {
		t.Fatalf("oversize authority error=%v", err)
	}
}

func TestHandoffPersistentOwnershipRejectsProfileDeleteRecreate(t *testing.T) {
	farm, _, store := newProvenRestartFixture(t, true)
	manager := farm.runtimeService.Manager()
	manager.Mutex.Lock()
	replacement := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	replacement.CreatedAt = "2026-09-08T00:00:01Z"
	manager.Profiles["profile-1"] = replacement
	manager.Mutex.Unlock()
	runtime := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: manager, Config: farm.runtimeService.config, Host: farm.runtimeService.host})
	restarted, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{BrowserRuntimeService: runtime, NodeUID: "node-test", ProviderInstanceID: "provider-test", FencingEpoch: 7, OwnershipStore: store})
	if err != nil {
		t.Fatal(err)
	}
	if _, owned := restarted.currentRecord("profile-1"); owned || runtime.Generation("profile-1") != 0 {
		t.Fatal("delete/recreate profile recovered ownership from the old same-ID provenance")
	}
}

func TestConnectionFenceRejectsOldSocketDispatch(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, _ := NewFarmRuntimeControlAdapter(fixture.farm)
	old, err := adapter.BeginAuthenticatedControlConnection("controller-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	adapter.EndControlConnection(old)
	current, err := adapter.BeginAuthenticatedControlConnection("controller-b", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer adapter.EndControlConnection(current)
	response := adapter.DispatchCommandForConnection(FarmRuntimeCommand{Type: "command", NodeUID: "node-test", CorrelationID: "old", Command: "ensure_runtime", Payload: map[string]any{"profile_id": "profile-1"}}, old)
	if response.OK || response.Error != ErrFarmRuntimeStale.Error() || fixture.startCalls.Load() != 0 {
		t.Fatalf("stale dispatch response=%+v starts=%d", response, fixture.startCalls.Load())
	}
}

func TestHandoffStopBarrierPreventsControllerRebindTOCTOU(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, true)
	validated := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	farm.handoffValidationHook = func() {
		once.Do(func() { close(validated); <-release })
	}
	stopDone := make(chan error, 1)
	go func() {
		_, err := farm.StopHandoffRuntime(request)
		stopDone <- err
	}()
	<-validated
	rebindDone := make(chan error, 1)
	go func() { rebindDone <- farm.RebindController("controller-next", 6) }()
	select {
	case err := <-rebindDone:
		t.Fatalf("controller rebind crossed validated stop boundary: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(release)
	if err := <-stopDone; err != nil {
		t.Fatalf("fenced stop: %v", err)
	}
	if err := <-rebindDone; err != nil {
		t.Fatalf("rebind after stop: %v", err)
	}
}

func TestControlledRestartAuthorizesTargetConfigOnlyAfterExactStop(t *testing.T) {
	farm, old, _ := newProvenRestartFixture(t, true)
	_, err := farm.ReconcileRuntime(FarmRuntimeReconcileRequest{
		Action:                    "restart",
		TargetConfigHash:          "config-b",
		TargetLaunchMode:          FarmRuntimeLaunchModeDirectNoProxy,
		FarmRuntimeHandoffRequest: old,
	})
	if errors.Is(err, ErrFarmRuntimeConfigMismatch) {
		t.Fatalf("controlled restart rejected its authoritative target config: %v", err)
	}
	if !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("controlled restart reached error = %v, want post-stop replacement boundary", err)
	}
	record, owned := farm.currentRecord(old.ProfileID)
	if !owned || record.runtime.State != FarmRuntimeStateStopped || record.runtime.ConfigHash != old.ConfigHash {
		t.Fatalf("failed replacement changed old authority: owned=%t record=%+v", owned, record.runtime)
	}
}

func TestOrdinaryEnsureCannotReplaceStoppedRuntimeConfig(t *testing.T) {
	farm, old, _ := newProvenRestartFixture(t, true)
	if _, err := farm.StopHandoffRuntime(old); err != nil {
		t.Fatalf("strict stop: %v", err)
	}
	_, err := farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		NodeUID: old.NodeUID, ProfileID: old.ProfileID,
		ProviderInstanceID: old.ProviderInstanceID, FencingEpoch: old.FencingEpoch,
		ConfigHash: "config-b", LaunchMode: FarmRuntimeLaunchModeDirectNoProxy,
	})
	if !errors.Is(err, ErrFarmRuntimeConfigMismatch) {
		t.Fatalf("ordinary ensure error = %v, want config mismatch", err)
	}
}

func TestControlledRestartBlocksControllerRebindThroughTargetLaunch(t *testing.T) {
	farm, old, _ := newProvenRestartFixture(t, true)
	beforeEnsure := make(chan struct{})
	releaseEnsure := make(chan struct{})
	farm.controlledRestartEnsureHook = func() {
		close(beforeEnsure)
		<-releaseEnsure
	}
	reconcileDone := make(chan error, 1)
	go func() {
		_, err := farm.ReconcileRuntime(FarmRuntimeReconcileRequest{
			Action:                    "restart",
			TargetConfigHash:          "config-b",
			TargetLaunchMode:          FarmRuntimeLaunchModeDirectNoProxy,
			FarmRuntimeHandoffRequest: old,
		})
		reconcileDone <- err
	}()
	<-beforeEnsure
	rebindDone := make(chan error, 1)
	go func() { rebindDone <- farm.RebindController("controller-next", 6) }()
	select {
	case err := <-rebindDone:
		t.Fatalf("controller rebind crossed controlled restart boundary: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseEnsure)
	if err := <-reconcileDone; !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("controlled restart result = %v", err)
	}
	if err := <-rebindDone; err != nil {
		t.Fatalf("rebind after controlled restart: %v", err)
	}
}
