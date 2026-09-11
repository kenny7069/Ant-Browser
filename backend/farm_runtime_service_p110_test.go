package backend

import (
	"ant-chrome/backend/internal/browser"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestFarmRuntimeP110RestartEnsureRejectsUnprovenSharedRuntime(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	owned, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: fixture.runtime,
		NodeUID:               "node-test",
		ProviderInstanceID:    "provider-test",
		FencingEpoch:          7,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: owned.ProfileID}); !errors.Is(err, ErrFarmRuntimeStale) {
		t.Fatalf("restart ensure error = %v, want stale", err)
	}
	if fixture.startCalls.Load() != 0 {
		t.Fatalf("restart ensure launched an unproven runtime: %d calls", fixture.startCalls.Load())
	}
}

func TestFarmRuntimeP110StartIfGenerationReservesProfileIncarnation(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	snapshot, err := fixture.runtime.RuntimeSnapshot("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	fixture.runtime.startReservationHook = func() {
		fixture.manager.Mutex.Lock()
		original := fixture.manager.Profiles["profile-1"]
		delete(fixture.manager.Profiles, "profile-1")
		fixture.manager.Profiles["profile-1"] = copyBrowserProfileSnapshot(original)
		fixture.manager.Mutex.Unlock()
	}
	if _, err := fixture.runtime.StartIfGeneration("profile-1", snapshot.Generation, snapshot.ProfileIncarnation); !errors.Is(err, ErrBrowserRuntimeProfileMismatch) {
		t.Fatalf("reserved StartIfGeneration error = %v, want profile mismatch", err)
	}
	if fixture.startCalls.Load() != 0 {
		t.Fatalf("reserved StartIfGeneration launched replacement: %d calls", fixture.startCalls.Load())
	}
	fixture.manager.Mutex.Lock()
	replacement := copyBrowserProfileSnapshot(fixture.manager.Profiles["profile-1"])
	fixture.manager.Mutex.Unlock()
	if replacement.Running || replacement.Pid != 0 || replacement.DebugPort != 0 {
		t.Fatalf("reserved StartIfGeneration touched replacement: %+v", replacement)
	}
}

func TestFarmRuntimeP110ProfileABARejectsStatusAndStop(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	owned, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.manager.Mutex.Lock()
	fixture.manager.Profiles[owned.ProfileID] = &browser.Profile{
		ProfileId:   owned.ProfileID,
		ProfileName: "replacement",
		Running:     true,
		DebugReady:  true,
		Pid:         7002,
		DebugPort:   9702,
	}
	fixture.manager.Mutex.Unlock()
	if _, err := fixture.farm.RuntimeStatus(FarmRuntimeStatusRequest{ProfileID: owned.ProfileID}); !errors.Is(err, ErrFarmRuntimeStale) {
		t.Fatalf("ABA status error = %v, want stale", err)
	}
	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            owned.NodeUID,
		ProfileID:          owned.ProfileID,
		RuntimeUID:         owned.RuntimeUID,
		ProviderInstanceID: owned.ProviderInstanceID,
		FencingEpoch:       owned.FencingEpoch,
		Generation:         owned.Generation,
	}); !errors.Is(err, ErrFarmRuntimeStale) {
		t.Fatalf("ABA stop error = %v, want stale", err)
	}
	if fixture.stopCalls.Load() != 0 {
		t.Fatal("ABA stop touched the replacement profile")
	}
}

func TestFarmRuntimeP110WireTelemetryMasksProfileSecrets(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	fixture.manager.Mutex.Lock()
	profile := fixture.manager.Profiles["profile-1"]
	profile.UserDataDir = "CANARY_USER_DATA_DIR"
	profile.ProxyConfig = "CANARY_PROXY_CONFIG"
	profile.LaunchCode = "CANARY_LAUNCH_CODE"
	profile.LaunchArgs = []string{"CANARY_LAUNCH_ARG"}
	profile.LastLaunchArgs = []string{"CANARY_LAST_LAUNCH_ARG"}
	profile.FingerprintArgs = []string{"CANARY_FINGERPRINT_ARG"}
	profile.LastError = "CANARY_RAW_ERROR"
	profile.RuntimeWarning = "CANARY_RAW_WARNING"
	fixture.manager.Mutex.Unlock()
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{
		"CANARY_USER_DATA_DIR",
		"CANARY_PROXY_CONFIG",
		"CANARY_LAUNCH_CODE",
		"CANARY_LAUNCH_ARG",
		"CANARY_LAST_LAUNCH_ARG",
		"CANARY_FINGERPRINT_ARG",
		"CANARY_RAW_ERROR",
		"CANARY_RAW_WARNING",
	} {
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("FarmRuntime JSON leaked %q: %s", canary, encoded)
		}
	}
	response, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type:          "command",
		NodeUID:       "node-test",
		CorrelationID: "telemetry",
		Command:       "runtime_status",
		Payload:       map[string]any{"profile_id": "profile-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err = json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range []string{"CANARY_USER_DATA_DIR", "CANARY_PROXY_CONFIG", "CANARY_LAUNCH_CODE", "CANARY_RAW_ERROR"} {
		if strings.Contains(string(encoded), canary) {
			t.Fatalf("command response leaked %q: %s", canary, encoded)
		}
	}
	unsafeResponse := FarmRuntimeCommandResponse{
		Type:    "command_response",
		NodeUID: "node-test",
		OK:      true,
		Payload: browser.Profile{UserDataDir: "CANARY_DIRECT_RESPONSE_PATH"},
	}
	unsafeEncoded, unsafeErr := json.Marshal(unsafeResponse)
	if unsafeErr == nil || strings.Contains(string(unsafeEncoded), "CANARY_DIRECT_RESPONSE_PATH") {
		t.Fatalf("unsafe direct response payload was serialized: err=%v json=%s", unsafeErr, unsafeEncoded)
	}
}

func TestFarmRuntimeP110StrictCommandEnvelope(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	valid := `{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{}}`
	response, err := fixture.farm.HandleCommandEnvelope(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("valid envelope: %v", err)
	}
	if response.Type != "command_response" || !response.OK {
		t.Fatalf("valid response = %+v", response)
	}
	tests := []string{
		`{"type":"command","node_uid":"","correlation_id":"corr","command":"inventory","payload":{}}`,
		`{"type":"command","node_uid":"wrong","correlation_id":"corr","command":"inventory","payload":{}}`,
		`{"type":"not-command","TYPE":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{}}`,
		`{"type":"command","node_uid":"wrong","NODE_UID":"node-test","correlation_id":"corr","command":"inventory","payload":{}}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{},"extra":1}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{"x":1,"x":2}}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"stop_runtime","payload":{"profile_id":"profile-1","runtime_uid":"stale","RUNTIME_UID":"replacement","provider_instance_id":"provider-test","fencing_epoch":7,"generation":1}}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{}} {}`,
	}
	for _, raw := range tests {
		if _, err := fixture.farm.HandleCommandEnvelope(strings.NewReader(raw)); err == nil {
			t.Fatalf("malformed envelope was accepted: %s", raw)
		}
	}
	if _, err := fixture.farm.HandleCommandEnvelope(strings.NewReader(strings.Repeat("x", maxFarmRuntimeEnvelopeBytes+1))); err == nil {
		t.Fatal("oversize envelope was accepted")
	}
	if _, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type:          "command",
		NodeUID:       "node-test",
		CorrelationID: "corr",
		Command:       "ensure_runtime",
		Payload:       json.RawMessage(`{"profile_id":"profile-1","profile_id":"profile-1"}`),
	}); !errors.Is(err, ErrFarmRuntimeCommand) {
		t.Fatalf("duplicate payload error = %v", err)
	}
	for _, alias := range []string{
		`{"TYPE":"command","node_uid":"node-test","correlation_id":"corr","command":"inventory","payload":{}}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"corr","command":"ensure_runtime","payload":{"profile_id":"profile-1","runtime_uid":"stale","RUNTIME_UID":"replacement"}}`,
	} {
		if _, err := fixture.farm.HandleCommandEnvelope(strings.NewReader(alias)); err == nil {
			t.Fatalf("case-alias envelope was accepted: %s", alias)
		}
	}
}

func TestFarmRuntimeP110StopRequiresFullNodeIdentity(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmRuntimeStopRequest{
		ProfileID:          runtime.ProfileID,
		RuntimeUID:         runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch:       runtime.FencingEpoch,
		Generation:         runtime.Generation,
	}
	if _, err := fixture.farm.StopRuntime(request); !errors.Is(err, ErrFarmRuntimeIdentityRequired) {
		t.Fatalf("missing node identity error = %v", err)
	}
	if fixture.stopCalls.Load() != 0 {
		t.Fatal("missing node identity attempted a stop")
	}
}
