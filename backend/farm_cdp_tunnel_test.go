package backend

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestFarmCDPTunnelRejectsUnknownRuntimeAndIdentityContradictions(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:   "session-1",
		TunnelToken: "token-1",
		RuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:            runtime.NodeUID,
			ProfileID:          runtime.ProfileID,
			RuntimeUID:         runtime.RuntimeUID,
			ProviderInstanceID: runtime.ProviderInstanceID,
			FencingEpoch:       runtime.FencingEpoch,
			ConfigHash:         runtime.ConfigHash,
			Generation:         runtime.Generation,
		},
	}
	request.RuntimeIdentity.RuntimeUID = "replacement-runtime"
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPIdentity) {
		t.Fatalf("contradictory runtime identity error = %v", err)
	}
	request.RuntimeIdentity = FarmRuntimeIdentity{}
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPIdentity) {
		t.Fatalf("missing runtime identity error = %v", err)
	}
	request.RuntimeIdentity = runtime.FarmRuntimeIdentity
	request.SessionID = "bad session"
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPRequestInvalid) {
		t.Fatalf("invalid token/session error = %v", err)
	}
}

func TestFarmCDPTunnelOneTimeSessionReplayBeforeLocalDial(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-replay",
		TunnelToken:     "token-replay",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	fixture.farm.cdpSessions[request.SessionID] = &farmCDPSession{}
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPReplay) {
		t.Fatalf("replay error = %v", err)
	}
	delete(fixture.farm.cdpSessions, request.SessionID)
}

func TestFarmCDPTunnelCleanupRemovesSessionForFutureAttempt(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-cleanup",
		TunnelToken:     "token-cleanup",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	fixture.farm.cdpSessionsMu.Lock()
	fixture.farm.cdpSessions[request.SessionID] = &farmCDPSession{}
	fixture.farm.cdpSessionsMu.Unlock()
	fixture.farm.CloseCDPTunnel(request.SessionID, nil)
	fixture.farm.cdpSessionsMu.Lock()
	_, stillPresent := fixture.farm.cdpSessions[request.SessionID]
	fixture.farm.cdpSessionsMu.Unlock()
	if stillPresent {
		t.Fatal("closed CDP session remained replay-protected")
	}
	if _, err := fixture.farm.OpenCDPTunnel(request); errors.Is(err, ErrFarmCDPReplay) {
		t.Fatalf("future attempt was incorrectly rejected as replay after cleanup: %v", err)
	}
}

func TestFarmCDPTunnelStrictStopClosesRuntimeSessions(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	fixture.farm.cdpSessions["session-stop"] = &farmCDPSession{identity: runtime.FarmRuntimeIdentity}
	fixture.farm.cdpSessionsMu.Unlock()
	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            runtime.NodeUID,
		ProfileID:          runtime.ProfileID,
		RuntimeUID:         runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch:       runtime.FencingEpoch,
		ConfigHash:         runtime.ConfigHash,
		Generation:         runtime.Generation,
	}); err != nil {
		t.Fatal(err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	_, stillPresent := fixture.farm.cdpSessions["session-stop"]
	fixture.farm.cdpSessionsMu.Unlock()
	if stillPresent {
		t.Fatal("strict runtime stop left a CDP session behind")
	}
}

func TestFarmCDPCommandPayloadIsStrictAndReadyWireIsAllowlisted(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"session_id":       "session-1",
		"tunnel_token":     "token-1",
		"runtime_identity": FarmRuntimeIdentity{},
		"unexpected":       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := farmCDPDecodeRequest(raw); !errors.Is(err, ErrFarmCDPRequestInvalid) {
		t.Fatalf("unknown command field error = %v", err)
	}
	encoded, err := json.Marshal(FarmRuntimeCommandResponse{
		Type:    "command_response",
		NodeUID: "node-test",
		OK:      true,
		Payload: FarmCDPTunnelReady{SessionID: "session-1", Ready: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" {
		t.Fatal("empty ready response")
	}
}
