package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func p111AttestationFixture() (FarmAttestationRequest, FarmAttestationLaunchState) {
	policy := FarmAttestationPolicy{
		AllowedDomains: []string{"xn--fsqu00a.xn--55qx5d", "例子.公司"},
		Locale:         "zh-TW",
		Timezone:       "Asia/Hong_Kong",
		WebRTCMode:     "disable_non_proxied_udp",
	}
	runtime := FarmAttestationRuntime{
		AllowedDomains: append([]string(nil), policy.AllowedDomains...),
		Locale:         policy.Locale,
		Timezone:       policy.Timezone,
		WebRTCMode:     policy.WebRTCMode,
		Proxy: FarmAttestationProxy{
			Enabled:            true,
			ConnectorType:      "xray",
			CredentialRevision: "credential-rev-7",
			ConfigRevision:     "config-rev-7",
			CredentialToken:    "opaque-credential-token",
		},
	}
	request := FarmAttestationRequest{
		Version: FarmAttestationVersion,
		RuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:            "node-a",
			ProfileID:          "profile-7",
			RuntimeUID:         "runtime-a",
			ProviderInstanceID: "agent-a",
			FencingEpoch:       4,
			ConfigHash:         "server-config-hash-token",
			Generation:         9,
		},
		// These values are opaque.  This Agent must not derive either one.
		PolicyHash:    "server-policy-hash-token",
		ConfigHash:    "server-config-hash-token",
		Policy:        policy,
		RuntimeConfig: runtime,
	}
	return request, FarmAttestationLaunchState{
		Ready:          true,
		Policy:         policy,
		AppliedRuntime: runtime,
	}
}

func p111Response(request FarmAttestationRequest, state FarmAttestationLaunchState) FarmAttestationResponse {
	return FarmAttestationResponse{
		Version:         FarmAttestationVersion,
		RuntimeIdentity: request.RuntimeIdentity,
		PolicyHash:      request.PolicyHash,
		ConfigHash:      request.ConfigHash,
		AppliedPolicy:   state.Policy,
		AppliedRuntime:  state.AppliedRuntime,
		Status:          "applied",
	}
}

func TestFarmAttestationP111OrdinaryAndOpaqueTokens(t *testing.T) {
	request, state := p111AttestationFixture()
	agent := NewFarmAttestationAgent()
	response, err := agent.ApplyAttestation(request, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFarmAttestationResponse(request, response); err != nil {
		t.Fatal(err)
	}
	if response.PolicyHash != request.PolicyHash || response.ConfigHash != request.ConfigHash {
		t.Fatalf("opaque tokens changed: request=%+v response=%+v", request, response)
	}
	if response.AppliedRuntime.AllowedDomains[1] != "例子.公司" {
		t.Fatalf("Unicode/IDN spelling changed: %+v", response.AppliedRuntime.AllowedDomains)
	}
	wire, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "password") || strings.Contains(string(wire), "socks5://") || strings.Contains(string(wire), "CANARY") {
		t.Fatalf("secret-bearing field reached attestation wire: %s", wire)
	}
	if got, ok := agent.Snapshot(request.RuntimeIdentity.RuntimeUID); !ok || VerifyFarmAttestationResponse(request, got) != nil {
		t.Fatal("saved attestation snapshot was not verifiable")
	}
}

func TestFarmAttestationP111LaunchStateAndStructuredMismatchesFailClosed(t *testing.T) {
	request, state := p111AttestationFixture()
	agent := NewFarmAttestationAgent()
	state.Ready = false
	if _, err := agent.ApplyAttestation(request, state); !errors.Is(err, ErrFarmAttestationNotReady) {
		t.Fatalf("not-ready launch state error = %v", err)
	}
	state.Ready = true
	for _, mutate := range []func(*FarmAttestationResponse){
		func(response *FarmAttestationResponse) {
			response.AppliedPolicy.Locale = "en-US"
			response.AppliedRuntime.Locale = "en-US"
		},
		func(response *FarmAttestationResponse) {
			response.AppliedPolicy.Timezone = "UTC"
			response.AppliedRuntime.Timezone = "UTC"
		},
		func(response *FarmAttestationResponse) {
			response.AppliedPolicy.WebRTCMode = "default_public_interface_only"
			response.AppliedRuntime.WebRTCMode = "default_public_interface_only"
		},
		func(response *FarmAttestationResponse) { response.AppliedRuntime.Proxy.ConfigRevision = "config-rev-8" },
	} {
		response := p111Response(request, state)
		mutate(&response)
		if err := VerifyFarmAttestationResponse(request, response); !errors.Is(err, ErrFarmAttestationStructuredMismatch) {
			t.Fatalf("structured mismatch error = %v", err)
		}
	}
	response := p111Response(request, state)
	response.PolicyHash = "tampered"
	if err := VerifyFarmAttestationResponse(request, response); !errors.Is(err, ErrFarmAttestationTokenMismatch) {
		t.Fatalf("tampered policy token error = %v", err)
	}
}

func TestFarmAttestationP111StrictWireRejectsUnknownDuplicateAndCaseAlias(t *testing.T) {
	request, _ := p111AttestationFixture()
	wire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFarmAttestationRequest(wire); err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), wire[:len(wire)-1]...), []byte(`,"extra":true}`)...)
	if _, err := DecodeFarmAttestationRequest(unknown); err == nil {
		t.Fatal("unknown request field was accepted")
	}
	duplicate := append(append([]byte(nil), wire[:len(wire)-1]...), []byte(`,"config_hash":"other"}`)...)
	if _, err := DecodeFarmAttestationRequest(duplicate); err == nil {
		t.Fatal("duplicate request field was accepted")
	}
	alias := strings.Replace(string(wire), `"PolicyHash":`, `"PolicyHash":`, 1)
	// The replacement above is deliberately a no-op for the canonical shape;
	// use a real case alias to exercise encoding/json's case-insensitive match.
	alias = strings.Replace(string(wire), `"policy_hash":`, `"Policy_Hash":`, 1)
	if _, err := DecodeFarmAttestationRequest([]byte(alias)); err == nil {
		t.Fatal("case-alias request field was accepted")
	}
}

func TestFarmAttestationP111ResponseWireIsClosedAndCanarySafe(t *testing.T) {
	request, state := p111AttestationFixture()
	response := p111Response(request, state)
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeFarmAttestationResponse(raw); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(map[string]any){
		func(value map[string]any) { delete(value, "applied_policy") },
		func(value map[string]any) { value["error"] = "CANARY /password /proxy-url" },
		func(value map[string]any) { value["status"] = "raw local error: /password" },
	} {
		value := map[string]any{}
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		mutate(value)
		mutated, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeFarmAttestationResponse(mutated); err == nil {
			t.Fatalf("unsafe or incomplete response was accepted: %s", mutated)
		}
	}
	// A response value cannot smuggle an arbitrary status through MarshalJSON.
	response.Status = "raw local error: /password"
	if _, err := json.Marshal(response); err == nil {
		t.Fatal("raw response status was serialized")
	}
}

func TestFarmRuntimeServiceP111ProviderErrorsFailClosed(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "server-config"})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := p111AttestationFixture()
	request.RuntimeIdentity = FarmRuntimeIdentity{
		NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID, RuntimeUID: runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID, FencingEpoch: runtime.FencingEpoch,
		ConfigHash: runtime.ConfigHash, Generation: runtime.Generation,
	}
	request.ConfigHash = runtime.ConfigHash
	fixture.farm.attestationStateProvider = func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
		return FarmAttestationLaunchState{}, errors.New("local /password proxy=socks5://CANARY")
	}
	response, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type: "command", NodeUID: runtime.NodeUID, CorrelationID: "provider-error",
		Command: "attest_runtime", Payload: request,
	})
	if err != nil || response.OK || response.Error != ErrFarmAttestationNotReady.Error() {
		t.Fatalf("provider error was not fail-closed: response=%+v err=%v", response, err)
	}
	wire, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "CANARY") || strings.Contains(string(wire), "password") || strings.Contains(string(wire), "socks5://") {
		t.Fatalf("provider error leaked to wire: %s", wire)
	}
	if _, ok := fixture.farm.attestation.Snapshot(runtime.RuntimeUID); ok {
		t.Fatal("provider error wrote an attestation record")
	}
}

func TestFarmAttestationP111GoldenRequestFromServerDecodesStrictly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "farm_attestation_request_p1_11.json"))
	if err != nil {
		t.Fatal(err)
	}
	request, err := DecodeFarmAttestationRequest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if request.RuntimeIdentity.NodeUID != "node-a" || request.RuntimeIdentity.ProfileID != "7" {
		t.Fatalf("golden identity = %+v", request.RuntimeIdentity)
	}
	if request.RuntimeIdentity.ConfigHash != request.ConfigHash {
		t.Fatal("golden config token is not identity-bound")
	}
	if request.RuntimeConfig.AllowedDomains[1] != "例子.公司" {
		t.Fatalf("golden Unicode/IDN domain changed: %+v", request.RuntimeConfig.AllowedDomains)
	}
}

func TestFarmAttestationP111ControlledRestartUsesStrictOldIdentity(t *testing.T) {
	request, _ := p111AttestationFixture()
	request.RuntimeIdentity.ConfigHash = request.ConfigHash
	selector, err := ControlledRestartSelector(request.RuntimeIdentity, true)
	if err != nil {
		t.Fatal(err)
	}
	if selector.RuntimeUID != request.RuntimeIdentity.RuntimeUID || selector.Generation != request.RuntimeIdentity.Generation || selector.NodeUID != request.RuntimeIdentity.NodeUID {
		t.Fatalf("restart selector changed old identity: %+v", selector)
	}
	if _, err := ControlledRestartSelector(request.RuntimeIdentity, false); !errors.Is(err, ErrFarmAttestationUnownedRestart) {
		t.Fatalf("unowned restart error = %v", err)
	}
}

func TestFarmAttestationP111ConcurrentApplyIsDeterministic(t *testing.T) {
	agent := NewFarmAttestationAgent()
	request, state := p111AttestationFixture()
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for index := 0; index < 32; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			localRequest := request
			localRequest.RuntimeIdentity.RuntimeUID = fmt.Sprintf("runtime-%02d", index)
			response, err := agent.ApplyAttestation(localRequest, state)
			if err == nil {
				err = VerifyFarmAttestationResponse(localRequest, response)
			}
			if err != nil {
				errs <- err
			}
		}(index)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestFarmRuntimeServiceP111AttestationUsesOwnedReadyRuntime(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "server-config"})
	if err != nil {
		t.Fatal(err)
	}
	policy := FarmAttestationPolicy{
		AllowedDomains: []string{"例子.公司"},
		Locale:         "zh-TW",
		Timezone:       "Asia/Hong_Kong",
		WebRTCMode:     "disable_non_proxied_udp",
	}
	applied := FarmAttestationRuntime{
		AllowedDomains: append([]string(nil), policy.AllowedDomains...),
		Locale:         policy.Locale,
		Timezone:       policy.Timezone,
		WebRTCMode:     policy.WebRTCMode,
		Proxy: FarmAttestationProxy{
			Enabled:            false,
			ConnectorType:      "",
			CredentialRevision: "",
			ConfigRevision:     "",
			CredentialToken:    "",
		},
	}
	request := FarmAttestationRequest{
		Version: FarmAttestationVersion,
		RuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:            runtime.NodeUID,
			ProfileID:          runtime.ProfileID,
			RuntimeUID:         runtime.RuntimeUID,
			ProviderInstanceID: runtime.ProviderInstanceID,
			FencingEpoch:       runtime.FencingEpoch,
			ConfigHash:         runtime.ConfigHash,
			Generation:         runtime.Generation,
		},
		PolicyHash:    "server-policy",
		ConfigHash:    "server-config",
		Policy:        policy,
		RuntimeConfig: applied,
	}
	response, err := fixture.farm.ApplyAttestation(request, FarmAttestationLaunchState{
		Ready:          true,
		Policy:         policy,
		AppliedRuntime: applied,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyFarmAttestationResponse(request, response); err != nil {
		t.Fatal(err)
	}
	fixture.farm.attestationStateProvider = func(identity FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
		if identity != request.RuntimeIdentity {
			return FarmAttestationLaunchState{}, ErrFarmAttestationIdentityMismatch
		}
		return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: applied}, nil
	}
	command, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type:          "command",
		NodeUID:       runtime.NodeUID,
		CorrelationID: "attest",
		Command:       "attest_runtime",
		Payload:       request,
	})
	if err != nil || !command.OK {
		t.Fatalf("attest command = %+v, err=%v", command, err)
	}
	if _, err := fixture.farm.ApplyAttestation(request, FarmAttestationLaunchState{Ready: false, Policy: policy, AppliedRuntime: applied}); !errors.Is(err, ErrFarmAttestationNotReady) {
		t.Fatalf("not-ready service attestation error = %v", err)
	}
}

func TestFarmRuntimeServiceP111CommandNeverAcceptsRemoteLaunchState(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "server-config"})
	if err != nil {
		t.Fatal(err)
	}
	request, state := p111AttestationFixture()
	request.RuntimeIdentity = FarmRuntimeIdentity{
		NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID, RuntimeUID: runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID, FencingEpoch: runtime.FencingEpoch,
		ConfigHash: runtime.ConfigHash, Generation: runtime.Generation,
	}
	request.ConfigHash = runtime.ConfigHash
	missingProviderResponse, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type: "command", NodeUID: runtime.NodeUID, CorrelationID: "no-provider",
		Command: "attest_runtime", Payload: request,
	})
	if err != nil || missingProviderResponse.OK || missingProviderResponse.Error != ErrFarmAttestationNotReady.Error() {
		t.Fatalf("missing local state provider response=%+v err=%v", missingProviderResponse, err)
	}
	fixture.farm.attestationStateProvider = func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
		return state, nil
	}
	state.Policy.Locale = "en-US"
	state.AppliedRuntime.Locale = "en-US"
	response, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type: "command", NodeUID: runtime.NodeUID, CorrelationID: "state-mismatch",
		Command: "attest_runtime", Payload: request,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.OK || response.Error == "" {
		t.Fatalf("mismatched local state was accepted: %+v", response)
	}
	// A remote launch_state is an unknown request field and must be rejected
	// before the local callback runs.
	raw, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"launch_state":{}}`)...)
	if _, err := fixture.farm.HandleCommand(FarmRuntimeCommand{
		Type: "command", NodeUID: runtime.NodeUID, CorrelationID: "remote-state",
		Command: "attest_runtime", Payload: json.RawMessage(raw),
	}); err == nil {
		t.Fatal("remote launch_state was accepted")
	}
}

func TestFarmAttestationP111ConfigTokenBindingRejectsBeforeRecordWrite(t *testing.T) {
	request, state := p111AttestationFixture()
	agent := NewFarmAttestationAgent()
	missingIdentityToken := request
	missingIdentityToken.RuntimeIdentity.ConfigHash = ""
	if _, err := agent.ApplyAttestation(missingIdentityToken, state); err == nil {
		t.Fatal("empty runtime identity config token was accepted")
	}
	mismatched := request
	mismatched.ConfigHash = "server-config-other"
	if _, err := agent.ApplyAttestation(mismatched, state); err == nil {
		t.Fatal("request config token mismatch was accepted")
	}
	if _, ok := agent.Snapshot(request.RuntimeIdentity.RuntimeUID); ok {
		t.Fatal("rejected config token wrote an attestation record")
	}
}
