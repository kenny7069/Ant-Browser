package backend

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func p113ProxyBinding() *FarmRuntimeProxyBinding {
	return &FarmRuntimeProxyBinding{
		Enabled:            true,
		ConnectorType:      "xray",
		CredentialRevision: "cred-rev-1",
		ConfigRevision:     "config-rev-1",
	}
}

func p113EnsureCommand(profile string) FarmRuntimeCommand {
	return FarmRuntimeCommand{
		Type: "command", NodeUID: "node-test", CorrelationID: "p113-" + profile,
		Command: "ensure_runtime",
		Payload: FarmRuntimeEnsureRequest{
			ProfileID: profile, LaunchMode: FarmRuntimeLaunchModeProfileProxy,
			Proxy: p113ProxyBinding(), ConfigHash: "p113-config-1",
		},
	}
}

func p113EnableLocalBinding(farm *FarmRuntimeService) {
	farm.proxyBindingVerifier = func(profileID string, binding FarmRuntimeProxyBinding) error {
		if profileID != "profile-1" || !binding.Enabled || binding.ConnectorType != "xray" {
			return errors.New("unexpected local proxy binding")
		}
		return nil
	}
}

func TestFarmRuntimeP113ProfileProxyCommandUsesClosedSecretFreeBinding(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	p113EnableLocalBinding(fixture.farm)
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	response, err := adapter.HandleCommand(p113EnsureCommand("profile-1"))
	if err != nil || !response.OK {
		t.Fatalf("profile proxy ensure = %+v, %v", response, err)
	}
	runtime, ok := response.Payload.(FarmRuntime)
	if !ok || runtime.LaunchMode != FarmRuntimeLaunchModeProfileProxy {
		t.Fatalf("profile proxy runtime = %#v", response.Payload)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"password", "proxy_url", "proxy-server", "credential_token"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("proxy command response leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestFarmRuntimeP113RejectsRawProxyFieldsBeforeLifecycle(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	p113EnableLocalBinding(fixture.farm)
	raw := []byte(`{"type":"command","node_uid":"node-test","correlation_id":"p113-raw","command":"ensure_runtime","payload":{"profile_id":"profile-1","launch_mode":"profile_proxy","config_hash":"p113-config-1","proxy":{"enabled":true,"connector_type":"xray","credential_revision":"cred-rev-1","config_revision":"config-rev-1","proxy_url":"http://user:password@127.0.0.1:18080"}}}`)
	response, err := fixture.farm.HandleCommandEnvelope(raw)
	if err == nil || response.OK || !errors.Is(err, ErrFarmRuntimeCommand) {
		t.Fatalf("raw proxy URL accepted: response=%+v err=%v", response, err)
	}
	if fixture.detectCalls.Load() != 0 || fixture.startCalls.Load() != 0 {
		t.Fatalf("raw proxy URL touched lifecycle: detect=%d start=%d", fixture.detectCalls.Load(), fixture.startCalls.Load())
	}
}

func TestFarmRuntimeP113RevisionMutationFailsClosedForOwnedRuntime(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	p113EnableLocalBinding(fixture.farm)
	first, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID: "profile-1", ConfigHash: "p113-config-1",
		LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: p113ProxyBinding(),
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := p113ProxyBinding()
	changed.CredentialRevision = "cred-rev-2"
	_, err = fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID: "profile-1", RuntimeUID: first.RuntimeUID, Generation: first.Generation,
		ConfigHash: "p113-config-1", LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: changed,
	})
	if !errors.Is(err, ErrFarmRuntimeConfigMismatch) {
		t.Fatalf("credential revision mutation = %v, want config mismatch", err)
	}
}

func TestFarmRuntimeP113RequiresLocalProxyBindingVerifier(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	_, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID: "profile-1", ConfigHash: "p113-config-1",
		LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: p113ProxyBinding(),
	})
	if !errors.Is(err, ErrFarmRuntimeLocalProxyBinding) {
		t.Fatalf("missing verifier = %v, want local proxy binding refusal", err)
	}
	if fixture.detectCalls.Load() != 0 || fixture.startCalls.Load() != 0 {
		t.Fatalf("missing verifier touched lifecycle: detect=%d start=%d", fixture.detectCalls.Load(), fixture.startCalls.Load())
	}
}

func TestFarmRuntimeP113ProductionFactoryUsesLocalProfileBindingBeforeLifecycle(t *testing.T) {
	started := 0
	cfg := DefaultConfig()
	cfg.Browser.DefaultConnectorType = "xray"
	profile := BrowserProfile{ProfileId: "profile-local", CoreId: "chrome", ProxyConfig: "socks5://local-user:local-password@127.0.0.1:19081", RestoreLastSession: "never"}
	farm, err := NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		NodeUID: "node-test", ProviderInstanceID: "agent-test", FencingEpoch: 1,
		BrowserRuntimeFactory: BrowserRuntimeServiceFactoryConfig{
			AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{profile},
			Host: BrowserRuntimeHost{
				StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
					started++
					return nil, errors.New("must not start")
				},
				StopProcess: func(*exec.Cmd) error { return nil },
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The public factory must create the existing production connector manager;
	// a direct-only host would leave this nil and the real bridge cannot start.
	if farm.runtimeService.xrayMgr == nil {
		t.Fatal("production Farm factory did not wire XrayManager")
	}
	local, err := farm.runtimeService.LocalProfileProxyBinding(profile.ProfileId)
	if err != nil {
		t.Fatal(err)
	}
	local.CredentialRevision = "different-local-revision"
	_, err = farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: profile.ProfileId, ConfigHash: "server-hash", LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: &local})
	if !errors.Is(err, ErrFarmRuntimeLocalProxyBinding) || started != 0 {
		t.Fatalf("production local binding mismatch = %v, started=%d", err, started)
	}
}
