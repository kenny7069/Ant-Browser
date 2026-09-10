package backend

import (
	"ant-chrome/backend/internal/browser"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestFarmRuntimeP112RealChrome is opt-in evidence for the complete Agent
// path. It uses the existing shared BrowserRuntimeService and only asserts
// CDP readiness/status; no CDP tunnel or production service is involved.
func TestFarmRuntimeP112RealChrome(t *testing.T) {
	if os.Getenv("P112_REAL_CHROME") != "1" {
		t.Skip("explicit P112_REAL_CHROME=1 opt-in required")
	}
	cfg := DefaultConfig()
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.StartReadyTimeoutMs = 15000
	cfg.Browser.StartStableWindowMs = 100
	cfg.Browser.DefaultStartURLs = []string{}
	coreRoot := os.Getenv("P112_REAL_CHROME_CORE")
	if coreRoot == "" {
		coreRoot = "/Applications"
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
	profileID := "p112-isolated"
	profile := BrowserProfile{
		ProfileId:   profileID,
		ProfileName: "P1.12 isolated",
		CoreId:      "chrome",
		UserDataDir: filepath.Join(t.TempDir(), "isolated-profile"),
		// This deliberately contradictory profile value proves that the
		// Farm direct mode, rather than an inherited profile proxy, is used.
		ProxyConfig:        "http://user:secret@example.invalid:8080",
		RestoreLastSession: "never",
		LaunchArgs: []string{
			"--headless=new",
			"--no-first-run",
			"--no-default-browser-check",
			"--disable-background-networking",
		},
	}
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
			StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
				return NewBrowserRuntimeLocalProcess(plan.Spec)
			},
			StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
			CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP,
			CreateTarget: createBrowserStartTarget,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	policy := FarmAttestationPolicy{
		AllowedDomains: []string{"example.com"},
		Locale:         "zh-TW",
		Timezone:       "Asia/Hong_Kong",
		WebRTCMode:     "disable_non_proxied_udp",
	}
	applied := FarmAttestationRuntime{
		AllowedDomains: append([]string(nil), policy.AllowedDomains...),
		Locale:         policy.Locale, Timezone: policy.Timezone, WebRTCMode: policy.WebRTCMode,
		Proxy: FarmAttestationProxy{},
	}
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: service,
		NodeUID:               "node-p112",
		ProviderInstanceID:    "provider-p112",
		FencingEpoch:          1,
		AttestationStateProvider: func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
			return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: applied}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		NodeUID: "node-p112", ProfileID: profileID, ConfigHash: "p112-config",
		LaunchMode: FarmRuntimeLaunchModeDirectNoProxy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if runtime.State != FarmRuntimeStateIdle || !runtime.DebugReady || runtime.DebugPort <= 0 || runtime.LaunchMode != FarmRuntimeLaunchModeDirectNoProxy {
		t.Fatalf("real Farm runtime not direct/ready: %+v", runtime)
	}
	request := FarmAttestationRequest{
		Version:         FarmAttestationVersion,
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
		PolicyHash:      "p112-policy", ConfigHash: runtime.ConfigHash,
		Policy: policy, RuntimeConfig: applied,
	}
	if _, err := farm.AttestRuntime(request, FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: applied}); err != nil {
		t.Fatal(err)
	}
	status, err := farm.RuntimeStatus(FarmRuntimeStatusRequest{
		NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID, RuntimeUID: runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID, FencingEpoch: runtime.FencingEpoch,
		ConfigHash: runtime.ConfigHash, Generation: runtime.Generation,
	})
	if err != nil || status.State != FarmRuntimeStateIdle || !status.DebugReady {
		t.Fatalf("real Farm status = %+v, err=%v", status, err)
	}
	if _, err := farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID, RuntimeUID: runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID, FencingEpoch: runtime.FencingEpoch,
		ConfigHash: runtime.ConfigHash, Generation: runtime.Generation,
	}); err != nil {
		t.Fatal(err)
	}
}
