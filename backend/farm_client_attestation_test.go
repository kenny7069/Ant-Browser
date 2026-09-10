package backend

import (
	"errors"
	"os/exec"
	"testing"

	"ant-chrome/backend/internal/browser"
)

func TestFarmClientAttestationProviderUsesCapturedDirectLaunchAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	manager := browser.NewManager(DefaultConfig(), root)
	manager.Profiles["profile-a"] = &browser.Profile{ProfileId: "profile-a", CreatedAt: "2026-01-01T00:00:00Z", Running: true, DebugReady: true, Pid: 1234, DebugPort: 9222}
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RestoreProvenRuntimeIdentity("profile-a", 7, 1234, 9222, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	capture := newFarmClientLaunchCapture()
	capture.CaptureStart("profile-a", BrowserRuntimeLaunchSpec{ProfileID: "profile-a", AssignedDebugPort: 9222, EffectiveProxy: "direct://", Args: []string{"--no-proxy-server", "--lang=zh-TW", "--timezone=Asia/Hong_Kong", "--disable-non-proxied-udp"}}, 1234)
	capture.MarkGeneration("profile-a", 7)
	provider := newFarmClientAttestationProvider(service, capture)
	state, err := provider(FarmRuntimeIdentity{ProfileID: "profile-a", Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !state.Ready || state.Policy.Locale != "zh-TW" || state.Policy.Timezone != "Asia/Hong_Kong" || state.Policy.WebRTCMode != "disable_non_proxied_udp" || len(state.Policy.AllowedDomains) != 0 {
		t.Fatalf("unexpected attestation state: %+v", state)
	}
	if state.AppliedRuntime.Proxy.Enabled {
		t.Fatal("direct launch projected proxy state")
	}
	if _, err := provider(FarmRuntimeIdentity{ProfileID: "profile-a", Generation: 8}); !errors.Is(err, ErrFarmAttestationIdentityMismatch) {
		t.Fatalf("old generation error = %v, want identity mismatch", err)
	}
	manager.Mutex.Lock()
	manager.Profiles["profile-a"].Running = false
	manager.Profiles["profile-a"].DebugReady = false
	manager.Mutex.Unlock()
	if _, err := provider(FarmRuntimeIdentity{ProfileID: "profile-a", Generation: 7}); !errors.Is(err, ErrFarmAttestationNotReady) {
		t.Fatalf("stopped profile error = %v, want not ready", err)
	}
}

func TestFarmClientAttestationCaptureDeepCopiesArgsAndClearsABA(t *testing.T) {
	capture := newFarmClientLaunchCapture()
	args := []string{"--lang=en-US"}
	capture.CaptureStart("profile-a", BrowserRuntimeLaunchSpec{ProfileID: "profile-a", Args: args}, 11)
	args[0] = "--lang=secret"
	capture.MarkGeneration("profile-a", 3)
	entry, ok := capture.Snapshot("profile-a")
	if !ok || entry.spec.Args[0] != "--lang=en-US" || entry.generation != 3 {
		t.Fatalf("capture was not deep copied: %+v %v", entry, ok)
	}
	capture.ClearGeneration("profile-a", 2)
	if _, ok := capture.Snapshot("profile-a"); !ok {
		t.Fatal("stale generation clear removed replacement evidence")
	}
	capture.ClearGeneration("profile-a", 3)
	if _, ok := capture.Snapshot("profile-a"); ok {
		t.Fatal("matching generation clear retained stale evidence")
	}
}

func TestFarmClientAttestationUsesFinalFingerprintArguments(t *testing.T) {
	root := t.TempDir()
	manager := browser.NewManager(DefaultConfig(), root)
	manager.Profiles["profile-a"] = &browser.Profile{ProfileId: "profile-a", CreatedAt: "2026-01-01T00:00:00Z", Running: true, DebugReady: true, Pid: 1234, DebugPort: 9222}
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RestoreProvenRuntimeIdentity("profile-a", 7, 1234, 9222, "2026-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	capture := newFarmClientLaunchCapture()
	capture.CaptureStart("profile-a", BrowserRuntimeLaunchSpec{
		ProfileID: "profile-a", AssignedDebugPort: 9222, EffectiveProxy: "direct://",
		Args: []string{"--no-proxy-server", "--lang=en-US", "--lang=zh-TW", "--timezone=UTC", "--timezone=Asia/Tokyo", "--webrtc-ip-handling-policy=default_public_interface_only", "--webrtc-ip-handling-policy=disable_non_proxied_udp"},
	}, 1234)
	capture.MarkGeneration("profile-a", 7)
	state, err := newFarmClientAttestationProvider(service, capture)(FarmRuntimeIdentity{ProfileID: "profile-a", Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	if state.Policy.Locale != "zh-TW" || state.Policy.Timezone != "Asia/Tokyo" || state.Policy.WebRTCMode != "disable_non_proxied_udp" {
		t.Fatalf("attestation did not use final fingerprint arguments: %+v", state.Policy)
	}
}

func TestBrowserRuntimeFactoryRetainsInitializedManagerAndFingerprintCallback(t *testing.T) {
	root := t.TempDir()
	manager := browser.NewManager(DefaultConfig(), root)
	callback := func(string, string, []string) []string { return []string{"--lang=zh-TW"} }
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager, FingerprintLaunchArgs: callback,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if service.Manager() != manager {
		t.Fatal("factory replaced initialized Manager")
	}
	if got := service.fingerprintLaunchArgs("profile-a", "", nil); len(got) != 1 || got[0] != "--lang=zh-TW" {
		t.Fatalf("fingerprint callback was not forwarded: %v", got)
	}
	if _, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager, Config: DefaultConfig(), Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	}); err == nil {
		t.Fatal("initialized Manager accepted conflicting legacy Config")
	}
	manager.Profiles["wrong-map-key"] = &browser.Profile{ProfileId: "profile-a"}
	if _, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	}); err == nil {
		t.Fatal("initialized Manager accepted a profile map key mismatch")
	}
}
