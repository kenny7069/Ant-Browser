package backend

import (
	"errors"
	"os/exec"
	"testing"

	"ant-chrome/backend/internal/browser"
)

func TestFarmProfileManagementRejectsUnownedDetectedBrowser(t *testing.T) {
	manager := browser.NewManager(DefaultConfig(), t.TempDir())
	manager.Profiles["manual"] = &browser.Profile{ProfileId: "manual", ProfileName: "manual", IncarnationID: "manual-inc", UserDataDir: "manual-data"}
	runtimeService := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{
		Manager: manager,
		Config:  DefaultConfig(),
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
			DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
				return BrowserRuntimeDetection{PID: 99, DebugPort: 9222, DebugReady: true}, true
			},
		},
	})
	host := &FarmClientHost{manager: manager, runtime: runtimeService}
	management, err := newFarmProfileManagement(host)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := management.Status("manual"); !errors.Is(err, ErrFarmClientProfileInUseUnowned) {
		t.Fatalf("status error=%v", err)
	}
	if _, err := management.Open("manual"); !errors.Is(err, ErrFarmClientProfileInUseUnowned) {
		t.Fatalf("open error=%v", err)
	}
	if _, err := management.Stop("manual"); !errors.Is(err, ErrFarmClientProfileInUseUnowned) {
		t.Fatalf("stop error=%v", err)
	}
	profile := manager.Profiles["manual"]
	if profile.Running || profile.Pid != 0 || profile.DebugPort != 0 {
		t.Fatalf("unowned browser mutated profile: %+v", profile)
	}
}

func TestFarmProfileManagementStopIsIdempotentForStoppedProfile(t *testing.T) {
	host := newFarmClientIPCTestHost(t)
	management, err := newFarmProfileManagement(host)
	if err != nil {
		t.Fatal(err)
	}
	first, err := management.Stop("profile-1")
	if err != nil || first.Running {
		t.Fatalf("first stop=%+v err=%v", first, err)
	}
	second, err := management.Stop("profile-1")
	if err != nil || second.Running || second.ProfileID != first.ProfileID {
		t.Fatalf("second stop=%+v err=%v", second, err)
	}
}
