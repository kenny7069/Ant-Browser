package backend

import (
	"ant-chrome/backend/internal/browser"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"
)

// This validator regression covers the tail of stale-generation cleanup:
// stopState has already removed generation N, but its host ClearActiveProfile
// callback has not returned when generation N+1 publishes a new active binding.
func TestP18IndependentOldGenerationClearActiveCannotEraseReplacement(t *testing.T) {
	service, manager := newRuntimeStartServiceTest(t, BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
		StopProcess:  func(*exec.Cmd) error { return nil },
	})
	profile := manager.Profiles["profile-1"]
	oldProcess, oldCmd := newCompletedRuntimeProcess(t, nil)
	oldIdentity := service.markRunning(profile.ProfileId, profile, oldCmd, oldCmd.Process.Pid, 9222, true, "")

	var activeMu sync.Mutex
	activeProfile := profile.ProfileId
	clearEntered := make(chan struct{})
	releaseClear := make(chan struct{})
	var clearOnce sync.Once
	var childrenMu sync.Mutex
	var children []*freshConcurrencyChild
	defer func() { killFreshConcurrencyChildren(children) }()

	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			child, err := newFreshConcurrencyChild(t, plan)
			if err != nil {
				return nil, err
			}
			childrenMu.Lock()
			children = append(children, child)
			childrenMu.Unlock()
			return child.process, nil
		},
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("missing process")
			}
			return cmd.Process.Kill()
		},
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			return BrowserRuntimeDetection{}, false
		},
		SetActiveProfile: func(p *browser.Profile) {
			activeMu.Lock()
			activeProfile = p.ProfileId
			activeMu.Unlock()
		},
		// This intentionally matches the App host adapter: the generation is
		// discarded and LaunchServer is cleared only by profile ID.
		ClearActiveProfile: func(profileID string, _ uint64) {
			clearOnce.Do(func() { close(clearEntered) })
			<-releaseClear
			activeMu.Lock()
			if activeProfile == profileID {
				activeProfile = ""
			}
			activeMu.Unlock()
		},
	}
	service.SetHost(host)
	service.monitorProcess(host, profile.ProfileId, oldProcess, oldIdentity)

	select {
	case <-clearEntered:
	case <-time.After(time.Second):
		t.Fatal("old generation did not reach delayed ClearActiveProfile")
	}

	started, err := service.Start(profile.ProfileId)
	if err != nil {
		close(releaseClear)
		t.Fatalf("replacement Start: %v", err)
	}
	if started == nil || !started.Running || !started.DebugReady || service.Generation(profile.ProfileId) <= oldIdentity.generation {
		close(releaseClear)
		t.Fatalf("replacement runtime = %+v generation=%d", started, service.Generation(profile.ProfileId))
	}
	close(releaseClear)
	time.Sleep(20 * time.Millisecond)

	activeMu.Lock()
	gotActive := activeProfile
	activeMu.Unlock()
	if gotActive != profile.ProfileId {
		t.Fatalf("old generation cleared replacement active binding: got %q want %q", gotActive, profile.ProfileId)
	}
}
