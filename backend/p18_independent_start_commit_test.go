package backend

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// A launch callback is a slow operation outside Manager.Mutex. Replacing the
// profile after the pre-launch CAS but before StartProcess returns must not let
// the old process become the runtime of the replacement profile.
func TestP18IndependentStartRejectsProfileABADuringProcessLaunch(t *testing.T) {
	launchEntered := make(chan struct{})
	releaseLaunch := make(chan struct{})
	var child *freshConcurrencyChild
	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			var err error
			child, err = newFreshConcurrencyChild(t, plan)
			if err != nil {
				return nil, err
			}
			close(launchEntered)
			<-releaseLaunch
			return child.process, nil
		},
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("missing process")
			}
			return cmd.Process.Kill()
		},
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) { return BrowserRuntimeDetection{}, false },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	defer func() {
		if child != nil {
			killFreshConcurrencyChildren([]*freshConcurrencyChild{child})
		}
	}()

	type result struct {
		profile *BrowserProfile
		err     error
	}
	resultCh := make(chan result, 1)
	go func() {
		profile, err := service.Start("profile-1")
		resultCh <- result{profile: profile, err: err}
	}()
	select {
	case <-launchEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not reach process-launch barrier")
	}

	manager.Mutex.Lock()
	original := manager.Profiles["profile-1"]
	replacement := copyBrowserProfileSnapshot(original)
	manager.Profiles["profile-1"] = replacement
	manager.Mutex.Unlock()
	close(releaseLaunch)

	select {
	case got := <-resultCh:
		if got.err == nil || (!strings.Contains(got.err.Error(), "配置") && !strings.Contains(got.err.Error(), "incarnation")) {
			t.Fatalf("Start after launch-time profile ABA = profile:%+v err:%v, want conflict and teardown", got.profile, got.err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Start did not return after releasing launch barrier")
	}

	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	manager.Mutex.Unlock()
	if current.Running || current.Pid != 0 || current.DebugPort != 0 {
		t.Fatalf("replacement profile adopted stale launch: %+v", current)
	}
}
