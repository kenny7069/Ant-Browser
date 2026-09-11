package backend

import (
	"ant-chrome/backend/internal/browser"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type freshConcurrencyChild struct {
	process     *BrowserRuntimeProcess
	owner       BrowserRuntimeProcessOwner
	cmd         *exec.Cmd
	cleanupDone chan struct{}
}

func newFreshConcurrencyChild(t *testing.T, plan *BrowserRuntimeLaunchPlan) (*freshConcurrencyChild, error) {
	t.Helper()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", plan.Spec.AssignedDebugPort))
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"Browser":"fresh-concurrency-test","webSocketDebuggerUrl":"ws://127.0.0.1/devtools"}`))
	})
	server := &http.Server{Handler: mux}
	go func() { _ = server.Serve(listener) }()

	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		_ = server.Close()
		return nil, err
	}
	owner, err := NewBrowserRuntimeCmdOwner(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		_ = server.Close()
		return nil, err
	}
	child := &freshConcurrencyChild{owner: owner, cmd: cmd, cleanupDone: make(chan struct{})}
	child.process, err = NewBrowserRuntimeProcess(cmd, owner, &blockingRuntimeMonitor{}, func() {
		_ = server.Close()
		close(child.cleanupDone)
	})
	if err != nil {
		_ = cmd.Process.Kill()
		<-owner.Done()
		_ = server.Close()
		return nil, err
	}
	return child, nil
}

func killFreshConcurrencyChildren(children []*freshConcurrencyChild) {
	for _, child := range children {
		if child == nil {
			continue
		}
		if child.cmd != nil && child.cmd.Process != nil {
			if err := child.cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
				continue
			}
		}
		if child.owner != nil && child.owner.Done() != nil {
			<-child.owner.Done()
		}
		if child.process != nil {
			child.process.cleanup()
		}
	}
}

func configureFreshConcurrencyStart(t *testing.T, service *BrowserRuntimeService, manager *browser.Manager) {
	t.Helper()
	manager.Config.Browser.StartReadyTimeoutMs = 2000
	manager.Config.Browser.StartStableWindowMs = 20
	if manager.Profiles["profile-1"] == nil {
		t.Fatal("fresh concurrency fixture is missing profile-1")
	}
	service.SetManager(manager)
}

func TestBrowserRuntimeFreshStartSameProfileContentionSingleLaunch(t *testing.T) {
	var startCalls atomic.Int32
	var prepareCalls atomic.Int32
	var startedCalls atomic.Int32
	var stoppedCalls atomic.Int32
	var childMu sync.Mutex
	var children []*freshConcurrencyChild
	defer func() { killFreshConcurrencyChildren(children) }()

	firstPrepare := make(chan struct{})
	secondPrepare := make(chan struct{})
	releasePrepare := make(chan struct{})
	var firstPrepareOnce sync.Once
	var secondPrepareOnce sync.Once
	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			child, err := newFreshConcurrencyChild(t, plan)
			if err != nil {
				return nil, err
			}
			childMu.Lock()
			children = append(children, child)
			childMu.Unlock()
			return child.process, nil
		},
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("missing process")
			}
			if err := cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
				return err
			}
			return nil
		},
		EmitStarted: func(*browser.Profile, bool) { startedCalls.Add(1) },
		EmitStopped: func(string) { stoppedCalls.Add(1) },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	configureFreshConcurrencyStart(t, service, manager)
	service.runtimeBookmarks = func(string, []string, *BrowserProfile, []BrowserBookmark) ([]BrowserBookmark, string, error) {
		switch prepareCalls.Add(1) {
		case 1:
			firstPrepareOnce.Do(func() { close(firstPrepare) })
			<-releasePrepare
		case 2:
			secondPrepareOnce.Do(func() { close(secondPrepare) })
		}
		return nil, "", nil
	}

	type startResult struct {
		profile *browser.Profile
		err     error
	}
	results := make(chan startResult, 2)
	go func() {
		profile, err := service.StartWithOptions("profile-1", BrowserRuntimeStartOptions{})
		results <- startResult{profile: profile, err: err}
	}()
	select {
	case <-firstPrepare:
	case <-time.After(time.Second):
		t.Fatal("first fresh Start did not reach preparation barrier")
	}
	go func() {
		profile, err := service.StartWithOptions("profile-1", BrowserRuntimeStartOptions{})
		results <- startResult{profile: profile, err: err}
	}()

	gateHeld := true
	select {
	case <-secondPrepare:
		gateHeld = false
	case <-time.After(100 * time.Millisecond):
	}
	close(releasePrepare)
	if !gateHeld {
		t.Error("second same-profile fresh Start entered preparation while the first was still active")
	}
	var got [2]startResult
	for i := range got {
		select {
		case got[i] = <-results:
		case <-time.After(2 * time.Second):
			t.Fatal("same-profile fresh Starts did not finish")
		}
		if got[i].err != nil {
			t.Fatalf("same-profile fresh Start error: %v", got[i].err)
		}
	}
	if startCalls.Load() != 1 {
		t.Fatalf("same-profile fresh StartProcess calls = %d, want 1", startCalls.Load())
	}
	if got[0].profile == nil || got[1].profile == nil || got[0].profile.Pid <= 0 || got[0].profile.Pid != got[1].profile.Pid || got[0].profile.DebugPort != got[1].profile.DebugPort || !got[0].profile.Running || !got[1].profile.Running {
		t.Fatalf("same-profile fresh Start results = %+v / %+v", got[0].profile, got[1].profile)
	}
	generation := service.Generation("profile-1")
	if generation == 0 || generation != service.Generation("profile-1") {
		t.Fatalf("same-profile runtime generation = %d, want one stable non-zero generation", generation)
	}
	status, err := service.Status("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	if status.Pid != got[0].profile.Pid || status.DebugPort != got[0].profile.DebugPort || !status.Running || !status.DebugReady {
		t.Fatalf("same-profile Status = %+v, want shared running runtime", status)
	}
	if startedCalls.Load() != 2 {
		t.Fatalf("same-profile started events = %d, want 2 caller acknowledgements", startedCalls.Load())
	}

	stopped, err := service.Stop("profile-1")
	if err != nil {
		t.Fatalf("same-profile Stop: %v", err)
	}
	if stopped == nil || stopped.Running || stopped.DebugReady || stopped.Pid != 0 || stopped.DebugPort != 0 {
		t.Fatalf("same-profile Stop result = %+v", stopped)
	}
	childMu.Lock()
	child := children[0]
	childMu.Unlock()
	select {
	case <-child.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("same-profile child owner did not reach Done")
	}
	select {
	case <-child.cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("same-profile child cleanup did not complete")
	}
	if stoppedCalls.Load() != 1 {
		t.Fatalf("same-profile stopped events = %d, want 1", stoppedCalls.Load())
	}
}

func TestBrowserRuntimeFreshStartDifferentProfilesParallelIdentity(t *testing.T) {
	var startCalls atomic.Int32
	var stoppedCalls atomic.Int32
	var childMu sync.Mutex
	children := make(map[string]*freshConcurrencyChild)
	defer func() {
		childMu.Lock()
		all := make([]*freshConcurrencyChild, 0, len(children))
		for _, child := range children {
			all = append(all, child)
		}
		childMu.Unlock()
		killFreshConcurrencyChildren(all)
	}()
	launchEntered := make(chan string, 2)
	readyEntered := make(chan string, 2)
	releaseLaunch := make(chan struct{})
	releaseReady := make(chan struct{})
	var releaseLaunchOnce sync.Once
	var releaseReadyOnce sync.Once
	defer releaseLaunchOnce.Do(func() { close(releaseLaunch) })
	defer releaseReadyOnce.Do(func() { close(releaseReady) })
	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			child, err := newFreshConcurrencyChild(t, plan)
			if err != nil {
				return nil, err
			}
			childMu.Lock()
			children[plan.Spec.ProfileID] = child
			childMu.Unlock()
			launchEntered <- plan.Spec.ProfileID
			<-releaseLaunch
			return child.process, nil
		},
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("missing process")
			}
			if err := cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
				return err
			}
			return nil
		},
		EmitStarted: func(profile *browser.Profile, reused bool) {
			if profile != nil && !reused {
				readyEntered <- profile.ProfileId
				<-releaseReady
			}
		},
		EmitStopped: func(string) { stoppedCalls.Add(1) },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	configureFreshConcurrencyStart(t, service, manager)
	manager.Profiles["profile-2"] = &browser.Profile{
		ProfileId:          "profile-2",
		ProfileName:        "Profile 2",
		CoreId:             "test-core",
		UserDataDir:        t.TempDir(),
		RestoreLastSession: "never",
	}

	type startResult struct {
		profileID string
		profile   *browser.Profile
		err       error
	}
	results := make(chan startResult, 2)
	for _, profileID := range []string{"profile-1", "profile-2"} {
		profileID := profileID
		go func() {
			profile, err := service.StartWithOptions(profileID, BrowserRuntimeStartOptions{})
			results <- startResult{profileID: profileID, profile: profile, err: err}
		}()
	}
	seenLaunch := map[string]bool{}
	launchBarrierHeld := true
	for len(seenLaunch) < 2 {
		select {
		case profileID := <-launchEntered:
			if profileID == "" || seenLaunch[profileID] {
				launchBarrierHeld = false
			}
			seenLaunch[profileID] = true
		case <-time.After(2 * time.Second):
			launchBarrierHeld = false
			break
		}
		if !launchBarrierHeld || len(seenLaunch) == 2 {
			break
		}
	}
	releaseLaunchOnce.Do(func() { close(releaseLaunch) })
	if !launchBarrierHeld {
		t.Error("different-profile fresh StartProcess/launch was not parallel")
	}
	seenReady := map[string]bool{}
	readyBarrierHeld := true
	for len(seenReady) < 2 {
		select {
		case profileID := <-readyEntered:
			if profileID == "" || seenReady[profileID] {
				readyBarrierHeld = false
			}
			seenReady[profileID] = true
		case <-time.After(2 * time.Second):
			readyBarrierHeld = false
			break
		}
		if !readyBarrierHeld || len(seenReady) == 2 {
			break
		}
	}
	releaseReadyOnce.Do(func() { close(releaseReady) })
	if !readyBarrierHeld {
		t.Error("different-profile fresh readiness was not parallel")
	}

	got := map[string]*browser.Profile{}
	for i := 0; i < 2; i++ {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("different-profile fresh Start %s: %v", result.profileID, result.err)
			}
			got[result.profileID] = result.profile
		case <-time.After(2 * time.Second):
			t.Fatal("different-profile fresh Starts did not finish")
		}
	}
	if startCalls.Load() != 2 || len(got) != 2 {
		t.Fatalf("different-profile fresh launches = StartProcess:%d profiles:%d, want 2 and 2", startCalls.Load(), len(got))
	}
	if got["profile-1"] == nil || got["profile-2"] == nil || got["profile-1"].Pid <= 0 || got["profile-2"].Pid <= 0 || got["profile-1"].Pid == got["profile-2"].Pid || got["profile-1"].DebugPort == got["profile-2"].DebugPort {
		t.Fatalf("different-profile fresh identities = profile-1:%+v profile-2:%+v", got["profile-1"], got["profile-2"])
	}
	if service.Generation("profile-1") == 0 || service.Generation("profile-2") == 0 {
		t.Fatalf("different-profile generations = %d and %d, want independent non-zero generations", service.Generation("profile-1"), service.Generation("profile-2"))
	}
	for _, profileID := range []string{"profile-1", "profile-2"} {
		status, err := service.Status(profileID)
		if err != nil {
			t.Fatal(err)
		}
		if !status.Running || !status.DebugReady || status.Pid != got[profileID].Pid || status.DebugPort != got[profileID].DebugPort {
			t.Fatalf("Status(%s) = %+v, want its fresh runtime", profileID, status)
		}
	}
	for _, profileID := range []string{"profile-1", "profile-2"} {
		stopped, err := service.Stop(profileID)
		if err != nil {
			t.Fatalf("Stop(%s): %v", profileID, err)
		}
		if stopped == nil || stopped.Running || stopped.DebugReady || stopped.Pid != 0 || stopped.DebugPort != 0 {
			t.Fatalf("Stop(%s) = %+v", profileID, stopped)
		}
		childMu.Lock()
		child := children[profileID]
		childMu.Unlock()
		select {
		case <-child.owner.Done():
		case <-time.After(time.Second):
			t.Fatalf("child owner for %s did not reach Done", profileID)
		}
		select {
		case <-child.cleanupDone:
		case <-time.After(time.Second):
			t.Fatalf("child cleanup for %s did not complete", profileID)
		}
	}
	if stoppedCalls.Load() != 2 {
		t.Fatalf("different-profile stopped events = %d, want 2", stoppedCalls.Load())
	}
}
