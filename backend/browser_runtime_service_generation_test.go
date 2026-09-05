package backend

import (
	"ant-chrome/backend/internal/browser"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestBrowserRuntimeGenerationInterleavePreservesReplacementResources(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	cleanupDone := make(chan struct{})
	var cleanupCalls atomic.Int32
	oldProcess, oldCmd := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() {
		cleanupCalls.Add(1)
		close(cleanupDone)
	})
	profile := manager.Profiles["profile-1"]
	oldIdentity := service.markRunning(profile.ProfileId, profile, oldCmd, oldCmd.Process.Pid, 9222, true, "")
	service.storeDeferredTargets(profile.ProfileId, oldIdentity, []string{"https://old.example"}, false)
	service.bindProxy(profile.ProfileId, oldIdentity, newProfileProxyBridgeRef(profileProxyBridgeEngineXray, "old-key"))

	attachEntered := make(chan struct{})
	releaseAttach := make(chan struct{})
	var attachOnce sync.Once
	var stoppedCalls atomic.Int32
	var crashedCalls atomic.Int32
	host := BrowserRuntimeHost{
		CanConnect: func(int, time.Duration) bool { return false },
		EmitStopped: func(string) {
			stoppedCalls.Add(1)
		},
		EmitCrashed: func(string, string, error) {
			crashedCalls.Add(1)
		},
	}
	service.waitRuntimeDebugAttach = func(func(int, time.Duration) bool, int, time.Duration) bool {
		attachOnce.Do(func() { close(attachEntered) })
		<-releaseAttach
		return true
	}
	service.waitRuntimeDebugDisconnect = func(canConnect func(int, time.Duration) bool, port int) bool {
		return waitForRuntimeDebugDisconnectWithInterval(canConnect, port, time.Millisecond)
	}
	service.monitorProcess(host, profile.ProfileId, oldProcess, oldIdentity)

	if err := oldCmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
		t.Fatalf("kill old child: %v", err)
	}
	select {
	case <-attachEntered:
	case <-time.After(time.Second):
		t.Fatal("old monitor did not reach the controlled interleave")
	}

	_, newCmd := newCompletedRuntimeProcess(t, nil)
	newIdentity := service.markRunning(profile.ProfileId, profile, newCmd, newCmd.Process.Pid, 9333, true, "")
	newTargets := []string{"https://new.example"}
	service.storeDeferredTargets(profile.ProfileId, newIdentity, newTargets, true)
	newProxy := newProfileProxyBridgeRef(profileProxyBridgeEngineXray, "new-key")
	service.bindProxy(profile.ProfileId, newIdentity, newProxy)
	close(releaseAttach)

	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("old monitor did not finish after the replacement was installed")
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("old process cleanup calls = %d, want 1", cleanupCalls.Load())
	}
	if stoppedCalls.Load() != 0 || crashedCalls.Load() != 0 {
		t.Fatalf("stale old monitor emitted events: stopped=%d crashed=%d", stoppedCalls.Load(), crashedCalls.Load())
	}

	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	tracked := manager.BrowserProcesses[profile.ProfileId]
	manager.Mutex.Unlock()
	if !current.Running || !current.DebugReady || current.Pid != newCmd.Process.Pid || current.DebugPort != 9333 {
		t.Fatalf("replacement profile state was changed by old monitor: %+v", current)
	}
	if tracked != newCmd {
		t.Fatal("old monitor removed the replacement process from Manager.BrowserProcesses")
	}
	if got := service.identity(profile.ProfileId); !sameBrowserRuntimeIdentity(got, newIdentity) {
		t.Fatalf("active identity = %+v, want replacement %+v", got, newIdentity)
	}
	service.deferredMu.Lock()
	deferred := service.deferred[profile.ProfileId]
	service.deferredMu.Unlock()
	if deferred.generation != newIdentity.generation || len(deferred.plan.targets) != 1 || deferred.plan.targets[0] != newTargets[0] || !deferred.plan.newTabs {
		t.Fatalf("replacement deferred targets = %+v, want generation %d and %v", deferred, newIdentity.generation, newTargets)
	}
	service.proxyMu.Lock()
	proxyRef := service.proxyRefs[profile.ProfileId]
	service.proxyMu.Unlock()
	if proxyRef.generation != newIdentity.generation || proxyRef.ref != newProxy {
		t.Fatalf("replacement proxy ref = %+v, want generation %d and %+v", proxyRef, newIdentity.generation, newProxy)
	}
}

func TestBrowserRuntimeStartSameProfileConcurrentSingleAdoption(t *testing.T) {
	var detectCalls atomic.Int32
	var startCalls atomic.Int32
	detectEntered := make(chan struct{})
	releaseDetect := make(chan struct{})
	var detectOnce sync.Once
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, errors.New("recovered concurrent Start must not launch")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			if detectCalls.Add(1) == 1 {
				detectOnce.Do(func() { close(detectEntered) })
				<-releaseDetect
			}
			return BrowserRuntimeDetection{PID: 7001, DebugPort: 9701, DebugReady: true}, true
		},
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	results := make(chan error, 2)
	go func() {
		_, err := service.StartWithOptions("profile-1", BrowserRuntimeStartOptions{})
		results <- err
	}()
	select {
	case <-detectEntered:
	case <-time.After(time.Second):
		t.Fatal("first real Start did not reach DetectRuntime")
	}
	go func() {
		_, err := service.StartWithOptions("profile-1", BrowserRuntimeStartOptions{})
		results <- err
	}()
	close(releaseDetect)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("concurrent Start error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("concurrent same-profile Start did not finish")
		}
	}
	if detectCalls.Load() != 1 || startCalls.Load() != 0 {
		t.Fatalf("same-profile concurrent launch calls = DetectRuntime:%d StartProcess:%d, want 1 and 0", detectCalls.Load(), startCalls.Load())
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	manager.Mutex.Unlock()
	if !current.Running || !current.DebugReady || current.Pid != 7001 || current.DebugPort != 9701 {
		t.Fatalf("same-profile concurrent recovered state = %+v", current)
	}
}

func TestBrowserRuntimeStartDifferentProfilesRunInParallel(t *testing.T) {
	var detectCalls atomic.Int32
	var startCalls atomic.Int32
	entered := make(chan string, 2)
	releaseDetect := make(chan struct{})
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, errors.New("recovered parallel Start must not launch")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	manager.Profiles["profile-2"] = &browser.Profile{
		ProfileId:          "profile-2",
		ProfileName:        "Profile 2",
		CoreId:             "test-core",
		UserDataDir:        t.TempDir(),
		RestoreLastSession: "never",
	}
	profileByDir := map[string]string{
		manager.Profiles["profile-1"].UserDataDir: "profile-1",
		manager.Profiles["profile-2"].UserDataDir: "profile-2",
	}
	host.DetectRuntime = func(userDataDir string) (BrowserRuntimeDetection, bool) {
		detectCalls.Add(1)
		entered <- profileByDir[userDataDir]
		<-releaseDetect
		port := 9801
		pid := 8001
		if profileByDir[userDataDir] == "profile-2" {
			port = 9802
			pid = 8002
		}
		return BrowserRuntimeDetection{PID: pid, DebugPort: port, DebugReady: true}, true
	}
	service.SetHost(host)
	results := make(chan error, 2)
	for _, profileID := range []string{"profile-1", "profile-2"} {
		profileID := profileID
		go func() {
			_, err := service.StartWithOptions(profileID, BrowserRuntimeStartOptions{})
			results <- err
		}()
	}
	seen := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case profileID := <-entered:
			if profileID == "" || seen[profileID] {
				t.Fatalf("unexpected DetectRuntime profile interleave: %q", profileID)
			}
			seen[profileID] = true
		case <-time.After(time.Second):
			t.Fatal("different-profile Starts were serialized before DetectRuntime")
		}
	}
	close(releaseDetect)
	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("parallel Start error: %v", err)
			}
		case <-time.After(time.Second):
			t.Fatal("parallel different-profile Start did not finish")
		}
	}
	if detectCalls.Load() != 2 || startCalls.Load() != 0 {
		t.Fatalf("different-profile launch calls = DetectRuntime:%d StartProcess:%d, want 2 and 0", detectCalls.Load(), startCalls.Load())
	}
	for _, profileID := range []string{"profile-1", "profile-2"} {
		manager.Mutex.Lock()
		current := copyBrowserProfileSnapshot(manager.Profiles[profileID])
		manager.Mutex.Unlock()
		if !current.Running || !current.DebugReady {
			t.Fatalf("parallel recovered profile %s state = %+v", profileID, current)
		}
	}
	if len(seen) != 2 {
		t.Fatalf("parallel DetectRuntime profiles = %v, want both profiles", seen)
	}
	if strings.TrimSpace(manager.Profiles["profile-1"].UserDataDir) == strings.TrimSpace(manager.Profiles["profile-2"].UserDataDir) {
		t.Fatal("parallel test profiles unexpectedly share a user-data directory")
	}
}
