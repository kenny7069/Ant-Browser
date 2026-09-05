package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newRuntimeServiceTest(t *testing.T) (*BrowserRuntimeService, *browser.Manager) {
	t.Helper()
	cfg := config.DefaultConfig()
	manager := browser.NewManager(cfg, t.TempDir())
	manager.Profiles["profile-1"] = &browser.Profile{ProfileId: "profile-1", ProfileName: "Profile 1"}
	manager.Profiles["profile-2"] = &browser.Profile{ProfileId: "profile-2", ProfileName: "Profile 2"}
	service := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: manager, Config: cfg})
	return service, manager
}

type runtimeStartTestMonitor struct {
	exited atomic.Bool
}

func (m *runtimeStartTestMonitor) HasExited() bool {
	return m.exited.Load()
}

type completedRuntimeOwner struct {
	done chan struct{}
	err  error
}

func newCompletedRuntimeOwner(err error) *completedRuntimeOwner {
	owner := &completedRuntimeOwner{done: make(chan struct{}), err: err}
	close(owner.done)
	return owner
}

func (o *completedRuntimeOwner) Done() <-chan struct{} { return o.done }
func (o *completedRuntimeOwner) Result() error         { return o.err }

func newStartedRuntimeProcess(t *testing.T, monitor BrowserRuntimeProcessMonitor, cleanup func()) (*BrowserRuntimeProcess, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test child: %v", err)
	}
	owner, err := NewBrowserRuntimeCmdOwner(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	process, err := NewBrowserRuntimeProcess(cmd, owner, monitor, cleanup)
	if err != nil {
		_ = cmd.Process.Kill()
		<-owner.Done()
		t.Fatal(err)
	}
	return process, cmd
}

func newRuntimeStartServiceTest(t *testing.T, host BrowserRuntimeHost) (*BrowserRuntimeService, *browser.Manager) {
	t.Helper()
	cfg := config.DefaultConfig()
	appRoot := t.TempDir()
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.StartReadyTimeoutMs = 1
	cfg.Browser.StartStableWindowMs = 1
	coreDir := t.TempDir()
	chromePath := filepath.Join(coreDir, "chrome")
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "test-core", CoreName: "test", CorePath: coreDir, IsDefault: true}}
	manager := browser.NewManager(cfg, appRoot)
	manager.Profiles["profile-1"] = &browser.Profile{
		ProfileId:          "profile-1",
		ProfileName:        "Profile 1",
		CoreId:             "test-core",
		UserDataDir:        t.TempDir(),
		RestoreLastSession: "never",
	}
	return NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: manager, Config: cfg, Host: host}), manager
}

func TestBrowserRuntimeStartWithOptionsAdoptsDetectedRuntime(t *testing.T) {
	tests := []struct {
		name          string
		options       BrowserRuntimeStartOptions
		wantTargets   []string
		createTarget  func(int, string) error
		wantStartErr  error
		wantStartErrs bool
		wantCallbacks bool
	}{
		{
			name:          "no options keeps recovered runtime",
			createTarget:  func(int, string) error { return errors.New("CreateTarget must not be called") },
			wantCallbacks: true,
		},
		{
			name:          "only extra args opens about blank",
			options:       BrowserRuntimeStartOptions{ExtraLaunchArgs: []string{"--new-window"}},
			wantTargets:   []string{"about:blank"},
			wantCallbacks: true,
		},
		{
			name:          "only urls opens requested target",
			options:       BrowserRuntimeStartOptions{StartURLs: []string{"https://recovered.example"}},
			wantTargets:   []string{"https://recovered.example"},
			wantCallbacks: true,
		},
		{
			name:          "CreateTarget failure preserves explicit error",
			options:       BrowserRuntimeStartOptions{StartURLs: []string{"https://recovered.example"}},
			wantTargets:   []string{"https://recovered.example"},
			createTarget:  func(int, string) error { return errRecoveredCreateTarget },
			wantStartErr:  errRecoveredCreateTarget,
			wantStartErrs: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var detectCalls atomic.Int32
			var startCalls atomic.Int32
			var setActiveCalls atomic.Int32
			var emitStartedCalls atomic.Int32
			var detectedUserDataDir string
			var targetMu sync.Mutex
			var gotTargets []string
			var gotActive *browser.Profile
			var gotStarted *browser.Profile
			var startedReused bool
			host := BrowserRuntimeHost{
				StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
					startCalls.Add(1)
					return nil, errors.New("StartProcess must not be called for recovered runtime")
				},
				StopProcess: func(*exec.Cmd) error { return nil },
				DetectRuntime: func(userDataDir string) (BrowserRuntimeDetection, bool) {
					detectCalls.Add(1)
					detectedUserDataDir = userDataDir
					return BrowserRuntimeDetection{PID: 4242, DebugPort: 9333, DebugReady: true}, true
				},
				CreateTarget: tt.createTarget,
				SetActiveProfile: func(profile *browser.Profile) {
					setActiveCalls.Add(1)
					gotActive = copyBrowserProfileSnapshot(profile)
				},
				EmitStarted: func(profile *browser.Profile, reused bool) {
					emitStartedCalls.Add(1)
					gotStarted = copyBrowserProfileSnapshot(profile)
					startedReused = reused
				},
			}
			originalCreateTarget := tt.createTarget
			host.CreateTarget = func(port int, target string) error {
				targetMu.Lock()
				gotTargets = append(gotTargets, target)
				targetMu.Unlock()
				if originalCreateTarget != nil {
					return originalCreateTarget(port, target)
				}
				return nil
			}
			service, manager := newRuntimeStartServiceTest(t, host)
			profileBefore := manager.Profiles["profile-1"]

			got, err := service.StartWithOptions("profile-1", tt.options)
			if tt.wantStartErrs {
				if err == nil || !errors.Is(err, tt.wantStartErr) {
					t.Fatalf("StartWithOptions error = %v, want %v", err, tt.wantStartErr)
				}
			} else if err != nil {
				t.Fatalf("StartWithOptions: %v", err)
			}
			if got == nil {
				t.Fatal("StartWithOptions returned nil profile")
			}
			if detectCalls.Load() != 1 {
				t.Fatalf("DetectRuntime calls = %d, want 1", detectCalls.Load())
			}
			if detectedUserDataDir == "" || detectedUserDataDir != profileBefore.UserDataDir {
				t.Fatalf("DetectRuntime user-data directory = %q, want %q", detectedUserDataDir, profileBefore.UserDataDir)
			}
			if startCalls.Load() != 0 {
				t.Fatalf("StartProcess calls = %d, want 0", startCalls.Load())
			}

			manager.Mutex.Lock()
			current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
			_, tracked := manager.BrowserProcesses["profile-1"]
			manager.Mutex.Unlock()
			if !current.Running || !current.DebugReady || current.Pid != 4242 || current.DebugPort != 9333 || current.LastStartAt == "" {
				t.Fatalf("recovered profile state = %+v", current)
			}
			identity := service.identity("profile-1")
			if identity.generation == 0 || identity.pid != 4242 || identity.debugPort != 9333 || identity.cmd != nil {
				t.Fatalf("recovered identity = %+v", identity)
			}
			if tracked {
				t.Fatal("recovered runtime unexpectedly retained a launcher command")
			}
			if got.Running != current.Running || got.DebugReady != current.DebugReady || got.Pid != current.Pid || got.DebugPort != current.DebugPort || got.LastStartAt == "" {
				t.Fatalf("returned profile did not include recovered state: got=%+v current=%+v", got, current)
			}
			if tt.wantCallbacks {
				if setActiveCalls.Load() != 1 || emitStartedCalls.Load() != 1 || !startedReused {
					t.Fatalf("recovered lifecycle callbacks = setActive:%d emitStarted:%d reused:%v", setActiveCalls.Load(), emitStartedCalls.Load(), startedReused)
				}
				if gotActive == nil || gotStarted == nil || gotActive.Pid != 4242 || gotStarted.DebugPort != 9333 {
					t.Fatalf("callbacks did not receive recovered snapshot: active=%+v started=%+v", gotActive, gotStarted)
				}
			} else if setActiveCalls.Load() != 0 || emitStartedCalls.Load() != 0 {
				t.Fatalf("failed recovered start emitted callbacks: setActive:%d emitStarted:%d", setActiveCalls.Load(), emitStartedCalls.Load())
			}
			targetMu.Lock()
			gotTargetsCopy := append([]string(nil), gotTargets...)
			targetMu.Unlock()
			if len(gotTargetsCopy) != len(tt.wantTargets) {
				t.Fatalf("CreateTarget targets = %v, want %v", gotTargetsCopy, tt.wantTargets)
			}
			for i := range tt.wantTargets {
				if gotTargetsCopy[i] != tt.wantTargets[i] {
					t.Fatalf("CreateTarget targets = %v, want %v", gotTargetsCopy, tt.wantTargets)
				}
			}
			if tt.wantStartErrs && current.LastError == "" {
				t.Fatal("CreateTarget failure did not preserve profile LastError")
			}
		})
	}
}

var errRecoveredCreateTarget = errors.New("recovered target creation failed")

func TestBrowserRuntimeServiceProfileGatesAllowDifferentProfilesInParallel(t *testing.T) {
	service, _ := newRuntimeServiceTest(t)
	release1, err := service.acquire("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	defer release1()

	started := make(chan struct{})
	release2 := make(chan func())
	go func() {
		release, acquireErr := service.acquire("profile-2")
		if acquireErr != nil {
			t.Errorf("profile-2 acquire: %v", acquireErr)
			close(started)
			return
		}
		close(started)
		release2 <- release
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("different-profile operation was serialized")
	}
	(<-release2)()
}

func TestBrowserRuntimeServiceProfileGateSerializesSameProfile(t *testing.T) {
	service, _ := newRuntimeServiceTest(t)
	release1, err := service.acquire("profile-1")
	if err != nil {
		t.Fatal(err)
	}
	defer release1()

	started := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		release, acquireErr := service.acquire("profile-1")
		if acquireErr != nil {
			t.Errorf("same-profile acquire: %v", acquireErr)
			return
		}
		close(started)
		release()
		close(finished)
	}()
	select {
	case <-started:
		t.Fatal("same-profile operations were not serialized")
	case <-time.After(20 * time.Millisecond):
	}
	release1()
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("same-profile operation did not proceed after release")
	}
}

func TestBrowserRuntimeServiceOldGenerationCannotCleanupNewResources(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	profile := manager.Profiles["profile-1"]
	oldCmd := &exec.Cmd{}
	old := service.markRunning(profile.ProfileId, profile, oldCmd, 100, 9222, true, "")
	service.storeDeferredTargets(profile.ProfileId, old, []string{"https://old.example"}, false)
	service.bindProxy(profile.ProfileId, old, newProfileProxyBridgeRef(profileProxyBridgeEngineXray, "old-key"))

	newCmd := &exec.Cmd{}
	newIdentity := service.markRunning(profile.ProfileId, profile, newCmd, 200, 9222, true, "")
	if newIdentity.generation == old.generation {
		t.Fatal("runtime generation did not advance")
	}

	cleared := atomic.Int32{}
	host := BrowserRuntimeHost{ClearActiveProfile: func(string, uint64) { cleared.Add(1) }}
	if _, stopped := service.stopState(host, profile.ProfileId, &old); stopped {
		t.Fatal("stale generation transitioned current profile")
	}
	if got := cleared.Load(); got != 0 {
		t.Fatalf("stale generation cleared active profile %d times", got)
	}
	service.deferredMu.Lock()
	deferred := service.deferred[profile.ProfileId]
	service.deferredMu.Unlock()
	if deferred.generation != old.generation {
		t.Fatalf("stale generation removed/replaced deferred resources: got %d want %d", deferred.generation, old.generation)
	}
	service.proxyMu.Lock()
	proxyRef := service.proxyRefs[profile.ProfileId]
	service.proxyMu.Unlock()
	if proxyRef.generation != old.generation {
		t.Fatalf("stale generation removed/replaced proxy resources: got %d want %d", proxyRef.generation, old.generation)
	}
}

func TestBrowserRuntimeProcessCleanupRunsOnce(t *testing.T) {
	var calls atomic.Int32
	process := &BrowserRuntimeProcess{cleanupFn: func() { calls.Add(1) }}
	process.cleanup()
	process.cleanup()
	if got := calls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestBrowserRuntimeCommitUsesValueCASAgainstInPlaceUpdate(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	profile := manager.Profiles["profile-1"]
	expected := copyBrowserProfileSnapshot(profile)
	snapshot := copyBrowserProfileSnapshot(profile)
	snapshot.UserDataDir = "/stale-launch-directory"

	if _, err := manager.Update(profile.ProfileId, browser.ProfileInput{
		ProfileName: "updated while preparing",
		UserDataDir: profile.UserDataDir,
		CoreId:      profile.CoreId,
		LaunchArgs:  []string{"--updated"},
	}); err != nil {
		t.Fatalf("Manager.Update: %v", err)
	}
	if service.commitProfileSnapshot(profile.ProfileId, expected, snapshot) {
		t.Fatal("stale launch snapshot committed over an in-place Manager.Update")
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	manager.Mutex.Unlock()
	if current.ProfileName != "updated while preparing" || len(current.LaunchArgs) != 1 || current.LaunchArgs[0] != "--updated" {
		t.Fatalf("Manager.Update fields were overwritten: %+v", current)
	}
}

func TestBrowserRuntimeStartCASRejectsInterleavedManagerUpdate(t *testing.T) {
	var startCalls atomic.Int32
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, nil
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	preparationEntered := make(chan struct{})
	releasePreparation := make(chan struct{})
	service.runtimeBookmarks = func(string, []string, *BrowserProfile, []BrowserBookmark) ([]BrowserBookmark, string, error) {
		close(preparationEntered)
		<-releasePreparation
		return nil, "", nil
	}

	result := make(chan error, 1)
	go func() {
		_, err := service.Start("profile-1")
		result <- err
	}()
	select {
	case <-preparationEntered:
	case <-time.After(time.Second):
		t.Fatal("launch preparation did not reach the controlled interleaving point")
	}
	if _, err := manager.Update("profile-1", browser.ProfileInput{
		ProfileName: "updated during launch",
		UserDataDir: manager.Profiles["profile-1"].UserDataDir,
		CoreId:      "test-core",
		LaunchArgs:  []string{"--updated-during-launch"},
	}); err != nil {
		t.Fatalf("Manager.Update during launch: %v", err)
	}
	close(releasePreparation)
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "配置在启动准备期间发生变化") {
			t.Fatalf("Start error = %v, want explicit CAS conflict", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not finish after preparation release")
	}
	if got := startCalls.Load(); got != 0 {
		t.Fatalf("StartProcess calls = %d, want 0 after CAS conflict", got)
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	manager.Mutex.Unlock()
	if current.ProfileName != "updated during launch" || len(current.LaunchArgs) != 1 || current.LaunchArgs[0] != "--updated-during-launch" {
		t.Fatalf("interleaved Manager.Update was overwritten: %+v", current)
	}
}

func TestBrowserRuntimeStartCASRejectsDeleteRecreateSameValueABA(t *testing.T) {
	var startCalls atomic.Int32
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, nil
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	preparationEntered := make(chan struct{})
	releasePreparation := make(chan struct{})
	service.runtimeBookmarks = func(string, []string, *BrowserProfile, []BrowserBookmark) ([]BrowserBookmark, string, error) {
		close(preparationEntered)
		<-releasePreparation
		return nil, "", nil
	}

	result := make(chan error, 1)
	go func() {
		_, err := service.Start("profile-1")
		result <- err
	}()
	select {
	case <-preparationEntered:
	case <-time.After(time.Second):
		t.Fatal("launch preparation did not reach the controlled interleaving point")
	}

	manager.Mutex.Lock()
	original := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
	delete(manager.Profiles, "profile-1")
	manager.Profiles["profile-1"] = copyBrowserProfileSnapshot(original)
	manager.Mutex.Unlock()
	close(releasePreparation)

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "配置在启动准备期间发生变化") {
			t.Fatalf("Start error = %v, want CAS conflict after delete/recreate ABA", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not finish after preparation release")
	}
	if got := startCalls.Load(); got != 0 {
		t.Fatalf("StartProcess calls = %d, want 0 after delete/recreate ABA", got)
	}
}

func TestBrowserRuntimeProcessConstructorRejectsZeroCommand(t *testing.T) {
	if _, err := NewBrowserRuntimeProcess(&exec.Cmd{}, newCompletedRuntimeOwner(nil), &runtimeStartTestMonitor{}, nil); !errors.Is(err, ErrInvalidBrowserRuntimeProcess) {
		t.Fatalf("constructor error = %v, want invalid process error", err)
	}
}

func TestBrowserRuntimeStartInvalidHandleStopsRealProcess(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start test process: %v", err)
	}
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	owner, err := NewBrowserRuntimeCmdOwner(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	process, err := NewBrowserRuntimeProcess(cmd, owner, nil, func() { cleanupCalls.Add(1) })
	if err != nil {
		_ = cmd.Process.Kill()
		<-owner.Done()
		t.Fatal(err)
	}
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			// A process without a readiness monitor is an invalid service handle,
			// but its explicit owner still permits safe stop/reap.
			return process, nil
		},
		StopProcess: func(processCmd *exec.Cmd) error {
			stopCalls.Add(1)
			if processCmd.Process != nil {
				_ = processCmd.Process.Kill()
			}
			return nil
		},
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	if _, err := service.Start("profile-1"); err == nil {
		t.Fatal("invalid process handle unexpectedly started")
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("StopProcess calls = %d, want 1", got)
	}
	select {
	case <-owner.Done():
	case <-time.After(time.Second):
		t.Fatal("invalid-handle child owner did not finish")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

type blockingRuntimeMonitor struct {
	exited atomic.Bool
}

func (m *blockingRuntimeMonitor) HasExited() bool { return false }

func TestBrowserRuntimeStartStopErrorDoesNotDeadlockOnBlockingMonitor(t *testing.T) {
	var cleanupCalls atomic.Int32
	stopErr := errors.New("stop capability failed")
	monitor := &blockingRuntimeMonitor{}
	process, _ := newStartedRuntimeProcess(t, monitor, func() { cleanupCalls.Add(1) })
	done := make(chan error, 1)
	go func() {
		done <- stopAndCleanupBrowserRuntimeProcess(BrowserRuntimeHost{
			StopProcess: func(*exec.Cmd) error {
				return stopErr
			},
		}, process)
	}()

	select {
	case err := <-done:
		if err == nil || !errors.Is(err, stopErr) {
			t.Fatalf("Start error = %v, want propagated stop error", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Start blocked in Monitor.Wait after StopProcess returned an error")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestBrowserRuntimeStartStopErrorFallsBackToRealChildKillAndReap(t *testing.T) {
	var cmd *exec.Cmd
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	stopErr := errors.New("stop capability failed")
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			cmd = exec.Command("/bin/sleep", "30")
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			owner, ownerErr := NewBrowserRuntimeCmdOwner(cmd)
			if ownerErr != nil {
				_ = cmd.Process.Kill()
				return nil, ownerErr
			}
			return NewBrowserRuntimeProcess(cmd, owner, nil, func() { cleanupCalls.Add(1) })
		},
		StopProcess: func(*exec.Cmd) error {
			stopCalls.Add(1)
			return stopErr
		},
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	_, err := service.Start("profile-1")
	if err == nil || !errors.Is(err, stopErr) {
		t.Fatalf("Start error = %v, want propagated stop error", err)
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("StopProcess calls = %d, want 1", got)
	}
	if cmd == nil {
		t.Fatal("StartProcess did not create a real child")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestBrowserRuntimeNoChildStopSuccessDoesNotWaitForever(t *testing.T) {
	if _, err := NewBrowserRuntimeProcess(&exec.Cmd{}, newCompletedRuntimeOwner(nil), &blockingRuntimeMonitor{}, nil); !errors.Is(err, ErrInvalidBrowserRuntimeProcess) {
		t.Fatalf("constructor error = %v, want invalid process error", err)
	}
}

type exitedRuntimeMonitor struct{}

func (exitedRuntimeMonitor) HasExited() bool { return true }

type nilDoneRuntimeOwner struct{}

func (nilDoneRuntimeOwner) Done() <-chan struct{} { return nil }
func (nilDoneRuntimeOwner) Result() error         { return nil }

func TestBrowserRuntimeAlreadyExitedMonitorStillCleans(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	var cleanupCalls atomic.Int32
	process, err := NewBrowserRuntimeProcess(cmd, newCompletedRuntimeOwner(nil), exitedRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	if err != nil {
		t.Fatal(err)
	}
	if err := stopAndCleanupBrowserRuntimeProcess(BrowserRuntimeHost{
		StopProcess: func(*exec.Cmd) error {
			t.Fatal("already exited process should not be stopped")
			return nil
		},
	}, process); err != nil {
		t.Fatalf("teardown error: %v", err)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1 for already-exited monitor", got)
	}
}

func TestBrowserRuntimeStopErrorBrokenMonitorReapsChild(t *testing.T) {
	var cleanupCalls atomic.Int32
	process, _ := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	stopErr := errors.New("stop capability failed")
	started := time.Now()
	err := stopAndCleanupBrowserRuntimeProcess(BrowserRuntimeHost{
		StopProcess: func(*exec.Cmd) error { return stopErr },
	}, process)
	if err == nil || !errors.Is(err, stopErr) {
		t.Fatalf("teardown error = %v, want propagated stop error", err)
	}
	if elapsed := time.Since(started); elapsed > browserRuntimeProcessReapTimeout+time.Second {
		t.Fatalf("bounded teardown took %s", elapsed)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1 after bounded failure teardown", got)
	}
}

func TestBrowserRuntimeProcessConstructorRejectsMissingOwner(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	owner, err := NewBrowserRuntimeCmdOwner(cmd)
	if err != nil {
		_ = cmd.Process.Kill()
		t.Fatal(err)
	}
	<-owner.Done()
	if _, err := NewBrowserRuntimeProcess(cmd, nil, &runtimeStartTestMonitor{}, nil); !errors.Is(err, ErrInvalidBrowserRuntimeProcess) {
		t.Fatalf("nil owner constructor error = %v, want invalid process error", err)
	}
	if _, err := NewBrowserRuntimeProcess(cmd, nilDoneRuntimeOwner{}, &runtimeStartTestMonitor{}, nil); !errors.Is(err, ErrInvalidBrowserRuntimeProcess) {
		t.Fatalf("nil Done owner constructor error = %v, want invalid process error", err)
	}
}

func TestBrowserRuntimePendingReapRetainsOwnershipUntilOwnerDone(t *testing.T) {
	var cleanupCalls atomic.Int32
	process, _ := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	service, _ := newRuntimeServiceTest(t)
	plan := &BrowserRuntimeLaunchPlan{Spec: BrowserRuntimeLaunchSpec{ProfileID: "profile-1"}}
	service.registerPendingReap(process, plan)
	if !service.hasPendingReap("profile-1") {
		t.Fatal("pending process was not admitted to the registry")
	}
	if got := cleanupCalls.Load(); got != 0 {
		t.Fatalf("cleanup calls = %d before owner completion, want 0", got)
	}
	if err := process.cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
		t.Fatal(err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("pending owner did not reach Done")
	}
	deadline := time.Now().Add(time.Second)
	for service.hasPendingReap("profile-1") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.hasPendingReap("profile-1") {
		t.Fatal("pending process remained after owner completion")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d after owner completion, want 1", got)
	}
}

func TestBrowserRuntimePendingReapBlocksSameProfileStart(t *testing.T) {
	process, _ := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, nil)
	service, _ := newRuntimeStartServiceTest(t, BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			t.Fatal("pending profile admitted a second StartProcess")
			return nil, nil
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	})
	service.registerPendingReap(process, &BrowserRuntimeLaunchPlan{Spec: BrowserRuntimeLaunchSpec{ProfileID: "profile-1"}})
	if _, err := service.Start("profile-1"); err == nil || !strings.Contains(err.Error(), "仍在回收") {
		t.Fatalf("Start error = %v, want pending-reap admission error", err)
	}
	if err := process.cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
		t.Fatal(err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("pending owner did not finish")
	}
}

func TestBrowserRuntimeShutdownReapsPendingOwner(t *testing.T) {
	var cleanupCalls atomic.Int32
	process, _ := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	service, _ := newRuntimeStartServiceTest(t, BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
		StopProcess: func(cmd *exec.Cmd) error {
			if cmd.Process != nil {
				return cmd.Process.Kill()
			}
			return nil
		},
	})
	service.registerPendingReap(process, &BrowserRuntimeLaunchPlan{Spec: BrowserRuntimeLaunchSpec{ProfileID: "profile-1"}})
	if err := service.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not reap pending owner")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1 after Shutdown", got)
	}
}

func TestBrowserRuntimeStartFailsClosedWithoutStopCapability(t *testing.T) {
	var startCalls atomic.Int32
	host := BrowserRuntimeHost{StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
		startCalls.Add(1)
		return nil, nil
	}}
	service, _ := newRuntimeStartServiceTest(t, host)
	if _, err := service.Start("profile-1"); err == nil {
		t.Fatal("service admitted a host without stop capability")
	}
	if got := startCalls.Load(); got != 0 {
		t.Fatalf("StartProcess calls = %d, want 0 for fail-closed host", got)
	}
}

func TestBrowserRuntimeDetachedMonitorGraceAndMisses(t *testing.T) {
	var mu sync.Mutex
	attachCalls := 0
	attached := waitForRuntimeDebugAttachWithInterval(func(int, time.Duration) bool {
		mu.Lock()
		defer mu.Unlock()
		attachCalls++
		return attachCalls >= 3
	}, 9222, 20*time.Millisecond, time.Millisecond)
	if !attached {
		t.Fatal("delayed debug attach was not accepted within grace window")
	}

	disconnectCalls := 0
	disconnected := waitForRuntimeDebugDisconnectWithInterval(func(int, time.Duration) bool {
		disconnectCalls++
		return disconnectCalls < 3
	}, 9222, time.Millisecond)
	if !disconnected {
		t.Fatal("debug disconnect did not require/observe consecutive misses")
	}
	if disconnectCalls != 5 {
		t.Fatalf("disconnect probes = %d, want 5 (two misses then third miss)", disconnectCalls)
	}
}

func newCompletedRuntimeProcess(t *testing.T, cleanup func()) (*BrowserRuntimeProcess, *exec.Cmd) {
	t.Helper()
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run test child: %v", err)
	}
	process, err := NewBrowserRuntimeProcess(cmd, newCompletedRuntimeOwner(nil), exitedRuntimeMonitor{}, cleanup)
	if err != nil {
		t.Fatal(err)
	}
	return process, cmd
}

func TestBrowserRuntimeMonitorDelayedAttachPreservesRuntimeBeforeDetach(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	cleanupDone := make(chan struct{})
	process, cmd := newCompletedRuntimeProcess(t, func() { close(cleanupDone) })
	profile := manager.Profiles["profile-1"]
	identity := service.markRunning(profile.ProfileId, profile, cmd, cmd.Process.Pid, 9333, true, "")

	var probes atomic.Int32
	var stateAtAttach atomic.Bool
	attachObserved := make(chan struct{})
	var attachOnce sync.Once
	stopped := make(chan string, 1)
	var stoppedCalls atomic.Int32
	host := BrowserRuntimeHost{
		CanConnect: func(int, time.Duration) bool {
			call := probes.Add(1)
			switch call {
			case 1, 2:
				return false
			case 3:
				manager.Mutex.Lock()
				current := manager.Profiles[profile.ProfileId]
				stateAtAttach.Store(current != nil && current.Running && current.DebugReady && current.Pid == cmd.Process.Pid)
				manager.Mutex.Unlock()
				attachOnce.Do(func() { close(attachObserved) })
				return true
			default:
				return false
			}
		},
		EmitStopped: func(profileID string) {
			stoppedCalls.Add(1)
			stopped <- profileID
		},
	}
	service.waitRuntimeDebugAttach = func(canConnect func(int, time.Duration) bool, port int, grace time.Duration) bool {
		return waitForRuntimeDebugAttachWithInterval(canConnect, port, 20*time.Millisecond, time.Millisecond)
	}
	service.waitRuntimeDebugDisconnect = func(canConnect func(int, time.Duration) bool, port int) bool {
		return waitForRuntimeDebugDisconnectWithInterval(canConnect, port, time.Millisecond)
	}
	service.monitorProcess(host, profile.ProfileId, process, identity)

	select {
	case <-attachObserved:
	case <-time.After(time.Second):
		t.Fatal("monitor did not observe delayed debug attach")
	}
	if !stateAtAttach.Load() {
		t.Fatal("delayed debug attach did not preserve the running runtime")
	}
	select {
	case got := <-stopped:
		if got != profile.ProfileId {
			t.Fatalf("stopped event profile = %q, want %q", got, profile.ProfileId)
		}
	case <-time.After(time.Second):
		t.Fatal("detached monitor did not stop after three misses")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("monitor cleanup did not complete")
	}
	if probes.Load() != 6 {
		t.Fatalf("CanConnect probes = %d, want 6 (false,false,true then three misses)", probes.Load())
	}
	if stoppedCalls.Load() != 1 {
		t.Fatalf("stopped events = %d, want 1", stoppedCalls.Load())
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	_, tracked := manager.BrowserProcesses[profile.ProfileId]
	manager.Mutex.Unlock()
	if current.Running || current.DebugReady || current.Pid != 0 || current.DebugPort != 0 {
		t.Fatalf("profile after detached stop = %+v", current)
	}
	if tracked {
		t.Fatal("detached stop left the launcher command tracked")
	}
}

func TestBrowserRuntimeMonitorDetachedMissesResetAfterSuccess(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	cleanupDone := make(chan struct{})
	process, cmd := newCompletedRuntimeProcess(t, func() { close(cleanupDone) })
	profile := manager.Profiles["profile-1"]
	identity := service.markRunning(profile.ProfileId, profile, cmd, cmd.Process.Pid, 9444, true, "")

	var probes atomic.Int32
	var stateAfterReset atomic.Bool
	stopped := make(chan struct{}, 1)
	var stoppedCalls atomic.Int32
	host := BrowserRuntimeHost{
		CanConnect: func(int, time.Duration) bool {
			call := probes.Add(1)
			switch call {
			case 1:
				return false
			case 2:
				manager.Mutex.Lock()
				current := manager.Profiles[profile.ProfileId]
				stateAfterReset.Store(current != nil && current.Running && current.DebugReady && current.Pid == 0)
				manager.Mutex.Unlock()
				return true
			case 3, 4, 5:
				return false
			default:
				t.Errorf("unexpected CanConnect probe %d", call)
				return false
			}
		},
		EmitStopped: func(string) {
			stoppedCalls.Add(1)
			stopped <- struct{}{}
		},
	}
	service.waitRuntimeDebugAttach = func(func(int, time.Duration) bool, int, time.Duration) bool { return true }
	service.waitRuntimeDebugDisconnect = func(canConnect func(int, time.Duration) bool, port int) bool {
		return waitForRuntimeDebugDisconnectWithInterval(canConnect, port, time.Millisecond)
	}
	service.monitorProcess(host, profile.ProfileId, process, identity)

	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("detached monitor did not stop after reset and three misses")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("monitor cleanup did not complete")
	}
	if probes.Load() != 5 {
		t.Fatalf("CanConnect probes = %d, want 5 (miss, success reset, three misses)", probes.Load())
	}
	if !stateAfterReset.Load() {
		t.Fatal("successful detached probe did not reset misses while preserving runtime")
	}
	if stoppedCalls.Load() != 1 {
		t.Fatalf("stopped events = %d, want 1", stoppedCalls.Load())
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	manager.Mutex.Unlock()
	if current.Running || current.DebugReady || current.Pid != 0 || current.DebugPort != 0 {
		t.Fatalf("profile after detached stop = %+v", current)
	}
}

func TestBrowserRuntimeStaleGenerationCannotStopOrReadyNewRuntime(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	oldCleanup := make(chan struct{})
	oldProcess, oldCmd := newCompletedRuntimeProcess(t, func() { close(oldCleanup) })
	_, newCmd := newCompletedRuntimeProcess(t, nil)
	profile := manager.Profiles["profile-1"]
	oldIdentity := service.markRunning(profile.ProfileId, profile, oldCmd, oldCmd.Process.Pid, 9555, true, "")
	newIdentity := service.markRunning(profile.ProfileId, profile, newCmd, newCmd.Process.Pid, 9666, true, "")
	if newIdentity.generation <= oldIdentity.generation {
		t.Fatalf("runtime generation did not advance: old=%d new=%d", oldIdentity.generation, newIdentity.generation)
	}

	var readyCallbacks atomic.Int32
	var stoppedCalls atomic.Int32
	host := BrowserRuntimeHost{
		SetActiveProfile: func(*browser.Profile) { readyCallbacks.Add(1) },
		EmitUpdated:      func(*browser.Profile) { readyCallbacks.Add(1) },
		EmitStopped:      func(string) { stoppedCalls.Add(1) },
		CanConnect: func(int, time.Duration) bool {
			t.Fatal("stale monitor probed the replacement runtime")
			return false
		},
	}
	service.waitRuntimeDebugAttach = func(func(int, time.Duration) bool, int, time.Duration) bool {
		t.Fatal("stale monitor entered delayed attach")
		return false
	}
	service.waitDebugReadyAsync(host, profile.ProfileId, oldIdentity.debugPort, oldIdentity, time.Second)
	service.monitorProcess(host, profile.ProfileId, oldProcess, oldIdentity)
	select {
	case <-oldCleanup:
	case <-time.After(time.Second):
		t.Fatal("stale monitor cleanup did not complete")
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	tracked := manager.BrowserProcesses[profile.ProfileId]
	manager.Mutex.Unlock()
	if !current.Running || !current.DebugReady || current.Pid != newCmd.Process.Pid || current.DebugPort != 9666 {
		t.Fatalf("replacement runtime was changed by stale completion: %+v", current)
	}
	if tracked != newCmd {
		t.Fatal("stale completion removed the replacement launcher command")
	}
	if readyCallbacks.Load() != 0 || stoppedCalls.Load() != 0 {
		t.Fatalf("stale completion emitted lifecycle callbacks: ready=%d stopped=%d", readyCallbacks.Load(), stoppedCalls.Load())
	}
}
