package backend

import (
	"ant-chrome/backend/internal/browser"
	"errors"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestP18ShutdownOwnActiveStopReapCleanupExactlyOnce(t *testing.T) {
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	var stoppedCalls atomic.Int32
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			return nil, errors.New("unused StartProcess in shutdown acceptance fixture")
		},
		StopProcess: func(cmd *exec.Cmd) error {
			stopCalls.Add(1)
			if cmd == nil || cmd.Process == nil {
				return errors.New("missing process")
			}
			if err := cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
				return err
			}
			return nil
		},
		EmitStopped: func(string) { stoppedCalls.Add(1) },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	process, cmd := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	identity := service.markRunning("profile-1", manager.Profiles["profile-1"], cmd, cmd.Process.Pid, 9811, true, "")
	service.trackProcess("profile-1", process, identity)

	stopped, err := service.Stop("profile-1")
	if err != nil {
		t.Fatalf("owned Stop: %v", err)
	}
	if stopped == nil || stopped.Running || stopped.DebugReady || stopped.Pid != 0 || stopped.DebugPort != 0 {
		t.Fatalf("owned Stop result = %+v", stopped)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("owned process owner did not reap after Stop")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("owned cleanup calls after Stop = %d, want 1", got)
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("owned StopProcess calls = %d, want 1", got)
	}
	if got := stoppedCalls.Load(); got != 1 {
		t.Fatalf("owned stopped events = %d, want 1", got)
	}
	if service.processFor("profile-1") != nil || len(service.ownedProcessSnapshots()) != 0 {
		t.Fatal("owned process remained tracked after Stop")
	}

	// A second Stop is a no-op and must not issue another termination request.
	if _, err := service.Stop("profile-1"); err != nil {
		t.Fatalf("second owned Stop: %v", err)
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("owned StopProcess calls after second Stop = %d, want 1", got)
	}
}

func TestP18ShutdownLeavesUnownedAndRecoveredRuntimesUntouched(t *testing.T) {
	for _, test := range []struct {
		name           string
		managerProcess bool
	}{
		{name: "unowned manager process", managerProcess: true},
		{name: "recovered runtime", managerProcess: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			var stopCalls atomic.Int32
			host := BrowserRuntimeHost{
				StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
					return nil, errors.New("unused StartProcess in unowned shutdown fixture")
				},
				StopProcess: func(*exec.Cmd) error {
					stopCalls.Add(1)
					return nil
				},
			}
			service, manager := newRuntimeStartServiceTest(t, host)
			manager.Mutex.Lock()
			profile := manager.Profiles["profile-1"]
			profile.Running = true
			profile.DebugReady = true
			profile.Pid = 4191
			profile.DebugPort = 9812
			if test.managerProcess {
				if manager.BrowserProcesses == nil {
					manager.BrowserProcesses = make(map[string]*exec.Cmd)
				}
				manager.BrowserProcesses[profile.ProfileId] = exec.Command("/bin/sleep", "30")
			}
			manager.Mutex.Unlock()

			if err := service.Shutdown(); err != nil {
				t.Fatalf("Shutdown: %v", err)
			}
			if got := stopCalls.Load(); got != 0 {
				t.Fatalf("unowned/recovered StopProcess calls = %d, want 0", got)
			}
			manager.Mutex.Lock()
			current := copyBrowserProfileSnapshot(manager.Profiles["profile-1"])
			manager.Mutex.Unlock()
			if current == nil || !current.Running || !current.DebugReady || current.Pid != 4191 || current.DebugPort != 9812 {
				t.Fatalf("unowned/recovered profile changed by Shutdown: %+v", current)
			}
		})
	}
}

func TestP18ShutdownBoundsBlockedStartAndLateStartSelfCleans(t *testing.T) {
	startEntered := make(chan struct{})
	releaseStart := make(chan struct{})
	var releaseStartOnce sync.Once
	release := func() { releaseStartOnce.Do(func() { close(releaseStart) }) }
	defer release()
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	processCh := make(chan struct {
		process *BrowserRuntimeProcess
		cmd     *exec.Cmd
	}, 1)
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			process, cmd := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
			processCh <- struct {
				process *BrowserRuntimeProcess
				cmd     *exec.Cmd
			}{process: process, cmd: cmd}
			close(startEntered)
			<-releaseStart
			return process, nil
		},
		StopProcess: func(cmd *exec.Cmd) error {
			stopCalls.Add(1)
			if cmd != nil && cmd.Process != nil {
				if err := cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
					return err
				}
			}
			return nil
		},
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	service.shutdownWaitTimeout = 40 * time.Millisecond
	startResult := make(chan struct {
		profile *BrowserProfile
		err     error
	}, 1)
	go func() {
		profile, err := service.Start("profile-1")
		startResult <- struct {
			profile *BrowserProfile
			err     error
		}{profile: profile, err: err}
	}()
	select {
	case <-startEntered:
	case <-time.After(time.Second):
		t.Fatal("Start did not reach blocked host callback")
	}
	started := <-processCh

	shutdownStarted := time.Now()
	shutdownErr := service.Shutdown()
	if elapsed := time.Since(shutdownStarted); elapsed > 500*time.Millisecond {
		t.Fatalf("blocked-start Shutdown took %s, want bounded return", elapsed)
	}
	if !errors.Is(shutdownErr, ErrBrowserRuntimeShutdownTimeout) {
		t.Fatalf("blocked-start Shutdown error = %v, want ErrBrowserRuntimeShutdownTimeout", shutdownErr)
	}

	release()
	var result struct {
		profile *BrowserProfile
		err     error
	}
	select {
	case result = <-startResult:
	case <-time.After(time.Second):
		t.Fatal("late Start did not return after host release")
	}
	if !errors.Is(result.err, ErrBrowserRuntimeServiceShutdown) {
		t.Fatalf("late Start error = %v, want ErrBrowserRuntimeServiceShutdown", result.err)
	}
	select {
	case <-started.process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("late-start process owner did not reap")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("late-start cleanup calls = %d, want 1", got)
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("late-start StopProcess calls = %d, want 1", got)
	}
	if service.processFor("profile-1") != nil || len(service.ownedProcessSnapshots()) != 0 || service.hasPendingReap("profile-1") {
		t.Fatal("late-start process remained owned or pending after self-cleanup")
	}
	if err := service.Shutdown(); err != nil {
		t.Fatalf("second Shutdown after late-start cleanup: %v", err)
	}
}

func TestP18ShutdownRejectsStartAfterAdmissionClosed(t *testing.T) {
	var startCalls atomic.Int32
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			return nil, errors.New("StartProcess must not run after Shutdown")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	if err := service.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if _, err := service.Start("profile-1"); !errors.Is(err, ErrBrowserRuntimeServiceShutdown) {
		t.Fatalf("Start after Shutdown error = %v, want ErrBrowserRuntimeServiceShutdown", err)
	}
	if got := startCalls.Load(); got != 0 {
		t.Fatalf("StartProcess calls after Shutdown = %d, want 0", got)
	}
}

type p18ShutdownPendingOwner struct {
	done chan struct{}
	once sync.Once
}

func newP18ShutdownPendingOwner() *p18ShutdownPendingOwner {
	return &p18ShutdownPendingOwner{done: make(chan struct{})}
}

func (o *p18ShutdownPendingOwner) Done() <-chan struct{} { return o.done }
func (o *p18ShutdownPendingOwner) Result() error         { return nil }
func (o *p18ShutdownPendingOwner) finish()               { o.once.Do(func() { close(o.done) }) }

func TestP18ShutdownPendingActiveReleasesProfileGateForStatus(t *testing.T) {
	owner := newP18ShutdownPendingOwner()
	defer owner.finish()
	var cleanupCalls atomic.Int32
	var stopCalls atomic.Int32
	stopEntered := make(chan struct{})
	var stopEnteredOnce sync.Once
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			return nil, errors.New("unused StartProcess in pending shutdown fixture")
		},
		StopProcess: func(*exec.Cmd) error {
			stopCalls.Add(1)
			stopEnteredOnce.Do(func() { close(stopEntered) })
			return nil
		},
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	service.shutdownWaitTimeout = 40 * time.Millisecond
	cmd := &exec.Cmd{Process: &os.Process{Pid: 49991}}
	process, err := NewBrowserRuntimeProcess(cmd, owner, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	if err != nil {
		t.Fatalf("pending process: %v", err)
	}
	profile := manager.Profiles["profile-1"]
	identity := service.markRunning(profile.ProfileId, profile, cmd, cmd.Process.Pid, 9813, true, "")
	service.trackProcess(profile.ProfileId, process, identity)

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- service.Shutdown() }()
	select {
	case <-stopEntered:
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not reach active process stop")
	}
	statusResult := make(chan struct {
		profile *browser.Profile
		err     error
	}, 1)
	go func() {
		status, statusErr := service.Status(profile.ProfileId)
		statusResult <- struct {
			profile *browser.Profile
			err     error
		}{profile: status, err: statusErr}
	}()
	select {
	case result := <-statusResult:
		t.Fatalf("Status returned while Shutdown held profile gate: %+v", result)
	case <-time.After(10 * time.Millisecond):
	}

	var shutdownErr error
	select {
	case shutdownErr = <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("pending Shutdown did not return within bounded timeout")
	}
	if !errors.Is(shutdownErr, ErrBrowserRuntimeReapPending) {
		t.Fatalf("pending Shutdown error = %v, want ErrBrowserRuntimeReapPending", shutdownErr)
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("pending Shutdown StopProcess calls = %d, want 1", got)
	}
	if !service.hasPendingReap(profile.ProfileId) {
		t.Fatal("pending active process was not retained for late reap")
	}

	select {
	case result := <-statusResult:
		if result.err != nil {
			t.Fatalf("Status after pending Shutdown: %v", result.err)
		}
		if result.profile == nil || !result.profile.Running || !result.profile.DebugReady || result.profile.Pid != cmd.Process.Pid {
			t.Fatalf("Status after pending Shutdown = %+v, want running active snapshot", result.profile)
		}
	case <-time.After(time.Second):
		t.Fatal("Status remained blocked after pending Shutdown released profile gate")
	}

	owner.finish()
	deadline := time.Now().Add(time.Second)
	for (service.hasPendingReap(profile.ProfileId) || cleanupCalls.Load() != 1) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.hasPendingReap(profile.ProfileId) || cleanupCalls.Load() != 1 {
		t.Fatalf("late pending cleanup = pending:%v calls:%d", service.hasPendingReap(profile.ProfileId), cleanupCalls.Load())
	}
	if _, stopped := service.stopState(host, profile.ProfileId, &identity); !stopped {
		t.Fatal("pending fixture did not clean its fenced profile state")
	}
}

func TestP18ShutdownConcurrentStopAndShutdownIssueOneStop(t *testing.T) {
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	var stoppedCalls atomic.Int32
	stopEntered := make(chan struct{})
	var stopEnteredOnce sync.Once
	releaseStop := make(chan struct{})
	var releaseStopOnce sync.Once
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			return nil, errors.New("unused StartProcess in concurrent shutdown fixture")
		},
		StopProcess: func(cmd *exec.Cmd) error {
			call := stopCalls.Add(1)
			if call == 1 {
				stopEnteredOnce.Do(func() { close(stopEntered) })
				<-releaseStop
			}
			if cmd == nil || cmd.Process == nil {
				return errors.New("missing process")
			}
			if err := cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
				return err
			}
			return nil
		},
		EmitStopped: func(string) { stoppedCalls.Add(1) },
	}
	service, manager := newRuntimeStartServiceTest(t, host)
	process, cmd := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	identity := service.markRunning("profile-1", manager.Profiles["profile-1"], cmd, cmd.Process.Pid, 9814, true, "")
	service.trackProcess("profile-1", process, identity)
	defer releaseStopOnce.Do(func() { close(releaseStop) })

	shutdownDone := make(chan error, 1)
	go func() { shutdownDone <- service.Shutdown() }()
	select {
	case <-stopEntered:
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not reach process stop")
	}

	stopDone := make(chan error, 1)
	go func() {
		_, err := service.Stop("profile-1")
		stopDone <- err
	}()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		service.gatesMu.Lock()
		gate := service.gates["profile-1"]
		refs := 0
		if gate != nil {
			refs = gate.refs
		}
		service.gatesMu.Unlock()
		if refs >= 2 {
			break
		}
		time.Sleep(time.Millisecond)
	}

	releaseStopOnce.Do(func() { close(releaseStop) })
	select {
	case err := <-shutdownDone:
		if err != nil {
			t.Fatalf("concurrent Shutdown: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Shutdown did not return")
	}
	select {
	case err := <-stopDone:
		if err != nil {
			t.Fatalf("concurrent Stop: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("concurrent Stop did not return")
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("concurrent process owner did not reap")
	}
	if got := stopCalls.Load(); got != 1 {
		t.Fatalf("concurrent Stop/Shutdown StopProcess calls = %d, want 1", got)
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("concurrent Stop/Shutdown cleanup calls = %d, want 1", got)
	}
	if got := stoppedCalls.Load(); got != 1 {
		t.Fatalf("concurrent Stop/Shutdown stopped events = %d, want 1", got)
	}
	if service.processFor("profile-1") != nil || len(service.ownedProcessSnapshots()) != 0 {
		t.Fatal("concurrent Stop/Shutdown left process owned")
	}
}
