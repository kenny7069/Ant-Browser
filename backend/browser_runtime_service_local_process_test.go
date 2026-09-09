package backend

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	stdruntime "runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func writeLocalProcessScript(t *testing.T, body string) string {
	t.Helper()
	path := t.TempDir() + "/browser-fixture"
	if err := os.WriteFile(path, []byte("#!/bin/sh\nset -eu\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func localProcessMonitor(t *testing.T, process *BrowserRuntimeProcess) *browserProcessMonitor {
	t.Helper()
	if process == nil {
		t.Fatal("local process is nil")
	}
	adapter, ok := process.monitor.(browserRuntimeMonitorAdapter)
	if !ok {
		t.Fatalf("local process monitor = %T, want browserRuntimeMonitorAdapter", process.monitor)
	}
	monitor, ok := adapter.monitor.(*browserProcessMonitor)
	if !ok {
		t.Fatalf("local process source monitor = %T, want browserProcessMonitor", adapter.monitor)
	}
	return monitor
}

func waitForLocalDebugPort(t *testing.T, monitor *browserProcessMonitor, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := monitor.DebugPort(); ok && got == want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("local process did not publish DevTools port %d", want)
}

func TestBrowserRuntimeLocalProcessFactoryCapturesStderrAndReapsOnce(t *testing.T) {
	const debugPort = 9771
	script := writeLocalProcessScript(t, fmt.Sprintf("printf 'DevTools listening on http://127.0.0.1:%d\\n' >&2\nprintf 'local-stderr-tail\\n' >&2\nwhile :; do sleep 1; done\n", debugPort))
	process, err := NewBrowserRuntimeLocalProcess(BrowserRuntimeLaunchSpec{ChromeBinaryPath: script})
	if err != nil {
		t.Fatalf("NewBrowserRuntimeLocalProcess: %v", err)
	}
	if process == nil || process.owner == nil || process.owner.Done() == nil {
		t.Fatal("local process did not expose a valid opaque owner")
	}
	monitor := localProcessMonitor(t, process)
	waitForLocalDebugPort(t, monitor, debugPort)
	deadline := time.Now().Add(time.Second)
	for !strings.Contains(monitor.stderrTail.String(), "local-stderr-tail") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if tail := monitor.stderrTail.String(); !strings.Contains(tail, "local-stderr-tail") {
		t.Fatalf("stderr tail = %q, want fixture marker", tail)
	}
	if err := process.cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
		t.Fatalf("kill local process: %v", err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("local process owner did not reap child")
	}
	if err := process.owner.Result(); err == nil {
		t.Fatal("killed local process owner result = nil, want exit error")
	}
	if result := monitor.Result(); result.Err == nil || !strings.Contains(result.StderrTail, "local-stderr-tail") {
		t.Fatalf("monitor result = %+v, want exit error and stderr tail", result)
	}
	process.cleanup()
	process.cleanup()
}

func TestBrowserRuntimeLocalProcessFactoryEarlyExitPublishesResult(t *testing.T) {
	script := writeLocalProcessScript(t, "printf 'early-exit-marker\\n' >&2\nexit 7\n")
	process, err := NewBrowserRuntimeLocalProcess(BrowserRuntimeLaunchSpec{ChromeBinaryPath: script})
	if err != nil {
		t.Fatalf("NewBrowserRuntimeLocalProcess: %v", err)
	}
	monitor := localProcessMonitor(t, process)
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("early-exit owner did not finish")
	}
	result := monitor.Result()
	if result.Err == nil || !strings.Contains(result.StderrTail, "early-exit-marker") {
		t.Fatalf("early-exit result = %+v", result)
	}
	if !monitor.HasExited() {
		t.Fatal("early-exit monitor did not report exited")
	}
	process.cleanup()
}

func TestBrowserRuntimeLocalProcessFactoryRejectsStartAndSetupFailures(t *testing.T) {
	if process, err := NewBrowserRuntimeLocalProcess(BrowserRuntimeLaunchSpec{}); err == nil || process != nil {
		t.Fatalf("empty local process spec = process:%v err:%v, want rejection", process, err)
	}
	missing := t.TempDir() + "/missing-browser"
	if process, err := NewBrowserRuntimeLocalProcess(BrowserRuntimeLaunchSpec{ChromeBinaryPath: missing}); err == nil || process != nil {
		t.Fatalf("missing local executable = process:%v err:%v, want rejection", process, err)
	}
}

func TestBrowserRuntimeLocalProcessFactoryMemoryLimitFailureReapsChild(t *testing.T) {
	if stdruntime.GOOS == "windows" {
		t.Skip("Windows Job Object memory-limit success is platform-specific; this test covers the unsupported branch on the current host")
	}
	pidFile := t.TempDir() + "/child.pid"
	script := writeLocalProcessScript(t, "echo $$ > \"$1\"\nwhile :; do :; done\n")
	process, err := NewBrowserRuntimeLocalProcess(BrowserRuntimeLaunchSpec{
		ChromeBinaryPath: script,
		Args:             []string{pidFile},
		MemoryLimitMB:    32,
	})
	if process == nil || process.owner == nil {
		t.Fatal("memory-limit failure lost the opaque process owner")
	}
	if err == nil || !strings.Contains(err.Error(), "memory limit") {
		t.Fatalf("memory-limit failure = %v, want unsupported memory-limit error", err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("memory-limit failure owner did not reap child")
	}
	if result := localProcessMonitor(t, process).Result(); result.Err == nil {
		t.Fatal("memory-limit failure owner result = nil, want killed child result")
	}
	process.cleanup()
}

func TestBrowserRuntimeLocalProcessFactoryIntegratesWithServiceFreshStart(t *testing.T) {
	var cleanupCalls atomic.Int32
	cleanupDone := make(chan struct{})
	var localProcess *BrowserRuntimeProcess
	var listener *net.TCPListener
	host := BrowserRuntimeHost{}
	host.StartProcess = func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
		var err error
		listener, err = net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: plan.Spec.AssignedDebugPort})
		if err != nil {
			return nil, err
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"Browser":"local-factory-test","webSocketDebuggerUrl":"ws://127.0.0.1/devtools"}`))
		})
		server := &http.Server{Handler: mux}
		go func() { _ = server.Serve(listener) }()
		localProcess, err = NewBrowserRuntimeLocalProcess(plan.Spec)
		if err != nil {
			_ = server.Close()
			return nil, err
		}
		localProcess.adoptCleanup(func() {
			cleanupCalls.Add(1)
			_ = server.Close()
			close(cleanupDone)
		})
		return localProcess, nil
	}
	host.StopProcess = stopBrowserProcessCommand
	host.DetectRuntime = func(string) (BrowserRuntimeDetection, bool) { return BrowserRuntimeDetection{}, false }
	service, manager := newRuntimeStartServiceTest(t, host)
	chromePath := manager.Config.Browser.Cores[0].CorePath + "/chrome"
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\nset -eu\nwhile :; do :; done\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	started, err := service.Start("profile-1")
	if err != nil {
		t.Fatalf("service Start with local factory: %v", err)
	}
	if localProcess == nil || started == nil || started.Pid <= 0 || !started.DebugReady {
		t.Fatalf("local service start = profile:%+v process:%v", started, localProcess != nil)
	}
	if listener == nil {
		t.Fatal("local factory did not create CDP fixture")
	}
	stopped, err := service.Stop("profile-1")
	if err != nil {
		t.Fatalf("service Stop with local factory: %v", err)
	}
	if stopped == nil || stopped.Running || stopped.Pid != 0 || stopped.DebugPort != 0 {
		t.Fatalf("local service stop = %+v", stopped)
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("local factory cleanup did not run")
	}
	if cleanupCalls.Load() != 1 {
		t.Fatalf("local factory cleanup calls = %d, want 1", cleanupCalls.Load())
	}
	if localProcess.owner == nil || localProcess.owner.Done() == nil {
		t.Fatal("local factory process owner disappeared")
	}
	select {
	case <-localProcess.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("service Stop did not reap local child")
	}
	if localProcess.owner.Result() == nil {
		// SIGKILL is expected to be reported by the sole owner. A nil result
		// would indicate that the service observed completion without reaping
		// the child, which is not a valid local-process lifecycle.
		t.Fatal("local child owner result unexpectedly nil after Stop")
	}
	if service.processFor("profile-1") != nil {
		t.Fatal("stopped local process remained tracked by service")
	}
}

func TestBrowserRuntimeServiceRetainsFactoryPendingProcessOnStartError(t *testing.T) {
	var cleanupCalls atomic.Int32
	process, _ := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, func() { cleanupCalls.Add(1) })
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			return process, ErrBrowserRuntimeReapPending
		},
		StopProcess: func(*exec.Cmd) error {
			t.Fatal("pending factory error must not issue a second stop before registry ownership")
			return nil
		},
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	if _, err := service.Start("profile-1"); err == nil || !errors.Is(err, ErrBrowserRuntimeReapPending) {
		t.Fatalf("Start pending factory error = %v, want ErrBrowserRuntimeReapPending", err)
	}
	if !service.hasPendingReap("profile-1") {
		t.Fatal("pending factory process was not retained by service registry")
	}
	if err := process.cmd.Process.Kill(); err != nil && !isProcessAlreadyFinished(err) {
		t.Fatal(err)
	}
	select {
	case <-process.owner.Done():
	case <-time.After(time.Second):
		t.Fatal("pending factory process owner did not finish")
	}
	deadline := time.Now().Add(time.Second)
	for service.hasPendingReap("profile-1") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if service.hasPendingReap("profile-1") || cleanupCalls.Load() != 1 {
		t.Fatalf("pending factory cleanup = pending:%v calls:%d", service.hasPendingReap("profile-1"), cleanupCalls.Load())
	}
}
