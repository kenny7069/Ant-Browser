package backend_test

import (
	"ant-chrome/backend"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type externalRuntimeMonitor struct{}

func (externalRuntimeMonitor) HasExited() bool { return true }

type externalRunningRuntimeMonitor struct{}

func (externalRunningRuntimeMonitor) HasExited() bool { return false }

func TestBrowserRuntimeExternalHostCanConstructTypedLaunchAndProcess(t *testing.T) {
	plan := &backend.BrowserRuntimeLaunchPlan{
		Spec: backend.BrowserRuntimeLaunchSpec{
			ProfileID:         "farm-profile",
			ChromeBinaryPath:  "/bin/chrome",
			Args:              []string{"--remote-debugging-port=9222"},
			AssignedDebugPort: 9222,
		},
	}
	if plan.Spec.ProfileID != "farm-profile" || plan.Spec.AssignedDebugPort != 9222 {
		t.Fatalf("typed launch spec was not externally readable: %+v", plan.Spec)
	}
	cmd := exec.Command("/usr/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	owner, err := backend.NewBrowserRuntimeCmdOwner(cmd)
	if err != nil {
		t.Fatal(err)
	}
	process, err := backend.NewBrowserRuntimeProcess(cmd, owner, externalRuntimeMonitor{}, nil)
	if err != nil || process == nil {
		t.Fatalf("external process construction failed: %v", err)
	}
	<-owner.Done()
}

func TestBrowserRuntimeExternalServiceFreshStartStatusStopAndShutdown(t *testing.T) {
	appRoot := t.TempDir()
	userDataRoot := t.TempDir()
	coreRoot := t.TempDir()
	chromePath := filepath.Join(coreRoot, "chrome")
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := backend.DefaultConfig()
	cfg.Browser.UserDataRoot = userDataRoot
	cfg.Browser.StartReadyTimeoutMs = 2000
	cfg.Browser.StartStableWindowMs = 20
	cfg.Browser.Cores = []backend.BrowserCore{{CoreId: "test-core", CoreName: "test", CorePath: coreRoot, IsDefault: true}}

	var startCalls atomic.Int32
	var stopCalls atomic.Int32
	var cleanupCalls atomic.Int32
	cleanupDone := make(chan struct{})
	var cleanupOnce sync.Once
	var owner backend.BrowserRuntimeProcessOwner
	var plannedProfileID string
	var plannedPort int
	var startedCalls atomic.Int32
	var stoppedCalls atomic.Int32
	host := backend.BrowserRuntimeHost{
		StartProcess: func(plan *backend.BrowserRuntimeLaunchPlan) (*backend.BrowserRuntimeProcess, error) {
			startCalls.Add(1)
			plannedProfileID = plan.Spec.ProfileID
			plannedPort = plan.Spec.AssignedDebugPort
			listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", plan.Spec.AssignedDebugPort))
			if err != nil {
				return nil, err
			}
			mux := http.NewServeMux()
			mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(`{"Browser":"external-test","webSocketDebuggerUrl":"ws://127.0.0.1/devtools"}`))
			})
			server := &http.Server{Handler: mux}
			go func() { _ = server.Serve(listener) }()

			cmd := exec.Command("/bin/sleep", "30")
			if err := cmd.Start(); err != nil {
				_ = server.Close()
				return nil, err
			}
			var ownerErr error
			owner, ownerErr = backend.NewBrowserRuntimeCmdOwner(cmd)
			if ownerErr != nil {
				_ = cmd.Process.Kill()
				_ = server.Close()
				return nil, ownerErr
			}
			cleanup := func() {
				cleanupOnce.Do(func() {
					cleanupCalls.Add(1)
					_ = server.Close()
					close(cleanupDone)
				})
			}
			return backend.NewBrowserRuntimeProcess(cmd, owner, externalRunningRuntimeMonitor{}, cleanup)
		},
		StopProcess: func(cmd *exec.Cmd) error {
			stopCalls.Add(1)
			if cmd == nil || cmd.Process == nil {
				return fmt.Errorf("missing child process")
			}
			return cmd.Process.Kill()
		},
		DetectRuntime: func(string) (backend.BrowserRuntimeDetection, bool) { return backend.BrowserRuntimeDetection{}, false },
		EmitStarted: func(profile *backend.BrowserProfile, _ bool) {
			if profile != nil && profile.Running && profile.DebugReady {
				startedCalls.Add(1)
			}
		},
		EmitStopped: func(string) { stoppedCalls.Add(1) },
	}
	service, err := backend.NewBrowserRuntimeServiceForHost(backend.BrowserRuntimeServiceFactoryConfig{
		AppRoot: appRoot,
		Config:  cfg,
		Profiles: []backend.BrowserProfile{{
			ProfileId:          "external-profile",
			ProfileName:        "External Profile",
			CoreId:             "test-core",
			UserDataDir:        t.TempDir(),
			RestoreLastSession: "never",
		}},
		Host: host,
	})
	if err != nil {
		t.Fatalf("NewBrowserRuntimeServiceForHost: %v", err)
	}
	before, err := service.Status("external-profile")
	if err != nil {
		t.Fatal(err)
	}
	if before.Running || before.DebugReady {
		t.Fatalf("fresh profile unexpectedly running: %+v", before)
	}
	started, err := service.StartWithOptions("external-profile", backend.BrowserRuntimeStartOptions{})
	if err != nil {
		t.Fatalf("StartWithOptions: %v", err)
	}
	if startCalls.Load() != 1 || plannedProfileID != "external-profile" || plannedPort <= 0 {
		t.Fatalf("launch callback = calls:%d profile:%q port:%d", startCalls.Load(), plannedProfileID, plannedPort)
	}
	if started == nil || !started.Running || !started.DebugReady || started.Pid <= 0 || started.DebugPort != plannedPort || started.LastStartAt == "" {
		t.Fatalf("fresh start result = %+v", started)
	}
	if startedCalls.Load() != 1 {
		t.Fatalf("started events = %d, want 1", startedCalls.Load())
	}
	generation := service.Generation("external-profile")
	if generation == 0 {
		t.Fatal("fresh Start did not publish a runtime generation")
	}
	status, err := service.Status("external-profile")
	if err != nil {
		t.Fatal(err)
	}
	if status.Pid != started.Pid || status.DebugPort != plannedPort || !status.Running || !status.DebugReady {
		t.Fatalf("Status after start = %+v, want started state", status)
	}

	stopped, err := service.Stop("external-profile")
	if err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if stopped == nil || stopped.Running || stopped.DebugReady || stopped.Pid != 0 || stopped.DebugPort != 0 {
		t.Fatalf("Stop result = %+v", stopped)
	}
	select {
	case <-owner.Done():
	case <-time.After(time.Second):
		t.Fatal("external child owner did not report reaped child")
	}
	select {
	case <-cleanupDone:
	case <-time.After(time.Second):
		t.Fatal("external process cleanup did not complete")
	}
	if stopCalls.Load() != 1 || cleanupCalls.Load() != 1 || stoppedCalls.Load() != 1 {
		t.Fatalf("stop lifecycle counts = stop:%d cleanup:%d stopped:%d", stopCalls.Load(), cleanupCalls.Load(), stoppedCalls.Load())
	}
	if err := service.Shutdown(); err != nil {
		t.Fatalf("Shutdown after Stop: %v", err)
	}
}

func TestBrowserRuntimeExternalServiceFactoryRejectsInvalidBoundary(t *testing.T) {
	validHost := backend.BrowserRuntimeHost{
		StartProcess: func(*backend.BrowserRuntimeLaunchPlan) (*backend.BrowserRuntimeProcess, error) { return nil, nil },
		StopProcess:  func(*exec.Cmd) error { return nil },
	}
	for _, test := range []struct {
		name string
		cfg  backend.BrowserRuntimeServiceFactoryConfig
	}{
		{name: "missing app root", cfg: backend.BrowserRuntimeServiceFactoryConfig{Host: validHost}},
		{name: "missing start capability", cfg: backend.BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Host: backend.BrowserRuntimeHost{StopProcess: validHost.StopProcess}}},
		{name: "missing stop capability", cfg: backend.BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Host: backend.BrowserRuntimeHost{StartProcess: validHost.StartProcess}}},
		{name: "missing profile id", cfg: backend.BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Host: validHost, Profiles: []backend.BrowserProfile{{ProfileName: "invalid"}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if service, err := backend.NewBrowserRuntimeServiceForHost(test.cfg); err == nil || service != nil {
				t.Fatalf("factory result = service:%v err:%v, want rejection", service, err)
			}
		})
	}
}
