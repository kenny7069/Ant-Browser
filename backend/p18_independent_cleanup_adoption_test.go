package backend

import (
	"ant-chrome/backend/internal/proxy"
	"errors"
	"os/exec"
	"sync/atomic"
	"testing"
)

// A host may return a terminal handle together with an error after its own
// bounded cleanup. The service adopts launch-plan cleanup only after the host
// callback returns, so that cleanup must still run even when process cleanup
// has already fired.
func TestP18IndependentTerminalErrorHandleStillReleasesAdoptedLaunchPlan(t *testing.T) {
	const bridgeKey = "validator-bridge"
	var hostCleanupCalls atomic.Int32
	xrayMgr := proxy.NewXrayManager(nil, t.TempDir())
	defer xrayMgr.StopAll()
	xrayMgr.Bridges[bridgeKey] = &proxy.XrayBridge{NodeKey: bridgeKey, RefCount: 1}

	host := BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			// Model a launch plan that owns one acquired bridge without invoking a
			// real connector binary in this bounded lifecycle test.
			plan.acquiredProxyBridge = newProfileProxyBridgeRef(profileProxyBridgeEngineXray, bridgeKey)
			plan.releaseProxyBridge = true

			cmd := exec.Command("/usr/bin/true")
			if err := cmd.Start(); err != nil {
				return nil, err
			}
			owner, err := NewBrowserRuntimeCmdOwner(cmd)
			if err != nil {
				return nil, err
			}
			<-owner.Done()
			process, err := NewBrowserRuntimeProcess(cmd, owner, exitedRuntimeMonitor{}, func() {
				hostCleanupCalls.Add(1)
			})
			if err != nil {
				return nil, err
			}
			// This is the exact terminal+already-cleaned ordering produced by a
			// local factory that finished its own error teardown.
			process.cleanup()
			return process, errors.New("host setup failed after child exit")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
		DetectRuntime: func(string) (BrowserRuntimeDetection, bool) {
			return BrowserRuntimeDetection{}, false
		},
	}
	service, _ := newRuntimeStartServiceTest(t, host)
	service.xrayMgr = xrayMgr
	if _, err := service.Start("profile-1"); err == nil {
		t.Fatal("Start unexpectedly succeeded")
	}
	if got := hostCleanupCalls.Load(); got != 1 {
		t.Fatalf("host cleanup calls = %d, want 1", got)
	}
	bridge := xrayMgr.Bridges[bridgeKey]
	if bridge == nil || bridge.RefCount != 0 {
		t.Fatalf("adopted launch-plan bridge refcount = %+v, want 0", bridge)
	}
}
