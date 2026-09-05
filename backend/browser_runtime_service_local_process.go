package backend

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

// browserRuntimeLocalProcessOwner adapts the existing stderr/debug-port
// monitor to the explicit single-reaper contract. The monitor owns Cmd.Wait;
// this adapter only exposes its completion and already-published result.
type browserRuntimeLocalProcessOwner struct {
	monitor *browserProcessMonitor
}

func (o browserRuntimeLocalProcessOwner) Done() <-chan struct{} {
	if o.monitor == nil {
		return nil
	}
	return o.monitor.Done()
}

func (o browserRuntimeLocalProcessOwner) Result() error {
	if o.monitor == nil {
		return ErrBrowserRuntimeOwnerNotReady
	}
	return o.monitor.Result().Err
}

// NewBrowserRuntimeLocalProcess starts one local browser command and returns
// the opaque process handle used by BrowserRuntimeService. It is intentionally
// limited to launch-spec/OS primitives: readiness, profile state, events,
// deferred targets and proxy ownership remain service responsibilities.
//
// The command monitor is started immediately after Cmd.Start, before applying
// a platform memory limit. Therefore every post-Start failure has a real,
// already-running owner: teardown is bounded, and a still-live handle is
// returned with the error so BrowserRuntimeService can retain it in pending
// registry rather than losing process or launch-plan ownership.
func NewBrowserRuntimeLocalProcess(spec BrowserRuntimeLaunchSpec) (*BrowserRuntimeProcess, error) {
	binaryPath := strings.TrimSpace(spec.ChromeBinaryPath)
	if binaryPath == "" {
		return nil, fmt.Errorf("browser runtime local process: chrome binary path is required")
	}

	cmd := exec.Command(binaryPath, append([]string(nil), spec.Args...)...)
	cmd.Dir = filepath.Dir(binaryPath)
	monitor, err := newBrowserProcessMonitor(cmd)
	if err != nil {
		return nil, fmt.Errorf("browser runtime local process: stderr monitor setup failed: %w", err)
	}
	if err := cmd.Start(); err != nil {
		if monitor.stderr != nil {
			_ = monitor.stderr.Close()
		}
		return nil, fmt.Errorf("%s", describeChromeProcessStartError(binaryPath, err))
	}

	// Start establishes the sole Cmd.Wait owner before any operation that can
	// fail. The monitor also captures stderr and DevTools listening lines.
	monitor.Start()
	memoryCleanup, err := applyBrowserProcessMemoryLimit(cmd, spec.MemoryLimitMB)
	owner := browserRuntimeLocalProcessOwner{monitor: monitor}
	process, processErr := NewBrowserRuntimeProcess(cmd, owner, monitor, memoryCleanup)
	if processErr != nil {
		reapErr := stopAndReapLocalProcess(cmd, monitor)
		if memoryCleanup != nil {
			memoryCleanup()
		}
		return nil, joinLocalProcessErrors(processErr, reapErr)
	}
	if err != nil {
		memoryErr := fmt.Errorf("browser runtime local process: unable to apply memory limit %d MB: %w", spec.MemoryLimitMB, err)
		reapErr := stopAndCleanupBrowserRuntimeProcessWithPending(BrowserRuntimeHost{StopProcess: stopBrowserProcessCommand}, process, nil)
		// Keep the opaque handle on every post-Start error. When teardown has
		// already completed it is a closed owner/result for diagnostics; when it
		// timed out the service can retain the same handle in pending registry.
		return process, joinLocalProcessErrors(memoryErr, reapErr)
	}
	return process, nil
}

func stopAndReapLocalProcess(cmd *exec.Cmd, monitor *browserProcessMonitor) error {
	if cmd == nil || monitor == nil {
		return ErrInvalidBrowserRuntimeProcess
	}
	stopErr := stopBrowserProcessCommand(cmd)
	if browserRuntimeWaitOwnerUntil(monitor.Done(), browserRuntimeProcessReapTimeout) {
		return stopErr
	}
	return joinLocalProcessErrors(stopErr, fmt.Errorf("%w: local process owner did not terminate within %s", ErrBrowserRuntimeReapPending, browserRuntimeProcessReapTimeout))
}

func joinLocalProcessErrors(left, right error) error {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	return errors.Join(left, right)
}
