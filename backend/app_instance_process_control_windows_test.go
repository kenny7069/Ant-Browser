//go:build windows

package backend

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStopBrowserProcessCommandTerminatesWindowsTree(t *testing.T) {
	readyPath := filepath.Join(t.TempDir(), "ready")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestFarmResourceTelemetryProcessHelper$")
	cmd.Env = append(os.Environ(), farmResourceTelemetryHelperRole+"=parent", "ANT_FARM_RESOURCE_TELEMETRY_HELPER_READY="+readyPath)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	childPID := 0
	defer func() {
		if childPID > 0 {
			if child, findErr := os.FindProcess(childPID); findErr == nil {
				_ = child.Kill()
			}
		}
		_ = cmd.Process.Kill()
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if raw, readErr := os.ReadFile(readyPath); readErr == nil {
			childPID, _ = strconv.Atoi(strings.TrimSpace(string(raw)))
			if childPID > 0 {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if childPID <= 0 {
		t.Fatal("process tree helper did not publish its child PID")
	}
	if err := stopBrowserProcessCommand(cmd); err != nil {
		t.Fatal(err)
	}
	_, _ = cmd.Process.Wait()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		rootAlive, _ := isProcessAliveWindows(cmd.Process.Pid)
		childAlive, _ := isProcessAliveWindows(childPID)
		if !rootAlive && !childAlive {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	rootAlive, _ := isProcessAliveWindows(cmd.Process.Pid)
	childAlive, _ := isProcessAliveWindows(childPID)
	t.Fatalf("Windows tree remained alive after stop: root=%v child=%v", rootAlive, childAlive)
}
