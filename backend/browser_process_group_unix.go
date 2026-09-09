//go:build !windows

package backend

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
	"time"
)

func configureBrowserProcessCommand(cmd *exec.Cmd) {
	if cmd != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
}

func stopBrowserProcessGroup(cmd *exec.Cmd) (bool, error) {
	if cmd == nil || cmd.Process == nil || cmd.Process.Pid <= 0 {
		return false, nil
	}
	pid := cmd.Process.Pid
	groupID, err := syscall.Getpgid(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return true, nil
		}
		return false, nil
	}
	if groupID != pid {
		return false, nil
	}
	if err := syscall.Kill(-groupID, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		return true, err
	}
	if waitBrowserProcessGroupExit(groupID, 2*time.Second) {
		return true, nil
	}
	if err := syscall.Kill(-groupID, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return true, err
	}
	if !waitBrowserProcessGroupExit(groupID, 2*time.Second) {
		return true, fmt.Errorf("browser process group %d remained alive after forced termination", groupID)
	}
	return true, nil
}

func waitBrowserProcessGroupExit(groupID int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if err := syscall.Kill(-groupID, 0); errors.Is(err, syscall.ESRCH) {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.Is(syscall.Kill(-groupID, 0), syscall.ESRCH)
}
