//go:build linux
// +build linux

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// findBrowserUserDataProcessesNativeOS reads Linux's NUL-separated argv
// metadata. It intentionally does not walk browser profile directories.
func findBrowserUserDataProcessesNativeOS(targetUserDataDir string) ([]browserUserDataProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("linux process table query failed: %w", err)
	}

	result := make([]browserUserDataProcess, 0)
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr != nil || pid <= 0 {
			continue
		}
		args, readErr := readLinuxProcessArgv(pid)
		if readErr != nil {
			// A process may exit or become inaccessible while /proc is being
			// enumerated. Skipping it is the safe result for recovery.
			continue
		}
		if candidate, ok := browserProcessCandidateFromArgs(pid, args, targetUserDataDir); ok {
			result = append(result, candidate)
		}
	}

	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func readLinuxProcessArgv(pid int) ([]string, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid process id %d", pid)
	}
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("process %d argv is empty", pid)
	}
	parts := strings.Split(string(raw), "\x00")
	if len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 || parts[0] == "" {
		return nil, fmt.Errorf("process %d argv is invalid", pid)
	}
	return parts, nil
}
