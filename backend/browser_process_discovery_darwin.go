//go:build darwin
// +build darwin

package backend

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"golang.org/x/sys/unix"
)

// findBrowserUserDataProcessesNativeOS reads only the Darwin process table and
// kern.procargs2. It does not inspect any Chrome files, profile contents, or
// environment variables.
func findBrowserUserDataProcessesNativeOS(targetUserDataDir string) ([]browserUserDataProcess, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return nil, fmt.Errorf("darwin process table query failed: %w", err)
	}

	currentUID := uint32(os.Getuid())
	result := make([]browserUserDataProcess, 0)
	for _, process := range processes {
		if process.Eproc.Pcred.P_ruid != currentUID {
			continue
		}
		pid := int(process.Proc.P_pid)
		args, readErr := readDarwinProcessArgv(pid)
		if readErr != nil {
			// Processes can exit between the table snapshot and argv read. A
			// transient read failure is fail-closed for that process.
			continue
		}
		if candidate, ok := browserProcessCandidateFromArgs(pid, args, targetUserDataDir); ok {
			result = append(result, candidate)
		}
	}

	sort.Slice(result, func(i, j int) bool { return result[i].PID < result[j].PID })
	return result, nil
}

func readDarwinProcessArgv(pid int) ([]string, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid process id %d", pid)
	}
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return nil, err
	}
	if len(raw) < 4 {
		return nil, fmt.Errorf("process %d argv payload is truncated", pid)
	}

	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	if argc <= 0 || argc > 4096 {
		return nil, fmt.Errorf("process %d argv count is invalid", pid)
	}
	payload := raw[4:]
	// kern.procargs2 stores the executable path before argv and may insert
	// additional NUL padding before argv begins.
	if executableEnd := bytes.IndexByte(payload, 0); executableEnd < 0 {
		return nil, fmt.Errorf("process %d executable argument is truncated", pid)
	} else {
		payload = payload[executableEnd+1:]
	}
	for len(payload) > 0 && payload[0] == 0 {
		payload = payload[1:]
	}

	args := make([]string, 0, argc)
	for index := 0; index < argc; index++ {
		end := bytes.IndexByte(payload, 0)
		if end < 0 {
			if index == argc-1 && len(payload) > 0 {
				args = append(args, string(payload))
				break
			}
			return nil, fmt.Errorf("process %d argv is truncated", pid)
		}
		args = append(args, string(payload[:end]))
		payload = payload[end+1:]
	}
	if len(args) != argc || args[0] == "" {
		return nil, fmt.Errorf("process %d argv is invalid", pid)
	}
	return args, nil
}
