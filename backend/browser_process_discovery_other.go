//go:build !windows
// +build !windows

package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func findBrowserUserDataProcessesOS(userDataDir string) ([]browserUserDataProcess, error) {
	if strings.TrimSpace(userDataDir) == "" {
		return nil, nil
	}

	fullUserDataDir, err := filepath.Abs(userDataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve browser user-data directory: %w", err)
	}
	return findBrowserUserDataProcessesNativeOS(filepath.Clean(fullUserDataDir))
}

// browserProcessCandidateFromArgs turns one OS-provided argv into a browser
// process record. The platform readers deliberately provide argv as a slice;
// splitting ps-style text cannot distinguish spaces inside a quoted path from
// argument separators. Keep this check conservative: only a browser's main
// process can be adopted, and it must have a fixed, valid debugging port.
func browserProcessCandidateFromArgs(pid int, args []string, targetUserDataDir string) (browserUserDataProcess, bool) {
	if pid <= 0 || len(args) == 0 {
		return browserUserDataProcess{}, false
	}
	if browserProcessIsHelper(args) {
		return browserUserDataProcess{}, false
	}

	processUserDataDir, ok := browserProcessFlagValue(args, "--user-data-dir")
	if !ok || !browserUserDataDirsEqual(processUserDataDir, targetUserDataDir) {
		return browserUserDataProcess{}, false
	}

	debugPort, ok := browserProcessDebugPort(args)
	if !ok {
		return browserUserDataProcess{}, false
	}

	return browserUserDataProcess{
		PID:         pid,
		DebugPort:   debugPort,
		CommandLine: formatBrowserProcessCommandLine(args),
	}, true
}

func browserProcessIsHelper(args []string) bool {
	if len(args) == 0 {
		return true
	}

	executable := strings.ToLower(filepath.Base(args[0]))
	for _, marker := range []string{"helper", "crashpad", "renderer", "utility", "gpu-process"} {
		if strings.Contains(executable, marker) {
			return true
		}
	}
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if arg == "--type" || strings.HasPrefix(arg, "--type=") {
			return true
		}
	}
	return false
}

func browserProcessFlagValue(args []string, flag string) (string, bool) {
	var value string
	occurrences := 0
	for index := 1; index < len(args); index++ {
		arg := args[index]
		if strings.HasPrefix(arg, flag+"=") {
			value = strings.TrimPrefix(arg, flag+"=")
			if value == "" {
				return "", false
			}
			occurrences++
			continue
		}
		if arg == flag && index+1 < len(args) {
			value = args[index+1]
			if value == "" {
				return "", false
			}
			occurrences++
			index++
			continue
		}
	}
	return value, occurrences == 1
}

func browserUserDataDirsEqual(candidate, target string) bool {
	if candidate == "" || target == "" || !filepath.IsAbs(candidate) || !filepath.IsAbs(target) {
		return false
	}

	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return false
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return false
	}
	return filepath.Clean(candidateAbs) == filepath.Clean(targetAbs)
}

func browserProcessDebugPort(args []string) (int, bool) {
	value, ok := browserProcessFlagValue(args, "--remote-debugging-port")
	if !ok {
		return 0, false
	}
	port, err := strconv.Atoi(value)
	if err != nil || port < 1 || port > 65535 {
		return 0, false
	}
	return port, true
}

// formatBrowserProcessCommandLine only exists for the legacy fingerprint
// recovery path. It is not logged. Quote whitespace-bearing arguments so the
// existing parser preserves user-data paths containing spaces and non-ASCII.
func formatBrowserProcessCommandLine(args []string) string {
	parts := make([]string, 0, len(args))
	for _, arg := range args {
		if strings.ContainsAny(arg, " \t\r\n") {
			parts = append(parts, `"`+strings.ReplaceAll(arg, `"`, `\"`)+`"`)
			continue
		}
		parts = append(parts, arg)
	}
	return strings.Join(parts, " ")
}

func terminateBrowserUserDataProcessOS(pid int, timeout time.Duration) error {
	if pid <= 0 {
		return nil
	}
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	if err := process.Kill(); err != nil {
		return err
	}
	return fmt.Errorf("process termination fallback does not wait for pid %d", pid)
}
