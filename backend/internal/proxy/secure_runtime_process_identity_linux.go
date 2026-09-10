//go:build linux

package proxy

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func secureRuntimeCurrentProcessIdentity() (secureRuntimeProcessIdentity, error) {
	return secureRuntimeProcessIdentityForPID(os.Getpid())
}

func secureRuntimeProcessIdentityForPID(pid int) (secureRuntimeProcessIdentity, error) {
	if pid <= 0 {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("invalid process id")
	}
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return secureRuntimeProcessIdentity{}, err
	}
	closeParen := strings.LastIndexByte(string(data), ')')
	if closeParen < 0 || closeParen+2 > len(data) {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("malformed process stat")
	}
	fields := strings.Fields(string(data)[closeParen+2:])
	// The slice starts at field 3 (state), so field 22 (starttime) is index 19.
	if len(fields) <= 19 || fields[19] == "" {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("missing process start identity")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("invalid process start identity: %w", err)
	}
	return secureRuntimeProcessIdentity{PID: pid, Start: fields[19]}, nil
}

func secureRuntimeProcessLiveness(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
	if !identity.valid() {
		return secureRuntimeProcessUnknown
	}
	current, err := secureRuntimeProcessIdentityForPID(identity.PID)
	if err != nil {
		if os.IsNotExist(err) {
			return secureRuntimeProcessExited
		}
		return secureRuntimeProcessUnknown
	}
	if current == identity {
		return secureRuntimeProcessAlive
	}
	return secureRuntimeProcessIdentityMismatch
}

func secureRuntimeOrphanSweepSupported() bool { return true }
