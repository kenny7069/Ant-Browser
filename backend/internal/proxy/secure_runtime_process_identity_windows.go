//go:build windows

package proxy

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows"
)

func secureRuntimeCurrentProcessIdentity() (secureRuntimeProcessIdentity, error) {
	return secureRuntimeProcessIdentityForPID(int(windows.GetCurrentProcessId()))
}

func secureRuntimeProcessIdentityForPID(pid int) (secureRuntimeProcessIdentity, error) {
	if pid <= 0 {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("invalid process id")
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return secureRuntimeProcessIdentity{}, err
	}
	defer windows.CloseHandle(handle)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return secureRuntimeProcessIdentity{}, err
	}
	start := (uint64(creation.HighDateTime) << 32) | uint64(creation.LowDateTime)
	return secureRuntimeProcessIdentity{PID: pid, Start: strconv.FormatUint(start, 10)}, nil
}

func secureRuntimeProcessLiveness(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
	if !identity.valid() {
		return secureRuntimeProcessUnknown
	}
	current, err := secureRuntimeProcessIdentityForPID(identity.PID)
	if err != nil {
		if err == windows.ERROR_INVALID_PARAMETER {
			return secureRuntimeProcessExited
		}
		return secureRuntimeProcessUnknown
	}
	if current == identity {
		return secureRuntimeProcessAlive
	}
	return secureRuntimeProcessIdentityMismatch
}

func secureRuntimeOrphanSweepSupported() bool { return false }
