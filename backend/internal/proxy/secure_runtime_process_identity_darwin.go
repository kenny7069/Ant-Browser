//go:build darwin

package proxy

import (
	"fmt"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

func secureRuntimeCurrentProcessIdentity() (secureRuntimeProcessIdentity, error) {
	return secureRuntimeProcessIdentityForPID(os.Getpid())
}

func secureRuntimeProcessIdentityForPID(pid int) (secureRuntimeProcessIdentity, error) {
	if pid <= 0 {
		return secureRuntimeProcessIdentity{}, fmt.Errorf("invalid process id")
	}
	proc, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return secureRuntimeProcessIdentity{}, err
	}
	return secureRuntimeProcessIdentity{PID: pid, Start: strconv.FormatInt(proc.Proc.P_starttime.Sec, 10) + ":" + strconv.FormatInt(int64(proc.Proc.P_starttime.Usec), 10)}, nil
}

func secureRuntimeProcessLiveness(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
	if !identity.valid() {
		return secureRuntimeProcessUnknown
	}
	current, err := secureRuntimeProcessIdentityForPID(identity.PID)
	if err != nil {
		if err == unix.ESRCH {
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
