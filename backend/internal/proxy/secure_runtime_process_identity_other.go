//go:build !darwin && !linux && !windows

package proxy

import "fmt"

func secureRuntimeCurrentProcessIdentity() (secureRuntimeProcessIdentity, error) {
	return secureRuntimeProcessIdentity{}, fmt.Errorf("process start identity is unsupported on this platform")
}

func secureRuntimeProcessIdentityForPID(pid int) (secureRuntimeProcessIdentity, error) {
	return secureRuntimeProcessIdentity{}, fmt.Errorf("process start identity is unsupported on this platform")
}

func secureRuntimeProcessLiveness(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
	return secureRuntimeProcessUnknown
}

func secureRuntimeOrphanSweepSupported() bool { return false }
