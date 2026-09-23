//go:build !windows

package backend

import "context"

func probeSuiteDoctorSessionDisplay(context.Context) suiteDoctorProbeResult {
	return suiteDoctorProbeResult{Status: "UNKNOWN", Code: "PLATFORM_SESSION_PROBE_DEFERRED"}
}
