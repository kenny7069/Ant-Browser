//go:build windows

package backend

import (
	"context"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wtsConnectStateClass = 8
	desktopReadObjects   = 0x0001
	desktopSwitchDesktop = 0x0100
	smCMonitors          = 80
)

var (
	wtsAPI32                        = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSQuerySessionInformationW = wtsAPI32.NewProc("WTSQuerySessionInformationW")
	procWTSFreeMemory               = wtsAPI32.NewProc("WTSFreeMemory")
	user32Doctor                    = windows.NewLazySystemDLL("user32.dll")
	procOpenInputDesktop            = user32Doctor.NewProc("OpenInputDesktop")
	procCloseDesktop                = user32Doctor.NewProc("CloseDesktop")
	procGetSystemMetrics            = user32Doctor.NewProc("GetSystemMetrics")
)

func probeSuiteDoctorSessionDisplay(ctx context.Context) suiteDoctorProbeResult {
	if ctx == nil || ctx.Err() != nil {
		return suiteDoctorProbeResult{Status: "FAIL", Code: "SESSION_PROBE_CANCELLED", Retryable: true}
	}
	var sessionID uint32
	if windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &sessionID) != nil {
		return suiteDoctorProbeResult{Status: "UNKNOWN", Code: "SESSION_PROBE_FAILED"}
	}
	var buffer uintptr
	var bytesReturned uint32
	ok, _, _ := procWTSQuerySessionInformationW.Call(0, uintptr(sessionID), wtsConnectStateClass, uintptr(unsafe.Pointer(&buffer)), uintptr(unsafe.Pointer(&bytesReturned)))
	if ok == 0 || buffer == 0 || bytesReturned < 4 {
		if buffer != 0 {
			procWTSFreeMemory.Call(buffer)
		}
		return suiteDoctorProbeResult{Status: "UNKNOWN", Code: "SESSION_PROBE_FAILED"}
	}
	state := *(*uint32)(unsafe.Pointer(buffer))
	procWTSFreeMemory.Call(buffer)
	if state != windows.WTSActive {
		return suiteDoctorProbeResult{Status: "FAIL", Code: "USER_SESSION_INACTIVE", Retryable: true}
	}
	desktop, _, _ := procOpenInputDesktop.Call(0, 0, desktopReadObjects|desktopSwitchDesktop)
	if desktop == 0 {
		return suiteDoctorProbeResult{Status: "FAIL", Code: "DISPLAY_UNAVAILABLE", Retryable: true}
	}
	closed, _, _ := procCloseDesktop.Call(desktop)
	if closed == 0 {
		return suiteDoctorProbeResult{Status: "UNKNOWN", Code: "SESSION_PROBE_FAILED"}
	}
	monitors, _, _ := procGetSystemMetrics.Call(smCMonitors)
	if monitors == 0 {
		return suiteDoctorProbeResult{Status: "FAIL", Code: "DISPLAY_UNAVAILABLE", Retryable: true}
	}
	return suiteDoctorProbeResult{Status: "PASS", Code: "SESSION_DISPLAY_READY"}
}
