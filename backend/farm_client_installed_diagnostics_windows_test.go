//go:build windows

package backend

import (
	"fmt"
	"os/exec"
)

func c8NativeAutostartDiagnostic() string {
	query, queryErr := exec.Command("schtasks.exe", "/Query", "/TN", farmClientScheduledTaskName, "/XML").CombinedOutput()
	decoded := farmClientWindowsCommandText(query)
	if len(decoded) > 2000 {
		decoded = decoded[:2000]
	}
	rawPrefix := query
	if len(rawPrefix) > 128 {
		rawPrefix = rawPrefix[:128]
	}
	return fmt.Sprintf("query_err=%v decoded=%q raw_prefix=%x", queryErr, decoded, rawPrefix)
}
