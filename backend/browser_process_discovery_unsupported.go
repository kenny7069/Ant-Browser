//go:build !windows && !darwin && !linux
// +build !windows,!darwin,!linux

package backend

import "fmt"

func findBrowserUserDataProcessesNativeOS(string) ([]browserUserDataProcess, error) {
	return nil, fmt.Errorf("browser process discovery is unsupported on this platform")
}
