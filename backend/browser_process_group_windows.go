//go:build windows

package backend

import "os/exec"

func configureBrowserProcessCommand(*exec.Cmd) {}

func stopBrowserProcessGroup(*exec.Cmd) (bool, error) { return false, nil }
