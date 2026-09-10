//go:build darwin

package backend

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

const farmClientLaunchAgentLabel = "com.antfarm.client"

type farmClientDarwinAutostart struct {
	home string
	run  func(string, ...string) error
}

func newFarmClientAutostartManager() farmClientAutostartManager {
	home, _ := os.UserHomeDir()
	return &farmClientDarwinAutostart{home: home, run: func(name string, args ...string) error {
		return exec.Command(name, args...).Run()
	}}
}

func (m *farmClientDarwinAutostart) path() string {
	return filepath.Join(m.home, "Library", "LaunchAgents", farmClientLaunchAgentLabel+".plist")
}

func farmClientLaunchAgentPlist(executablePath, configPath string) []byte {
	var executable, config bytes.Buffer
	_ = xml.EscapeText(&executable, []byte(executablePath))
	_ = xml.EscapeText(&config, []byte(configPath))
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>` + farmClientLaunchAgentLabel + `</string>
<key>ProgramArguments</key><array><string>` + executable.String() + `</string><string>-config</string><string>` + config.String() + `</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Interactive</string>
</dict></plist>
`)
}

func (m *farmClientDarwinAutostart) domain() string {
	return "gui/" + strconv.Itoa(os.Getuid())
}

func (m *farmClientDarwinAutostart) Install(executablePath, configPath string) error {
	if m.home == "" {
		return fmt.Errorf("%w: user home unavailable", ErrFarmClientAutostart)
	}
	path := m.path()
	_ = m.run("launchctl", "bootout", m.domain(), path)
	if err := farmClientAtomicWrite(path, farmClientLaunchAgentPlist(executablePath, configPath), 0o600); err != nil {
		return err
	}
	if err := m.run("launchctl", "bootstrap", m.domain(), path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("%w: launchctl bootstrap", ErrFarmClientAutostart)
	}
	if err := m.run("launchctl", "enable", m.domain()+"/"+farmClientLaunchAgentLabel); err != nil {
		_ = m.run("launchctl", "bootout", m.domain(), path)
		_ = os.Remove(path)
		return fmt.Errorf("%w: launchctl enable", ErrFarmClientAutostart)
	}
	return nil
}

func (m *farmClientDarwinAutostart) Remove() error {
	path := m.path()
	_ = m.run("launchctl", "bootout", m.domain(), path)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%w: remove LaunchAgent", ErrFarmClientAutostart)
	}
	return nil
}

func (m *farmClientDarwinAutostart) Status() (FarmClientAutostartStatus, error) {
	_, err := os.Stat(m.path())
	installed := err == nil
	if err != nil && !os.IsNotExist(err) {
		return FarmClientAutostartStatus{}, fmt.Errorf("%w: inspect LaunchAgent", ErrFarmClientAutostart)
	}
	active := m.run("launchctl", "print", m.domain()+"/"+farmClientLaunchAgentLabel) == nil
	return FarmClientAutostartStatus{Installed: installed, Active: active, Method: "launchagent"}, nil
}
