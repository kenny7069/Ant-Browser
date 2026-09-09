//go:build linux

package backend

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

const farmClientSystemdUnitName = "ant-farm-client.service"

type farmClientLinuxAutostart struct {
	home string
	run  func(string, ...string) error
}

func newFarmClientAutostartManager() farmClientAutostartManager {
	home, _ := os.UserHomeDir()
	return &farmClientLinuxAutostart{home: home, run: func(name string, args ...string) error {
		return exec.Command(name, args...).Run()
	}}
}

func (m *farmClientLinuxAutostart) systemdPath() string {
	return filepath.Join(m.home, ".config", "systemd", "user", farmClientSystemdUnitName)
}

func (m *farmClientLinuxAutostart) desktopPath() string {
	return filepath.Join(m.home, ".config", "autostart", "ant-farm-client.desktop")
}

func farmClientSystemdQuote(value string) string {
	return strconv.Quote(strings.ReplaceAll(value, "%", "%%"))
}

func farmClientSystemdUnit(executablePath, configPath string) []byte {
	return []byte("[Unit]\nDescription=Ant Farm Client\nAfter=network-online.target graphical-session.target\nWants=network-online.target\n\n" +
		"[Service]\nType=simple\nExecStart=" + farmClientSystemdQuote(executablePath) + " -config " + farmClientSystemdQuote(configPath) + "\n" +
		"Restart=on-failure\nRestartSec=5\nKillMode=process\nTimeoutStopSec=30\n\n" +
		"[Install]\nWantedBy=default.target\n")
}

func farmClientDesktopQuote(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", "$", `\$`)
	return `"` + replacer.Replace(value) + `"`
}

func farmClientXDGDesktop(executablePath, configPath string) []byte {
	return []byte("[Desktop Entry]\nType=Application\nName=Ant Farm Client\n" +
		"Exec=" + farmClientDesktopQuote(executablePath) + " -config " + farmClientDesktopQuote(configPath) + "\n" +
		"Terminal=false\nX-GNOME-Autostart-enabled=true\n")
}

func (m *farmClientLinuxAutostart) Install(executablePath, configPath string) error {
	if m.home == "" {
		return fmt.Errorf("%w: user home unavailable", ErrFarmClientAutostart)
	}
	if m.run("systemctl", "--user", "show-environment") == nil {
		if err := farmClientAtomicWrite(m.systemdPath(), farmClientSystemdUnit(executablePath, configPath), 0o600); err != nil {
			return err
		}
		if err := m.run("systemctl", "--user", "daemon-reload"); err != nil {
			return fmt.Errorf("%w: systemd user daemon-reload", ErrFarmClientAutostart)
		}
		if err := m.run("systemctl", "--user", "enable", "--now", farmClientSystemdUnitName); err != nil {
			_ = os.Remove(m.systemdPath())
			_ = m.run("systemctl", "--user", "daemon-reload")
			return fmt.Errorf("%w: systemd user enable", ErrFarmClientAutostart)
		}
		_ = os.Remove(m.desktopPath())
		return nil
	}
	if err := farmClientAtomicWrite(m.desktopPath(), farmClientXDGDesktop(executablePath, configPath), 0o600); err != nil {
		return err
	}
	return nil
}

func (m *farmClientLinuxAutostart) Remove() error {
	_ = m.run("systemctl", "--user", "disable", "--now", farmClientSystemdUnitName)
	for _, path := range []string{m.systemdPath(), m.desktopPath()} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w: remove autostart file", ErrFarmClientAutostart)
		}
	}
	_ = m.run("systemctl", "--user", "daemon-reload")
	return nil
}

func (m *farmClientLinuxAutostart) Status() (FarmClientAutostartStatus, error) {
	if _, err := os.Stat(m.systemdPath()); err == nil {
		active := m.run("systemctl", "--user", "is-active", "--quiet", farmClientSystemdUnitName) == nil
		return FarmClientAutostartStatus{Installed: true, Active: active, Method: "systemd-user"}, nil
	} else if !os.IsNotExist(err) {
		return FarmClientAutostartStatus{}, fmt.Errorf("%w: inspect systemd unit", ErrFarmClientAutostart)
	}
	if _, err := os.Stat(m.desktopPath()); err == nil {
		return FarmClientAutostartStatus{Installed: true, Active: false, Method: "xdg-autostart"}, nil
	} else if !os.IsNotExist(err) {
		return FarmClientAutostartStatus{}, fmt.Errorf("%w: inspect XDG autostart", ErrFarmClientAutostart)
	}
	return FarmClientAutostartStatus{Method: "systemd-user"}, nil
}
