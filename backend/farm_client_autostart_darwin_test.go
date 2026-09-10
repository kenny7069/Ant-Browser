//go:build darwin

package backend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFarmClientDarwinAutostartUsesPerUserLaunchAgent(t *testing.T) {
	home := t.TempDir()
	var calls [][]string
	manager := &farmClientDarwinAutostart{home: home, run: func(name string, args ...string) error {
		calls = append(calls, append([]string{name}, args...))
		return nil
	}}
	executable := filepath.Join(home, `Ant & Farm Client`, "ant-farm-client")
	config := filepath.Join(home, `Config & State`, "client.yaml")
	if err := manager.Install(executable, config); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(manager.path())
	if err != nil {
		t.Fatal(err)
	}
	value := string(raw)
	for _, required := range []string{
		"<key>ProgramArguments</key>", "Ant &amp; Farm Client", "Config &amp; State",
		"<key>RunAtLoad</key><true/>", "<key>KeepAlive</key><true/>",
		"<key>ProcessType</key><string>Interactive</string>",
	} {
		if !strings.Contains(value, required) {
			t.Fatalf("LaunchAgent missing %q: %s", required, value)
		}
	}
	if strings.Contains(value, "/bin/sh") || len(calls) != 3 || calls[1][1] != "bootstrap" || calls[2][1] != "enable" {
		t.Fatalf("unsafe or incomplete LaunchAgent install: calls=%v plist=%s", calls, value)
	}
	status, err := manager.Status()
	if err != nil || !status.Installed || !status.Active || status.Method != "launchagent" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	if err := manager.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(manager.path()); !os.IsNotExist(err) {
		t.Fatalf("LaunchAgent survived removal: %v", err)
	}
}
