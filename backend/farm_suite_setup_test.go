package backend

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapConfigRejectsUntrustedShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint.json")
	valid := BootstrapConfig{ServerURL: "https://farm.example.test:8443", StatePath: path, NodeName: "  Farmer One  "}
	if err := valid.Validate(); err != nil || valid.NodeName != "Farmer One" {
		t.Fatalf("valid bootstrap: %#v, %v", valid, err)
	}
	for _, raw := range []string{"http://farm.example.test", "https://user:pass@farm.example.test", "https://farm.example.test/path", "https://farm.example.test?x=y", "https://farm.example.test#fragment"} {
		config := BootstrapConfig{ServerURL: raw, StatePath: path, NodeName: "Farmer"}
		if err := config.Validate(); !errors.Is(err, ErrFarmClientConfig) {
			t.Errorf("server %q: want config error, got %v", raw, err)
		}
	}
	badPath := BootstrapConfig{ServerURL: "https://farm.example.test", StatePath: "relative.json", NodeName: "Farmer"}
	if err := badPath.Validate(); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("relative state path: %v", err)
	}
}

func TestSuiteUserRoots(t *testing.T) {
	env := func(key string) string {
		return map[string]string{"LOCALAPPDATA": "/users/farmer/AppData/Local", "XDG_CONFIG_HOME": "/xdg/config", "XDG_DATA_HOME": "/xdg/data", "XDG_STATE_HOME": "/xdg/state"}[key]
	}
	for _, tc := range []struct{ os, expected string }{
		{"windows", filepath.Join("/users/farmer/AppData/Local", "AntSuite", "browser-data")},
		{"linux", filepath.Join("/xdg/data", "AntSuite", "browser-data")},
		{"darwin", filepath.Join("/users/farmer", "Library", "Application Support", "AntSuite", "browser-data")},
	} {
		roots, err := resolveSuiteUserRoots(tc.os, "/users/farmer", env)
		if err != nil || roots.BrowserData != tc.expected {
			t.Errorf("%s roots = %#v, %v", tc.os, roots, err)
		}
		for _, path := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
			if !filepath.IsAbs(path) || strings.Contains(path, "%LOCALAPPDATA%") {
				t.Errorf("%s unresolved path %q", tc.os, path)
			}
		}
	}
	badEnv := func(key string) string {
		if key == "XDG_DATA_HOME" {
			return "relative/data"
		}
		return ""
	}
	if _, err := resolveSuiteUserRoots("linux", "/users/farmer", badEnv); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("relative XDG data: %v", err)
	}
	if _, err := resolveSuiteUserRoots("windows", "/users/farmer", func(string) string { return "" }); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("missing LOCALAPPDATA: %v", err)
	}
}

func TestSetupCheckpointResumesInOrderWithoutSecrets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-state", "setup.json")
	if current, err := LoadSetupCheckpoint(path); err != nil || current != nil {
		t.Fatalf("fresh checkpoint = %#v, %v", current, err)
	}
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	for _, stage := range setupStageOrder {
		checkpoint := SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: requestUID}
		if err := SaveSetupCheckpoint(path, checkpoint); err != nil {
			t.Fatalf("save %s: %v", stage, err)
		}
		if err := SaveSetupCheckpoint(path, checkpoint); err != nil {
			t.Fatalf("repeat %s: %v", stage, err)
		}
		loaded, err := LoadSetupCheckpoint(path)
		if err != nil || *loaded != checkpoint {
			t.Fatalf("load %s = %#v, %v", stage, loaded, err)
		}
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("checkpoint permission = %v, %v", info, err)
	}
	data, _ := os.ReadFile(path)
	for _, forbidden := range []string{"private_key", "enrollment_code", "cookie", "password"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("checkpoint contains %s", forbidden)
		}
	}
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("regression accepted: %v", err)
	}
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupReadyForManagement, RequestUID: "64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("new identity accepted: %v", err)
	}
}

func TestSetupCheckpointRejectsSkippedAndUnknownState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup.json")
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupEnrolled, RequestUID: requestUID}); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("skipped first stage: %v", err)
	}
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}); err != nil {
		t.Fatal(err)
	}
	if err := SaveSetupCheckpoint(path, SetupCheckpoint{SchemaVersion: 1, Stage: SetupEnrolled, RequestUID: requestUID}); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("skipped later stage: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"stage":"PRECHECK","request_uid":"b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6","private_key":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSetupCheckpoint(path); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("unknown secret field accepted: %v", err)
	}
}
