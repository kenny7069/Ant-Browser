package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
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
	// Use paths native to the runner. filepath.IsAbs("/users/farmer") is false
	// on Windows, even when the case is modelling a different target OS.
	base := t.TempDir()
	home := filepath.Join(base, "farmer")
	localAppData := filepath.Join(home, "AppData", "Local")
	xdgConfig := filepath.Join(base, "xdg", "config")
	xdgData := filepath.Join(base, "xdg", "data")
	xdgState := filepath.Join(base, "xdg", "state")
	env := func(key string) string {
		return map[string]string{"LOCALAPPDATA": localAppData, "XDG_CONFIG_HOME": xdgConfig, "XDG_DATA_HOME": xdgData, "XDG_STATE_HOME": xdgState}[key]
	}
	for _, tc := range []struct{ os, expected string }{
		{"windows", filepath.Join(localAppData, "AntSuite", "browser-data")},
		{"linux", filepath.Join(xdgData, "AntSuite", "browser-data")},
		{"darwin", filepath.Join(home, "Library", "Application Support", "AntSuite", "browser-data")},
	} {
		roots, err := resolveSuiteUserRoots(tc.os, home, env)
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
	if _, err := resolveSuiteUserRoots("linux", home, badEnv); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("relative XDG data: %v", err)
	}
	if _, err := resolveSuiteUserRoots("windows", home, func(string) string { return "" }); !errors.Is(err, ErrFarmClientRoots) {
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
	if err != nil || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
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

func TestSetupCheckpointRecoversInterruptedReplacement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setup.json")
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	precheck := SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}
	staged := SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: requestUID}
	if err := SaveSetupCheckpoint(path, precheck); err != nil {
		t.Fatal(err)
	}
	if err := SaveSetupCheckpoint(path, staged); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"stage":`), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadSetupCheckpoint(path)
	if err != nil || *loaded != precheck {
		t.Fatalf("backup recovery = %#v, %v", loaded, err)
	}
	if err := SaveSetupCheckpoint(path, staged); err != nil {
		t.Fatalf("resume after recovery: %v", err)
	}
	loaded, err = LoadSetupCheckpoint(path)
	if err != nil || *loaded != staged {
		t.Fatalf("resumed checkpoint = %#v, %v", loaded, err)
	}
	// An unknown field indicates a schema or security mismatch, not an
	// interrupted replacement; it must not be hidden by an older backup.
	if err := os.WriteFile(path, []byte(`{"schema_version":1,"stage":"STAGED","request_uid":"b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6","private_key":"secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSetupCheckpoint(path); !errors.Is(err, ErrSetupCheckpoint) {
		t.Fatalf("unknown field hidden by backup: %v", err)
	}
}

func TestSetupCheckpointRejectsUnsafePrimaryAndBackup(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	checkpoint := SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}
	raw, _ := json.Marshal(checkpoint)
	for _, location := range []string{"primary", "backup"} {
		for _, test := range []struct {
			name  string
			write func(*testing.T, string)
		}{
			{"oversize", func(t *testing.T, path string) {
				if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxSetupCheckpointBytes+1), 0o600); err != nil {
					t.Fatal(err)
				}
			}},
			{"directory", func(t *testing.T, path string) {
				if err := os.Mkdir(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}},
			{"symlink", func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "target.json")
				if err := os.WriteFile(target, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}},
		} {
			t.Run(location+" "+test.name, func(t *testing.T) {
				root := t.TempDir()
				path := filepath.Join(root, "setup.json")
				badPath, goodPath := path, path+".bak"
				if location == "backup" {
					badPath, goodPath = goodPath, badPath
				}
				if err := os.WriteFile(goodPath, append(raw, '\n'), 0o600); err != nil {
					t.Fatal(err)
				}
				test.write(t, badPath)
				if _, err := LoadSetupCheckpoint(path); !errors.Is(err, errSetupCheckpointUnsafeFile) {
					t.Fatalf("unsafe evidence error=%v", err)
				}
			})
		}
	}
	if runtime.GOOS != "windows" {
		for _, location := range []string{"primary", "backup"} {
			t.Run(location+" wrong mode", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "setup.json")
				badPath, goodPath := path, path+".bak"
				if location == "backup" {
					badPath, goodPath = goodPath, badPath
				}
				if err := os.WriteFile(goodPath, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(badPath, raw, 0o644); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadSetupCheckpoint(path); !errors.Is(err, errSetupCheckpointUnsafeFile) {
					t.Fatalf("wrong mode error=%v", err)
				}
			})
		}
	}
}

func TestSetupCheckpointClosedJSONCannotBeHiddenByOtherCopy(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	checkpoint := SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}
	valid, _ := json.Marshal(checkpoint)
	bad := map[string][]byte{
		"duplicate":         []byte(`{"schema_version":1,"stage":"PRECHECK","stage":"PRECHECK","request_uid":"b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"}`),
		"unknown":           []byte(`{"schema_version":1,"stage":"PRECHECK","request_uid":"b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6","private_key":"secret"}`),
		"unknown truncated": []byte(`{"schema_version":1,"private_key":"secret",`),
		"trailing":          append(append([]byte{}, valid...), []byte(` {}`)...),
	}
	for _, location := range []string{"primary", "backup"} {
		for name, malformed := range bad {
			t.Run(location+" "+name, func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "setup.json")
				badPath, goodPath := path, path+".bak"
				if location == "backup" {
					badPath, goodPath = goodPath, badPath
				}
				if err := os.WriteFile(goodPath, valid, 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(badPath, malformed, 0o600); err != nil {
					t.Fatal(err)
				}
				if _, err := LoadSetupCheckpoint(path); !errors.Is(err, ErrSetupCheckpoint) {
					t.Fatalf("closed JSON error=%v", err)
				}
			})
		}
	}
}

func TestSetupCheckpointPrimaryBackupConsistency(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	otherUID := "64473c80-0e26-4d7d-9b17-fd9cc6c959d8"
	for _, test := range []struct {
		name    string
		primary SetupCheckpoint
		backup  SetupCheckpoint
		valid   bool
	}{
		{"same stage", SetupCheckpoint{1, SetupStaged, requestUID}, SetupCheckpoint{1, SetupStaged, requestUID}, true},
		{"previous stage", SetupCheckpoint{1, SetupStaged, requestUID}, SetupCheckpoint{1, SetupPrecheck, requestUID}, true},
		{"future backup", SetupCheckpoint{1, SetupPrecheck, requestUID}, SetupCheckpoint{1, SetupStaged, requestUID}, false},
		{"nonadjacent backup", SetupCheckpoint{1, SetupConfigDrafted, requestUID}, SetupCheckpoint{1, SetupPrecheck, requestUID}, false},
		{"different request", SetupCheckpoint{1, SetupStaged, requestUID}, SetupCheckpoint{1, SetupPrecheck, otherUID}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "setup.json")
			if err := writeSetupCheckpointFile(path, test.primary); err != nil {
				t.Fatal(err)
			}
			if err := writeSetupCheckpointFile(path+".bak", test.backup); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadSetupCheckpoint(path)
			if test.valid {
				if err != nil || loaded == nil || *loaded != test.primary {
					t.Fatalf("loaded=%+v err=%v", loaded, err)
				}
			} else if !errors.Is(err, ErrSetupCheckpoint) {
				t.Fatalf("inconsistent evidence accepted: %+v", loaded)
			}
		})
	}
}

func TestSetupCheckpointMissingOrMalformedPrimaryRecoveryIsBounded(t *testing.T) {
	requestUID := "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6"
	backup := SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: requestUID}
	for _, test := range []struct {
		name       string
		primaryRaw []byte
	}{
		{"missing", nil},
		{"empty", []byte{}},
		{"truncated", []byte(`{"schema_version":1,"stage":`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "setup.json")
			if test.primaryRaw != nil {
				if err := os.WriteFile(path, test.primaryRaw, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := writeSetupCheckpointFile(path+".bak", backup); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadSetupCheckpoint(path)
			if err != nil || loaded == nil || *loaded != backup {
				t.Fatalf("loaded=%+v err=%v", loaded, err)
			}
			if err := SaveSetupCheckpoint(path, backup); err != nil {
				t.Fatalf("restore primary: %v", err)
			}
			if restored, err := LoadSetupCheckpoint(path); err != nil || restored == nil || *restored != backup {
				t.Fatalf("restored=%+v err=%v", restored, err)
			}
		})
	}

	t.Run("malformed backup cannot be hidden", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "setup.json")
		if err := writeSetupCheckpointFile(path, backup); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".bak", []byte(`{"schema_version":`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSetupCheckpoint(path); !errors.Is(err, ErrSetupCheckpoint) {
			t.Fatalf("malformed backup hidden: %v", err)
		}
	})

	t.Run("exact size limit", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "setup.json")
		raw, _ := json.Marshal(backup)
		raw = append(raw, bytes.Repeat([]byte{' '}, maxSetupCheckpointBytes-len(raw))...)
		if len(raw) != maxSetupCheckpointBytes {
			t.Fatal("bad boundary fixture")
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if loaded, err := LoadSetupCheckpoint(path); err != nil || loaded == nil || *loaded != backup {
			t.Fatalf("boundary loaded=%+v err=%v", loaded, err)
		}
	})
}
