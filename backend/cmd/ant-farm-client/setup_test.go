package main

import (
	"ant-chrome/backend"
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func setupCommandFixture(t *testing.T) backend.SuiteUserRoots {
	t.Helper()
	root := t.TempDir()
	return backend.SuiteUserRoots{
		Config: filepath.Join(root, "config"), BrowserData: filepath.Join(root, "browser"),
		AgentState: filepath.Join(root, "state"), Logs: filepath.Join(root, "logs"),
	}
}

func withSetupRoots(t *testing.T, roots backend.SuiteUserRoots) {
	t.Helper()
	t.Setenv("FARM_V3_SETUP_ENABLED", "1")
	previous := resolveSetupUserRoots
	resolveSetupUserRoots = func() (backend.SuiteUserRoots, error) { return roots, nil }
	t.Cleanup(func() { resolveSetupUserRoots = previous })
}

func TestSetupSubcommandIsDisabledByDefault(t *testing.T) {
	t.Setenv("FARM_V3_SETUP_ENABLED", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"setup", "--server", "https://farm.example.test", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != setupExitInput || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var problem setupCommandError
	if err := json.Unmarshal(stderr.Bytes(), &problem); err != nil || problem.Code != "SETUP_DISABLED" {
		t.Fatalf("problem=%+v err=%v", problem, err)
	}
}

func TestSetupSubcommandParsesFlagsAfterPositionalCommand(t *testing.T) {
	roots := setupCommandFixture(t)
	withSetupRoots(t, roots)
	var stdout, stderr bytes.Buffer
	code := run([]string{"setup", "--server", "https://farm.example.test:8443", "--node-name", "Node One", "--json"}, strings.NewReader("secret-must-not-be-read"), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("run code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	var result setupCommandResult
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.PreparationState != backend.SetupBootstrapDrafted || result.Classification != backend.SuiteSetupFresh || result.RequestUID == "" || result.Connected || result.NextAction != "run_precheck" {
		t.Fatalf("result = %+v", result)
	}
	if strings.Contains(stdout.String(), "secret-must-not-be-read") {
		t.Fatal("setup read or exposed stdin before enrollment")
	}
}

func TestSetupSubcommandResumesWithStableRequestUID(t *testing.T) {
	roots := setupCommandFixture(t)
	withSetupRoots(t, roots)
	args := []string{"setup", "--server", "https://farm.example.test", "--node-name", "Node One", "--json"}
	var firstOut, secondOut, stderr bytes.Buffer
	if code := run(args, strings.NewReader(""), &firstOut, &stderr); code != 0 {
		t.Fatalf("first code=%d stderr=%q", code, stderr.String())
	}
	if code := run(args, strings.NewReader(""), &secondOut, &stderr); code != 0 {
		t.Fatalf("second code=%d stderr=%q", code, stderr.String())
	}
	var first, second setupCommandResult
	_ = json.Unmarshal(firstOut.Bytes(), &first)
	_ = json.Unmarshal(secondOut.Bytes(), &second)
	if first.RequestUID == "" || first.RequestUID != second.RequestUID || second.Classification != backend.SuiteSetupExisting {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestSetupSubcommandFailsClosedWithSafeJSONErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"missing server", []string{"setup", "--json"}},
		{"http server", []string{"setup", "--server", "http://farm.example.test", "--json"}},
		{"invalid node name", []string{"setup", "--server", "https://farm.example.test", "--node-name", "bad\nname", "--json"}},
		{"unknown flag", []string{"setup", "--server", "https://farm.example.test", "--enrollment-code", "CANARY-CODE", "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := setupCommandFixture(t)
			withSetupRoots(t, roots)
			var stdout, stderr bytes.Buffer
			code := run(tc.args, strings.NewReader(""), &stdout, &stderr)
			if code != setupExitInput || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			var problem setupCommandError
			if err := json.Unmarshal(stderr.Bytes(), &problem); err != nil || problem.Code == "" || problem.SafeMessage == "" || problem.Stage != "INPUT_VALIDATION" {
				t.Fatalf("problem=%+v err=%v raw=%q", problem, err, stderr.String())
			}
			if tc.name == "http server" && problem.Field != "server" {
				t.Fatalf("server error field = %q", problem.Field)
			}
			if tc.name == "invalid node name" && problem.Field != "node_name" {
				t.Fatalf("node error field = %q", problem.Field)
			}
			if strings.Contains(stderr.String(), "CANARY-CODE") {
				t.Fatal("unknown secret-like value leaked")
			}
		})
	}
}

func TestSetupSubcommandDoesNotExposeStatePathOverride(t *testing.T) {
	roots := setupCommandFixture(t)
	withSetupRoots(t, roots)
	var stdout, stderr bytes.Buffer
	code := run([]string{"setup", "--server", "https://farm.example.test", "--state-path", "/tmp/redirected.json", "--json"}, strings.NewReader(""), &stdout, &stderr)
	if code != setupExitInput || stdout.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if entries, _ := filepath.Glob(filepath.Join(roots.AgentState, "*")); len(entries) != 0 {
		t.Fatalf("invalid input wrote state: %v", entries)
	}
}
