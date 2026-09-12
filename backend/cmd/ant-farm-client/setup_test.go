package main

import (
	"ant-chrome/backend"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
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

func withCanonicalSetupRunner(t *testing.T, runner func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, io.Reader, io.Writer) (setupCommandResult, error)) {
	t.Helper()
	previous := executeCanonicalSetup
	executeCanonicalSetup = runner
	t.Cleanup(func() { executeCanonicalSetup = previous })
}

func successfulSetupRunner(_ context.Context, _ backend.BootstrapConfig, _ backend.SuiteUserRoots, _ io.Reader, _ io.Writer) (setupCommandResult, error) {
	return setupCommandResult{State: backend.SetupEnrolled, NextAction: "service_activation"}, nil
}

type setupPanicReader struct{}

func (setupPanicReader) Read([]byte) (int, error) { panic("setup unexpectedly read enrollment input") }

func TestSetupSubcommandDefaultOffGateHasNoSideEffects(t *testing.T) {
	for _, value := range []string{"", "false", "unknown"} {
		name := value
		if name == "" {
			name = "unset"
		}
		t.Run(name, func(t *testing.T) {
			t.Setenv("FARM_V3_SETUP_ENABLED", "restore-after-test")
			if value == "" {
				if err := os.Unsetenv("FARM_V3_SETUP_ENABLED"); err != nil {
					t.Fatal(err)
				}
			} else {
				t.Setenv("FARM_V3_SETUP_ENABLED", value)
			}
			rootCalls, canonicalCalls := 0, 0
			previousRoots := resolveSetupUserRoots
			resolveSetupUserRoots = func() (backend.SuiteUserRoots, error) {
				rootCalls++
				return backend.SuiteUserRoots{}, errors.New("must not resolve roots")
			}
			t.Cleanup(func() { resolveSetupUserRoots = previousRoots })
			withCanonicalSetupRunner(t, func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, io.Reader, io.Writer) (setupCommandResult, error) {
				canonicalCalls++
				return setupCommandResult{}, errors.New("must not execute setup")
			})
			var stdout, stderr bytes.Buffer
			code := run([]string{"setup", "--server", "value-that-must-not-be-parsed", "--json"}, setupPanicReader{}, &stdout, &stderr)
			if code != setupExitInput || stdout.Len() != 0 || rootCalls != 0 || canonicalCalls != 0 {
				t.Fatalf("code=%d roots=%d canonical=%d stdout=%q stderr=%q", code, rootCalls, canonicalCalls, stdout.String(), stderr.String())
			}
			var problem setupCommandError
			if err := json.Unmarshal(stderr.Bytes(), &problem); err != nil || problem.Code != "SETUP_DISABLED" {
				t.Fatalf("problem=%+v err=%v", problem, err)
			}
		})
	}
}

func TestSetupSubcommandGateAllowsOnlyDocumentedTrueValues(t *testing.T) {
	for _, value := range []string{"1", "true", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("FARM_V3_SETUP_ENABLED", value)
			roots := setupCommandFixture(t)
			previousRoots := resolveSetupUserRoots
			resolveSetupUserRoots = func() (backend.SuiteUserRoots, error) { return roots, nil }
			t.Cleanup(func() { resolveSetupUserRoots = previousRoots })
			withCanonicalSetupRunner(t, successfulSetupRunner)
			var stdout, stderr bytes.Buffer
			if code := run([]string{"setup", "--server", "https://farm.example.test", "--json"}, setupPanicReader{}, &stdout, &stderr); code != 0 || stderr.Len() != 0 {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			var result setupCommandResult
			if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.State != backend.SetupEnrolled || result.NextAction != "service_activation" {
				t.Fatalf("result=%+v err=%v", result, err)
			}
		})
	}
}

func TestSetupSubcommandRunsCanonicalSetupAndReportsOnlyFinalState(t *testing.T) {
	roots := setupCommandFixture(t)
	withSetupRoots(t, roots)
	called := false
	withCanonicalSetupRunner(t, func(_ context.Context, config backend.BootstrapConfig, gotRoots backend.SuiteUserRoots, input io.Reader, _ io.Writer) (setupCommandResult, error) {
		called = true
		if config.ServerURL != "https://farm.example.test:8443" || config.NodeName != "Node One" || config.StatePath != filepath.Join(roots.AgentState, "setup.json") || gotRoots != roots {
			t.Fatalf("config=%+v roots=%+v", config, gotRoots)
		}
		if input == nil {
			t.Fatal("stdin was not forwarded to canonical setup")
		}
		return successfulSetupRunner(nil, backend.BootstrapConfig{}, backend.SuiteUserRoots{}, nil, nil)
	})
	var stdout, stderr bytes.Buffer
	code := run([]string{"setup", "--server", "https://farm.example.test:8443", "--node-name", "Node One", "--json"}, strings.NewReader("secret-must-not-be-read"), &stdout, &stderr)
	if code != 0 || !called || stderr.Len() != 0 {
		t.Fatalf("run code=%d called=%v stdout=%q stderr=%q", code, called, stdout.String(), stderr.String())
	}
	var result map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, map[string]any{"state": "ENROLLED", "next_action": "service_activation"}) {
		t.Fatalf("result=%v", result)
	}
	for _, forbidden := range []string{"secret-must-not-be-read", "request_uid", "identity", "control"} {
		if strings.Contains(strings.ToLower(stdout.String()), strings.ToLower(forbidden)) {
			t.Fatalf("success output exposed %q: %s", forbidden, stdout.String())
		}
	}
}

func TestSetupSubcommandOnlyExposesCanonicalOperatorFlags(t *testing.T) {
	for _, flagName := range []string{"--root", "--state-path", "--manifest", "--envelope", "--key-id", "--public-key", "--enrollment-code"} {
		t.Run(flagName, func(t *testing.T) {
			roots := setupCommandFixture(t)
			withSetupRoots(t, roots)
			called := false
			withCanonicalSetupRunner(t, func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, io.Reader, io.Writer) (setupCommandResult, error) {
				called = true
				return setupCommandResult{}, nil
			})
			canary := "CANARY-SECRET-VALUE"
			var stdout, stderr bytes.Buffer
			code := run([]string{"setup", "--server", "https://farm.example.test", flagName, canary, "--json"}, strings.NewReader(""), &stdout, &stderr)
			if code != setupExitInput || called || stdout.Len() != 0 || strings.Contains(stderr.String(), canary) {
				t.Fatalf("flag=%s code=%d called=%v stdout=%q stderr=%q", flagName, code, called, stdout.String(), stderr.String())
			}
			if entries, _ := filepath.Glob(filepath.Join(roots.AgentState, "*")); len(entries) != 0 {
				t.Fatalf("invalid input wrote state: %v", entries)
			}
		})
	}
}

func TestSetupSubcommandFailsClosedWithSafeJSONInputErrors(t *testing.T) {
	for _, tc := range []struct {
		name  string
		args  []string
		field string
	}{
		{"missing server", []string{"setup", "--json"}, "server"},
		{"http server", []string{"setup", "--server", "http://farm.example.test", "--json"}, "server"},
		{"invalid node name", []string{"setup", "--server", "https://farm.example.test", "--node-name", "bad\nname", "--json"}, "node_name"},
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
			if err := json.Unmarshal(stderr.Bytes(), &problem); err != nil || problem.Code == "" || problem.SafeMessage == "" || problem.Stage != "INPUT_VALIDATION" || problem.Field != tc.field {
				t.Fatalf("problem=%+v err=%v raw=%q", problem, err, stderr.String())
			}
		})
	}
}

func TestSetupSubcommandUsesTypedCanonicalExitCodesWithoutSecretLeak(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"transport", canonicalSetupError{"TRANSPORT_VERIFIED", errors.New("transport canary")}, setupExitTransport},
		{"enrollment", canonicalSetupError{"ENROLLMENT", errors.New("CODE-CANARY")}, setupExitEnrollment},
		{"ack state", canonicalSetupError{"ACK_STATE", backend.ErrSuiteCanonicalEnrollmentACK}, setupExitNativeStore},
		{"native", canonicalSetupError{"RELEASE", errors.New("path canary")}, setupExitNativeStore},
	} {
		t.Run(tc.name, func(t *testing.T) {
			roots := setupCommandFixture(t)
			withSetupRoots(t, roots)
			withCanonicalSetupRunner(t, func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, io.Reader, io.Writer) (setupCommandResult, error) {
				return setupCommandResult{}, tc.err
			})
			t.Setenv("ANT_FARM_ENROLLMENT_CODE", "ENV-CODE-CANARY")
			var stdout, stderr bytes.Buffer
			if code := run([]string{"setup", "--server", "https://farm.example.test", "--json"}, strings.NewReader("STDIN-CODE-CANARY\n"), &stdout, &stderr); code != tc.code || stdout.Len() != 0 {
				t.Fatalf("code=%d want=%d stdout=%q stderr=%q", code, tc.code, stdout.String(), stderr.String())
			}
			for _, secret := range []string{"CODE-CANARY", "ENV-CODE-CANARY", "STDIN-CODE-CANARY", "path canary", "transport canary"} {
				if strings.Contains(stderr.String(), secret) {
					t.Fatalf("error leaked %q: %s", secret, stderr.String())
				}
			}
		})
	}
}

func TestCanonicalSetupResumesEachDurableStageInOrder(t *testing.T) {
	stages := []*backend.SetupCheckpoint{
		nil,
		{SchemaVersion: 1, Stage: backend.SetupPrecheck, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
		{SchemaVersion: 1, Stage: backend.SetupStaged, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
		{SchemaVersion: 1, Stage: backend.SetupConfigDrafted, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
		{SchemaVersion: 1, Stage: backend.SetupTransportVerified, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
		{SchemaVersion: 1, Stage: backend.SetupIdentityReady, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
		{SchemaVersion: 1, Stage: backend.SetupEnrolled, RequestUID: "123e4567-e89b-12d3-a456-426614174001"},
	}
	for _, initial := range stages {
		name := "none"
		if initial != nil {
			name = string(initial.Stage)
		}
		t.Run(name, func(t *testing.T) {
			current := initial
			var calls []string
			step := func(name string, expected backend.SetupStage) canonicalSetupStep {
				return func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) error {
					calls = append(calls, name)
					current = &backend.SetupCheckpoint{SchemaVersion: 1, Stage: expected, RequestUID: "123e4567-e89b-12d3-a456-426614174001"}
					return nil
				}
			}
			ops := canonicalSetupOperations{
				Executable: func() (string, error) {
					return filepath.Join(t.TempDir(), "versions", "1.2.3", "ant-farm-client.exe"), nil
				},
				LoadRelease:    func(string, string) (backend.VerifiedSuiteRelease, error) { return setupVerifiedRelease(t), nil },
				LoadCheckpoint: func(string) (*backend.SetupCheckpoint, error) { return current, nil },
				Precheck:       step("precheck", backend.SetupPrecheck), Stage: step("stage", backend.SetupStaged),
				ConfigDraft: step("config", backend.SetupConfigDrafted), Transport: step("transport", backend.SetupTransportVerified),
				Identity: step("identity", backend.SetupIdentityReady),
				ProbeACK: func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) (backend.SuiteCanonicalEnrollmentACKState, error) {
					calls = append(calls, "probe-ack")
					return backend.SuiteCanonicalEnrollmentACKDurable, nil
				},
				EnrollmentACK: func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string, string) error {
					calls = append(calls, "ack")
					return nil
				},
				ApplicationInit: step("application", backend.SetupIdentityReady), EnrollmentFinish: step("finalize", backend.SetupEnrolled),
			}
			result, err := runCanonicalSetupWithOperations(context.Background(), backend.BootstrapConfig{}, backend.SuiteUserRoots{}, setupPanicReader{}, &bytes.Buffer{}, ops)
			if err != nil || result.State != backend.SetupEnrolled || result.NextAction != "service_activation" {
				t.Fatalf("result=%+v err=%v calls=%v", result, err, calls)
			}
			all := []string{"precheck", "stage", "config", "transport", "identity", "probe-ack", "application", "finalize"}
			start := 0
			if initial != nil {
				switch initial.Stage {
				case backend.SetupPrecheck:
					start = 1
				case backend.SetupStaged:
					start = 2
				case backend.SetupConfigDrafted:
					start = 3
				case backend.SetupTransportVerified:
					start = 4
				case backend.SetupIdentityReady:
					start = 5
				case backend.SetupEnrolled:
					start = 7
				}
			}
			if want := all[start:]; !reflect.DeepEqual(calls, want) {
				t.Fatalf("calls=%v want=%v", calls, want)
			}
		})
	}
}

func TestCanonicalSetupReadsEnrollmentCodeOnceOnlyWhenProbeRequiresIt(t *testing.T) {
	t.Setenv("ANT_FARM_ENROLLMENT_CODE", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x72}, 32)))
	current := &backend.SetupCheckpoint{SchemaVersion: 1, Stage: backend.SetupIdentityReady, RequestUID: "123e4567-e89b-12d3-a456-426614174001"}
	calls, received := 0, ""
	step := func(stage backend.SetupStage) canonicalSetupStep {
		return func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) error {
			current = &backend.SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: current.RequestUID}
			return nil
		}
	}
	unreachable := func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) error {
		t.Fatal("earlier stage ran")
		return nil
	}
	ops := canonicalSetupOperations{
		Executable: func() (string, error) {
			return filepath.Join(t.TempDir(), "versions", "1.2.3", "ant-farm-client.exe"), nil
		},
		LoadRelease:    func(string, string) (backend.VerifiedSuiteRelease, error) { return setupVerifiedRelease(t), nil },
		LoadCheckpoint: func(string) (*backend.SetupCheckpoint, error) { return current, nil },
		Precheck:       unreachable, Stage: unreachable, ConfigDraft: unreachable, Transport: unreachable, Identity: unreachable,
		ProbeACK: func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) (backend.SuiteCanonicalEnrollmentACKState, error) {
			return backend.SuiteCanonicalEnrollmentACKCodeRequired, nil
		},
		EnrollmentACK: func(_ context.Context, _ backend.BootstrapConfig, _ backend.SuiteUserRoots, _ backend.VerifiedSuiteRelease, _, code string) error {
			calls++
			received = code
			return nil
		},
		ApplicationInit: step(backend.SetupIdentityReady), EnrollmentFinish: step(backend.SetupEnrolled),
	}
	secret := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x61}, 32))
	result, err := runCanonicalSetupWithOperations(context.Background(), backend.BootstrapConfig{}, backend.SuiteUserRoots{}, strings.NewReader(secret+"\nignored\n"), &bytes.Buffer{}, ops)
	if err != nil || result.State != backend.SetupEnrolled || calls != 1 || received != secret {
		t.Fatalf("result=%+v err=%v calls=%d received=%q", result, err, calls, received)
	}
}

func TestCanonicalSetupRejectsExecutableOutsideVersionRootBeforeReleaseRead(t *testing.T) {
	called := false
	ops := canonicalSetupOperations{
		Executable: func() (string, error) { return filepath.Join(t.TempDir(), "ant-farm-client.exe"), nil },
		LoadRelease: func(string, string) (backend.VerifiedSuiteRelease, error) {
			called = true
			return backend.VerifiedSuiteRelease{}, nil
		},
		LoadCheckpoint: func(string) (*backend.SetupCheckpoint, error) { return nil, nil },
	}
	noop := func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) error {
		return nil
	}
	ops.Precheck, ops.Stage, ops.ConfigDraft, ops.Transport, ops.Identity, ops.ApplicationInit, ops.EnrollmentFinish = noop, noop, noop, noop, noop, noop, noop
	ops.ProbeACK = func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string) (backend.SuiteCanonicalEnrollmentACKState, error) {
		return backend.SuiteCanonicalEnrollmentACKDurable, nil
	}
	ops.EnrollmentACK = func(context.Context, backend.BootstrapConfig, backend.SuiteUserRoots, backend.VerifiedSuiteRelease, string, string) error {
		return nil
	}
	if _, err := runCanonicalSetupWithOperations(context.Background(), backend.BootstrapConfig{}, backend.SuiteUserRoots{}, strings.NewReader(""), &bytes.Buffer{}, ops); err == nil || called {
		t.Fatalf("err=%v releaseCalled=%v", err, called)
	}
}

func setupVerifiedRelease(t *testing.T) backend.VerifiedSuiteRelease {
	t.Helper()
	manifest := []byte(`{"schema_version":1,"version":"1.2.3","target":{"os":"windows","arch":"amd64"},"commits":{"ant_browser":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","farm_agent":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","farm_control":"cccccccccccccccccccccccccccccccccccccccc"},"config_schema":1,"capabilities":["setup-plan"],"core_versions":{"chromium":"120.0.0"},"dependencies":[{"name":"Ant-Suite","version":"1.2.3","license_ref":"LICENSE"}],"entries":[{"path":"Ant.exe","role":"binary","size":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","executable":true},{"path":"LICENSE","role":"legal","size":1,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","executable":false}]}`)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := backend.SignSuiteReleaseManifest(manifest, "suite-key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	release, err := backend.VerifySuiteReleaseManifest(manifest, envelope, backend.SuiteReleaseTrustAnchor{KeyID: "suite-key-1", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	return release
}
