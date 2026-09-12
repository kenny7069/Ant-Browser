package backend

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func newSuiteEnrollmentFinalizeFixture(t *testing.T, nodeUID string) suiteIdentityFixture {
	t.Helper()
	fixture := newSuiteEnrollmentACKFixture(t)
	ackDeps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentACKResponseForNode(fixture.discovery, "ENROLLED", nodeUID), nil
	})
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x71), ackDeps); err != nil {
		t.Fatal(err)
	}
	initDeps := suiteApplicationInitTestDependencies(fixture)
	if _, err := runSuiteCanonicalApplicationInitWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, initDeps); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func suiteEnrollmentACKResponseForNode(discovery SuiteBootstrapDiscovery, state, nodeUID string) *http.Response {
	raw := `{"node_uid":"` + nodeUID + `","enrollment_state":"` + state + `","control_endpoint":"` + discovery.ControlEndpoint + `"}`
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: ioNopCloserString(raw)}
}

type suiteStringReadCloser struct{ *strings.Reader }

func (suiteStringReadCloser) Close() error { return nil }

func ioNopCloserString(value string) suiteStringReadCloser {
	return suiteStringReadCloser{Reader: strings.NewReader(value)}
}

func suiteEnrollmentFinalizeTestDependencies(fixture suiteIdentityFixture) suiteCanonicalEnrollmentFinalizeDependencies {
	stage := suiteStageTestDependencies()
	var handoff *SuiteOwnershipHandoff
	return suiteCanonicalEnrollmentFinalizeDependencies{
		CurrentGOOS: "windows", NewStore: func(string) (FarmClientIdentityStore, error) { return fixture.store, nil },
		ValidateInstall: stage.ValidateInstall,
		AcquireInstance: func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:  func(string) error { return nil }, EnsureApplication: ensureSuiteApplicationRootIdentity,
		Readback: readbackSuiteApplication, SaveCheckpoint: SaveSetupCheckpoint,
		FinalizeHandoff: func(roots SuiteUserRoots, requestUID, suiteRoot, guiPath string) (SuiteOwnershipHandoff, error) {
			_, digest, err := loadSuiteHandoffClientConfig(filepath.Join(roots.Config, SuiteClientConfigName))
			if err != nil {
				return SuiteOwnershipHandoff{}, err
			}
			value := SuiteOwnershipHandoff{SchemaVersion: 1, HandoffState: suiteHandoffIntentDurable, SetupRequestUID: requestUID, GUIBinaryPath: guiPath, SuiteBinaryRoot: suiteRoot, ClientConfigPath: filepath.Join(roots.Config, SuiteClientConfigName), AntConfigPath: filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml"), AgentStateRoot: roots.AgentState, ApplicationRoot: filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir), ClientConfigSHA256: digest, ManifestSHA256: fixture.plan.ManifestSHA256, SetupStageID: fixture.plan.StageID, ReleaseTarget: fixture.plan.Target}
			if handoff != nil && *handoff != value {
				return SuiteOwnershipHandoff{}, ErrSuiteOwnershipHandoffConflict
			}
			handoff = &value
			return value, nil
		},
		LoadHandoff: func(SuiteUserRoots) (*SuiteOwnershipHandoff, error) {
			if handoff == nil {
				return nil, nil
			}
			copy := *handoff
			return &copy, nil
		},
	}
}

func TestSuiteCanonicalEnrollmentFinalizePublishesExactArtifactsThenEnrolls(t *testing.T) {
	nodeUID := strings.Repeat("a", 128)
	fixture := newSuiteEnrollmentFinalizeFixture(t, nodeUID)
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	progress := "start"
	deps.AfterConfig = func() error { progress = "config"; return nil }
	deps.AfterHandoff = func() error { progress = "handoff"; return nil }
	deps.BeforeCheckpoint = func() error { progress = "checkpoint"; return nil }
	var first SuiteCanonicalEnrollmentFinalizeResult
	for run := 0; run < 2; run++ {
		result, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		if err != nil || result.Stage != SetupEnrolled || result.RequestUID != fixture.preparation.RequestUID || !validLowerSHA256(result.ClientConfigSHA256) || result.HandoffState != suiteHandoffIntentDurable {
			t.Fatalf("run=%d progress=%s result=%+v err=%v", run, progress, result, err)
		}
		if run == 0 {
			first = result
		} else if result != first {
			t.Fatalf("idempotent result changed: %+v != %+v", result, first)
		}
	}
	configPath := filepath.Join(fixture.roots.Config, SuiteClientConfigName)
	config, err := LoadFarmClientConfig(configPath)
	if err != nil || config.ValidateFarmClientConfig() != nil || config.Identity.NodeUID != nodeUID || config.Identity.PrivateKeyRef == "" || len(config.ProviderInstanceID) > 128 || !farmClientNodeUIDPattern.MatchString(config.ProviderInstanceID) || config.ControlURL != fixture.discovery.ControlEndpoint || config.EnrollmentURL != fixture.discovery.EnrollmentEndpoint || config.PairingURL != fixture.bootstrap.ServerURL+"/api/farm/pair" {
		t.Fatalf("config=%+v err=%v", config, err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	attempt, _ := loadSuiteBootstrapEnrollmentAttempt(fixture.roots)
	for _, forbidden := range []string{suiteEnrollmentCode(0x71), attempt.PublicKeySHA256, "private_key:", "device_public_key", "enrollment_code"} {
		if bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("client config contains forbidden enrollment material %q", forbidden)
		}
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	handoff, handoffErr := deps.LoadHandoff(fixture.roots)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupEnrolled || handoffErr != nil || handoff == nil || handoff.ClientConfigSHA256 != first.ClientConfigSHA256 {
		t.Fatalf("checkpoint=%+v handoff=%+v errors=%v/%v", checkpoint, handoff, err, handoffErr)
	}
}

func TestSuiteCanonicalEnrollmentFinalizeRecoversEveryCommitBoundary(t *testing.T) {
	tests := []struct {
		name string
		set  func(*suiteCanonicalEnrollmentFinalizeDependencies)
	}{
		{"config", func(deps *suiteCanonicalEnrollmentFinalizeDependencies) {
			deps.AfterConfig = func() error { return errors.New("crash") }
		}},
		{"handoff", func(deps *suiteCanonicalEnrollmentFinalizeDependencies) {
			deps.AfterHandoff = func() error { return errors.New("crash") }
		}},
		{"checkpoint commit unknown", func(deps *suiteCanonicalEnrollmentFinalizeDependencies) {
			deps.AfterCheckpoint = func() error { return errors.New("lost result") }
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteEnrollmentFinalizeFixture(t, "node-finalize")
			deps := suiteEnrollmentFinalizeTestDependencies(fixture)
			test.set(&deps)
			if _, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
				t.Fatalf("fault error=%v", err)
			}
			checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
			if err != nil || checkpoint == nil {
				t.Fatal(err)
			}
			if test.name == "checkpoint commit unknown" && checkpoint.Stage != SetupEnrolled {
				t.Fatalf("commit was not durable: %+v", checkpoint)
			}
			deps = suiteEnrollmentFinalizeTestDependencies(fixture)
			if result, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil || result.Stage != SetupEnrolled {
				t.Fatalf("recovery result=%+v err=%v", result, err)
			}
		})
	}
}

func TestSuiteCanonicalEnrollmentFinalizeRecoversExactUnpublishedStaging(t *testing.T) {
	fixture := newSuiteEnrollmentFinalizeFixture(t, "node-staging")
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	layout, err := captureSuitePrecheckRootLayout(fixture.roots, fixture.source)
	if err != nil {
		t.Fatal(err)
	}
	evidence, err := loadSuiteEnrollmentFinalizeEvidence(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, layout, deps)
	if err != nil {
		t.Fatal(err)
	}
	_, raw, _, stagingPath, err := buildSuiteFinalClientConfig(fixture.bootstrap, fixture.roots, evidence)
	if err != nil || os.WriteFile(stagingPath, raw, 0o600) != nil {
		t.Fatal(err)
	}
	result, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	if err != nil || result.Stage != SetupEnrolled {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if _, err := os.Lstat(stagingPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("staging remains: %v", err)
	}
}

func TestSuiteCanonicalEnrollmentFinalizeRejectsProofChainAndKeyDrift(t *testing.T) {
	t.Run("native key", func(t *testing.T) {
		fixture := newSuiteEnrollmentFinalizeFixture(t, "node-key-drift")
		attempt, _ := loadSuiteBootstrapEnrollmentAttempt(fixture.roots)
		ref, _ := NewFarmClientIdentityKeyRef(attempt.IdentityRef)
		fixture.store.mu.Lock()
		fixture.store.keys[ref] = bytes.Repeat([]byte{0x33}, 64)
		fixture.store.mu.Unlock()
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("key drift error=%v", err)
		}
		assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
	})
	t.Run("durable ACK", func(t *testing.T) {
		fixture := newSuiteEnrollmentFinalizeFixture(t, "node-ack-drift")
		path := filepath.Join(fixture.roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("ACK drift error=%v", err)
		}
		assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
	})
	t.Run("initialized application", func(t *testing.T) {
		fixture := newSuiteEnrollmentFinalizeFixture(t, "node-app-drift")
		if err := os.WriteFile(filepath.Join(fixture.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml"), []byte("database: {}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("application drift error=%v", err)
		}
		assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
	})
}

func TestSuiteCanonicalEnrollmentFinalizeProductionIsWindowsOnly(t *testing.T) {
	fixture := newSuiteEnrollmentFinalizeFixture(t, "node-platform")
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	deps.CurrentGOOS = "linux"
	_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
		t.Fatalf("non-Windows error=%v", err)
	}
	assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
}

func TestSuiteCanonicalEnrollmentFinalizeRejectsForeignArtifactsAndMissingInit(t *testing.T) {
	t.Run("foreign before publish", func(t *testing.T) {
		fixture := newSuiteEnrollmentFinalizeFixture(t, "node-foreign")
		if err := os.WriteFile(filepath.Join(fixture.roots.Config, "foreign.yaml"), []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("foreign artifact error=%v", err)
		}
		assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
	})
	t.Run("missing initialized receipt", func(t *testing.T) {
		fixture := newSuiteApplicationInitFixture(t)
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("missing init error=%v", err)
		}
		assertSuiteEnrollmentFinalizeNoArtifacts(t, fixture)
	})
	t.Run("foreign config does not clobber", func(t *testing.T) {
		fixture := newSuiteEnrollmentFinalizeFixture(t, "node-conflict")
		path := filepath.Join(fixture.roots.Config, SuiteClientConfigName)
		if err := os.WriteFile(path, []byte("foreign: true\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
		if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
			t.Fatalf("foreign config error=%v", err)
		}
		raw, _ := os.ReadFile(path)
		if string(raw) != "foreign: true\n" {
			t.Fatalf("foreign config was replaced: %q", raw)
		}
	})
}

func TestSuiteCanonicalEnrollmentFinalizeRejectsForeignArtifactInjectedAfterConfig(t *testing.T) {
	fixture := newSuiteEnrollmentFinalizeFixture(t, "node-race")
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	deps.AfterConfig = func() error {
		return os.WriteFile(filepath.Join(fixture.roots.AgentState, "foreign.json"), []byte("{}\n"), 0o600)
	}
	_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	if !errors.Is(err, ErrSuiteCanonicalEnrollmentFinalize) {
		t.Fatalf("injected foreign artifact error=%v", err)
	}
	checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if checkpoint == nil || checkpoint.Stage != SetupIdentityReady {
		t.Fatalf("checkpoint advanced: %+v", checkpoint)
	}
}

func TestSuiteCanonicalEnrollmentFinalizeSerializesConcurrentCallers(t *testing.T) {
	fixture := newSuiteEnrollmentFinalizeFixture(t, "node-concurrent")
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	entered, release := make(chan struct{}), make(chan struct{})
	deps.AfterConfig = func() error { close(entered); <-release; return nil }
	first := make(chan error, 1)
	go func() {
		_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		first <- err
	}()
	<-entered
	_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentFinalizeTestDependencies(fixture))
	if !errors.Is(err, ErrSuiteSetupLocked) {
		t.Fatalf("second caller error=%v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first caller error=%v", err)
	}
}

func TestSuiteCanonicalEnrollmentFinalizeHundredCallers(t *testing.T) {
	fixture := newSuiteEnrollmentFinalizeFixture(t, "node-hundred")
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	var wait sync.WaitGroup
	errorsOut := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
			errorsOut <- err
		}()
	}
	wait.Wait()
	close(errorsOut)
	wins := 0
	for err := range errorsOut {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if wins == 0 {
		t.Fatal("no finalizer completed")
	}
}

func assertSuiteEnrollmentFinalizeNoArtifacts(t *testing.T, fixture suiteIdentityFixture) {
	t.Helper()
	for _, path := range []string{filepath.Join(fixture.roots.Config, SuiteClientConfigName), filepath.Join(fixture.roots.AgentState, SuiteOwnershipHandoffName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact exists: %s", path)
		}
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupIdentityReady {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}
