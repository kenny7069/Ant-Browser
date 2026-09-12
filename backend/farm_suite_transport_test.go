package backend

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type suiteTransportFixture struct {
	suiteConfigDraftFixture
	discovery SuiteBootstrapDiscovery
}

func newSuiteTransportFixture(t *testing.T) suiteTransportFixture {
	t.Helper()
	fixture := newSuiteConfigDraftFixture(t)
	if _, err := runSuiteCanonicalConfigDraftWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteConfigDraftTestDependencies()); err != nil {
		t.Fatal(err)
	}
	origin := fixture.bootstrap.ServerURL
	return suiteTransportFixture{suiteConfigDraftFixture: fixture, discovery: SuiteBootstrapDiscovery{
		SchemaVersion: 3, DeploymentUID: "123e4567-e89b-12d3-a456-426614174000",
		MinimumSuiteVersion: "3.0.0", MinimumProtocolVersion: FarmSuiteBootstrapProtocolVersion,
		EnrollmentEndpoint:    origin + "/api/farm/v3/bootstrap/enroll",
		ControlEndpoint:       "wss" + strings.TrimPrefix(origin, "https") + "/control/ws",
		SupportedCapabilities: []string{"browser.manage", "profile.list"}, EndpointAllowlist: []string{origin},
	}}
}

func suiteTransportTestDependencies(discovery SuiteBootstrapDiscovery) suiteCanonicalTransportDependencies {
	stage := suiteStageTestDependencies()
	return suiteCanonicalTransportDependencies{
		CurrentSuiteVersion: "3.0.0",
		Fetch:               func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) { return discovery, nil },
		ValidateInstall:     stage.ValidateInstall,
		AcquireInstance:     func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:      func(string) error { return nil }, EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
		SaveReceipt: saveSuiteTransportReceipt, SaveCheckpoint: SaveSetupCheckpoint,
	}
}

func TestSuiteCanonicalTransportBindsExecutingVersionToSignedRelease(t *testing.T) {
	for _, version := range []string{"2.9.9", "not-semver"} {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.CurrentSuiteVersion = version
		called := false
		deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
			called = true
			return fixture.discovery, nil
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil || called {
			t.Fatalf("executing version %q accepted or fetched: err=%v called=%v", version, err, called)
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	}
}

func TestSuiteCanonicalTransportWritesReceiptAndRefetchesIdempotently(t *testing.T) {
	fixture := newSuiteTransportFixture(t)
	deps := suiteTransportTestDependencies(fixture.discovery)
	var fetches atomic.Int32
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		fetches.Add(1)
		return fixture.discovery, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		if err != nil || result.Stage != SetupTransportVerified || result.RequestUID != fixture.preparation.RequestUID || result.ManifestSHA256 != fixture.plan.ManifestSHA256 || result.DeploymentUID != fixture.discovery.DeploymentUID || !validLowerSHA256(result.DiscoverySHA256) {
			t.Fatalf("attempt=%d result=%+v err=%v", attempt, result, err)
		}
	}
	if fetches.Load() != 2 {
		t.Fatalf("fetches=%d", fetches.Load())
	}
	receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap)
	if err != nil || receipt == nil || !reflect.DeepEqual(receipt.discovery(), fixture.discovery) {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	assertSuiteTransportCheckpoint(t, fixture, SetupTransportVerified)
	assertSuiteTransportNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalTransportProductionFetchWiringCannotBeInjected(t *testing.T) {
	production := suiteCanonicalTransportProductionDependencies()
	if reflect.ValueOf(production.Fetch).Pointer() != reflect.ValueOf(FetchSuiteBootstrapDiscovery).Pointer() {
		t.Fatal("production discovery fetch is not the system-trust implementation")
	}
	if runtime.GOOS != "windows" {
		fixture := newSuiteTransportFixture(t)
		if _, err := RunSuiteCanonicalTransport(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); !errors.Is(err, ErrSuiteCanonicalTransport) {
			t.Fatalf("unsupported production platform err=%v", err)
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	}
}

func TestSuiteCanonicalTransportFetchFailureDoesNotMutate(t *testing.T) {
	fixture := newSuiteTransportFixture(t)
	deps := suiteTransportTestDependencies(fixture.discovery)
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapTransport
	}
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil || strings.Contains(err.Error(), fixture.bootstrap.ServerURL) {
		t.Fatalf("fetch failure=%v", err)
	}
	assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	if receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err != nil || receipt != nil {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	assertSuiteTransportNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalTransportRejectsDiscoveryDriftAndReceiptConflict(t *testing.T) {
	fixture := newSuiteTransportFixture(t)
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
		t.Fatal(err)
	}
	changed := fixture.discovery
	changed.DeploymentUID = "223e4567-e89b-12d3-a456-426614174000"
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(changed)); err == nil {
		t.Fatal("changed trusted discovery accepted against durable receipt")
	}
	assertSuiteTransportCheckpoint(t, fixture, SetupTransportVerified)

	fixture = newSuiteTransportFixture(t)
	draft, _ := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap)
	conflict, err := newSuiteTransportReceipt(fixture.preparation, fixture.plan, *draft, fixture.bootstrap, fixture.roots, fixture.release.manifest.Version, changed)
	if err != nil || saveSuiteTransportReceipt(fixture.roots, fixture.bootstrap, conflict) != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err == nil {
		t.Fatal("conflicting receipt accepted")
	}
	assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
}

func TestSuiteCanonicalTransportRequiresExactConfigDraftedCheckpoint(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  string
	}{
		{"corrupt", `{"stage":`},
		{"cross request", `{"schema_version":1,"stage":"CONFIG_DRAFTED","request_uid":"64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}`},
		{"future", `{"schema_version":1,"stage":"IDENTITY_READY","request_uid":"REQUEST"}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteTransportFixture(t)
			raw := strings.ReplaceAll(test.raw, "REQUEST", fixture.preparation.RequestUID)
			if err := os.WriteFile(fixture.bootstrap.StatePath, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err == nil {
				t.Fatal("invalid checkpoint accepted")
			}
			if receipt, _ := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); receipt != nil {
				t.Fatal("invalid checkpoint wrote receipt")
			}
		})
	}
}

func TestSuiteTransportReceiptClosedOwnerOnlyContract(t *testing.T) {
	for _, test := range []struct {
		name string
		raw  []byte
	}{
		{"duplicate", []byte(`{"schema_version":1,"schema_version":1}`)},
		{"unknown", []byte(`{"secret":"value"}`)}, {"trailing", []byte(`{} {}`)}, {"type", []byte(`[]`)},
		{"oversize", []byte(strings.Repeat("x", suiteTransportReceiptMaxBytes+1))},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteTransportFixture(t)
			path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
			if err := os.WriteFile(path, test.raw, 0o600); err != nil {
				t.Fatal(err)
			}
			if receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err == nil || receipt != nil {
				t.Fatalf("receipt=%+v err=%v", receipt, err)
			}
		})
	}
	t.Run("symlink", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		target := filepath.Join(t.TempDir(), "receipt")
		_ = os.WriteFile(target, []byte(`{}`), 0o600)
		if err := os.Symlink(target, filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)); err != nil {
			t.Skip(err)
		}
		if _, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err == nil {
			t.Fatal("symlink accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("mode", func(t *testing.T) {
			fixture := newSuiteTransportFixture(t)
			if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err == nil {
				t.Fatal("permissive receipt accepted")
			}
		})
	}
}

func TestSuiteTransportReceiptLoadFencesConfigAndStateRootIdentity(t *testing.T) {
	for _, rootName := range []string{"config", "state"} {
		t.Run(rootName, func(t *testing.T) {
			fixture := newSuiteTransportFixture(t)
			if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
				t.Fatal(err)
			}
			raw, err := os.ReadFile(filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName))
			if err != nil {
				t.Fatal(err)
			}
			root := fixture.roots.Config
			if rootName == "state" {
				root = fixture.roots.AgentState
			}
			moved := root + "-moved"
			dependencies := suiteTransportReceiptLoadDependencies{ReadFile: func(string, os.FileInfo) ([]byte, error) {
				if err := os.Rename(root, moved); err != nil {
					return nil, err
				}
				if err := os.Mkdir(root, 0o700); err != nil {
					return nil, err
				}
				return raw, nil
			}}
			if receipt, err := loadSuiteTransportReceiptWithDependencies(fixture.roots, fixture.bootstrap, dependencies); err == nil || receipt != nil {
				t.Fatalf("root replacement accepted: receipt=%+v err=%v", receipt, err)
			}
			if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, root); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSuiteCanonicalTransportFaultsAndCommitUnknown(t *testing.T) {
	t.Run("handle security failure leaves recoverable final", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveReceipt = func(r SuiteUserRoots, b BootstrapConfig, receipt SuiteTransportReceipt) error {
			return saveSuiteTransportReceiptWithDependencies(r, b, receipt, suiteTransportReceiptSaveDependencies{
				Open: openSuiteTransportReceiptHandle,
				Write: func(*os.File, os.FileInfo, []byte, *suiteTransportReceiptRecoveryEvidence) error {
					return errors.New("injected handle security failure")
				},
			})
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("handle security failure accepted")
		}
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() != 0 {
			t.Fatalf("recoverable final info=%v err=%v", info, err)
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatalf("recover empty final: %v", err)
		}
	})
	t.Run("receipt write", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveReceipt = func(SuiteUserRoots, BootstrapConfig, SuiteTransportReceipt) error { return errors.New("injected") }
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("receipt failure accepted")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	})
	t.Run("receipt commit unknown", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveReceipt = func(r SuiteUserRoots, b BootstrapConfig, receipt SuiteTransportReceipt) error {
			if err := saveSuiteTransportReceipt(r, b, receipt); err != nil {
				return err
			}
			return errors.New("ack lost")
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("commit unknown reported success")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("checkpoint after receipt", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveCheckpoint = func(string, SetupCheckpoint) error { return errors.New("injected") }
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("failure accepted")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
		if receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err != nil || receipt == nil {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("checkpoint commit unknown", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveCheckpoint = func(path string, checkpoint SetupCheckpoint) error {
			if err := SaveSetupCheckpoint(path, checkpoint); err != nil {
				return err
			}
			return errors.New("ack lost")
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("unknown reported success")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupTransportVerified)
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("local drift after receipt", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.SaveReceipt = func(r SuiteUserRoots, b BootstrapConfig, receipt SuiteTransportReceipt) error {
			if err := saveSuiteTransportReceipt(r, b, receipt); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(r.Config, SuiteClientConfigDraftName), []byte(`{"bad":true}`), 0o600)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("post-receipt drift accepted")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
		if receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err != nil || receipt == nil {
			t.Fatalf("durable receipt=%+v err=%v", receipt, err)
		}
	})
}

func TestSuiteCanonicalTransportRevalidatesLocalEvidenceAfterFetch(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, suiteTransportFixture) error
	}{
		{"tree", func(_ *testing.T, f suiteTransportFixture) error {
			return os.WriteFile(filepath.Join(f.source, "evil.dll"), []byte("evil"), 0o600)
		}},
		{"draft", func(_ *testing.T, f suiteTransportFixture) error {
			return os.WriteFile(filepath.Join(f.roots.Config, SuiteClientConfigDraftName), []byte(`{"bad":true}`), 0o600)
		}},
		{"stage receipt", func(_ *testing.T, f suiteTransportFixture) error {
			return os.WriteFile(filepath.Join(f.roots.AgentState, SuiteStageReceiptName), []byte(`{"bad":true}`), 0o600)
		}},
		{"application", func(_ *testing.T, f suiteTransportFixture) error {
			return os.WriteFile(filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "data"), []byte("x"), 0o600)
		}},
		{"plan", func(_ *testing.T, f suiteTransportFixture) error {
			return os.WriteFile(filepath.Join(f.roots.AgentState, suiteSetupPlanName), []byte(`{"bad":true}`), 0o600)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteTransportFixture(t)
			deps := suiteTransportTestDependencies(fixture.discovery)
			deps.AfterFetch = func() error { return test.mutate(t, fixture) }
			if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("drift accepted")
			}
			assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
			if receipt, _ := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); receipt != nil {
				t.Fatal("drift wrote receipt")
			}
		})
	}
}

func TestSuiteCanonicalTransportRejectsLaterFootprint(t *testing.T) {
	for _, pathFor := range []func(suiteTransportFixture) string{
		func(f suiteTransportFixture) string { return filepath.Join(f.roots.Config, SuiteClientConfigName) },
		func(f suiteTransportFixture) string {
			return filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml")
		},
		func(f suiteTransportFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		},
		func(f suiteTransportFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName)
		},
		func(f suiteTransportFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteActivationJournalName)
		},
	} {
		fixture := newSuiteTransportFixture(t)
		path := pathFor(fixture)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("early"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err == nil {
			t.Fatalf("early artifact accepted: %s", path)
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	}
}

func TestSuiteCanonicalTransportLocksAndHundredCallers(t *testing.T) {
	t.Run("active locks", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("err=%v", err)
		}
	})
	t.Run("active instance", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		lock, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Release()
		deps := suiteTransportTestDependencies(fixture.discovery)
		deps.AcquireInstance = func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) }
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("active instance accepted")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	})
	t.Run("100 callers", func(t *testing.T) {
		fixture := newSuiteTransportFixture(t)
		var wait sync.WaitGroup
		results := make(chan error, 100)
		for i := 0; i < 100; i++ {
			wait.Add(1)
			go func() {
				defer wait.Done()
				_, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery))
				results <- err
			}()
		}
		wait.Wait()
		close(results)
		wins := 0
		for err := range results {
			if err == nil {
				wins++
			} else if !errors.Is(err, ErrSuiteSetupLocked) {
				t.Fatalf("err=%v", err)
			}
		}
		if wins == 0 {
			t.Fatal("no winner")
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupTransportVerified)
	})
}

func TestSuiteTransportFinalJournalRecoveryIsClosed(t *testing.T) {
	for _, raw := range [][]byte{{}, []byte(`{"schema_version":`)} {
		fixture := newSuiteTransportFixture(t)
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatalf("invalid JSON recovery: %v", err)
		}
		if receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap); err != nil || receipt == nil {
			t.Fatalf("receipt=%+v err=%v", receipt, err)
		}
	}
	if runtime.GOOS != "windows" {
		fixture := newSuiteTransportFixture(t)
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
			t.Fatalf("restrictive birth mode recovery: %v", err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("birth mode not normalized: info=%v err=%v", info, err)
		}
	}
	for _, raw := range [][]byte{[]byte(`{"unknown":true}`), []byte(`{"secret":"keep"}`), []byte(`[]`)} {
		fixture := newSuiteTransportFixture(t)
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err == nil {
			t.Fatal("valid JSON drift overwritten")
		}
		if preserved, err := os.ReadFile(path); err != nil || string(preserved) != string(raw) {
			t.Fatalf("valid drift mutated=%q err=%v", preserved, err)
		}
	}
	fixture := newSuiteTransportFixture(t)
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
	if err := os.WriteFile(path, []byte(`{"schema_version":`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err == nil {
		t.Fatal("TRANSPORT_VERIFIED corrupt receipt recovered")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != `{"schema_version":` {
		t.Fatalf("completed corrupt receipt mutated=%q err=%v", raw, err)
	}
}

func TestSuiteTransportReceiptCreateBirthIsOwnerOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), SuiteTransportReceiptName)
	file, err := openSuiteTransportReceiptHandle(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := validateSuiteSetupPathSecurity(path, false); err != nil {
		t.Fatalf("receipt birth was not owner-only: %v", err)
	}
}

func TestSuiteTransportRecoveryRechecksSameInodeBytesBeforeSecurityMutation(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows handle/DACL evidence not run")
	}
	for _, changed := range [][]byte{[]byte(`{"secret":"keep"}`), []byte(`{"y":`), []byte(`[`)} {
		fixture := newSuiteTransportFixture(t)
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		initial := []byte(`{"x":`)
		if err := os.WriteFile(path, initial, 0o600); err != nil {
			t.Fatal(err)
		}
		draft, _ := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap)
		receipt, err := newSuiteTransportReceipt(fixture.preparation, fixture.plan, *draft, fixture.bootstrap, fixture.roots, fixture.release.manifest.Version, fixture.discovery)
		if err != nil {
			t.Fatal(err)
		}
		dependencies := suiteTransportReceiptSaveDependencies{
			Open: openSuiteTransportReceiptHandle, Write: writeSuiteTransportReceiptHandle,
			AfterOpen: func(_ string, file *os.File) error {
				if err := file.Truncate(0); err != nil {
					return err
				}
				if _, err := file.Seek(0, 0); err != nil {
					return err
				}
				if _, err := file.Write(changed); err != nil {
					return err
				}
				return file.Chmod(0o400)
			},
		}
		if err := saveSuiteTransportReceiptWithDependencies(fixture.roots, fixture.bootstrap, receipt, dependencies); err == nil {
			t.Fatalf("same-inode drift %q accepted", changed)
		}
		if raw, err := os.ReadFile(path); err != nil || string(raw) != string(changed) {
			t.Fatalf("same-inode drift mutated=%q err=%v", raw, err)
		}
		if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o400 {
			t.Fatalf("security mutation preceded byte recheck: info=%v err=%v", info, err)
		}
		assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
	}
}

func TestSuiteTransportHandleWriteNeverMutatesPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows handle/DACL evidence not run")
	}
	fixture := newSuiteTransportFixture(t)
	draft, _ := LoadSuiteClientConfigDraft(fixture.roots, fixture.bootstrap)
	receipt, err := newSuiteTransportReceipt(fixture.preparation, fixture.plan, *draft, fixture.bootstrap, fixture.roots, fixture.release.manifest.Version, fixture.discovery)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
	openedPath := path + ".opened"
	dependencies := suiteTransportReceiptSaveDependencies{
		Open: openSuiteTransportReceiptHandle, Write: writeSuiteTransportReceiptHandle,
		AfterOpen: func(path string, _ *os.File) error {
			if err := os.Rename(path, openedPath); err != nil {
				return err
			}
			return os.WriteFile(path, []byte("foreign"), 0o644)
		},
	}
	if err := saveSuiteTransportReceiptWithDependencies(fixture.roots, fixture.bootstrap, receipt, dependencies); err == nil {
		t.Fatal("pathname replacement reported success")
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != "foreign" {
		t.Fatalf("replacement content mutated=%q err=%v", raw, err)
	}
	if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("replacement mode mutated info=%v err=%v", info, err)
	}
	assertSuiteTransportCheckpoint(t, fixture, SetupConfigDrafted)
}

func assertSuiteTransportCheckpoint(t *testing.T, f suiteTransportFixture, stage SetupStage) {
	t.Helper()
	checkpoint, err := LoadSetupCheckpoint(f.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != stage || checkpoint.RequestUID != f.preparation.RequestUID {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}

func assertSuiteTransportNoLaterArtifacts(t *testing.T, f suiteTransportFixture) {
	t.Helper()
	for _, path := range []string{filepath.Join(f.roots.Config, SuiteClientConfigName), filepath.Join(f.roots.BrowserData, suiteConfigDraftApplicationDir, "config.yaml"), filepath.Join(f.roots.AgentState, SuiteBootstrapEnrollmentAttemptName), filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName), filepath.Join(f.roots.AgentState, SuiteActivationJournalName)} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact %s: %v", filepath.Base(path), err)
		}
	}
}
