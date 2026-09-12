package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

type suitePrecheckFixture struct {
	roots     SuiteUserRoots
	bootstrap BootstrapConfig
	release   VerifiedSuiteRelease
	source    string
	manifest  SuiteReleaseManifest
}

type suitePrecheckTestLock struct{ released bool }

func (lock *suitePrecheckTestLock) Release() error { lock.released = true; return nil }

func newSuitePrecheckFixture(t *testing.T) suitePrecheckFixture {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := SuiteUserRoots{
		Config: filepath.Join(base, "config"), BrowserData: filepath.Join(base, "browser-data"),
		AgentState: filepath.Join(base, "agent-state"), Logs: filepath.Join(base, "logs"),
	}
	bootstrap := BootstrapConfig{ServerURL: "https://farm.example.test:8443", StatePath: filepath.Join(roots.AgentState, "setup.json"), NodeName: "Farm One"}
	coordinator, err := NewSuiteSetupCoordinatorWithRoots(bootstrap, roots)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Run(); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(t.TempDir(), "source-parent", "suite-source")
	files := map[string][]byte{
		"AntBrowser.exe":            []byte("gui"),
		"ant-farm-client.exe":       []byte("agent"),
		"runtime/xray.exe":          []byte("xray"),
		"runtime/sing-box.exe":      []byte("sing-box"),
		"runtime/chrome/chrome.exe": []byte("chrome"),
		"LICENSES.json":             []byte("licenses"),
	}
	entries := make([]SuiteReleaseEntry, 0, len(files))
	for path, content := range files {
		digest := sha256.Sum256(content)
		role, executable := SuiteReleaseEntryBinary, true
		if path == "LICENSES.json" {
			role, executable = SuiteReleaseEntryLegal, false
		}
		entries = append(entries, SuiteReleaseEntry{Path: path, Role: role, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Executable: executable})
	}
	commit := strings.Repeat("a", 40)
	manifest := SuiteReleaseManifest{
		SchemaVersion: 1, Version: "3.0.0", Target: SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH},
		Commits: SuiteReleaseCommits{AntBrowser: commit, FarmAgent: commit, FarmControl: commit}, ConfigSchema: 3,
		Capabilities: []string{}, CoreVersions: map[string]string{"chromium": "128.0.0"}, Dependencies: []SuiteReleaseDependency{}, Entries: entries,
	}
	manifestRaw, err := MarshalSuiteReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := SignSuiteReleaseManifest(manifestRaw, "precheck-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	release, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, SuiteReleaseTrustAnchor{KeyID: "precheck-test", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	for path, content := range files {
		candidate := filepath.Join(source, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(candidate), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(candidate, content, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(source, "release-manifest.json"), manifestRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "release-manifest.envelope.json"), envelopeRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		t.Fatal(err)
	}
	return suitePrecheckFixture{roots: roots, bootstrap: bootstrap, release: release, source: source, manifest: manifest}
}

func suitePrecheckTestDependencies() suiteCanonicalPrecheckDependencies {
	return suiteCanonicalPrecheckDependencies{
		ProbeRoot:      probeSuitePrecheckOwnerRoot,
		AvailableSpace: func(string) (string, uint64, error) { return "volume", math.MaxUint64, nil },
		AcquireInstance: func(string) (suitePrecheckInstanceLock, error) {
			return &suitePrecheckTestLock{}, nil
		},
		SecureInstance: func(string) error { return nil },
		ValidateSource: validateInstalledSuiteRelease,
		SaveCheckpoint: SaveSetupCheckpoint,
	}
}

func TestSuiteCanonicalPrecheckSecuresInstanceLockBeforeContinuing(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	deps := suitePrecheckTestDependencies()
	lock := &suitePrecheckTestLock{}
	deps.AcquireInstance = func(string) (suitePrecheckInstanceLock, error) { return lock, nil }
	calls := 0
	deps.SecureInstance = func(path string) error {
		calls++
		if path != filepath.Join(fixture.roots.AgentState, ".ant-farm-client.lock") {
			t.Fatalf("secure path=%q", path)
		}
		return errors.New("injected DACL failure")
	}
	if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); !errors.Is(err, ErrSuiteCanonicalPrecheck) {
		t.Fatalf("secure failure error=%v", err)
	}
	if calls != 1 || !lock.released {
		t.Fatalf("secure calls=%d lock released=%v", calls, lock.released)
	}
	if checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath); checkpoint != nil {
		t.Fatalf("secure failure wrote checkpoint: %+v", checkpoint)
	}
	for _, path := range []string{
		filepath.Join(fixture.roots.Config, SuiteClientConfigName),
		filepath.Join(fixture.roots.AgentState, SuiteBootstrapEnrollmentAttemptName),
		filepath.Join(fixture.roots.AgentState, SuiteActivationJournalName),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("secure failure created later artifact %s: %v", filepath.Base(path), err)
		}
	}
}

func TestSuiteCanonicalPrecheckWritesOnlyPrecheckAndIsIdempotent(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	if err := validateSuitePrecheckRootLayout(fixture.roots, fixture.source); err != nil {
		t.Fatalf("root layout: %v", err)
	}
	preparation, plan, err := loadSuitePrecheckProofChain(fixture.bootstrap, fixture.roots, fixture.release)
	if err != nil || preparation == nil || plan == nil {
		t.Fatalf("proof chain: prep=%+v plan=%+v err=%v", preparation, plan, err)
	}
	if _, _, err := validateInstalledSuiteRelease(fixture.source, *plan); err != nil {
		t.Fatalf("source: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies())
		if err != nil || result.Stage != SetupPrecheck || result.RequestUID == "" || result.ManifestSHA256 == "" || result.PayloadMinimumBytes == 0 || result.VolumeCount != 1 {
			t.Fatalf("attempt %d result=%+v err=%v", attempt, result, err)
		}
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupPrecheck {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
	for _, path := range []string{
		filepath.Join(fixture.roots.Config, SuiteClientConfigName),
		filepath.Join(fixture.roots.AgentState, SuiteBootstrapEnrollmentAttemptName),
		filepath.Join(fixture.roots.AgentState, SuiteActivationJournalName),
	} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("unexpected later-stage artifact %s: %v", filepath.Base(path), err)
		}
	}
	entries, err := os.ReadDir(fixture.roots.BrowserData)
	if err != nil || len(entries) != 0 {
		t.Fatalf("browser data changed: %v %v", entries, err)
	}
}

func TestSuiteCanonicalPrecheckProductionFilesystemAndDiskAdapters(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	result, err := RunSuiteCanonicalPrecheck(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source)
	if err != nil || result.Stage != SetupPrecheck || result.VolumeCount < 1 || result.PayloadMinimumBytes == 0 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSuiteCanonicalPrecheckRejectsProofPlanAndCheckpointDrift(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *suitePrecheckFixture)
	}{
		{"unverified proof", func(_ *testing.T, fixture *suitePrecheckFixture) { fixture.release.verified = false }},
		{"wrong target", func(_ *testing.T, fixture *suitePrecheckFixture) {
			fixture.release.manifest.Target.OS = "linux"
			if runtime.GOOS == "linux" {
				fixture.release.manifest.Target.OS = "windows"
			}
		}},
		{"bootstrap drift", func(_ *testing.T, fixture *suitePrecheckFixture) { fixture.bootstrap.NodeName = "Other" }},
		{"conflicting plan", func(t *testing.T, fixture *suitePrecheckFixture) {
			preparation, err := loadSetupPreparationCheckpoint(filepath.Join(fixture.roots.AgentState, suitePreparationStateName))
			if err != nil {
				t.Fatal(err)
			}
			other := fixture.release
			other.manifest.Version = "3.0.1"
			raw, _ := MarshalSuiteReleaseManifest(other.manifest)
			other.manifestSHA256 = suiteBootstrapSHA256(raw)
			plan, err := NewSuiteSetupPlan(*preparation, other)
			if err != nil {
				t.Fatal(err)
			}
			if err := SaveSuiteSetupPlan(fixture.roots, plan); err != nil {
				t.Fatal(err)
			}
		}},
		{"different checkpoint request", func(t *testing.T, fixture *suitePrecheckFixture) {
			if err := SaveSetupCheckpoint(fixture.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: "64473c80-0e26-4d7d-9b17-fd9cc6c959d8"}); err != nil {
				t.Fatal(err)
			}
		}},
		{"future checkpoint", func(t *testing.T, fixture *suitePrecheckFixture) {
			preparation, _ := loadSetupPreparationCheckpoint(filepath.Join(fixture.roots.AgentState, suitePreparationStateName))
			if err := SaveSetupCheckpoint(fixture.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupPrecheck, RequestUID: preparation.RequestUID}); err != nil {
				t.Fatal(err)
			}
			if err := SaveSetupCheckpoint(fixture.bootstrap.StatePath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: preparation.RequestUID}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuitePrecheckFixture(t)
			test.mutate(t, &fixture)
			if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err == nil {
				t.Fatal("drift accepted")
			}
		})
	}
}

func TestSuiteCanonicalPrecheckRejectsSourceRootAndCapacityFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, *suitePrecheckFixture, *suiteCanonicalPrecheckDependencies)
	}{
		{"tampered entry", func(t *testing.T, fixture *suitePrecheckFixture, _ *suiteCanonicalPrecheckDependencies) {
			if err := os.WriteFile(filepath.Join(fixture.source, "AntBrowser.exe"), []byte("bad"), 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"extra file", func(t *testing.T, fixture *suitePrecheckFixture, _ *suiteCanonicalPrecheckDependencies) {
			if err := os.WriteFile(filepath.Join(fixture.source, "evil.dll"), []byte("bad"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"source symlink", func(t *testing.T, fixture *suitePrecheckFixture, _ *suiteCanonicalPrecheckDependencies) {
			target := filepath.Join(fixture.source, "AntBrowser.exe")
			content, err := os.ReadFile(target)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(target); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "AntBrowser.exe")
			if err := os.WriteFile(outside, content, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, target); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
		}},
		{"existing browser data", func(t *testing.T, fixture *suitePrecheckFixture, _ *suiteCanonicalPrecheckDependencies) {
			if err := os.WriteFile(filepath.Join(fixture.roots.BrowserData, "config.yaml"), []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"disk error", func(_ *testing.T, _ *suitePrecheckFixture, deps *suiteCanonicalPrecheckDependencies) {
			deps.AvailableSpace = func(string) (string, uint64, error) { return "", 0, errors.New("disk") }
		}},
		{"disk insufficient", func(_ *testing.T, _ *suitePrecheckFixture, deps *suiteCanonicalPrecheckDependencies) {
			deps.AvailableSpace = func(string) (string, uint64, error) { return "volume", 1, nil }
		}},
		{"root probe cleanup failure", func(_ *testing.T, _ *suitePrecheckFixture, deps *suiteCanonicalPrecheckDependencies) {
			deps.ProbeRoot = func(string) error { return errors.New("cleanup") }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuitePrecheckFixture(t)
			deps := suitePrecheckTestDependencies()
			test.mutate(t, &fixture, &deps)
			if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("failure accepted")
			}
			if checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath); checkpoint != nil {
				t.Fatalf("checkpoint written after failure: %+v", checkpoint)
			}
		})
	}
	if _, err := suitePrecheckPayloadBytes(SuiteReleaseManifest{Entries: []SuiteReleaseEntry{{Size: math.MaxInt64}, {Size: math.MaxInt64}, {Size: math.MaxInt64}}}); !errors.Is(err, ErrSuiteCanonicalPrecheckCapacity) {
		t.Fatalf("aggregate overflow error=%v", err)
	}
}

func TestSuiteCanonicalPrecheckRejectsUncleanPaths(t *testing.T) {
	t.Run("source", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		unclean := fixture.source + string(filepath.Separator) + "."
		if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, unclean, suitePrecheckTestDependencies()); err == nil {
			t.Fatal("unclean source root accepted")
		}
	})
	t.Run("state path", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		fixture.bootstrap.StatePath = fixture.roots.AgentState + string(filepath.Separator) + "." + string(filepath.Separator) + "setup.json"
		if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err == nil {
			t.Fatal("unclean state path accepted")
		}
	})
}

func TestSuiteCanonicalPrecheckRejectsResolvedPathAliases(t *testing.T) {
	t.Run("source ancestor symlink", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		aliasParent := filepath.Join(t.TempDir(), "redirected")
		if err := os.Symlink(filepath.Dir(fixture.source), aliasParent); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		aliasedSource := filepath.Join(aliasParent, filepath.Base(fixture.source))
		if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, aliasedSource, suitePrecheckTestDependencies()); err == nil {
			t.Fatal("source with redirected ancestor accepted")
		}
	})
	t.Run("same inode case alias", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		caseAlias := strings.ToUpper(fixture.roots.Config)
		aliasInfo, aliasErr := os.Stat(caseAlias)
		configInfo, configErr := os.Stat(fixture.roots.Config)
		if aliasErr != nil || configErr != nil || !os.SameFile(aliasInfo, configInfo) || caseAlias == fixture.roots.Config {
			t.Skip("filesystem has no usable case-fold alias")
		}
		aliasedRoots := fixture.roots
		aliasedRoots.BrowserData = caseAlias
		if err := validateSuitePrecheckRootLayout(aliasedRoots, fixture.source); err == nil {
			t.Fatal("two roots sharing an inode through a case alias accepted")
		}
	})
}

func TestSuitePrecheckContainmentUsesFilesystemIdentity(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	makeDirectory := func(name string) string {
		path := filepath.Join(base, name)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	t.Run("case distinct siblings", func(t *testing.T) {
		upper := makeDirectory("Data")
		lower := makeDirectory("data")
		upperInfo, upperErr := os.Stat(upper)
		lowerInfo, lowerErr := os.Stat(lower)
		if upperErr != nil || lowerErr != nil || os.SameFile(upperInfo, lowerInfo) {
			t.Skip("filesystem is case-insensitive")
		}
		roots := SuiteUserRoots{Config: upper, BrowserData: lower, AgentState: makeDirectory("state"), Logs: makeDirectory("logs")}
		if err := validateSuitePrecheckRootLayout(roots, makeDirectory("source")); err != nil {
			t.Fatalf("case-distinct sibling directories rejected: %v", err)
		}
	})
	t.Run("physical ancestor", func(t *testing.T) {
		parent := makeDirectory("Parent")
		child := filepath.Join(parent, "Child")
		if err := os.MkdirAll(child, 0o700); err != nil {
			t.Fatal(err)
		}
		aliasParent := filepath.Join(base, "parent")
		if parentInfo, parentErr := os.Stat(parent); parentErr == nil {
			if aliasInfo, aliasErr := os.Stat(aliasParent); aliasErr != nil || !os.SameFile(parentInfo, aliasInfo) {
				aliasParent = parent
			}
		}
		roots := SuiteUserRoots{Config: parent, BrowserData: filepath.Join(aliasParent, "Child"), AgentState: makeDirectory("other-state"), Logs: makeDirectory("other-logs")}
		if err := validateSuitePrecheckRootLayout(roots, makeDirectory("other-source")); err == nil {
			t.Fatal("physical ancestor overlap accepted")
		}
	})
}

func TestSuitePrecheckWindowsResolvedPathComparisonUsesCaseInsensitiveIdentity(t *testing.T) {
	if !suitePrecheckWindowsResolvedPathMatches(`C:\Users\Farm\AntSuite`, `c:\users\farm\antsuite`) {
		t.Fatal("Windows casing aliases were treated as different paths")
	}
	for _, candidate := range []string{`C:\Users\Farm\AntSuite2`, `D:\Users\Farm\AntSuite`, `C:\Users\Other\AntSuite`} {
		if suitePrecheckWindowsResolvedPathMatches(`C:\Users\Farm\AntSuite`, candidate) {
			t.Fatalf("different Windows path %q treated as equivalent", candidate)
		}
	}
}

func TestSuiteCanonicalPrecheckRejectsUnrecognizedMutableFootprint(t *testing.T) {
	for _, test := range []struct {
		name string
		path func(suitePrecheckFixture) string
	}{
		{"config", func(f suitePrecheckFixture) string { return filepath.Join(f.roots.Config, SuiteClientConfigName) }},
		{"browser data", func(f suitePrecheckFixture) string { return filepath.Join(f.roots.BrowserData, "Default") }},
		{"agent state", func(f suitePrecheckFixture) string {
			return filepath.Join(f.roots.AgentState, SuiteOwnershipHandoffName)
		}},
		{"logs", func(f suitePrecheckFixture) string { return filepath.Join(f.roots.Logs, "agent.log") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuitePrecheckFixture(t)
			path := test.path(fixture)
			if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); !errors.Is(err, ErrSuiteCanonicalPrecheckExisting) {
				t.Fatalf("existing footprint error=%v", err)
			}
			if checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath); checkpoint != nil {
				t.Fatalf("existing footprint wrote checkpoint: %+v", checkpoint)
			}
			if _, err := os.Stat(filepath.Join(fixture.roots.AgentState, suiteSetupPlanName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("existing footprint created setup plan: %v", err)
			}
		})
	}
}

func TestSuiteCanonicalPrecheckCountsDistinctVolumes(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	deps := suitePrecheckTestDependencies()
	deps.AvailableSpace = func(root string) (string, uint64, error) {
		if root == fixture.roots.BrowserData {
			return "browser-volume", math.MaxUint64, nil
		}
		return "state-volume", math.MaxUint64, nil
	}
	result, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
	if err != nil || result.VolumeCount != 2 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestSuiteCanonicalPrecheckCheckpointWriteFailureCanRetry(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	deps := suitePrecheckTestDependencies()
	deps.SaveCheckpoint = func(string, SetupCheckpoint) error { return errors.New("injected checkpoint failure") }
	if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
		t.Fatal("checkpoint failure accepted")
	}
	if checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath); checkpoint != nil {
		t.Fatalf("failed write advanced checkpoint: %+v", checkpoint)
	}
	if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err != nil {
		t.Fatalf("retry failed: %v", err)
	}
}

func TestSuiteCanonicalPrecheckRejectsRootAndCheckpointCorruption(t *testing.T) {
	t.Run("corrupt checkpoint", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		if err := os.WriteFile(fixture.bootstrap.StatePath, []byte(`{"schema_version":1,"private_key":"secret"}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err == nil {
			t.Fatal("corrupt checkpoint accepted")
		}
	})
	if runtime.GOOS != "windows" {
		t.Run("wrong root mode", func(t *testing.T) {
			fixture := newSuitePrecheckFixture(t)
			if err := os.Chmod(fixture.roots.Logs, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err == nil {
				t.Fatal("permissive root accepted")
			}
		})
	}
	t.Run("redirected root", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		if err := os.Remove(fixture.roots.Logs); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(t.TempDir(), fixture.roots.Logs); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suitePrecheckTestDependencies()); err == nil {
			t.Fatal("redirected root accepted")
		}
	})
}

func TestSuiteCanonicalPrecheckRevalidatesAfterProbes(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, suitePrecheckFixture) error
	}{
		{"source", func(_ *testing.T, fixture suitePrecheckFixture) error {
			return os.WriteFile(filepath.Join(fixture.source, "evil.dll"), []byte("late"), 0o600)
		}},
		{"preparation", func(t *testing.T, fixture suitePrecheckFixture) error {
			preparation, err := loadSetupPreparationCheckpoint(filepath.Join(fixture.roots.AgentState, suitePreparationStateName))
			if err != nil {
				t.Fatal(err)
			}
			preparation.BootstrapSHA256 = strings.Repeat("b", 64)
			raw, err := json.Marshal(preparation)
			if err != nil {
				return err
			}
			return writeOwnerAtomic(filepath.Join(fixture.roots.AgentState, suitePreparationStateName), append(raw, '\n'))
		}},
		{"plan", func(t *testing.T, fixture suitePrecheckFixture) error {
			plan, err := LoadSuiteSetupPlan(fixture.roots)
			if err != nil {
				t.Fatal(err)
			}
			plan.ManifestSHA256 = strings.Repeat("b", 64)
			plan.StageID = deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
			raw, err := jsonMarshalSuiteSetupPlan(*plan)
			if err != nil {
				return err
			}
			return writeOwnerAtomic(filepath.Join(fixture.roots.AgentState, suiteSetupPlanName), raw)
		}},
		{"source ancestor redirect", func(_ *testing.T, fixture suitePrecheckFixture) error {
			parent := filepath.Dir(fixture.source)
			moved := parent + "-moved"
			if err := os.Rename(parent, moved); err != nil {
				return err
			}
			return os.Symlink(moved, parent)
		}},
		{"source replaced by equal ordinary tree", func(t *testing.T, fixture suitePrecheckFixture) error {
			original := fixture.source + "-original"
			if err := os.Rename(fixture.source, original); err != nil {
				return err
			}
			return cloneSuitePrecheckTree(t, original, fixture.source)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuitePrecheckFixture(t)
			deps := suitePrecheckTestDependencies()
			deps.AfterProbes = func() error { return test.mutate(t, fixture) }
			if _, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("late drift accepted")
			}
			if checkpoint, _ := LoadSetupCheckpoint(fixture.bootstrap.StatePath); checkpoint != nil {
				t.Fatalf("late drift wrote checkpoint: %+v", checkpoint)
			}
		})
	}
}

func cloneSuitePrecheckTree(t *testing.T, source, destination string) error {
	t.Helper()
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, info.Mode().Perm())
	})
}

func TestSuiteCanonicalPrecheckActiveAgentAndSetupLockFailClosed(t *testing.T) {
	t.Run("active agent", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		active, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState)
		if err != nil {
			t.Fatal(err)
		}
		defer active.Release()
		if _, err := RunSuiteCanonicalPrecheck(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); err == nil {
			t.Fatal("active Agent accepted")
		}
	})
	t.Run("setup lock", func(t *testing.T) {
		fixture := newSuitePrecheckFixture(t)
		lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName))
		if err != nil {
			t.Fatal(err)
		}
		defer lock.release()
		if _, err := RunSuiteCanonicalPrecheck(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("setup contention error=%v", err)
		}
	})
}

func TestSuiteCanonicalPrecheckConcurrentCallersRemainAtOneStage(t *testing.T) {
	fixture := newSuitePrecheckFixture(t)
	deps := suitePrecheckTestDependencies()
	deps.ProbeRoot = func(string) error { return nil }
	var wait sync.WaitGroup
	errorsSeen := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalPrecheckWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
			errorsSeen <- err
		}()
	}
	wait.Wait()
	close(errorsSeen)
	successes := 0
	for err := range errorsSeen {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("unexpected error=%v", err)
		}
	}
	if successes == 0 {
		t.Fatal("no precheck winner")
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupPrecheck {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
}

func TestSuitePrecheckOwnerRootProbeLeavesNoArtifact(t *testing.T) {
	root := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(root, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := probeSuitePrecheckOwnerRoot(root); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("probe residue=%v err=%v", entries, err)
	}
}
