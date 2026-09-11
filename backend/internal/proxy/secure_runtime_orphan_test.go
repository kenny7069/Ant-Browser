package proxy

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

const secureRuntimeCrashRestartHelperEnv = "ANT_PROXY_SECURE_RUNTIME_CRASH_RESTART_HELPER"

func TestSecureRuntimeCrashRestartHelper(t *testing.T) {
	if os.Getenv(secureRuntimeCrashRestartHelperEnv) != "1" {
		return
	}
	parent := os.Getenv("ANT_PROXY_SECURE_RUNTIME_PARENT")
	appRoot := os.Getenv("ANT_PROXY_SECURE_RUNTIME_APP_ROOT")
	mode := os.Getenv("ANT_PROXY_SECURE_RUNTIME_HELPER_MODE")
	report := os.Getenv("ANT_PROXY_SECURE_RUNTIME_REPORT")
	if parent == "" || appRoot == "" || (mode != "crash" && mode != "sweep") {
		t.Fatalf("invalid crash/restart helper environment")
	}
	// This helper deliberately uses the production app-root constructor. The
	// test only redirects TMPDIR to an isolated directory; it never reads or
	// prints the persistent HMAC key or any proxy credential.
	writer, err := newSecureRuntimeWriterForApp("xray", appRoot)
	if err != nil {
		t.Fatalf("newSecureRuntimeWriterForApp() error = %v", err)
	}
	key := "helper-node-" + mode
	if _, err := writer.runtimeDir(key); err != nil {
		t.Fatalf("runtimeDir() error = %v", err)
	}
	if _, err := writer.writeAtomic(key, "xray-config.json", []byte("synthetic-runtime-config")); err != nil {
		t.Fatalf("writeAtomic() error = %v", err)
	}
	if report != "" {
		if err := os.WriteFile(report, []byte(writer.root), secureRuntimeFileMode); err != nil {
			t.Fatalf("write helper report: %v", err)
		}
	}
	if mode == "crash" {
		// os.Exit skips testing cleanup and simulates a process crash after the
		// secure writer has registered a live runtime root.
		os.Exit(0)
	}
}

func TestSecureRuntimeCrashRestartSubprocessSweep(t *testing.T) {
	if !secureRuntimeOrphanSweepSupported() {
		t.Skip("platform intentionally keeps orphan sweep fail-closed")
	}
	parent := t.TempDir()
	appRoot := filepath.Join(t.TempDir(), "app")
	if err := os.Mkdir(appRoot, secureRuntimeDirMode); err != nil {
		t.Fatalf("mkdir app root: %v", err)
	}
	baseEnv := append(os.Environ(),
		secureRuntimeCrashRestartHelperEnv+"=1",
		"ANT_PROXY_SECURE_RUNTIME_PARENT="+parent,
		"ANT_PROXY_SECURE_RUNTIME_APP_ROOT="+appRoot,
		"TMPDIR="+parent,
	)
	startHelper := func(mode string, reportPath string) (*exec.Cmd, error) {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSecureRuntimeCrashRestartHelper$", "-test.v")
		cmd.Env = append(append([]string{}, baseEnv...), "ANT_PROXY_SECURE_RUNTIME_HELPER_MODE="+mode)
		if reportPath != "" {
			cmd.Env = append(cmd.Env, "ANT_PROXY_SECURE_RUNTIME_REPORT="+reportPath)
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		cmd.Stdout = &stderr
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start %s helper: %w", mode, err)
		}
		if err := cmd.Wait(); err != nil {
			return nil, fmt.Errorf("%s helper failed: %w (%s)", mode, err, stderr.String())
		}
		return cmd, nil
	}

	liveWriter, err := newSecureRuntimeWriterForApp("xray", appRoot)
	if err != nil {
		t.Fatal(err)
	}
	liveRoot, err := liveWriter.runtimeDir("parent-live")
	if err != nil {
		t.Fatalf("live runtimeDir() error = %v", err)
	}
	if _, err := liveWriter.writeAtomic("parent-live", "xray-config.json", []byte("synthetic-live-runtime-config")); err != nil {
		t.Fatalf("live writeAtomic() error = %v", err)
	}
	if _, err := os.Stat(liveRoot); err != nil {
		t.Fatalf("live/current root missing before crash: %v", err)
	}

	crashReport := filepath.Join(parent, "crash-helper-report")
	_, err = startHelper("crash", crashReport)
	if err != nil {
		t.Fatal(err)
	}
	crashData, err := os.ReadFile(crashReport)
	if err != nil || len(crashData) == 0 {
		t.Fatalf("crash helper did not publish runtime root: %q, error = %v", crashData, err)
	}
	staleRoot := string(crashData)
	staleBase := filepath.Base(staleRoot)
	if staleRoot == liveRoot || len(staleBase) <= len("ant-proxy-xray-") || staleBase[:len("ant-proxy-xray-")] != "ant-proxy-xray-" {
		t.Fatalf("crash helper published unexpected runtime root: %q", staleRoot)
	}
	if _, err := os.Stat(filepath.Join(staleRoot, "helper-node-crash", "xray-config.json")); err != nil {
		t.Fatalf("crash helper managed config missing: %v", err)
	}

	unknownRoot := filepath.Join(parent, "ant-proxy-xray-unknown")
	if err := os.Mkdir(unknownRoot, secureRuntimeDirMode); err != nil {
		t.Fatal(err)
	}
	unknownFile := filepath.Join(unknownRoot, "unknown-artifact")
	if err := os.WriteFile(unknownFile, []byte("retain"), secureRuntimeFileMode); err != nil {
		t.Fatal(err)
	}
	tamperedRoot := filepath.Join(parent, "ant-proxy-xray-tampered")
	if err := os.Mkdir(tamperedRoot, secureRuntimeDirMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tamperedRoot, secureRuntimeMarkerName), []byte(`{"version":1,"mac":"tampered"}`), secureRuntimeFileMode); err != nil {
		t.Fatal(err)
	}

	currentReport := filepath.Join(parent, "current-helper-report")
	if _, err := startHelper("sweep", currentReport); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(staleRoot); !os.IsNotExist(err) {
		t.Fatalf("authenticated crashed root was not removed, lstat error = %v", err)
	}
	currentData, err := os.ReadFile(currentReport)
	if err != nil || len(currentData) == 0 {
		t.Fatalf("sweep helper did not publish current runtime root: %q, error = %v", currentData, err)
	}
	if _, err := os.Lstat(string(currentData)); err != nil {
		t.Fatalf("current runtime root was removed during its startup sweep: %v", err)
	}
	if _, err := os.Lstat(liveRoot); err != nil {
		t.Fatalf("live root was removed by restart sweep: %v", err)
	}
	if _, err := os.Lstat(unknownRoot); err != nil {
		t.Fatalf("unknown root was removed by restart sweep: %v", err)
	}
	if data, err := os.ReadFile(unknownFile); err != nil || string(data) != "retain" {
		t.Fatalf("unknown artifact changed after restart sweep: %q, error = %v", data, err)
	}
	if _, err := os.Lstat(tamperedRoot); err != nil {
		t.Fatalf("tampered root was removed by restart sweep: %v", err)
	}
}

func TestSecureRuntimeProductionWriterReusesAuthenticatedRootAfterCleanup(t *testing.T) {
	appRoot := t.TempDir()
	writer, err := newSecureRuntimeWriterForApp("xray", appRoot)
	if err != nil {
		t.Fatalf("newSecureRuntimeWriterForApp() error = %v", err)
	}
	root := writer.root
	firstGeneration := writer.rootToken
	t.Cleanup(func() {
		_ = writer.cleanup("reuse-first")
		_ = writer.cleanup("reuse-second")
		_ = os.Remove(writer.root)
	})
	if _, err := writer.writeAtomic("reuse-first", "xray-config.json", []byte("first")); err != nil {
		t.Fatalf("first writeAtomic() error = %v", err)
	}
	firstHandle, err := writer.handle("reuse-first")
	if err != nil {
		t.Fatalf("first handle() error = %v", err)
	}
	if err := firstHandle.cleanup(); err != nil {
		t.Fatalf("first cleanup() error = %v", err)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("first cleanup left runtime root, lstat error = %v", err)
	}
	if _, err := firstHandle.markProcessLaunchPendingToken(); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("stale handle transition = %v, want ErrSecureRuntimePath", err)
	}
	if _, err := writer.writeAtomic("reuse-second", "xray-config.json", []byte("second")); err != nil {
		t.Fatalf("second writeAtomic() after root cleanup error = %v", err)
	}
	if writer.root != root {
		t.Fatalf("writer root changed unexpectedly: got %q, want %q", writer.root, root)
	}
	if writer.rootToken == firstGeneration || writer.rootToken == "" {
		t.Fatalf("writer root generation was not replaced: old=%q new=%q", firstGeneration, writer.rootToken)
	}
	markerData, err := secureRuntimeReadMetadata(filepath.Join(writer.root, secureRuntimeMarkerName))
	if err != nil {
		t.Fatalf("read replacement marker = %v", err)
	}
	var marker secureRuntimeMarker
	if err := json.Unmarshal(markerData, &marker); err != nil {
		t.Fatalf("decode replacement marker = %v", err)
	}
	if marker.Token != writer.rootToken || marker.Pending != 0 || len(marker.Children) != 0 {
		t.Fatalf("replacement marker = token %q pending %d children %d", marker.Token, marker.Pending, len(marker.Children))
	}
}

func TestSecureRuntimeProductionWriterRejectsUnauthenticatedRootReplacement(t *testing.T) {
	appRoot := t.TempDir()
	writer, err := newSecureRuntimeWriterForApp("singbox", appRoot)
	if err != nil {
		t.Fatalf("newSecureRuntimeWriterForApp() error = %v", err)
	}
	root := writer.root
	t.Cleanup(func() {
		_ = writer.cleanup("replacement-negative")
		_ = os.Remove(root)
	})
	if _, err := writer.writeAtomic("replacement-negative", "singbox-config.json", []byte("first")); err != nil {
		t.Fatalf("first writeAtomic() error = %v", err)
	}
	if err := writer.cleanup("replacement-negative"); err != nil {
		t.Fatalf("first cleanup() error = %v", err)
	}
	if err := os.Mkdir(root, secureRuntimeDirMode); err != nil {
		t.Fatalf("replace root with unauthenticated directory = %v", err)
	}
	if _, err := writer.writeAtomic("replacement-negative", "singbox-config.json", []byte("second")); !errors.Is(err, ErrSecureRuntimeAuth) {
		t.Fatalf("write into unauthenticated root = %v, want ErrSecureRuntimeAuth", err)
	}
	if err := os.Remove(root); err != nil {
		t.Fatalf("remove unauthenticated root = %v", err)
	}
	if err := os.Symlink(t.TempDir(), root); err == nil {
		if _, err := writer.writeAtomic("replacement-negative", "singbox-config.json", []byte("third")); !errors.Is(err, ErrSecureRuntimePath) {
			t.Fatalf("write through replacement symlink = %v, want ErrSecureRuntimePath", err)
		}
		if err := os.Remove(root); err != nil {
			t.Fatalf("remove replacement symlink = %v", err)
		}
	}
}

func TestSecureRuntimeProductionWriterReuseConcurrentHandles(t *testing.T) {
	appRoot := t.TempDir()
	writer, err := newSecureRuntimeWriterForApp("mihomo", appRoot)
	if err != nil {
		t.Fatalf("newSecureRuntimeWriterForApp() error = %v", err)
	}
	if _, err := writer.writeAtomic("reuse-seed", "mihomo-config.yaml", []byte("seed")); err != nil {
		t.Fatalf("seed writeAtomic() error = %v", err)
	}
	if err := writer.cleanup("reuse-seed"); err != nil {
		t.Fatalf("seed cleanup() error = %v", err)
	}
	const workers = 16
	errs := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		key := fmt.Sprintf("reuse-concurrent-%02d", i)
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			_, err := writer.writeAtomic(key, "mihomo-config.yaml", []byte("concurrent"))
			errs <- err
		}(key)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent reuse writeAtomic() error = %v", err)
		}
	}
	cleanupErrs := make(chan error, workers)
	for i := 0; i < workers; i++ {
		key := fmt.Sprintf("reuse-concurrent-%02d", i)
		wg.Add(1)
		go func(key string) {
			defer wg.Done()
			cleanupErrs <- writer.cleanup(key)
		}(key)
	}
	wg.Wait()
	close(cleanupErrs)
	for err := range cleanupErrs {
		if err != nil {
			t.Fatalf("concurrent cleanup() error = %v", err)
		}
	}
}

func TestSecureRuntimeKeyCreationConcurrentFirstCreate(t *testing.T) {
	appRoot := t.TempDir()
	const constructors = 32
	type result struct {
		writer *secureRuntimeWriter
		err    error
	}
	results := make(chan result, constructors)
	var wg sync.WaitGroup
	for i := 0; i < constructors; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writer, err := newSecureRuntimeWriterForApp("xray", appRoot)
			results <- result{writer: writer, err: err}
		}()
	}
	wg.Wait()
	close(results)
	writers := make([]*secureRuntimeWriter, 0, constructors)
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent production constructor error = %v", result.err)
		}
		writers = append(writers, result.writer)
	}
	securityDir, _, err := secureRuntimePersistentSecurityDir(appRoot)
	if err != nil {
		t.Fatalf("secureRuntimePersistentSecurityDir() error = %v", err)
	}
	keyData, err := os.ReadFile(filepath.Join(securityDir, secureRuntimeRegistryKeyName))
	if err != nil || len(keyData) != 32 {
		t.Fatalf("persisted key length = %d, error = %v", len(keyData), err)
	}
	for _, writer := range writers {
		if !bytes.Equal(writer.key, keyData) {
			t.Fatalf("constructor received a different key")
		}
		if err := writer.removeRootIfEmpty(); err != nil {
			t.Fatalf("remove test runtime root = %v", err)
		}
	}
}

func TestSecureRuntimeKeyCreationRejectsInvalidExistingArtifacts(t *testing.T) {
	t.Run("invalid", func(t *testing.T) {
		securityDir := testSecureRuntimeSecurityDir(t)
		path := filepath.Join(securityDir, secureRuntimeRegistryKeyName)
		if err := os.WriteFile(path, []byte("short"), secureRuntimeFileMode); err != nil {
			t.Fatalf("write invalid key = %v", err)
		}
		if _, err := secureRuntimeLoadOrCreateKey(securityDir); !errors.Is(err, ErrSecureRuntimeAuth) {
			t.Fatalf("invalid key load = %v, want ErrSecureRuntimeAuth", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		securityDir := testSecureRuntimeSecurityDir(t)
		path := filepath.Join(securityDir, secureRuntimeRegistryKeyName)
		if err := os.Symlink(t.TempDir(), path); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := secureRuntimeLoadOrCreateKey(securityDir); !errors.Is(err, ErrSecureRuntimeAuth) {
			t.Fatalf("symlink key load = %v, want ErrSecureRuntimeAuth", err)
		}
	})
	t.Run("unowned", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("Windows owner check requires a Windows runner")
		}
		securityDir := testSecureRuntimeSecurityDir(t)
		path := filepath.Join(securityDir, secureRuntimeRegistryKeyName)
		if err := os.WriteFile(path, make([]byte, 32), secureRuntimeFileMode); err != nil {
			t.Fatalf("write unowned fixture = %v", err)
		}
		if err := os.Chown(path, os.Getuid()+1, -1); err != nil {
			t.Skipf("cannot chown fixture: %v", err)
		}
		if _, err := secureRuntimeLoadOrCreateKey(securityDir); !errors.Is(err, ErrSecureRuntimeAuth) {
			t.Fatalf("unowned key load = %v, want ErrSecureRuntimeAuth", err)
		}
	})
}

func testSecureRuntimeSecurityDir(t *testing.T) string {
	t.Helper()
	securityDir := filepath.Join(t.TempDir(), secureRuntimeRegistryDirName)
	if err := secureRuntimeEnsurePrivateDirectory(securityDir); err != nil {
		t.Fatalf("secureRuntimeEnsurePrivateDirectory() error = %v", err)
	}
	return securityDir
}

type secureRuntimeSweepFixture struct {
	parent      string
	securityDir string
	registry    string
	lock        string
	appID       string
	key         []byte
	identity    secureRuntimeProcessIdentity
	liveness    func(secureRuntimeProcessIdentity) secureRuntimeProcessState
}

func newSecureRuntimeSweepFixture(t *testing.T, liveness func(secureRuntimeProcessIdentity) secureRuntimeProcessState) secureRuntimeSweepFixture {
	t.Helper()
	parent := t.TempDir()
	securityDir := filepath.Join(t.TempDir(), "security")
	if err := secureRuntimeEnsurePrivateDirectory(securityDir); err != nil {
		t.Fatalf("secureRuntimeEnsurePrivateDirectory() error = %v", err)
	}
	key := []byte("0123456789abcdef0123456789abcdef")
	registry := filepath.Join(securityDir, secureRuntimeRegistryName)
	if err := secureRuntimeEnsureRegistry(registry, "fixture-app", key); err != nil {
		t.Fatalf("secureRuntimeEnsureRegistry() error = %v", err)
	}
	if liveness == nil {
		liveness = func(secureRuntimeProcessIdentity) secureRuntimeProcessState {
			return secureRuntimeProcessExited
		}
	}
	return secureRuntimeSweepFixture{
		parent: parent, securityDir: securityDir, registry: registry,
		lock:  filepath.Join(securityDir, secureRuntimeRegistryLockName),
		appID: "fixture-app", key: key,
		identity: secureRuntimeProcessIdentity{PID: 9001, Start: "fixture-current"},
		liveness: liveness,
	}
}

func (f secureRuntimeSweepFixture) options() secureRuntimeWriterOptions {
	enabled := true
	return secureRuntimeWriterOptions{
		tempParent: f.parent, securityDir: f.securityDir, appID: f.appID,
		key: f.key, registryPath: f.registry, lockPath: f.lock,
		processIdentity: f.identity, processLiveness: f.liveness,
		ownerCheck: secureRuntimeCheckOwnerAndMode, sweepEnabled: &enabled,
	}
}

func addFixtureRoot(t *testing.T, f secureRuntimeSweepFixture, name, stack, token string, owner secureRuntimeProcessIdentity, children map[string]secureRuntimeProcessIdentity, pending int, managed map[string][]string, markerOverride []byte) string {
	t.Helper()
	root := filepath.Join(f.parent, name)
	if err := os.Mkdir(root, secureRuntimeDirMode); err != nil {
		t.Fatalf("mkdir fixture root: %v", err)
	}
	if managed == nil {
		managed = map[string][]string{}
	}
	if children == nil {
		children = map[string]secureRuntimeProcessIdentity{}
	}
	for key, names := range managed {
		dir := filepath.Join(root, key)
		if err := secureRuntimeCreateDirectory(dir); err != nil {
			t.Fatalf("mkdir fixture runtime key: %v", err)
		}
		for _, filename := range names {
			file, err := secureRuntimeCreateExclusiveFile(filepath.Join(dir, filename))
			if err != nil {
				t.Fatalf("create fixture runtime file: %v", err)
			}
			_, _ = file.WriteString("fixture")
			_ = file.Close()
		}
	}
	marker := secureRuntimeMarker{Version: secureRuntimeMarkerVersion, Root: name, Stack: stack, Token: token, Owner: owner, Children: children, Pending: pending, Entries: managed}
	markerMAC, err := secureRuntimeMarkerMAC(marker, f.key)
	if err != nil {
		t.Fatalf("marker MAC: %v", err)
	}
	marker.MAC = markerMAC
	markerData, err := json.Marshal(marker)
	if err != nil {
		t.Fatalf("marshal marker: %v", err)
	}
	if markerOverride != nil {
		markerData = markerOverride
	}
	if err := secureRuntimeWriteMetadata(filepath.Join(root, secureRuntimeMarkerName), markerData); err != nil {
		t.Fatalf("write fixture marker: %v", err)
	}
	registry, err := secureRuntimeReadRegistry(f.registry, f.appID, f.key)
	if err != nil {
		t.Fatalf("read fixture registry: %v", err)
	}
	registry.Roots[name] = secureRuntimeRegistryEntry{Stack: stack, Token: token, MarkerMAC: markerMAC}
	if err := secureRuntimeWriteRegistry(f.registry, registry, f.key); err != nil {
		t.Fatalf("write fixture registry: %v", err)
	}
	return root
}

func fixtureToken(t *testing.T, seed byte) string {
	t.Helper()
	b := make([]byte, 32)
	for i := range b {
		b[i] = seed + byte(i)
	}
	return hex.EncodeToString(b)
}

func TestSecureRuntimeStartupSweepRemovesAuthenticatedStaleRoot(t *testing.T) {
	f := newSecureRuntimeSweepFixture(t, func(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
		if identity.PID == 9001 {
			return secureRuntimeProcessExited
		}
		return secureRuntimeProcessExited
	})
	stale := addFixtureRoot(t, f, "ant-proxy-xray-stale", "xray", fixtureToken(t, 1), secureRuntimeProcessIdentity{PID: 9001, Start: "old-start"}, nil, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	if _, err := newSecureRuntimeWriterWithOptions("xray", f.options()); err != nil {
		t.Fatalf("startup writer error = %v", err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale authenticated root remains, lstat error = %v", err)
	}
}

func TestSecureRuntimeStartupSweepRetainsLiveAndCurrentRoots(t *testing.T) {
	currentIdentity := secureRuntimeProcessIdentity{PID: 9001, Start: "fixture-current"}
	f := newSecureRuntimeSweepFixture(t, func(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
		if identity == currentIdentity {
			return secureRuntimeProcessAlive
		}
		if identity.PID == 9002 {
			return secureRuntimeProcessAlive
		}
		if identity.PID == 9003 {
			return secureRuntimeProcessExited
		}
		return secureRuntimeProcessAlive
	})
	live := addFixtureRoot(t, f, "ant-proxy-xray-live", "xray", fixtureToken(t, 2), secureRuntimeProcessIdentity{PID: 9002, Start: "live-start"}, map[string]secureRuntimeProcessIdentity{}, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	childLive := addFixtureRoot(t, f, "ant-proxy-xray-child-live", "xray", fixtureToken(t, 20), secureRuntimeProcessIdentity{PID: 9003, Start: "dead-owner"}, map[string]secureRuntimeProcessIdentity{"0000000000000001": {PID: 9002, Start: "live-child"}}, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	writer, err := newSecureRuntimeWriterWithOptions("xray", f.options())
	if err != nil {
		t.Fatalf("startup writer error = %v", err)
	}
	for _, path := range []string{live, childLive} {
		if _, err := os.Lstat(path); err != nil {
			t.Fatalf("live root removed (%s): %v", path, err)
		}
	}
	if _, err := os.Lstat(writer.root); err != nil {
		t.Fatalf("current root missing: %v", err)
	}
}

func TestSecureRuntimeStartupSweepRetainsMalformedSymlinkAndUnknownRoots(t *testing.T) {
	f := newSecureRuntimeSweepFixture(t, func(secureRuntimeProcessIdentity) secureRuntimeProcessState {
		return secureRuntimeProcessExited
	})
	malformed := filepath.Join(f.parent, "ant-proxy-xray-malformed")
	if err := os.Mkdir(malformed, secureRuntimeDirMode); err != nil {
		t.Fatal(err)
	}
	if err := secureRuntimeWriteMetadata(filepath.Join(malformed, secureRuntimeMarkerName), []byte(`{"version":1}`)); err != nil {
		t.Fatal(err)
	}
	registry, err := secureRuntimeReadRegistry(f.registry, f.appID, f.key)
	if err != nil {
		t.Fatal(err)
	}
	registry.Roots[filepath.Base(malformed)] = secureRuntimeRegistryEntry{Stack: "xray", Token: fixtureToken(t, 3), MarkerMAC: fixtureToken(t, 4)}
	if err := secureRuntimeWriteRegistry(f.registry, registry, f.key); err != nil {
		t.Fatal(err)
	}
	unknown := addFixtureRoot(t, f, "ant-proxy-xray-unknown", "xray", fixtureToken(t, 5), secureRuntimeProcessIdentity{PID: 9003, Start: "dead"}, nil, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	if err := os.WriteFile(filepath.Join(unknown, "unknown-artifact"), []byte("keep"), secureRuntimeFileMode); err != nil {
		t.Fatal(err)
	}
	tampered := addFixtureRoot(t, f, "ant-proxy-xray-tampered", "xray", fixtureToken(t, 10), secureRuntimeProcessIdentity{PID: 9006, Start: "dead"}, nil, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	markerPath := filepath.Join(tampered, secureRuntimeMarkerName)
	markerData, err := secureRuntimeReadMetadata(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	var marker secureRuntimeMarker
	if err := json.Unmarshal(markerData, &marker); err != nil {
		t.Fatal(err)
	}
	marker.MAC = fixtureToken(t, 11)
	markerData, err = json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	if err := secureRuntimeWriteMetadata(markerPath, markerData); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(f.parent, "ant-proxy-xray-missing-marker")
	if err := os.Mkdir(missing, secureRuntimeDirMode); err != nil {
		t.Fatal(err)
	}
	registry, err = secureRuntimeReadRegistry(f.registry, f.appID, f.key)
	if err != nil {
		t.Fatal(err)
	}
	registry.Roots[filepath.Base(missing)] = secureRuntimeRegistryEntry{Stack: "xray", Token: fixtureToken(t, 12), MarkerMAC: fixtureToken(t, 13)}
	if err := secureRuntimeWriteRegistry(f.registry, registry, f.key); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(f.parent, "ant-proxy-xray-symlink")
	if err := os.Symlink(t.TempDir(), symlink); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	registry, err = secureRuntimeReadRegistry(f.registry, f.appID, f.key)
	if err != nil {
		t.Fatal(err)
	}
	registry.Roots[filepath.Base(symlink)] = secureRuntimeRegistryEntry{Stack: "xray", Token: fixtureToken(t, 6), MarkerMAC: fixtureToken(t, 7)}
	if err := secureRuntimeWriteRegistry(f.registry, registry, f.key); err != nil {
		t.Fatal(err)
	}
	if _, err := newSecureRuntimeWriterWithOptions("xray", f.options()); err != nil {
		t.Fatalf("startup writer error = %v", err)
	}
	for _, path := range []string{malformed, unknown, tampered, missing, symlink} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("protected root %q removed: %v", path, err)
		}
	}
	if got, err := os.ReadFile(filepath.Join(unknown, "unknown-artifact")); err != nil || string(got) != "keep" {
		t.Fatalf("unknown artifact changed: %q, error = %v", got, err)
	}
}

func TestSecureRuntimeStartupSweepRetainsPIDReuseAndPendingContradictions(t *testing.T) {
	f := newSecureRuntimeSweepFixture(t, func(identity secureRuntimeProcessIdentity) secureRuntimeProcessState {
		if identity.PID == 9004 {
			return secureRuntimeProcessIdentityMismatch
		}
		return secureRuntimeProcessExited
	})
	mismatch := addFixtureRoot(t, f, "ant-proxy-xray-pid-reuse", "xray", fixtureToken(t, 8), secureRuntimeProcessIdentity{PID: 9004, Start: "old"}, nil, 0, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	pending := addFixtureRoot(t, f, "ant-proxy-xray-pending", "xray", fixtureToken(t, 9), secureRuntimeProcessIdentity{PID: 9005, Start: "dead"}, nil, 1, map[string][]string{"node-a": {"xray-config.json"}}, nil)
	if _, err := newSecureRuntimeWriterWithOptions("xray", f.options()); err != nil {
		t.Fatalf("startup writer error = %v", err)
	}
	for _, path := range []string{mismatch, pending} {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("contradictory root %q removed: %v", path, err)
		}
	}
}

func TestSecureRuntimeStartupSweepConcurrentWritersRetainCurrentRoots(t *testing.T) {
	f := newSecureRuntimeSweepFixture(t, func(secureRuntimeProcessIdentity) secureRuntimeProcessState {
		return secureRuntimeProcessAlive
	})
	const writers = 4
	var wg sync.WaitGroup
	results := make(chan *secureRuntimeWriter, writers)
	errorsCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			writer, err := newSecureRuntimeWriterWithOptions("xray", f.options())
			if err != nil {
				errorsCh <- err
				return
			}
			results <- writer
		}()
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent startup sweep did not complete")
	}
	close(results)
	close(errorsCh)
	for err := range errorsCh {
		if !errors.Is(err, ErrSecureRuntimeSweepUnsupported) {
			t.Fatalf("concurrent writer error = %v", err)
		}
	}
	count := 0
	entries, err := os.ReadDir(f.parent)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if filepath.Base(entry.Name()) != entry.Name() || len(entry.Name()) < len("ant-proxy-xray-") || entry.Name()[:len("ant-proxy-xray-")] != "ant-proxy-xray-" {
			continue
		}
		count++
	}
	if count != writers {
		t.Fatalf("concurrent writer roots = %d, want %d", count, writers)
	}
}
