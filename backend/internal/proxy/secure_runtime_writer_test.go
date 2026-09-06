package proxy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecureRuntimeWriterUsesPrivateTempRootAndAtomicFiles(t *testing.T) {
	writer, err := newSecureRuntimeWriter("xray")
	if err != nil {
		t.Fatalf("newSecureRuntimeWriter() error = %v", err)
	}
	t.Cleanup(func() {
		_ = writer.cleanup("node-a")
		_ = os.Remove(writer.root)
	})

	dir, err := writer.runtimeDir("node-a")
	if err != nil {
		t.Fatalf("runtimeDir() error = %v", err)
	}
	if got := writer.runtimeDirIfExists("node-b"); got != "" {
		t.Fatalf("runtimeDirIfExists() created an unexpected directory: %q", got)
	}
	if _, err := os.Stat(filepath.Join(writer.root, "node-b")); !os.IsNotExist(err) {
		t.Fatalf("runtimeDirIfExists() changed filesystem, stat error = %v", err)
	}
	assertUnixMode(t, writer.root, 0o700)
	assertUnixMode(t, dir, 0o700)

	configPath, err := writer.writeAtomic("node-a", "xray-config.json", []byte(`{"secret":"password-value"}`))
	if err != nil {
		t.Fatalf("writeAtomic() error = %v", err)
	}
	assertUnixMode(t, configPath, 0o600)
	if got, err := os.ReadFile(configPath); err != nil || string(got) != `{"secret":"password-value"}` {
		t.Fatalf("config contents = %q, error = %v", got, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir() error = %v", err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Fatalf("atomic temp file was left behind: %s", entry.Name())
		}
	}

	logPath, err := writer.ensureLog("node-a", "xray-error.log")
	if err != nil {
		t.Fatalf("ensureLog() error = %v", err)
	}
	assertUnixMode(t, logPath, 0o600)
	logFile, openedPath, err := writer.openLog("node-a", "xray-stderr.log")
	if err != nil {
		t.Fatalf("openLog() error = %v", err)
	}
	if openedPath == "" || logFile == nil {
		t.Fatalf("openLog() returned empty path/file")
	}
	if _, err := logFile.WriteString("safe stderr\n"); err != nil {
		t.Fatalf("write log = %v", err)
	}
	if err := logFile.Close(); err != nil {
		t.Fatalf("close log = %v", err)
	}
	assertUnixMode(t, openedPath, 0o600)
}

func TestSecureRuntimeWriterRejectsTraversalSymlinkAndUnownedOverwrite(t *testing.T) {
	writer, err := newSecureRuntimeWriter("singbox")
	if err != nil {
		t.Fatalf("newSecureRuntimeWriter() error = %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(writer.root) })

	for _, key := range []string{"", ".", "..", "../../outside", `a\\b`, "node/child"} {
		if _, err := writer.runtimeDir(key); !errors.Is(err, ErrSecureRuntimePath) {
			t.Errorf("runtimeDir(%q) error = %v, want ErrSecureRuntimePath", key, err)
		}
	}
	if _, err := writer.writeAtomic("node-a", "../../outside.json", []byte("x")); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("writeAtomic traversal error = %v", err)
	}

	dir, err := writer.runtimeDir("node-a")
	if err != nil {
		t.Fatalf("runtimeDir() error = %v", err)
	}
	target := filepath.Join(dir, "xray-config.json")
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("must remain"), 0o600); err != nil {
		t.Fatalf("write outside = %v", err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := writer.writeAtomic("node-a", "xray-config.json", []byte("overwrite")); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("writeAtomic symlink error = %v, want ErrSecureRuntimePath", err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "must remain" {
		t.Fatalf("outside target changed: %q, error = %v", got, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove symlink = %v", err)
	}
	if err := os.WriteFile(target, []byte("unowned"), 0o600); err != nil {
		t.Fatalf("write unowned target = %v", err)
	}
	if _, err := writer.writeAtomic("node-a", "xray-config.json", []byte("overwrite")); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("writeAtomic unowned error = %v, want ErrSecureRuntimePath", err)
	}
}

func TestSecureRuntimeWriterCleanupIsOwnershipAndProcessBound(t *testing.T) {
	writer, err := newSecureRuntimeWriter("mihomo")
	if err != nil {
		t.Fatalf("newSecureRuntimeWriter() error = %v", err)
	}
	dir, err := writer.runtimeDir("node-a")
	if err != nil {
		t.Fatalf("runtimeDir() error = %v", err)
	}
	configPath, err := writer.writeAtomic("node-a", "mihomo-config.yaml", []byte("proxies: []\n"))
	if err != nil {
		t.Fatalf("writeAtomic() error = %v", err)
	}
	handle, err := writer.handle("node-a")
	if err != nil {
		t.Fatalf("handle() error = %v", err)
	}
	handle.markProcessStarted()
	if err := handle.cleanup(); !errors.Is(err, ErrSecureRuntimeActive) {
		t.Fatalf("cleanup while active = %v, want ErrSecureRuntimeActive", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("active config was removed: %v", err)
	}
	handle.markProcessTerminated()
	unknown := filepath.Join(dir, "unknown-runtime-artifact")
	if err := os.WriteFile(unknown, []byte("leave me"), 0o600); err != nil {
		t.Fatalf("write unknown artifact = %v", err)
	}
	if err := handle.cleanup(); !errors.Is(err, ErrSecureRuntimePath) {
		t.Fatalf("cleanup with unknown artifact = %v, want ErrSecureRuntimePath", err)
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatalf("unknown artifact was removed: %v", err)
	}
	if err := os.Remove(unknown); err != nil {
		t.Fatalf("remove unknown artifact = %v", err)
	}
	if err := handle.cleanup(); err != nil {
		t.Fatalf("owned cleanup = %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir still exists, stat error = %v", err)
	}
}

func TestMaskProxySensitiveTextDoesNotExposeSecrets(t *testing.T) {
	raw := `connect failed: vmess://user:super-password@example.test:443?token=top-secret password=another-secret {"credential":"json-secret","api-key":"key-secret"}`
	masked := maskProxySensitiveText(raw)
	for _, secret := range []string{"user:super-password@example.test:443", "top-secret", "another-secret", "json-secret", "key-secret"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("masked text contains secret %q: %s", secret, masked)
		}
	}
	if !strings.Contains(masked, "vmess://<redacted>") {
		t.Fatalf("masked URI = %q, want redacted scheme marker", masked)
	}
	if got := safeProxyURI("socks5://alice:secret@example.test:1080"); got != "socks5://<redacted>" {
		t.Fatalf("safeProxyURI() = %q", got)
	}
	if got := maskProxyConfig("password: yaml-secret\ntoken: yaml-token"); strings.Contains(got, "yaml-secret") || strings.Contains(got, "yaml-token") {
		t.Fatalf("masked config contains credentials: %q", got)
	}
}

func TestRuntimeDiagnosticMasksCredentialBearingLogTail(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stderr.log"), []byte("failed vmess://user:secret@example.test:443 token=log-token\n"), 0o600); err != nil {
		t.Fatalf("write diagnostic log = %v", err)
	}
	runtime := buildRuntimeDiagnostic(dir, "config.json", "stderr.log", "", "")
	got := runtime.RecentLogs["stderr"]
	for _, secret := range []string{"user:secret@example.test:443", "log-token"} {
		if strings.Contains(got, secret) {
			t.Fatalf("diagnostic log contains secret %q: %s", secret, got)
		}
	}
	if !strings.Contains(got, "vmess://<redacted>") {
		t.Fatalf("diagnostic log = %q, want redacted URI", got)
	}
}

func assertUnixMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%q) error = %v", path, err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("mode(%q) = %04o, want %04o", path, info.Mode().Perm(), want)
	}
}
