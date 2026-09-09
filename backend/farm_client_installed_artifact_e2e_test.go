package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// TestFarmClientInstalledArtifactRealChrome is the process-boundary portion of
// C8. It deliberately cannot run against a source-built temporary binary: the
// caller must provide the native installed executable, its install root and
// the SHA-256 of the release artifact that produced it.
func TestFarmClientInstalledArtifactRealChrome(t *testing.T) {
	if os.Getenv("C8_INSTALLED_ARTIFACT_E2E") != "1" {
		t.Skip("set C8_INSTALLED_ARTIFACT_E2E=1 on a native installed-artifact host")
	}
	executable := requireC8AbsolutePath(t, "C8_INSTALLED_CLIENT")
	installRoot := requireC8AbsolutePath(t, "C8_INSTALLED_ROOT")
	artifact := requireC8AbsolutePath(t, "C8_RELEASE_ARTIFACT")
	wantArtifactSHA := strings.ToLower(strings.TrimSpace(os.Getenv("C8_RELEASE_ARTIFACT_SHA256")))
	wantVersion := strings.TrimSpace(os.Getenv("C8_INSTALLED_VERSION"))
	if wantArtifactSHA == "" || wantVersion == "" || strings.Contains(wantVersion, "dev") {
		t.Fatal("C8 release artifact SHA-256 and non-development version are required")
	}
	assertC8InstalledPath(t, executable, installRoot)
	workingTree, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if c8PathWithin(executable, workingTree) {
		t.Fatalf("C8 installed executable must be outside the source working tree: %s", executable)
	}
	if got := c8FileSHA256(t, artifact); got != wantArtifactSHA {
		t.Fatalf("release artifact SHA-256 = %s, want %s", got, wantArtifactSHA)
	}
	versionOutput, err := exec.Command(executable, "-version").Output()
	if err != nil {
		t.Fatalf("execute installed client version: %v", err)
	}
	var version FarmClientVersionInfo
	if err := json.Unmarshal(bytes.TrimSpace(versionOutput), &version); err != nil {
		t.Fatalf("decode installed version: %v", err)
	}
	if version.Version != wantVersion || version.GOOS != runtime.GOOS || version.GOARCH != runtime.GOARCH {
		t.Fatalf("installed version = %+v, want version=%s target=%s/%s", version, wantVersion, runtime.GOOS, runtime.GOARCH)
	}
	t.Logf("C8 release artifact sha256=%s installed_client=%s", wantArtifactSHA, executable)

	root := t.TempDir()
	coreRoot := strings.TrimSpace(os.Getenv("C8_REAL_CHROME_CORE"))
	if coreRoot == "" {
		t.Fatal("C8_REAL_CHROME_CORE must select a native Chrome installation")
	}
	profileID := "c8-installed-real-chrome"
	profileDir := filepath.Join(root, "profile-data")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "C8 installed real Chrome", CoreId: "chrome", UserDataDir: profileDir,
		CreatedAt: "2026-09-09T00:00:00Z", IncarnationID: "c8-installed-incarnation", RestoreLastSession: "never",
		FingerprintArgs: []string{"--lang=zh-TW", "--timezone=Asia/Hong_Kong", "--disable-non-proxied-udp"},
		LaunchArgs:      []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"},
	}
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	antConfig.Browser.UserDataRoot = root
	antConfig.Browser.StartReadyTimeoutMs = 60000
	antConfig.Browser.StartStableWindowMs = 100
	antConfig.Browser.DefaultStartURLs = []string{}
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	seedFarmClientChromeDB(t, filepath.Join(root, "profiles.db"), profile, browser.Core{CoreId: "chrome", CoreName: "Chrome", CorePath: coreRoot, IsDefault: true})
	key := newFarmClientTestPrivateKey(t)

	serverDone := make(chan error, 1)
	var launchedRuntime FarmRuntime
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if upgradeErr != nil {
			serverDone <- upgradeErr
			return
		}
		defer connection.Close()
		incarnation, _ := farmClientProfileIncarnation(profileID, profile.IncarnationID)
		serverDone <- runFarmClientRealChromeWSSFixture(connection, key.Public().(ed25519.PublicKey), profileID, incarnation, func(runtime FarmRuntime) error {
			launchedRuntime = runtime
			return probeC8ChromeCDP(runtime)
		})
	}))
	defer server.Close()

	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"), AntConfigPath: antConfigPath,
		ControlURL:         "ws" + strings.TrimPrefix(server.URL, "http"),
		Identity:           FarmClientIdentityConfig{NodeUID: "c8-installed-node", PrivateKey: base64.StdEncoding.EncodeToString(key)},
		ProviderInstanceID: "provider-c1", FencingEpoch: 1,
		CommandTimeoutMs: 75000,
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-config", configPath)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start installed client: %v", err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			_ = command.Process.Kill()
			logRaw, _ := os.ReadFile(filepath.Join(clientConfig.StateRoot, "logs", "ant-farm-client.log"))
			t.Fatalf("installed real Chrome flow: %v; stderr=%s; log=%s", err, stderr.String(), logRaw)
		}
	case <-ctx.Done():
		_ = command.Process.Kill()
		logRaw, _ := os.ReadFile(filepath.Join(clientConfig.StateRoot, "logs", "ant-farm-client.log"))
		t.Fatalf("installed real Chrome flow timed out: %v; stderr=%s; log=%s", ctx.Err(), stderr.String(), logRaw)
	}
	if runtime.GOOS == "windows" {
		_ = command.Process.Kill()
	} else {
		_ = command.Process.Signal(os.Interrupt)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case <-finished:
	case <-time.After(10 * time.Second):
		_ = command.Process.Kill()
		t.Fatal("installed client did not stop within 10 seconds")
	}
	shutdownDeadline := time.Now().Add(10 * time.Second)
	for launchedRuntime.PID > 0 && isProcessAlive(launchedRuntime.PID) && time.Now().Before(shutdownDeadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if launchedRuntime.PID > 0 && isProcessAlive(launchedRuntime.PID) {
		t.Fatalf("installed client shutdown left Chrome pid %d running", launchedRuntime.PID)
	}
	listOutput, err := exec.Command(executable, "-config", configPath, "profiles", "list").Output()
	if err != nil || !bytes.Contains(listOutput, []byte(profileID)) {
		t.Fatalf("installed profile persistence check failed: err=%v output=%s", err, listOutput)
	}
}

// TestFarmClientInstalledArtifactAutostartNative exercises the real per-user
// registration backend. It refuses to replace a pre-existing registration so
// a CI or operator run cannot take over an unrelated installation.
func TestFarmClientInstalledArtifactAutostartNative(t *testing.T) {
	if os.Getenv("C8_INSTALLED_AUTOSTART_E2E") != "1" {
		t.Skip("set C8_INSTALLED_AUTOSTART_E2E=1 on a native disposable login session")
	}
	executable := requireC8AbsolutePath(t, "C8_INSTALLED_CLIENT")
	installRoot := requireC8AbsolutePath(t, "C8_INSTALLED_ROOT")
	wantMethod := strings.TrimSpace(os.Getenv("C8_AUTOSTART_METHOD"))
	if wantMethod == "" {
		t.Fatal("C8_AUTOSTART_METHOD is required")
	}
	assertC8InstalledPath(t, executable, installRoot)
	workingTree, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if c8PathWithin(executable, workingTree) {
		t.Fatalf("C8 installed executable must be outside the source working tree: %s", executable)
	}

	root := t.TempDir()
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	antConfig.Browser.UserDataRoot = root
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	key := newFarmClientTestPrivateKey(t)
	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"), AntConfigPath: antConfigPath,
		ControlURL:         "ws://127.0.0.1:1",
		Identity:           FarmClientIdentityConfig{NodeUID: "c8-autostart-node", PrivateKey: base64.StdEncoding.EncodeToString(key)},
		ProviderInstanceID: "provider-c8-autostart", FencingEpoch: 1,
		ReconnectMinBackoffMs: 100, ReconnectMaxBackoffMs: 500,
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	status := readC8AutostartStatus(t, executable, configPath)
	if status.Installed {
		t.Fatal("refusing to replace a pre-existing Farm Client autostart registration")
	}
	if output, err := exec.Command(executable, "-config", configPath, "autostart", "install").CombinedOutput(); err != nil {
		t.Fatalf("install native autostart: %v output=%s", err, output)
	}
	removed := false
	defer func() {
		if removed {
			return
		}
		_, _ = exec.Command(executable, "-config", configPath, "autostart", "remove").CombinedOutput()
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		status = readC8AutostartStatus(t, executable, configPath)
		if status.Installed && status.Active {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("native autostart did not become active: %+v", status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if status.Method != wantMethod {
		t.Fatalf("native autostart method = %q, want %q", status.Method, wantMethod)
	}
	if output, err := exec.Command(executable, "-config", configPath, "autostart", "remove").CombinedOutput(); err != nil {
		t.Fatalf("remove native autostart: %v output=%s", err, output)
	}
	removed = true
	status = readC8AutostartStatus(t, executable, configPath)
	if status.Installed || status.Active {
		t.Fatalf("native autostart remained after removal: %+v", status)
	}
}

func readC8AutostartStatus(t *testing.T, executable, configPath string) FarmClientAutostartStatus {
	t.Helper()
	output, err := exec.Command(executable, "-config", configPath, "autostart", "status").CombinedOutput()
	if err != nil {
		t.Fatalf("read native autostart status: %v output=%s", err, output)
	}
	var status FarmClientAutostartStatus
	if err := json.Unmarshal(bytes.TrimSpace(output), &status); err != nil {
		t.Fatalf("decode native autostart status: %v output=%s", err, output)
	}
	return status
}

func probeC8ChromeCDP(runtime FarmRuntime) error {
	if !runtime.DebugReady || runtime.DebugPort <= 0 {
		return fmt.Errorf("installed Chrome did not publish a ready CDP port")
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/json/list", runtime.DebugPort))
	if err != nil {
		return fmt.Errorf("query installed Chrome CDP targets: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("query installed Chrome CDP targets: status %d", response.StatusCode)
	}
	var targets []struct {
		Type         string `json:"type"`
		WebSocketURL string `json:"webSocketDebuggerUrl"`
	}
	if err := json.NewDecoder(response.Body).Decode(&targets); err != nil {
		return fmt.Errorf("decode installed Chrome CDP targets: %w", err)
	}
	webSocketURL := ""
	for _, target := range targets {
		if target.Type == "page" && strings.HasPrefix(target.WebSocketURL, "ws://127.0.0.1:") {
			webSocketURL = target.WebSocketURL
			break
		}
	}
	if webSocketURL == "" {
		return fmt.Errorf("installed Chrome did not expose a loopback page CDP target")
	}
	dialer := websocket.Dialer{Proxy: nil, HandshakeTimeout: 5 * time.Second}
	connection, _, err := dialer.Dial(webSocketURL, nil)
	if err != nil {
		return fmt.Errorf("connect installed Chrome CDP: %w", err)
	}
	defer connection.Close()
	if err := connection.WriteJSON(map[string]any{"id": 1, "method": "Runtime.evaluate", "params": map[string]any{"expression": "40+2", "returnByValue": true}}); err != nil {
		return fmt.Errorf("write installed Chrome CDP: %w", err)
	}
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		var message struct {
			ID     int `json:"id"`
			Result struct {
				Result struct {
					Value float64 `json:"value"`
				} `json:"result"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := connection.ReadJSON(&message); err != nil {
			return fmt.Errorf("read installed Chrome CDP: %w", err)
		}
		if message.ID != 1 {
			continue
		}
		if len(message.Error) != 0 || message.Result.Result.Value != 42 {
			return fmt.Errorf("installed Chrome CDP evaluation failed")
		}
		return nil
	}
}

func requireC8AbsolutePath(t *testing.T, name string) string {
	t.Helper()
	value := filepath.Clean(strings.TrimSpace(os.Getenv(name)))
	if value == "." || !filepath.IsAbs(value) {
		t.Fatalf("%s must be an absolute path", name)
	}
	if _, err := os.Stat(value); err != nil {
		t.Fatalf("%s is unavailable: %v", name, err)
	}
	return value
}

func assertC8InstalledPath(t *testing.T, executable, installRoot string) {
	t.Helper()
	if !c8PathWithin(executable, installRoot) || filepath.Clean(executable) == filepath.Clean(installRoot) {
		t.Fatalf("installed client %s is outside install root %s", executable, installRoot)
	}
}

func c8PathWithin(path, root string) bool {
	resolvedPath, pathErr := filepath.EvalSymlinks(filepath.Clean(path))
	resolvedRoot, rootErr := filepath.EvalSymlinks(filepath.Clean(root))
	if pathErr != nil || rootErr != nil {
		return false
	}
	relative, err := filepath.Rel(resolvedRoot, resolvedPath)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func c8FileSHA256(t *testing.T, path string) string {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
