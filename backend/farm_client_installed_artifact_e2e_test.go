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
	"sync/atomic"
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

type c8InstalledReconnectSessionEvidence struct {
	runtime   FarmRuntime
	telemetry FarmResourceTelemetry
}

// TestFarmClientInstalledArtifactReconnectReconcile proves that the same
// installed executable preserves an owned browser runtime across an active
// Control WSS loss. The fixture authenticates twice, deliberately closes the
// first session, then requires the second session to publish an authoritative
// handoff inventory and receive the matching reconcile completion ACK.
func TestFarmClientInstalledArtifactReconnectReconcile(t *testing.T) {
	if os.Getenv("C8_INSTALLED_RECONNECT_RECONCILE_E2E") != "1" {
		t.Skip("set C8_INSTALLED_RECONNECT_RECONCILE_E2E=1 on a native installed-artifact host")
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

	root := t.TempDir()
	coreRoot := strings.TrimSpace(os.Getenv("C8_REAL_CHROME_CORE"))
	if coreRoot == "" {
		t.Fatal("C8_REAL_CHROME_CORE must select a native Chrome installation")
	}
	const (
		nodeUID            = "c8-installed-reconnect-node"
		profileID          = "c8-installed-reconnect-profile"
		providerInstanceID = "provider-c8-reconnect"
		configHash         = "config-c8-reconnect"
		controllerID       = "c8-reconnect-controller"
	)
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "C8 installed reconnect", CoreId: "chrome",
		UserDataDir: filepath.Join(root, "profile-data"), CreatedAt: "2026-09-09T00:00:00Z",
		IncarnationID: "c8-installed-reconnect-incarnation", RestoreLastSession: "never",
		FingerprintArgs: []string{"--lang=zh-TW", "--timezone=Asia/Hong_Kong", "--disable-non-proxied-udp"},
		LaunchArgs:      []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"},
	}
	if err := os.MkdirAll(profile.UserDataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	pairingIncarnation, err := farmClientProfileIncarnation(profileID, profile.IncarnationID)
	if err != nil {
		t.Fatal(err)
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

	firstEvidence := make(chan c8InstalledReconnectSessionEvidence, 1)
	runtimePID := make(chan int, 1)
	serverDone := make(chan error, 2)
	shutdownFixture := make(chan struct{})
	var session atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if upgradeErr != nil {
			serverDone <- upgradeErr
			return
		}
		defer connection.Close()
		sessionNumber := session.Add(1)
		if sessionNumber > 2 {
			serverDone <- fmt.Errorf("unexpected third Control WSS session")
			return
		}
		var sessionErr error
		switch sessionNumber {
		case 1:
			sessionErr = runC8InstalledReconnectFirstSession(connection, key.Public().(ed25519.PublicKey), nodeUID, controllerID, profileID, pairingIncarnation, providerInstanceID, configHash, firstEvidence)
		case 2:
			sessionErr = runC8InstalledReconnectSecondSession(connection, key.Public().(ed25519.PublicKey), nodeUID, controllerID, profileID, providerInstanceID, firstEvidence, runtimePID)
		}
		serverDone <- sessionErr
		if sessionNumber == 2 {
			// Keep the second authenticated session alive while the test stops the
			// installed process; this prevents a third reconnect racing cleanup.
			<-shutdownFixture
		}
	}))
	defer server.Close()
	defer close(shutdownFixture)

	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"), AntConfigPath: antConfigPath,
		ControlURL:         "ws" + strings.TrimPrefix(server.URL, "http"),
		Identity:           FarmClientIdentityConfig{NodeUID: nodeUID, PrivateKey: base64.StdEncoding.EncodeToString(key)},
		ProviderInstanceID: providerInstanceID, FencingEpoch: 1,
		// Windows may spend several seconds synchronously stopping Chrome's
		// process tree. Keep the ACK deadline (4x interval) above that bounded
		// stop while retaining the deliberately fast reconnect backoff below.
		CommandTimeoutMs: 75000, HeartbeatIntervalMs: 2000,
		ReconnectMinBackoffMs: 50, ReconnectMaxBackoffMs: 500,
	}
	configRaw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-config", configPath)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatalf("start installed client: %v", err)
	}
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	var clientStopped atomic.Bool
	stopClient := func() {
		if !clientStopped.CompareAndSwap(false, true) {
			return
		}
		if command.Process == nil {
			return
		}
		if runtime.GOOS == "windows" {
			_ = command.Process.Kill()
		} else {
			_ = command.Process.Signal(os.Interrupt)
		}
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			_ = command.Process.Kill()
			<-finished
		}
	}
	defer stopClient()

	for i := 0; i < 2; i++ {
		select {
		case sessionErr := <-serverDone:
			if sessionErr != nil {
				logRaw, _ := os.ReadFile(filepath.Join(clientConfig.StateRoot, "logs", "ant-farm-client.log"))
				t.Fatalf("installed reconnect/reconcile session %d: %v; stderr=%s; log=%s", i+1, sessionErr, stderr.String(), logRaw)
			}
		case <-ctx.Done():
			logRaw, _ := os.ReadFile(filepath.Join(clientConfig.StateRoot, "logs", "ant-farm-client.log"))
			t.Fatalf("installed reconnect/reconcile timed out: %v; stderr=%s; log=%s", ctx.Err(), stderr.String(), logRaw)
		}
	}
	stopClient()
	select {
	case pid := <-runtimePID:
		deadline := time.Now().Add(10 * time.Second)
		for pid > 0 && isProcessAlive(pid) && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if pid > 0 && isProcessAlive(pid) {
			t.Fatalf("installed reconnect cleanup left Chrome pid %d running", pid)
		}
	case <-ctx.Done():
		t.Fatalf("installed reconnect runtime identity was not reported: %v", ctx.Err())
	}
}

func authenticateC8InstalledReconnectSession(connection *websocket.Conn, publicKey ed25519.PublicKey, nodeUID, controllerID string, controllerGeneration uint64) error {
	var begin farmControlAuthBegin
	if err := connection.ReadJSON(&begin); err != nil {
		return fmt.Errorf("auth begin: %w", err)
	}
	if begin.Type != "auth_begin" || begin.NodeUID != nodeUID {
		return fmt.Errorf("invalid auth begin: type=%q node=%q", begin.Type, begin.NodeUID)
	}
	deviceKey, err := base64.StdEncoding.DecodeString(begin.DevicePubKey)
	if err != nil || !bytes.Equal(deviceKey, publicKey) {
		return fmt.Errorf("unregistered device key")
	}
	challengeRaw := bytes.Repeat([]byte{0x63}, 32)
	challenge := base64.StdEncoding.EncodeToString(challengeRaw)
	if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: nodeUID, Challenge: challenge}); err != nil {
		return fmt.Errorf("auth challenge: %w", err)
	}
	var prove farmControlAuthProve
	if err := connection.ReadJSON(&prove); err != nil {
		return fmt.Errorf("auth prove: %w", err)
	}
	if prove.Type != "auth_prove" || prove.Protocol != farmControlProtocolVersion || prove.NodeUID != nodeUID || prove.Challenge != challenge || prove.DevicePubKey != begin.DevicePubKey {
		return fmt.Errorf("invalid auth proof")
	}
	message, err := farmControlAuthMessage(nodeUID, challenge)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(prove.Signature)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid auth signature")
	}
	if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: nodeUID, ControllerID: controllerID, ControllerGeneration: controllerGeneration}); err != nil {
		return fmt.Errorf("authenticated: %w", err)
	}
	return nil
}

func runC8InstalledReconnectFirstSession(connection *websocket.Conn, publicKey ed25519.PublicKey, nodeUID, controllerID, profileID, pairingIncarnation, providerInstanceID, configHash string, evidence chan<- c8InstalledReconnectSessionEvidence) error {
	if err := authenticateC8InstalledReconnectSession(connection, publicKey, nodeUID, controllerID, 1); err != nil {
		return err
	}
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: nodeUID, CorrelationID: "c8-reconnect-ensure", Command: "ensure_runtime", Payload: map[string]any{
		"node_uid": nodeUID, "profile_id": profileID, "provider_instance_id": providerInstanceID, "fencing_epoch": 1,
		"config_hash": configHash, "launch_mode": FarmRuntimeLaunchModeDirectNoProxy, "pairing_incarnation": pairingIncarnation,
	}}); err != nil {
		return fmt.Errorf("ensure command: %w", err)
	}
	raw, err := readFarmClientFixtureCommandResponse(connection, "c8-reconnect-ensure")
	if err != nil {
		return fmt.Errorf("ensure response: %w", err)
	}
	var response struct {
		OK      bool            `json:"ok"`
		Error   string          `json:"error"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return fmt.Errorf("decode ensure response: %w", err)
	}
	if !response.OK {
		return fmt.Errorf("ensure failed: %s", response.Error)
	}
	var launched FarmRuntime
	if err := json.Unmarshal(response.Payload, &launched); err != nil {
		return fmt.Errorf("decode ensured runtime: %w", err)
	}
	if launched.NodeUID != nodeUID || launched.ProfileID != profileID || launched.RuntimeUID == "" || launched.PID <= 0 || launched.Generation == 0 || launched.ProfileIncarnation == "" {
		return fmt.Errorf("ensure did not return an owned runtime: %+v", launched)
	}
	telemetry, err := readFarmClientFixtureHeartbeat(connection)
	if err != nil {
		return fmt.Errorf("first-session heartbeat: %w", err)
	}
	if telemetry.ConnectionGeneration == 0 || telemetry.SampleSequence == 0 || !c8TelemetryHasRuntime(telemetry, launched.RuntimeUID, launched.PID) {
		return fmt.Errorf("first-session heartbeat omitted owned runtime: %+v", telemetry)
	}
	evidence <- c8InstalledReconnectSessionEvidence{runtime: launched, telemetry: telemetry}
	// This is the deliberate transport loss. The process and Chrome remain
	// alive; only the authenticated Control session is interrupted.
	_ = connection.Close()
	return nil
}

func runC8InstalledReconnectSecondSession(connection *websocket.Conn, publicKey ed25519.PublicKey, nodeUID, controllerID, profileID, providerInstanceID string, firstEvidence <-chan c8InstalledReconnectSessionEvidence, runtimePID chan<- int) error {
	if err := authenticateC8InstalledReconnectSession(connection, publicKey, nodeUID, controllerID, 1); err != nil {
		return err
	}
	previous := <-firstEvidence
	secondHeartbeat, err := readFarmClientFixtureHeartbeat(connection)
	if err != nil {
		return fmt.Errorf("second-session heartbeat: %w", err)
	}
	if secondHeartbeat.ConnectionGeneration <= previous.telemetry.ConnectionGeneration || secondHeartbeat.SampleSequence <= previous.telemetry.SampleSequence {
		return fmt.Errorf("reconnect did not advance authenticated heartbeat identity: first=%+v second=%+v", previous.telemetry, secondHeartbeat)
	}
	if !c8TelemetryHasRuntime(secondHeartbeat, previous.runtime.RuntimeUID, previous.runtime.PID) {
		return fmt.Errorf("reconnect heartbeat lost owned runtime: %+v", secondHeartbeat)
	}

	const inventoryCorrelation = "c8-reconnect-inventory"
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: nodeUID, CorrelationID: inventoryCorrelation, Command: "inventory_handoff", Payload: map[string]any{}}); err != nil {
		return fmt.Errorf("inventory_handoff command: %w", err)
	}
	inventoryRaw, err := readFarmClientFixtureCommandResponse(connection, inventoryCorrelation)
	if err != nil {
		return fmt.Errorf("inventory_handoff response: %w", err)
	}
	var inventoryResponse struct {
		OK      bool            `json:"ok"`
		Error   string          `json:"error"`
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(inventoryRaw, &inventoryResponse); err != nil {
		return fmt.Errorf("decode inventory_handoff response: %w", err)
	}
	if !inventoryResponse.OK {
		return fmt.Errorf("inventory_handoff failed: %s", inventoryResponse.Error)
	}
	var snapshot FarmRuntimeInventorySnapshot
	if err := json.Unmarshal(inventoryResponse.Payload, &snapshot); err != nil {
		return fmt.Errorf("decode inventory_handoff snapshot: %w", err)
	}
	if snapshot.ConnectionGeneration != secondHeartbeat.ConnectionGeneration || len(snapshot.Inventory) != 1 || snapshot.InventoryDigest != farmRuntimeInventoryDigest(snapshot.Inventory) {
		return fmt.Errorf("inventory_handoff was not authoritative: %+v", snapshot)
	}
	owned := snapshot.Inventory[0]
	if owned.RuntimeUID != previous.runtime.RuntimeUID || owned.ProfileID != profileID || owned.PID != previous.runtime.PID || owned.NodeUID != nodeUID || owned.ProviderInstanceID != providerInstanceID {
		return fmt.Errorf("reconnected inventory changed runtime ownership: first=%+v second=%+v", previous.runtime, owned)
	}

	const completionCorrelation = "c8-reconnect-complete"
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: nodeUID, CorrelationID: completionCorrelation, Command: "handoff_reconcile_complete", Payload: FarmRuntimeHandoffCompletion{
		Status: "completed", ControllerID: controllerID, ControllerGeneration: 1,
		ConnectionGeneration: snapshot.ConnectionGeneration, InventoryDigest: snapshot.InventoryDigest, InventoryCount: len(snapshot.Inventory),
	}}); err != nil {
		return fmt.Errorf("handoff_reconcile_complete command: %w", err)
	}
	completionRaw, err := readFarmClientFixtureCommandResponse(connection, completionCorrelation)
	if err != nil {
		return fmt.Errorf("handoff_reconcile_complete response: %w", err)
	}
	var completionResponse struct {
		OK      bool                         `json:"ok"`
		Error   string                       `json:"error"`
		Payload FarmRuntimeHandoffCompletion `json:"payload"`
	}
	if err := json.Unmarshal(completionRaw, &completionResponse); err != nil {
		return fmt.Errorf("decode handoff_reconcile_complete response: %w", err)
	}
	if !completionResponse.OK || completionResponse.Payload.Status != "completed" || completionResponse.Payload.ConnectionGeneration != snapshot.ConnectionGeneration || completionResponse.Payload.InventoryDigest != snapshot.InventoryDigest || completionResponse.Payload.InventoryCount != len(snapshot.Inventory) {
		return fmt.Errorf("handoff_reconcile_complete ACK was not exact: %+v", completionResponse)
	}
	postReconcileHeartbeat, err := readFarmClientFixtureHeartbeat(connection)
	if err != nil {
		return fmt.Errorf("post-reconcile heartbeat: %w", err)
	}
	if postReconcileHeartbeat.SampleSequence <= secondHeartbeat.SampleSequence || postReconcileHeartbeat.ConnectionGeneration != snapshot.ConnectionGeneration || !c8TelemetryHasRuntime(postReconcileHeartbeat, owned.RuntimeUID, owned.PID) {
		return fmt.Errorf("heartbeat/owned runtime did not remain healthy after reconcile: %+v", postReconcileHeartbeat)
	}
	runtimePID <- owned.PID

	stopCorrelation := "c8-reconnect-stop"
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: nodeUID, CorrelationID: stopCorrelation, Command: "stop_runtime", Payload: FarmRuntimeStopRequest{
		Provider: "farm", NodeUID: owned.NodeUID, ProfileID: owned.ProfileID, RuntimeUID: owned.RuntimeUID,
		ProviderInstanceID: owned.ProviderInstanceID, FencingEpoch: owned.FencingEpoch, ConfigHash: owned.ConfigHash,
		Generation: owned.Generation, PID: owned.PID, ProcessStartIdentity: owned.ProcessStartIdentity,
		ProfileIncarnation: owned.ProfileIncarnation, ControllerID: owned.ControllerID, ControllerGeneration: owned.ControllerGeneration,
		TelemetrySequence: postReconcileHeartbeat.SampleSequence, TelemetryObservedAt: postReconcileHeartbeat.ObservedAt,
	}}); err != nil {
		return fmt.Errorf("stop_runtime command: %w", err)
	}
	stopRaw, err := readFarmClientFixtureCommandResponse(connection, stopCorrelation)
	if err != nil {
		return fmt.Errorf("stop_runtime response: %w", err)
	}
	var stopResponse struct {
		OK    bool   `json:"ok"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(stopRaw, &stopResponse); err != nil {
		return fmt.Errorf("decode stop_runtime response: %w", err)
	}
	if !stopResponse.OK {
		return fmt.Errorf("stop_runtime failed: %s", stopResponse.Error)
	}
	return nil
}

func c8TelemetryHasRuntime(telemetry FarmResourceTelemetry, runtimeUID string, pid int) bool {
	for _, runtime := range telemetry.Runtimes {
		if runtime.RuntimeUID == runtimeUID && runtime.PID == pid && runtime.State == FarmRuntimeStateIdle {
			return true
		}
	}
	return false
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
			if diagnostic := c8NativeAutostartDiagnostic(); diagnostic != "" {
				t.Fatalf("native autostart did not become active: %+v %s", status, diagnostic)
			}
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
