package backend

// This file is deliberately opt-in. It exercises the installed immutable
// launcher and two native release payloads; it is not a source-build fixture.
// The test server is intentionally small, but it remains authoritative for
// the authenticated controller lease, inventory expectation and completion.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	goversion "go/version"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

type c8UpdateRelease struct {
	path    string
	raw     []byte
	digest  string
	version string
}

type c8UpdateControlFixture struct {
	mu          sync.Mutex
	nodeUID     string
	publicKey   ed25519.PublicKey
	sessions    int
	connections map[*websocket.Conn]struct{}
	healthy     map[int]chan struct{}
	failure     chan struct{}
	recovered   chan struct{}
	recoveryOK  chan struct{}
	closeOnce   sync.Once
	healthyOnce map[int]*sync.Once
	failureOnce sync.Once
	recoverOnce sync.Once
	allowOnce   sync.Once
	reject      bool
	failed      bool
}

func newC8UpdateControlFixture(nodeUID string, publicKey ed25519.PublicKey) *c8UpdateControlFixture {
	fixture := &c8UpdateControlFixture{
		nodeUID: nodeUID, publicKey: append(ed25519.PublicKey(nil), publicKey...),
		connections: make(map[*websocket.Conn]struct{}), healthy: make(map[int]chan struct{}),
		healthyOnce: make(map[int]*sync.Once), failure: make(chan struct{}), recovered: make(chan struct{}), recoveryOK: make(chan struct{}),
	}
	for session := 1; session <= 4; session++ {
		fixture.healthy[session] = make(chan struct{})
		fixture.healthyOnce[session] = &sync.Once{}
	}
	return fixture
}

func (fixture *c8UpdateControlFixture) nextSession(connection *websocket.Conn) int {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.sessions++
	fixture.connections[connection] = struct{}{}
	if _, ok := fixture.healthy[fixture.sessions]; !ok {
		fixture.healthy[fixture.sessions] = make(chan struct{})
		fixture.healthyOnce[fixture.sessions] = &sync.Once{}
	}
	return fixture.sessions
}

func (fixture *c8UpdateControlFixture) removeConnection(connection *websocket.Conn) {
	fixture.mu.Lock()
	delete(fixture.connections, connection)
	fixture.mu.Unlock()
}

func (fixture *c8UpdateControlFixture) healthySignal(session int) <-chan struct{} {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.healthy[session]
}

func (fixture *c8UpdateControlFixture) signalHealthy(session int) {
	fixture.mu.Lock()
	once := fixture.healthyOnce[session]
	signal := fixture.healthy[session]
	failed := fixture.failed
	fixture.mu.Unlock()
	if once != nil {
		once.Do(func() { close(signal) })
	}
	if failed {
		fixture.recoverOnce.Do(func() { close(fixture.recovered) })
	}
}

func (fixture *c8UpdateControlFixture) signalFailure() {
	fixture.mu.Lock()
	fixture.failed = true
	fixture.mu.Unlock()
	fixture.failureOnce.Do(func() { close(fixture.failure) })
}

func (fixture *c8UpdateControlFixture) rejectUpdateCandidate() {
	fixture.mu.Lock()
	fixture.reject = true
	fixture.mu.Unlock()
}

func (fixture *c8UpdateControlFixture) allowRollbackRecovery() {
	fixture.mu.Lock()
	fixture.reject = false
	fixture.mu.Unlock()
	fixture.allowOnce.Do(func() { close(fixture.recoveryOK) })
}

func (fixture *c8UpdateControlFixture) shouldReject() bool {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	return fixture.reject
}

func (fixture *c8UpdateControlFixture) closeAll() {
	fixture.closeOnce.Do(func() {
		fixture.allowOnce.Do(func() { close(fixture.recoveryOK) })
		fixture.mu.Lock()
		connections := make([]*websocket.Conn, 0, len(fixture.connections))
		for connection := range fixture.connections {
			connections = append(connections, connection)
		}
		fixture.mu.Unlock()
		for _, connection := range connections {
			_ = connection.Close()
		}
	})
}

// TestFarmClientInstalledArtifactSignedUpdateRollback is the C8 update gate.
// It requires a real installed launcher, plus native release payload A and B.
// The default suite skips; setting the opt-in flag with incomplete inputs is a
// failure, never a pass.
func TestFarmClientInstalledArtifactSignedUpdateRollback(t *testing.T) {
	if os.Getenv("C8_INSTALLED_UPDATE_E2E") != "1" {
		t.Skip("set C8_INSTALLED_UPDATE_E2E=1 on a native installed-artifact host")
	}
	installed := requireC8UpdatePath(t, "C8_UPDATE_INSTALLED_CLIENT")
	installRoot := requireC8UpdateRoot(t, "C8_UPDATE_INSTALLED_ROOT")
	releaseA := requireC8UpdatePath(t, "C8_UPDATE_RELEASE_A")
	releaseB := requireC8UpdatePath(t, "C8_UPDATE_RELEASE_B")
	versionA := strings.TrimSpace(os.Getenv("C8_UPDATE_VERSION_A"))
	versionB := strings.TrimSpace(os.Getenv("C8_UPDATE_VERSION_B"))
	if versionA == "" || versionB == "" || strings.Contains(versionA, "dev") || strings.Contains(versionB, "dev") {
		t.Fatal("C8_UPDATE_VERSION_A/B must be non-development versions")
	}
	if versionA == versionB {
		t.Fatal("C8 update versions must differ")
	}
	assertC8InstalledPath(t, installed, installRoot)
	workingTree, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if c8PathWithin(installed, workingTree) {
		t.Fatalf("installed launcher is inside source tree: %s", installed)
	}
	a := readC8UpdateRelease(t, releaseA, versionA)
	b := readC8UpdateRelease(t, releaseB, versionB)
	if c8PathWithin(a.path, workingTree) || c8PathWithin(b.path, workingTree) {
		t.Fatalf("release payloads must be copied outside the source tree: A=%s B=%s", a.path, b.path)
	}
	if expected := strings.TrimSpace(os.Getenv("C8_UPDATE_RELEASE_A_SHA256")); expected != "" && expected != a.digest {
		t.Fatalf("release A SHA-256=%s want=%s", a.digest, expected)
	}
	if expected := strings.TrimSpace(os.Getenv("C8_UPDATE_RELEASE_B_SHA256")); expected != "" && expected != b.digest {
		t.Fatalf("release B SHA-256=%s want=%s", b.digest, expected)
	}
	if got := c8FileSHA256(t, installed); got != c8FileSHA256(t, releaseA) {
		t.Fatalf("installed launcher SHA-256=%s differs from release A=%s", got, a.digest)
	}
	t.Logf("C8 update release A version=%s sha256=%s path=%s", a.version, a.digest, a.path)
	t.Logf("C8 update release B version=%s sha256=%s path=%s", b.version, b.digest, b.path)

	updateSignerPublic, updateSignerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controlPrivate := newFarmClientTestPrivateKey(t)
	const nodeUID = "c8-installed-update-node"
	manifestMu := sync.RWMutex{}
	var currentManifest []byte
	requestMu := sync.Mutex{}
	requestCounts := make(map[string]int)
	artifactServer := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestMu.Lock()
		requestCounts[request.URL.Path]++
		requestMu.Unlock()
		manifestMu.RLock()
		manifest := append([]byte(nil), currentManifest...)
		manifestMu.RUnlock()
		switch request.URL.Path {
		case "/manifest":
			if len(manifest) == 0 {
				http.Error(writer, "manifest unavailable", http.StatusServiceUnavailable)
				return
			}
			writer.Header().Set("Content-Type", "application/json")
			_, _ = writer.Write(manifest)
		case "/artifact-a":
			_, _ = writer.Write(a.raw)
		case "/artifact-b":
			_, _ = writer.Write(b.raw)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer artifactServer.Close()
	trustRoot := filepath.Join(t.TempDir(), "c8-update-test-ca.pem")
	if err := os.WriteFile(trustRoot, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: artifactServer.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	installC8LegacyPlatformTrustRoot(t, trustRoot, artifactServer.Certificate().Raw)
	manifestA, err := buildC8UpdateManifest(versionA, a, true, artifactServer.URL+"/artifact-a", updateSignerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifestB, err := buildC8UpdateManifest(versionB, b, false, artifactServer.URL+"/artifact-b", updateSignerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	manifestMu.Lock()
	currentManifest = manifestB
	manifestMu.Unlock()

	controlFixture := newC8UpdateControlFixture(nodeUID, controlPrivate.Public().(ed25519.PublicKey))
	defer controlFixture.closeAll()
	controlServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, upgradeErr := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if upgradeErr != nil {
			return
		}
		session := controlFixture.nextSession(connection)
		defer func() {
			controlFixture.removeConnection(connection)
			_ = connection.Close()
		}()
		if sessionErr := runC8UpdateControlSession(connection, controlFixture, session); sessionErr != nil && !controlFixture.shouldReject() {
			t.Logf("C8 Control fixture session %d ended: %v", session, sessionErr)
		}
	}))
	defer controlServer.Close()

	root := t.TempDir()
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	antConfig.Browser.UserDataRoot = root
	antConfig.Browser.DefaultStartURLs = []string{}
	antConfig.Browser.StartReadyTimeoutMs = 15000
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	profile := BrowserProfile{
		ProfileId: "c8-installed-update-profile", ProfileName: "C8 installed update", CoreId: "chrome",
		UserDataDir: filepath.Join(root, "profile-data"), CreatedAt: "2026-09-09T00:00:00Z",
		IncarnationID: "c8-installed-update-incarnation", RestoreLastSession: "never",
	}
	if err := os.MkdirAll(profile.UserDataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	seedFarmClientChromeDB(t, filepath.Join(root, "profiles.db"), profile, browser.Core{CoreId: "chrome", CoreName: "Chrome", CorePath: installed, IsDefault: true})
	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"), AntConfigPath: antConfigPath,
		ControlURL:        "ws" + strings.TrimPrefix(controlServer.URL, "http"),
		UpdateManifestURL: artifactServer.URL + "/manifest", UpdatePublicKey: base64.StdEncoding.EncodeToString(updateSignerPublic),
		UpdateChannel: "stable", AllowUpdateDowngrade: true,
		UpdateCheckIntervalMs: 60000, UpdateHealthTimeoutMs: 10000, UpdateProbationMs: 30000,
		HeartbeatIntervalMs: 100, ReconnectMinBackoffMs: 50, ReconnectMaxBackoffMs: 500,
		Identity:           FarmClientIdentityConfig{NodeUID: nodeUID, PrivateKey: base64.StdEncoding.EncodeToString(controlPrivate)},
		ProviderInstanceID: "provider-c8-update", FencingEpoch: 1,
	}
	configRaw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, configRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, installed, "-config", configPath)
	// Go's macOS/Windows platform verifier otherwise ignores SSL_CERT_FILE;
	// forcing the documented on-disk root path keeps this fixture disposable
	// and avoids mutating the host trust store.
	command.Env = append(os.Environ(), "SSL_CERT_FILE="+trustRoot, "GODEBUG=x509sslcertoverrideplatform=1")
	var stderr bytes.Buffer
	command.Stderr = io.MultiWriter(&stderr, os.Stderr)
	if err := command.Start(); err != nil {
		t.Fatalf("start installed launcher: %v", err)
	}
	stopLauncher := func() {
		if command.Process == nil {
			return
		}
		if runtime.GOOS == "windows" {
			_ = command.Process.Kill()
		} else {
			_ = command.Process.Signal(os.Interrupt)
		}
	}
	defer stopLauncher()

	waitCtx, waitCancel := context.WithTimeout(ctx, 150*time.Second)
	defer waitCancel()
	t.Logf("C8 update state root=%s", clientConfig.StateRoot)
	diagnostic := func() string {
		requestMu.Lock()
		counts := fmt.Sprintf("%v", requestCounts)
		requestMu.Unlock()
		logRaw, _ := os.ReadFile(filepath.Join(clientConfig.StateRoot, "logs", "ant-farm-client.log"))
		return fmt.Sprintf("stderr=%s artifact_requests=%s client_log=%s", stderr.String(), counts, logRaw)
	}
	waitC8UpdateActivation(t, waitCtx, clientConfig.StateRoot, func(activation FarmClientUpdateActivation) bool {
		return activation.Phase == farmClientUpdatePhaseStable && activation.Active != nil && activation.Active.Version == versionB && activation.Pending == nil
	}, diagnostic)
	select {
	case <-controlFixture.healthySignal(2):
	case <-waitCtx.Done():
		t.Fatalf("release B never passed authenticated health probation: %v; stderr=%s", waitCtx.Err(), stderr.String())
	}

	manifestMu.Lock()
	currentManifest = manifestA
	manifestMu.Unlock()
	controlFixture.rejectUpdateCandidate()
	rollbackCtx, rollbackCancel := context.WithTimeout(ctx, 150*time.Second)
	defer rollbackCancel()
	waitC8UpdateActivation(t, rollbackCtx, clientConfig.StateRoot, func(activation FarmClientUpdateActivation) bool {
		return activation.Phase == farmClientUpdatePhaseProbation && activation.Pending != nil && activation.Pending.Version == versionA
	}, diagnostic)
	select {
	case <-controlFixture.failure:
	case <-rollbackCtx.Done():
		t.Fatalf("release A rollback failure session was not observed: %v; stderr=%s", rollbackCtx.Err(), stderr.String())
	}
	waitC8UpdateActivation(t, rollbackCtx, clientConfig.StateRoot, func(activation FarmClientUpdateActivation) bool {
		return activation.Phase == farmClientUpdatePhaseStable && activation.Active != nil && activation.Active.Version == versionB && activation.Pending == nil
	}, diagnostic)
	controlFixture.allowRollbackRecovery()
	select {
	case <-controlFixture.recovered:
	case <-rollbackCtx.Done():
		t.Fatalf("previous release B did not reconnect and pass health after rollback: %v; stderr=%s", rollbackCtx.Err(), stderr.String())
	}

	stopLauncher()
	finished := make(chan error, 1)
	go func() { finished <- command.Wait() }()
	select {
	case err := <-finished:
		if err != nil && ctx.Err() == nil {
			t.Fatalf("installed launcher shutdown: %v; stderr=%s", err, stderr.String())
		}
	case <-time.After(20 * time.Second):
		_ = command.Process.Kill()
		t.Fatalf("installed launcher did not stop: stderr=%s", stderr.String())
	}
	controlFixture.closeAll()

	activation, err := LoadFarmClientUpdateActivation(clientConfig.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if activation.Active == nil || activation.Active.Version != versionB || activation.Pending != nil || activation.Phase != farmClientUpdatePhaseStable {
		t.Fatalf("final activation=%+v", activation)
	}
	t.Logf("C8 installed signed update evidence: A=%s, B committed then failed A downgrade rolled back to B", versionA)
}

// Go 1.27 added SSL_CERT_FILE overrides on Windows and macOS. The release
// workflows still exercise the module's Go 1.22 floor, so those two native
// jobs temporarily trust this random test certificate in the current-user
// store and remove that exact fingerprint during cleanup.
func installC8LegacyPlatformTrustRoot(t *testing.T, certificatePath string, certificateRaw []byte) {
	t.Helper()
	if runtime.GOOS != "windows" && runtime.GOOS != "darwin" {
		return
	}
	if goversion.IsValid(runtime.Version()) && goversion.Compare(runtime.Version(), "go1.27") >= 0 {
		return
	}
	digest := sha1.Sum(certificateRaw) // OS certificate stores identify entries by SHA-1 thumbprint.
	thumbprint := strings.ToUpper(hex.EncodeToString(digest[:]))
	var add, remove *exec.Cmd
	if runtime.GOOS == "windows" {
		add = exec.Command("certutil.exe", "-user", "-addstore", "Root", certificatePath)
		remove = exec.Command("certutil.exe", "-user", "-delstore", "Root", thumbprint)
	} else {
		keychainRaw, err := exec.Command("security", "default-keychain", "-d", "user").Output()
		if err != nil {
			t.Fatalf("locate user keychain: %v", err)
		}
		keychain := strings.Trim(strings.TrimSpace(string(keychainRaw)), "\"")
		if keychain == "" {
			t.Fatal("default user keychain is empty")
		}
		add = exec.Command("security", "add-trusted-cert", "-r", "trustRoot", "-p", "ssl", "-k", keychain, certificatePath)
		remove = exec.Command("security", "delete-certificate", "-Z", thumbprint, keychain)
	}
	if output, err := add.CombinedOutput(); err != nil {
		t.Fatalf("install temporary current-user test trust root: %v: %s", err, strings.TrimSpace(string(output)))
	}
	t.Cleanup(func() {
		if output, err := remove.CombinedOutput(); err != nil {
			t.Errorf("remove temporary current-user test trust root %s: %v: %s", thumbprint, err, strings.TrimSpace(string(output)))
		}
	})
}

func requireC8UpdatePath(t *testing.T, name string) string {
	t.Helper()
	value := filepath.Clean(strings.TrimSpace(os.Getenv(name)))
	if value == "." || !filepath.IsAbs(value) {
		t.Fatalf("%s must be an absolute path", name)
	}
	info, err := os.Stat(value)
	if err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s must be a regular file: %v", name, err)
	}
	return value
}

func requireC8UpdateRoot(t *testing.T, name string) string {
	t.Helper()
	value := filepath.Clean(strings.TrimSpace(os.Getenv(name)))
	if value == "." || !filepath.IsAbs(value) {
		t.Fatalf("%s must be an absolute path", name)
	}
	info, err := os.Stat(value)
	if err != nil || !info.IsDir() {
		t.Fatalf("%s must be an existing directory: %v", name, err)
	}
	return value
}

func readC8UpdateRelease(t *testing.T, path, wantVersion string) c8UpdateRelease {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if !farmClientBinaryMatchesTarget(path, runtime.GOOS, runtime.GOARCH) {
		t.Fatalf("release payload %s is not a native %s-%s binary", path, runtime.GOOS, runtime.GOARCH)
	}
	output, err := exec.Command(path, "-version").Output()
	if err != nil {
		t.Fatalf("execute release payload %s: %v", path, err)
	}
	var version FarmClientVersionInfo
	if err := json.Unmarshal(bytes.TrimSpace(output), &version); err != nil {
		t.Fatalf("decode %s version: %v", path, err)
	}
	if version.Version != wantVersion || version.GOOS != runtime.GOOS || version.GOARCH != runtime.GOARCH {
		t.Fatalf("release %s version=%+v want version=%s target=%s/%s", path, version, wantVersion, runtime.GOOS, runtime.GOARCH)
	}
	return c8UpdateRelease{path: path, raw: raw, digest: hex.EncodeToString(digest[:]), version: version.Version}
}

func buildC8UpdateManifest(version string, release c8UpdateRelease, allowDowngrade bool, artifactURL string, privateKey ed25519.PrivateKey) ([]byte, error) {
	now := time.Now().UTC()
	artifacts := make(map[string]FarmClientUpdateArtifact, len(farmClientUpdateTargets))
	for target := range farmClientUpdateTargets {
		artifacts[target] = FarmClientUpdateArtifact{URL: artifactURL, SHA256: release.digest, Size: int64(len(release.raw))}
	}
	manifestRaw, err := json.Marshal(FarmClientUpdateManifest{
		Version: version, ProtocolVersion: FarmClientControlProtocolVersion, MinimumProtocolVersion: FarmClientControlProtocolVersion,
		Channel: "stable", PublishedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(20 * time.Minute).Format(time.RFC3339),
		AllowDowngrade: allowDowngrade, Artifacts: artifacts,
	})
	if err != nil {
		return nil, err
	}
	return BuildFarmClientUpdateEnvelope(manifestRaw, base64.StdEncoding.EncodeToString(privateKey), now)
}

func runC8UpdateControlSession(connection *websocket.Conn, fixture *c8UpdateControlFixture, session int) error {
	var begin farmControlAuthBegin
	if err := connection.ReadJSON(&begin); err != nil {
		return err
	}
	if begin.Type != "auth_begin" || begin.NodeUID != fixture.nodeUID {
		return fmt.Errorf("invalid auth_begin")
	}
	deviceKey, err := base64.StdEncoding.DecodeString(begin.DevicePubKey)
	if err != nil || !bytes.Equal(deviceKey, fixture.publicKey) {
		return fmt.Errorf("unregistered device key")
	}
	challengeRaw := make([]byte, 32)
	if _, err := rand.Read(challengeRaw); err != nil {
		return err
	}
	challenge := base64.StdEncoding.EncodeToString(challengeRaw)
	if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: begin.NodeUID, Challenge: challenge}); err != nil {
		return err
	}
	var prove farmControlAuthProve
	if err := connection.ReadJSON(&prove); err != nil {
		return err
	}
	message, err := farmControlAuthMessage(begin.NodeUID, challenge)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(prove.Signature)
	if err != nil || !ed25519.Verify(fixture.publicKey, message, signature) {
		return fmt.Errorf("invalid auth proof")
	}
	controllerID := fmt.Sprintf("c8-update-controller-%d", session)
	if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: begin.NodeUID, ControllerID: controllerID, ControllerGeneration: uint64(session)}); err != nil {
		return err
	}
	inventoryCorrelation := fmt.Sprintf("c8-update-inventory-%d", session)
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: begin.NodeUID, CorrelationID: inventoryCorrelation, Command: "inventory_handoff", Payload: map[string]any{}}); err != nil {
		return err
	}
	inventorySeen := false
	completionSent := false
	completionAck := false
	heartbeatSeen := false
	for {
		_, raw, err := connection.ReadMessage()
		if err != nil {
			return err
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			return err
		}
		switch envelope.Type {
		case "heartbeat":
			var heartbeat farmControlHeartbeat
			if err := json.Unmarshal(raw, &heartbeat); err != nil || heartbeat.HeartbeatID == "" {
				return fmt.Errorf("invalid heartbeat")
			}
			if err := connection.WriteJSON(farmControlHeartbeatAck{Type: "heartbeat_ack", HeartbeatID: heartbeat.HeartbeatID}); err != nil {
				return err
			}
			heartbeatSeen = true
		case "command_response":
			var response struct {
				Type          string          `json:"type"`
				NodeUID       string          `json:"node_uid"`
				CorrelationID string          `json:"correlation_id"`
				OK            bool            `json:"ok"`
				Error         string          `json:"error"`
				Payload       json.RawMessage `json:"payload"`
			}
			if err := json.Unmarshal(raw, &response); err != nil || response.NodeUID != begin.NodeUID || !response.OK {
				return fmt.Errorf("command response failed correlation=%s error=%s", response.CorrelationID, response.Error)
			}
			switch response.CorrelationID {
			case inventoryCorrelation:
				var snapshot FarmRuntimeInventorySnapshot
				if err := json.Unmarshal(response.Payload, &snapshot); err != nil || snapshot.ConnectionGeneration == 0 || len(snapshot.Inventory) != 0 || snapshot.InventoryDigest != farmRuntimeInventoryDigest(nil) {
					return fmt.Errorf("inventory snapshot is not the authoritative empty live set")
				}
				inventorySeen = true
				if fixture.shouldReject() {
					fixture.signalFailure()
					// Deliberately withhold Server completion. Hold this one WSS
					// session while still ACKing heartbeats. The transport remains
					// healthy but reconcile readiness never becomes true, proving
					// probation cannot be committed by heartbeat alone.
					return holdC8RejectedUpdateSession(connection, fixture.recoveryOK)
				}
				completionCorrelation := fmt.Sprintf("c8-update-complete-%d", session)
				completionSent = true
				if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: begin.NodeUID, CorrelationID: completionCorrelation, Command: "handoff_reconcile_complete", Payload: FarmRuntimeHandoffCompletion{
					Status: "completed", ControllerID: controllerID, ControllerGeneration: uint64(session), ConnectionGeneration: snapshot.ConnectionGeneration,
					InventoryDigest: snapshot.InventoryDigest, InventoryCount: len(snapshot.Inventory),
				}}); err != nil {
					return err
				}
			case strings.TrimSpace(fmt.Sprintf("c8-update-complete-%d", session)):
				completionAck = true
			}
		}
		if inventorySeen && completionSent && completionAck && heartbeatSeen {
			fixture.signalHealthy(session)
		}
	}
}

func holdC8RejectedUpdateSession(connection *websocket.Conn, recovery <-chan struct{}) error {
	messages := make(chan []byte)
	readErrors := make(chan error, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			_, raw, err := connection.ReadMessage()
			if err != nil {
				select {
				case readErrors <- err:
				case <-done:
				}
				return
			}
			select {
			case messages <- raw:
			case <-done:
				return
			}
		}
	}()
	for {
		select {
		case <-recovery:
			_ = connection.Close()
			return nil
		case err := <-readErrors:
			return err
		case raw := <-messages:
			var heartbeat farmControlHeartbeat
			if json.Unmarshal(raw, &heartbeat) == nil && heartbeat.Type == "heartbeat" && heartbeat.HeartbeatID != "" {
				if err := connection.WriteJSON(farmControlHeartbeatAck{Type: "heartbeat_ack", HeartbeatID: heartbeat.HeartbeatID}); err != nil {
					return err
				}
			}
		}
	}
}

func waitC8UpdateActivation(t *testing.T, ctx context.Context, stateRoot string, predicate func(FarmClientUpdateActivation) bool, diagnostic func() string) {
	t.Helper()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var last FarmClientUpdateActivation
	var lastErr error
	for {
		activation, err := LoadFarmClientUpdateActivation(stateRoot)
		last, lastErr = activation, err
		if err == nil && predicate(activation) {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("activation predicate timed out: %v last=%+v lastErr=%v %s", ctx.Err(), last, lastErr, diagnostic())
		case <-ticker.C:
		}
	}
}
