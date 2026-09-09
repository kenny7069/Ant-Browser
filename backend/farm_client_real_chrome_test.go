package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/database"
	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// TestFarmClientHostRealChromeEnsureAttest is an explicit opt-in C1 evidence
// gate. It exercises the real Host composition: authenticated WSS command →
// ensure → local Chrome process → captured launch attestation provider.
func TestFarmClientHostRealChromeEnsureAttest(t *testing.T) {
	if os.Getenv("C1_REAL_CHROME") != "1" {
		t.Skip("explicit C1_REAL_CHROME=1 opt-in required")
	}
	root := t.TempDir()
	coreRoot := os.Getenv("C1_REAL_CHROME_CORE")
	if coreRoot == "" {
		coreRoot = "/Applications"
	}
	profileID := "c1-real-chrome"
	profileDir := filepath.Join(root, "profile data")
	if err := os.MkdirAll(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "C1 real Chrome", CoreId: "chrome", UserDataDir: profileDir,
		CreatedAt:          "2026-09-09T00:00:00Z",
		IncarnationID:      "c1-fixed-profile-generation",
		RestoreLastSession: "never",
		FingerprintArgs:    []string{"--lang=zh-TW", "--timezone=Asia/Hong_Kong", "--disable-non-proxied-udp"},
		LaunchArgs:         []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"},
	}
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	antConfig.Browser.UserDataRoot = root
	antConfig.Browser.StartReadyTimeoutMs = 15000
	antConfig.Browser.StartStableWindowMs = 100
	antConfig.Browser.DefaultStartURLs = []string{}
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	seedFarmClientChromeDB(t, filepath.Join(root, "profiles.db"), profile, browser.Core{CoreId: "chrome", CoreName: "Chrome", CorePath: coreRoot, IsDefault: true})
	key := newFarmClientTestPrivateKey(t)

	serverDone := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		incarnation, _ := farmClientProfileIncarnation(profileID, profile.IncarnationID)
		serverDone <- runFarmClientRealChromeWSSFixture(connection, key.Public().(ed25519.PublicKey), profileID, incarnation, nil)
	}))
	defer server.Close()
	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"), AntConfigPath: antConfigPath,
		ControlURL:         "ws" + strings.TrimPrefix(server.URL, "http"),
		Identity:           FarmClientIdentityConfig{NodeUID: "c1-node", PrivateKey: base64.StdEncoding.EncodeToString(key)},
		ProviderInstanceID: "provider-c1",
		FencingEpoch:       1,
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := NewFarmClientHost(configPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- host.Run(ctx) }()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatalf("real Chrome WSS fixture timed out: %v", ctx.Err())
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		_ = host.Shutdown()
		t.Fatal("C1 real Chrome Host did not shut down")
	}
}

func runFarmClientRealChromeWSSFixture(connection *websocket.Conn, publicKey ed25519.PublicKey, profileID, pairingIncarnation string, afterEnsure func(FarmRuntime) error) error {
	var begin farmControlAuthBegin
	if err := connection.ReadJSON(&begin); err != nil {
		return fmt.Errorf("auth begin: %w", err)
	}
	challengeRaw := bytes.Repeat([]byte{0x2a}, 32)
	challenge := base64.StdEncoding.EncodeToString(challengeRaw)
	if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: begin.NodeUID, Challenge: challenge}); err != nil {
		return fmt.Errorf("challenge: %w", err)
	}
	var prove farmControlAuthProve
	if err := connection.ReadJSON(&prove); err != nil {
		return fmt.Errorf("auth prove: %w", err)
	}
	message, err := farmControlAuthMessage(begin.NodeUID, challenge)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(prove.Signature)
	if err != nil || !ed25519.Verify(publicKey, message, signature) {
		return fmt.Errorf("invalid auth signature")
	}
	if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: begin.NodeUID, ControllerID: "c1-real-controller", ControllerGeneration: 1}); err != nil {
		return fmt.Errorf("authenticated: %w", err)
	}
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: begin.NodeUID, CorrelationID: "c1-ensure", Command: "ensure_runtime", Payload: map[string]any{
		"node_uid": begin.NodeUID, "profile_id": profileID, "provider_instance_id": "provider-c1", "fencing_epoch": 1,
		"config_hash": "config-c1-real", "launch_mode": FarmRuntimeLaunchModeDirectNoProxy, "pairing_incarnation": pairingIncarnation,
	}}); err != nil {
		return fmt.Errorf("ensure command: %w", err)
	}
	ensureRaw, err := readFarmClientFixtureCommandResponse(connection, "c1-ensure")
	if err != nil {
		return fmt.Errorf("ensure response: %w", err)
	}
	var ensure struct {
		OK      bool            `json:"ok"`
		Payload json.RawMessage `json:"payload"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(ensureRaw, &ensure); err != nil {
		return fmt.Errorf("decode ensure response: %w", err)
	}
	if !ensure.OK {
		return fmt.Errorf("ensure failed: %s", ensure.Error)
	}
	var runtime FarmRuntime
	if err := json.Unmarshal(ensure.Payload, &runtime); err != nil {
		return fmt.Errorf("decode ensure runtime: %w", err)
	}
	if afterEnsure != nil {
		if err := afterEnsure(runtime); err != nil {
			return err
		}
	}
	policy := FarmAttestationPolicy{AllowedDomains: []string{}, Locale: "zh-TW", Timezone: "Asia/Hong_Kong", WebRTCMode: "disable_non_proxied_udp"}
	runtimeConfig := FarmAttestationRuntime{AllowedDomains: []string{}, Locale: policy.Locale, Timezone: policy.Timezone, WebRTCMode: policy.WebRTCMode, Proxy: FarmAttestationProxy{}}
	if err := connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: begin.NodeUID, CorrelationID: "c1-attest", Command: "attest_runtime", Payload: FarmAttestationRequest{
		Version: FarmAttestationVersion, RuntimeIdentity: runtime.FarmRuntimeIdentity, PolicyHash: "policy-c1-real", ConfigHash: runtime.ConfigHash,
		Policy: policy, RuntimeConfig: runtimeConfig,
	}}); err != nil {
		return fmt.Errorf("attest command: %w", err)
	}
	attestRaw, err := readFarmClientFixtureCommandResponse(connection, "c1-attest")
	if err != nil {
		return fmt.Errorf("attest response: %w", err)
	}
	var attest struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Payload struct {
			Status string `json:"status"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(attestRaw, &attest); err != nil {
		return fmt.Errorf("decode attest response: %w", err)
	}
	if !attest.OK || attest.Payload.Status != "applied" {
		return fmt.Errorf("attest failed: ok=%v status=%q error=%s", attest.OK, attest.Payload.Status, attest.Error)
	}
	return nil
}

func readFarmClientFixtureCommandResponse(connection *websocket.Conn, correlationID string) ([]byte, error) {
	for {
		_, raw, err := connection.ReadMessage()
		if err != nil {
			return nil, err
		}
		var header struct {
			Type          string `json:"type"`
			CorrelationID string `json:"correlation_id"`
			HeartbeatID   string `json:"heartbeat_id"`
		}
		if err := json.Unmarshal(raw, &header); err != nil {
			return nil, err
		}
		switch header.Type {
		case "heartbeat":
			if header.HeartbeatID == "" {
				return nil, fmt.Errorf("heartbeat omitted identity")
			}
			if err := connection.WriteJSON(farmControlHeartbeatAck{Type: "heartbeat_ack", HeartbeatID: header.HeartbeatID}); err != nil {
				return nil, err
			}
		case "command_response":
			if header.CorrelationID != correlationID {
				return nil, fmt.Errorf("command response correlation = %q, want %q", header.CorrelationID, correlationID)
			}
			return raw, nil
		default:
			return nil, fmt.Errorf("unexpected client message type %q", header.Type)
		}
	}
}

func seedFarmClientChromeDB(t *testing.T, path string, profile BrowserProfile, core browser.Core) {
	t.Helper()
	db, err := database.NewDB(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	profileDAO := browser.NewSQLiteProfileDAO(db.GetConn())
	coreDAO := browser.NewSQLiteCoreDAO(db.GetConn())
	if err := profileDAO.Upsert(&profile); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := coreDAO.Upsert(core); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}

func newFarmClientTestPrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
