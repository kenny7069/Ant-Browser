package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// TestFarmResourceRTTCrossRepo is an opt-in isolated production-wire proof:
// the Python ControlWSServer receives real Agent memory/RSS/RTT telemetry and
// sends one strict generation/fencing remote recycle back through Go.
func TestFarmResourceRTTCrossRepo(t *testing.T) {
	if os.Getenv("P117_RESOURCE_RTT_CROSS_REPO") != "1" {
		t.Skip("explicit P117_RESOURCE_RTT_CROSS_REPO=1 opt-in required")
	}
	serverRepo := os.Getenv("P117_SERVER_REPO")
	if serverRepo == "" {
		t.Skip("P117_SERVER_REPO must point at the Server worktree")
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_17_resource_rtt_fixture.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("resource/RTT fixture unavailable: %v", err)
	}

	const (
		nodeUID    = "node-p117-cross"
		providerID = "provider-p117-cross"
		profileID  = "profile-p117-cross"
	)
	fixture := newFarmRuntimeTestFixture(t, profileID)
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: profileID})
	if err != nil {
		t.Fatalf("ensure isolated runtime: %v", err)
	}
	// The helper fixture uses a deterministic recovered runtime; telemetry
	// hooks make the E2E independent from host process discovery while keeping
	// the real WSS/Go/Server wire and strict stop path.
	fixture.farm.nodeUID = nodeUID
	fixture.farm.providerInstance = providerID
	fixture.farm.fencingEpoch = 7
	fixture.farm.recordsMu.Lock()
	record := fixture.farm.records[profileID]
	record.runtime.NodeUID = nodeUID
	record.runtime.ProviderInstanceID = providerID
	record.runtime.FencingEpoch = 7
	fixture.farm.records[profileID] = record
	fixture.farm.recordsMu.Unlock()
	// Keep BrowserRuntime identity and Agent service identity aligned after the
	// test fixture's default node/provider values are replaced.
	runtime = record.runtime
	fixture.farm.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		NodeMemory: func() (FarmNodeMemoryTelemetry, error) {
			return FarmNodeMemoryTelemetry{TotalMB: 8192, AvailableMB: 4096, UsedPercent: 50, Health: "healthy"}, nil
		},
		ProcessRSS: func(pid int) (int64, error) { return 321, nil },
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	urlFile := filepath.Join(t.TempDir(), "control-wss.url")
	evidenceFile := filepath.Join(t.TempDir(), "resource-rtt-evidence.json")
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	serverCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	serverCommand := exec.CommandContext(serverCtx, "python3", fixtureScript,
		"--url-file", urlFile, "--evidence-file", evidenceFile, "--ca-file", caFile,
		"--node-uid", nodeUID, "--public-key", publicKey, "--profile-id", profileID,
		"--runtime-uid", runtime.RuntimeUID, "--provider-instance-id", providerID,
		"--fencing-epoch", "7", "--generation", strconv.FormatUint(runtime.Generation, 10))
	if err := serverCommand.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if serverCommand.Process != nil {
			_ = serverCommand.Process.Kill()
		}
	}()
	var controlURL string
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if raw, readErr := os.ReadFile(urlFile); readErr == nil && strings.TrimSpace(string(raw)) != "" {
			controlURL = strings.TrimSpace(string(raw))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if controlURL == "" {
		t.Fatal("Control WSS fixture did not publish URL")
	}
	caRaw, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		t.Fatal("invalid fixture CA")
	}
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 8 * time.Second,
		HeartbeatInterval: 100 * time.Millisecond,
		Dialer:            &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(nil); err != nil {
		t.Fatalf("Agent telemetry WSS connect: %v", err)
	}
	if err := serverCommand.Wait(); err != nil {
		t.Fatalf("Python resource RTT fixture: %v", err)
	}
	_ = client.Close()
	select {
	case <-client.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Agent connection did not close after remote recycle")
	}
	var evidence struct {
		TelemetrySeen bool           `json:"telemetry_seen"`
		Recycled      bool           `json:"recycled"`
		Resource      map[string]any `json:"resource"`
	}
	raw, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if !evidence.TelemetrySeen || !evidence.Recycled {
		t.Fatalf("resource/RTT evidence not accepted: %s", raw)
	}
	if evidence.Resource["provider"] != "farm" || strings.Contains(string(raw), "password") || strings.Contains(string(raw), "proxy") {
		t.Fatalf("invalid provider or secret-bearing telemetry evidence: %s", raw)
	}
}
