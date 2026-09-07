package backend

import (
	"bytes"
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
	"strings"
	"sync"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
)

// TestFarmRuntimeP112CrossRepoRealChrome is an explicit cross-repo evidence
// gate. The default test suite never starts Python, opens a socket, or starts
// Chrome; operators opt in with P112_CROSS_REPO_REAL_CHROME=1.
func TestFarmRuntimeP112CrossRepoRealChrome(t *testing.T) {
	if os.Getenv("P112_CROSS_REPO_REAL_CHROME") != "1" {
		t.Skip("explicit P112_CROSS_REPO_REAL_CHROME=1 opt-in required")
	}
	serverRepo := os.Getenv("P112_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/Desktop/p18-acceptance-docs"
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_12_control_wss_fixture.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("requested cross-repo fixture is unavailable: %v", err)
	}

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeUID    = "node-p112-cross"
		providerID = "provider-p112-cross"
		profileID  = "p112-cross-isolated"
	)
	urlFile := filepath.Join(t.TempDir(), "control-wss.url")
	evidenceFile := filepath.Join(t.TempDir(), "p112-evidence.json")
	caFile := filepath.Join(t.TempDir(), "p112-ca.pem")
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	serverCtx, stopServer := context.WithTimeout(context.Background(), 55*time.Second)
	defer stopServer()
	serverCommand := exec.CommandContext(serverCtx, "python3", fixtureScript,
		"--url-file", urlFile, "--evidence-file", evidenceFile,
		"--ca-file", caFile,
		"--node-uid", nodeUID, "--public-key", publicKey,
		"--profile-id", profileID, "--provider-instance-id", providerID,
		"--fencing-epoch", "1")
	var serverOutput bytes.Buffer
	serverCommand.Stdout = &serverOutput
	serverCommand.Stderr = &serverOutput
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
		stopServer()
		_ = serverCommand.Wait()
		t.Fatalf("Control WSS fixture did not publish URL: %s", serverOutput.String())
	}

	cfg := DefaultConfig()
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.StartReadyTimeoutMs = 15000
	cfg.Browser.StartStableWindowMs = 100
	cfg.Browser.DefaultStartURLs = []string{}
	coreRoot := os.Getenv("P112_REAL_CHROME_CORE")
	if coreRoot == "" {
		coreRoot = "/Applications"
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "P1.12 cross-repo isolated", CoreId: "chrome",
		UserDataDir: filepath.Join(t.TempDir(), "isolated-profile"),
		// This contradictory value must never reach the direct/no-proxy launch.
		ProxyConfig: "http://user:secret@example.invalid:8080", RestoreLastSession: "never",
		LaunchArgs: []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"},
	}
	var launchMu sync.Mutex
	var launchSpec *BrowserRuntimeLaunchSpec
	var chromeProcess *BrowserRuntimeProcess
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
			StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
				process, err := NewBrowserRuntimeLocalProcess(plan.Spec)
				launchMu.Lock()
				spec := plan.Spec
				spec.Args = append([]string(nil), plan.Spec.Args...)
				launchSpec, chromeProcess = &spec, process
				launchMu.Unlock()
				return process, err
			},
			StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
			CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP,
			CreateTarget: createBrowserStartTarget,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: service, NodeUID: nodeUID, ProviderInstanceID: providerID, FencingEpoch: 1,
		AttestationStateProvider: func(identity FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
			// Observe the shared launch plan and runtime, never request fields.
			// Empty locale/timezone report that no overrides were configured.
			launchMu.Lock()
			defer launchMu.Unlock()
			if launchSpec == nil || launchSpec.ProfileID != identity.ProfileID || launchSpec.EffectiveProxy != "direct://" {
				return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
			}
			noProxy, webrtc := false, ""
			for _, arg := range launchSpec.Args {
				if arg == "--no-proxy-server" {
					noProxy = true
				}
				if strings.HasPrefix(arg, "--force-webrtc-ip-handling-policy=") {
					webrtc = strings.TrimPrefix(arg, "--force-webrtc-ip-handling-policy=")
				}
				if strings.HasPrefix(arg, "--lang=") || strings.Contains(arg, "proxy-server=") || strings.Contains(arg, "example.invalid") {
					return FarmAttestationLaunchState{}, ErrFarmAttestationStructuredMismatch
				}
			}
			snapshot, err := service.RuntimeSnapshot(identity.ProfileID)
			if err != nil || snapshot.Generation != identity.Generation || !snapshot.Profile.Running || !snapshot.Profile.DebugReady || !noProxy || webrtc == "" {
				return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
			}
			policy := FarmAttestationPolicy{AllowedDomains: []string{}, WebRTCMode: webrtc}
			applied := FarmAttestationRuntime{AllowedDomains: []string{}, WebRTCMode: webrtc, Proxy: FarmAttestationProxy{}}
			return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: applied}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewFarmRuntimeControlAdapter(farm)
	if err != nil {
		t.Fatal(err)
	}
	caRaw, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caRaw) {
		t.Fatal("invalid test TLS CA")
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 8 * time.Second,
		HeartbeatInterval: 200 * time.Millisecond,
		Dialer:            &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(nil); err != nil {
		t.Fatalf("real Go Agent authenticated connect: %v", err)
	}
	defer client.Close()
	if err := serverCommand.Wait(); err != nil {
		t.Fatalf("Python ControlWSS fixture: %v output=%s", err, serverOutput.String())
	}
	select {
	case <-client.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("Agent connection did not close after strict stop/fixture cleanup")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	launchMu.Lock()
	process := chromeProcess
	launchMu.Unlock()
	if process == nil {
		t.Fatal("real Chrome process was never started")
	}
	select {
	case <-process.owner.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("strict stop did not reap real Chrome")
	}
	var evidence struct {
		Accepted   bool   `json:"accepted"`
		ConfigHash string `json:"verified_config_hash"`
		PolicyHash string `json:"verified_policy_hash"`
		Commands   []struct {
			Command string         `json:"command"`
			OK      bool           `json:"ok"`
			Error   any            `json:"error"`
			Payload map[string]any `json:"payload"`
		} `json:"commands"`
	}
	raw, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &evidence); err != nil {
		t.Fatal(err)
	}
	if !evidence.Accepted || len(evidence.Commands) != 4 {
		t.Fatalf("cross-repo evidence not accepted: %s", raw)
	}
	if len(evidence.ConfigHash) != 64 || evidence.PolicyHash == "" {
		t.Fatalf("Server hashes were not verified: %s", raw)
	}
	wantCommands := []string{"ensure_runtime", "attest_runtime", "runtime_status", "stop_runtime"}
	for index, command := range evidence.Commands {
		if command.Command != wantCommands[index] || !command.OK {
			t.Fatalf("cross-repo command %d = %+v", index, command)
		}
	}
	if status := evidence.Commands[2].Payload; status["state"] != "idle" || status["debug_ready"] != true || status["launch_mode"] != FarmRuntimeLaunchModeDirectNoProxy {
		t.Fatalf("cross-repo status was not direct CDP-ready: %+v", status)
	}
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "proxy-server") {
		t.Fatalf("cross-repo evidence leaked forbidden proxy data: %s", raw)
	}
	if port, ok := evidence.Commands[2].Payload["debug_port"].(float64); !ok || port <= 0 || canConnectDebugPort(int(port), 150*time.Millisecond) {
		t.Fatal("strict stop did not close the real Chrome debugging endpoint")
	}
	t.Logf("cross-repo TLS WSS / Ed25519 / real Chrome / verified readiness / strict stop evidence: %s", raw)
}
