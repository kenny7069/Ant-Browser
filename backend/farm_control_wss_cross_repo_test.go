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
	"sync/atomic"
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

// TestFarmRuntimeP114CrossRepoRealChromeCDPGateway is the opt-in production
// topology proof: Python loopback gateway → authenticated Go Agent outbound
// tunnel → owned browser-level Chrome CDP → real Playwright client.  It is
// intentionally separate from P1.12 readiness and does not claim the later
// Infrastructure example.com/cookies gate.
func TestFarmRuntimeP114CrossRepoRealChromeCDPGateway(t *testing.T) {
	if os.Getenv("P114_CROSS_REPO_REAL_CHROME") != "1" {
		t.Skip("explicit P114_CROSS_REPO_REAL_CHROME=1 opt-in required")
	}
	serverRepo := os.Getenv("P114_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/Desktop/p18-acceptance-docs"
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_14_cdp_gateway_fixture.py")
	playwrightScript := filepath.Join(serverRepo, "輔助程式", "p1_14_playwright_client.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("requested P1.14 fixture is unavailable: %v", err)
	}
	if _, err := os.Stat(playwrightScript); err != nil {
		t.Fatalf("requested P1.14 Playwright client is unavailable: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeUID    = "node-p114-cross"
		providerID = "provider-p114-cross"
		profileID  = "p114-cross-isolated"
	)
	root := t.TempDir()
	urlFile := filepath.Join(root, "control-wss.url")
	gatewayFile := filepath.Join(root, "gateway.url")
	reattachRequestFile := filepath.Join(root, "reattach.request")
	reattachGatewayFile := filepath.Join(root, "reattach.gateway.url")
	doneFile := filepath.Join(root, "playwright.done.json")
	evidenceFile := filepath.Join(root, "p114-evidence.json")
	caFile := filepath.Join(root, "p114-ca.pem")
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	serverCtx, stopServer := context.WithTimeout(context.Background(), 90*time.Second)
	defer stopServer()
	serverCommand := exec.CommandContext(serverCtx, "python3", fixtureScript,
		"--url-file", urlFile, "--gateway-file", gatewayFile,
		"--reattach-request-file", reattachRequestFile,
		"--reattach-gateway-file", reattachGatewayFile,
		"--done-file", doneFile, "--evidence-file", evidenceFile,
		"--ca-file", caFile, "--node-uid", nodeUID,
		"--public-key", publicKey, "--profile-id", profileID,
		"--provider-instance-id", providerID, "--fencing-epoch", "1")
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
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if raw, readErr := os.ReadFile(urlFile); readErr == nil && strings.TrimSpace(string(raw)) != "" {
			controlURL = strings.TrimSpace(string(raw))
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if controlURL == "" {
		_ = serverCommand.Process.Kill()
		_ = serverCommand.Wait()
		t.Fatalf("P1.14 Control WSS fixture did not publish URL: %s", serverOutput.String())
	}

	cfg := DefaultConfig()
	cfg.Browser.UserDataRoot = filepath.Join(root, "profiles")
	cfg.Browser.StartReadyTimeoutMs = 15000
	cfg.Browser.StartStableWindowMs = 100
	cfg.Browser.DefaultStartURLs = []string{}
	coreRoot := os.Getenv("P114_REAL_CHROME_CORE")
	if coreRoot == "" {
		coreRoot = "/Applications"
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "P1.14 cross-repo isolated", CoreId: "chrome",
		UserDataDir: filepath.Join(root, "chrome-profile"), RestoreLastSession: "never",
		LaunchArgs: []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"},
	}
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
			StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
				return NewBrowserRuntimeLocalProcess(plan.Spec)
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
		BrowserRuntimeService: service, NodeUID: nodeUID,
		ProviderInstanceID: providerID, FencingEpoch: 1,
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
		t.Fatal("invalid P1.14 test TLS CA")
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 12 * time.Second,
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
	deadline = time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if raw, readErr := os.ReadFile(gatewayFile); readErr == nil && strings.TrimSpace(string(raw)) != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if raw, err := os.ReadFile(gatewayFile); err != nil || strings.TrimSpace(string(raw)) == "" {
		t.Fatalf("P1.14 gateway did not publish endpoint: %v output=%s", err, serverOutput.String())
	}
	playwrightCtx, cancelPlaywright := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelPlaywright()
	playwright := exec.CommandContext(playwrightCtx, "python3", playwrightScript,
		"--gateway-file", gatewayFile,
		"--reattach-request-file", reattachRequestFile,
		"--reattach-gateway-file", reattachGatewayFile,
		"--done-file", doneFile)
	var playwrightOutput bytes.Buffer
	playwright.Stdout = &playwrightOutput
	playwright.Stderr = &playwrightOutput
	if err := playwright.Run(); err != nil {
		raw, _ := os.ReadFile(doneFile)
		t.Fatalf("real Playwright.connect_over_cdp failed: %v done=%s output=%s", err, raw, playwrightOutput.String())
	}
	if err := serverCommand.Wait(); err != nil {
		t.Fatalf("P1.14 Python fixture failed: %v output=%s", err, serverOutput.String())
	}
	var evidence struct {
		Accepted   bool `json:"accepted"`
		Playwright struct {
			Connected        bool   `json:"connected"`
			BasicIO          bool   `json:"basic_io"`
			Title            string `json:"title"`
			Evaluate         int    `json:"evaluate"`
			NewPage          bool   `json:"new_page"`
			Cookies          bool   `json:"cookies"`
			ClearPermissions bool   `json:"clear_permissions"`
			Disconnected     bool   `json:"disconnected"`
			Reattached       bool   `json:"reattached"`
		} `json:"playwright"`
		Commands []struct {
			Command string         `json:"command"`
			OK      bool           `json:"ok"`
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
	if !evidence.Accepted {
		t.Fatalf("P1.14 evidence not accepted: %s", raw)
	}
	if !evidence.Playwright.Connected ||
		!evidence.Playwright.BasicIO ||
		evidence.Playwright.Title != "Example Domain" ||
		evidence.Playwright.Evaluate != 42 ||
		!evidence.Playwright.NewPage ||
		!evidence.Playwright.Cookies ||
		!evidence.Playwright.ClearPermissions ||
		!evidence.Playwright.Disconnected ||
		!evidence.Playwright.Reattached {
		t.Fatalf("P1.14 Playwright infrastructure evidence incomplete: %+v", evidence.Playwright)
	}
	want := []string{"ensure_runtime", "open_cdp_tunnel", "open_cdp_tunnel", "stop_runtime"}
	if len(evidence.Commands) != len(want) {
		t.Fatalf("P1.14 command count = %d, want %d: %s", len(evidence.Commands), len(want), raw)
	}
	for index, command := range evidence.Commands {
		if command.Command != want[index] || !command.OK {
			t.Fatalf("P1.14 command %d = %+v", index, command)
		}
	}
	ensurePayload := evidence.Commands[0].Payload
	initialDebugPort, ok := ensurePayload["debug_port"].(float64)
	if !ok || initialDebugPort <= 0 {
		t.Fatalf("P1.14 ensure evidence debug_port = %#v", ensurePayload["debug_port"])
	}
	stopPayload := evidence.Commands[len(evidence.Commands)-1].Payload
	if debugPort, ok := stopPayload["debug_port"].(float64); !ok || debugPort != 0 {
		t.Fatalf("P1.14 stop evidence debug_port = %#v, want 0", stopPayload["debug_port"])
	}
	if debugReady, ok := stopPayload["debug_ready"].(bool); !ok || debugReady {
		t.Fatalf("P1.14 stop evidence debug_ready = %#v, want false", stopPayload["debug_ready"])
	}
	closedDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(closedDeadline) && canConnectDebugPort(int(initialDebugPort), 100*time.Millisecond) {
		time.Sleep(50 * time.Millisecond)
	}
	if canConnectDebugPort(int(initialDebugPort), 100*time.Millisecond) {
		t.Fatalf("P1.14 browser debug port %d remained reachable after strict stop", int(initialDebugPort))
	}
	t.Logf("P1.14 deferred loopback gateway / outbound Agent tunnel / real Chrome / Playwright basic I/O evidence: %s", raw)
}

// TestFarmRuntimeP113CrossRepoRealXrayProxyChrome is the P1.13 production
// chain evidence path. It reuses the Python ControlWSServer fixture and the
// Go FarmControlWSSClient, then proves the authenticated profile proxy through
// the existing XrayManager/secure-writer/real-Chrome path. Operators opt in
// explicitly because it starts local servers, Xray, and Chrome.
func TestFarmRuntimeP113CrossRepoRealXrayProxyChrome(t *testing.T) {
	if os.Getenv("P113_CROSS_REPO_REAL_PROXY") != "1" {
		t.Skip("explicit P113_CROSS_REPO_REAL_PROXY=1 opt-in required")
	}
	serverRepo := os.Getenv("P113_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/Desktop/p18-acceptance-docs"
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_12_control_wss_fixture.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("requested cross-repo fixture is unavailable: %v", err)
	}
	xrayPath := os.Getenv("P113_REAL_XRAY")
	if xrayPath == "" {
		xrayPath = "/tmp/bf-p113-xray-v26.7.11/xray"
	}
	if _, err := os.Stat(xrayPath); err != nil {
		t.Fatalf("approved local Xray fixture is unavailable: %v", err)
	}

	initialRoots := p113XrayRoots()
	var targetHits atomic.Int64
	target := httptestP113Target(t, &targetHits)
	upstream := startP113AuthenticatedXrayWithAccessLog(t, xrayPath)
	defer upstream.stop()

	runFarmRuntimeP113CrossRepoProxyCase(t, fixtureScript, xrayPath, target, &targetHits, upstream, initialRoots, "correct", "p113-password", false)
	runFarmRuntimeP113CrossRepoProxyCase(t, fixtureScript, xrayPath, target, &targetHits, upstream, initialRoots, "wrong", "p113-wrong", true)

	if !waitP113(func() bool { return p113SameRoots(initialRoots, p113XrayRoots()) }, 5*time.Second) {
		t.Fatal("P1.13 cross-repo strict stop did not clean released Xray bridge configs")
	}
}

func runFarmRuntimeP113CrossRepoProxyCase(
	t *testing.T,
	fixtureScript string,
	xrayPath string,
	target p113HTTPServer,
	targetHits *atomic.Int64,
	upstream p113XrayUpstream,
	initialRoots map[string]struct{},
	label string,
	password string,
	expectFailure bool,
) {
	t.Helper()
	t.Run(label, func(t *testing.T) {
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		nodeUID := "node-p113-cross-" + label
		providerID := "provider-p113-cross-" + label
		profileID := "p113-cross-isolated-" + label
		urlFile := filepath.Join(t.TempDir(), "control-wss.url")
		evidenceFile := filepath.Join(t.TempDir(), "p113-evidence.json")
		caFile := filepath.Join(t.TempDir(), "p113-ca.pem")

		cfg := DefaultConfig()
		cfg.Browser.XrayBinaryPath = xrayPath
		cfg.Browser.DefaultConnectorType = "xray"
		cfg.Browser.UserDataRoot = t.TempDir()
		cfg.Browser.StartReadyTimeoutMs = 15000
		cfg.Browser.StartStableWindowMs = 100
		cfg.Browser.DefaultStartURLs = []string{target.url}
		coreRoot := os.Getenv("P113_REAL_CHROME_CORE")
		if coreRoot == "" {
			coreRoot = "/Applications"
		}
		cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
		profile := BrowserProfile{
			ProfileId: profileID, ProfileName: "P1.13 cross-repo isolated", CoreId: "chrome",
			UserDataDir:        filepath.Join(t.TempDir(), "isolated-profile"),
			ProxyConfig:        "socks5://p113-user:" + password + "@" + upstream.address,
			RestoreLastSession: "never",
			LaunchArgs: []string{
				"--headless=new",
				"--no-first-run",
				"--no-default-browser-check",
				"--disable-background-networking",
				"--proxy-bypass-list=<-loopback>",
				"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
			},
		}

		targetBaseline := targetHits.Load()
		accessBaseline := p113XrayAccessLogSize(upstream.accessLog)
		var launchMu sync.Mutex
		var launchSpec *BrowserRuntimeLaunchSpec
		var chromeProcess *BrowserRuntimeProcess
		var secureRootChecked atomic.Bool
		var farm *FarmRuntimeService
		farm, err = NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
			NodeUID: nodeUID, ProviderInstanceID: providerID, FencingEpoch: 1,
			BrowserRuntimeFactory: BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
				StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
					process, startErr := NewBrowserRuntimeLocalProcess(plan.Spec)
					launchMu.Lock()
					spec := plan.Spec
					spec.Args = append([]string(nil), plan.Spec.Args...)
					spec.DeferredStartTargets = append([]string(nil), plan.Spec.DeferredStartTargets...)
					launchSpec, chromeProcess = &spec, process
					launchMu.Unlock()
					return process, startErr
				},
				StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
				CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP,
				CreateTarget: createBrowserStartTarget,
			}},
			AttestationStateProvider: func(identity FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
				launchMu.Lock()
				spec := launchSpec
				launchMu.Unlock()
				if spec == nil || spec.ProfileID != identity.ProfileID {
					return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
				}
				if spec.EffectiveProxy == "direct://" || !strings.HasPrefix(spec.EffectiveProxy, "socks5://127.0.0.1:") || strings.Contains(spec.EffectiveProxy, "p113-") {
					return FarmAttestationLaunchState{}, ErrFarmAttestationStructuredMismatch
				}
				for _, arg := range spec.Args {
					if strings.Contains(arg, "p113-password") || strings.Contains(arg, "p113-wrong") ||
						strings.Contains(arg, "p113-user") || strings.Contains(arg, upstream.address) {
						return FarmAttestationLaunchState{}, ErrFarmAttestationStructuredMismatch
					}
				}
				if err := p113SecureRootsError(initialRoots); err != nil {
					return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
				}
				secureRootChecked.Store(true)
				if !waitP113(func() bool {
					return targetHits.Load() > targetBaseline &&
						p113XrayAccessedTargetAfter(upstream.accessLog, target, accessBaseline)
				}, 5*time.Second) {
					return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
				}
				snapshot, err := farm.runtimeService.RuntimeSnapshot(identity.ProfileID)
				if err != nil || snapshot == nil || snapshot.Profile == nil ||
					snapshot.Generation != identity.Generation || !snapshot.Profile.Running || !snapshot.Profile.DebugReady {
					return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
				}
				binding, err := farm.runtimeService.LocalProfileProxyBinding(profileID)
				if err != nil {
					return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
				}
				policy := FarmAttestationPolicy{AllowedDomains: []string{}, WebRTCMode: "disable_non_proxied_udp"}
				return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: FarmAttestationRuntime{
					AllowedDomains: []string{}, WebRTCMode: policy.WebRTCMode,
					Proxy: FarmAttestationProxy{
						Enabled:            true,
						ConnectorType:      binding.ConnectorType,
						CredentialRevision: binding.CredentialRevision,
						ConfigRevision:     binding.ConfigRevision,
					},
				}}, nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		defer farm.runtimeService.Shutdown()
		binding, err := farm.runtimeService.LocalProfileProxyBinding(profileID)
		if err != nil {
			t.Fatal(err)
		}

		publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
		args := []string{
			fixtureScript,
			"--url-file", urlFile,
			"--evidence-file", evidenceFile,
			"--ca-file", caFile,
			"--node-uid", nodeUID,
			"--public-key", publicKey,
			"--profile-id", profileID,
			"--provider-instance-id", providerID,
			"--fencing-epoch", "1",
			"--mode", "profile-proxy",
			"--proxy-connector-type", binding.ConnectorType,
			"--proxy-credential-revision", binding.CredentialRevision,
			"--proxy-config-revision", binding.ConfigRevision,
		}
		if expectFailure {
			args = append(args, "--expect-failure")
		}
		serverCtx, stopServer := context.WithTimeout(context.Background(), 75*time.Second)
		defer stopServer()
		serverCommand := exec.CommandContext(serverCtx, "python3", args...)
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
			t.Fatal("Control WSS fixture did not publish URL")
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
		}, mustFarmRuntimeControlAdapter(t, farm))
		if err != nil {
			t.Fatal(err)
		}
		if err := client.Connect(nil); err != nil {
			t.Fatalf("real Go Agent authenticated connect: %v", err)
		}
		if err := serverCommand.Wait(); err != nil {
			t.Fatalf("Python P1.13 ControlWSS fixture failed: %v", err)
		}
		select {
		case <-client.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("Agent connection did not close after P1.13 fixture cleanup")
		}
		if err := client.Close(); err != nil {
			t.Fatal(err)
		}

		launchMu.Lock()
		spec := launchSpec
		process := chromeProcess
		launchMu.Unlock()
		if spec == nil || process == nil {
			t.Fatal("P1.13 cross-repo did not start real Chrome")
		}
		if spec.EffectiveProxy == "direct://" || !strings.HasPrefix(spec.EffectiveProxy, "socks5://127.0.0.1:") || strings.Contains(spec.EffectiveProxy, "p113-") {
			t.Fatal("P1.13 launch proxy was not a local secret-free bridge")
		}
		select {
		case <-process.owner.Done():
		case <-time.After(3 * time.Second):
			t.Fatal("P1.13 strict stop did not reap real Chrome")
		}
		if canConnectDebugPort(spec.AssignedDebugPort, 150*time.Millisecond) {
			t.Fatal("P1.13 strict stop did not close the real Chrome debugging endpoint")
		}
		if !secureRootChecked.Load() {
			t.Fatal("P1.13 attestation did not audit secure Xray runtime root")
		}
		if !waitP113(func() bool { return p113SameRoots(initialRoots, p113XrayRoots()) }, 5*time.Second) {
			t.Fatal("P1.13 strict stop did not remove released Xray config")
		}

		raw, err := os.ReadFile(evidenceFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"p113-password", "p113-wrong", "p113-user", upstream.address, "proxy-server=", "proxy_url", "proxy_config", "credential_token", "password", "path", "args", "UserDataDir", "LaunchArgs"} {
			if strings.Contains(string(raw), forbidden) {
				t.Fatalf("P1.13 evidence leaked forbidden field/value %q", forbidden)
			}
		}
		var evidence struct {
			Accepted bool   `json:"accepted"`
			Error    string `json:"error"`
			Mode     string `json:"mode"`
			Commands []struct {
				Command string         `json:"command"`
				OK      bool           `json:"ok"`
				Error   any            `json:"error"`
				Payload map[string]any `json:"payload"`
			} `json:"commands"`
		}
		if err := json.Unmarshal(raw, &evidence); err != nil {
			t.Fatal(err)
		}
		if evidence.Mode != "profile-proxy" {
			t.Fatalf("P1.13 fixture mode = %q", evidence.Mode)
		}
		if expectFailure {
			if evidence.Accepted || evidence.Error == "" {
				t.Fatal("wrong credential was not recorded as fail-closed")
			}
			if targetHits.Load() != targetBaseline {
				t.Fatal("wrong credential unexpectedly reached controlled endpoint")
			}
			want := []string{"ensure_runtime", "attest_runtime", "stop_runtime"}
			assertFarmRuntimeCommandTrace(t, evidence.Commands, want)
			if !evidence.Commands[0].OK || evidence.Commands[1].OK || !evidence.Commands[2].OK {
				t.Fatalf("wrong credential command statuses are not fail-closed: %+v", evidence.Commands)
			}
			return
		}
		if !evidence.Accepted || evidence.Error != "" {
			t.Fatal("P1.13 correct credential was not accepted")
		}
		if targetHits.Load() <= targetBaseline || !p113XrayAccessedTargetAfter(upstream.accessLog, target, accessBaseline) {
			t.Fatal("correct credential did not prove proxy-mediated endpoint access")
		}
		want := []string{"ensure_runtime", "attest_runtime", "runtime_status", "stop_runtime"}
		assertFarmRuntimeCommandTrace(t, evidence.Commands, want)
		status := evidence.Commands[2].Payload
		if status["state"] != "idle" || status["debug_ready"] != true || status["launch_mode"] != FarmRuntimeLaunchModeProfileProxy {
			t.Fatalf("P1.13 status was not proxy CDP-ready: %+v", status)
		}
		t.Log("cross-repo TLS WSS / Ed25519 / authenticated Xray proxy / real Chrome / strict stop evidence recorded")
	})
}

func mustFarmRuntimeControlAdapter(t *testing.T, farm *FarmRuntimeService) *FarmRuntimeControlAdapter {
	t.Helper()
	adapter, err := NewFarmRuntimeControlAdapter(farm)
	if err != nil {
		t.Fatal(err)
	}
	return adapter
}

func assertFarmRuntimeCommandTrace(t *testing.T, commands []struct {
	Command string         `json:"command"`
	OK      bool           `json:"ok"`
	Error   any            `json:"error"`
	Payload map[string]any `json:"payload"`
}, want []string) {
	t.Helper()
	if len(commands) != len(want) {
		t.Fatalf("command count = %d, want %d: %+v", len(commands), len(want), commands)
	}
	for index, command := range commands {
		if command.Command != want[index] {
			t.Fatalf("command %d = %q, want %q; commands=%+v", index, command.Command, want[index], commands)
		}
	}
}
