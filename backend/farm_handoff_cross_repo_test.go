package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
)

type p118SynchronizedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *p118SynchronizedBuffer) Write(value []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(value)
}

func (b *p118SynchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func p118TransportDiagnostic(client *FarmControlWSSClient) string {
	if client == nil {
		return "client=nil"
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	category := "none"
	switch {
	case errors.Is(client.closeErr, ErrFarmControlWSSMessageLimit):
		category = "message_limit"
	case errors.Is(client.closeErr, ErrFarmControlWSSProtocol):
		category = "protocol"
	case errors.Is(client.closeErr, ErrFarmControlWSSAuth):
		category = "authentication"
	case errors.Is(client.closeErr, context.DeadlineExceeded):
		category = "command_deadline"
	case errors.Is(client.closeErr, ErrFarmControlWSSClosed):
		ackDeadline := 4 * client.config.HeartbeatInterval
		if ackDeadline < 300*time.Millisecond {
			ackDeadline = 300 * time.Millisecond
		}
		if !client.lastHeartbeatAck.IsZero() && time.Since(client.lastHeartbeatAck) >= ackDeadline {
			category = "heartbeat_deadline_exceeded"
		} else {
			category = "closed_transport"
		}
	case client.closeErr != nil:
		category = fmt.Sprintf("transport_type=%T", client.closeErr)
	}
	return fmt.Sprintf(
		"category=%s connected=%t connecting=%t connection_fence=%d",
		category, client.conn != nil, client.connecting, client.connectionFence,
	)
}

func p118AllowlistedJSONDiagnostic(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "unavailable"
	}
	var source map[string]json.RawMessage
	if json.Unmarshal(raw, &source) != nil {
		return "invalid_json"
	}
	allowed := map[string]json.RawMessage{}
	for _, key := range []string{
		"accepted", "control_db_cleanup", "failure_stage", "failure_type",
		"cleanup_error_type", "old_connection_disconnected", "old_operation_rejected",
		"marker_preserved", "new_io", "reattached", "child_actor",
		"reconcile_error_type", "reconcile_outcomes", "running", "actor", "stage",
		// Crash/execv progress fields are deliberately limited to enum-like
		// strings, booleans, and counters emitted by the fixtures.  Do not add
		// capability-bearing tokens or free-form error payloads here.
		"scenario", "pid", "boot_nonce", "controller_a_execv_requested",
		"controller_b_started_new_image", "same_pid", "boot_nonce_changed",
		"controller_pid_before", "controller_pid_after", "boot_nonce_before",
		"boot_nonce_after", "runtime_created_by_ensure",
		"runtime_persisted_by_authenticated_telemetry", "runtime_lease_acquired",
		"initial_cdp_published", "watcher_reconciled", "production_startup_wiring",
		"production_watcher_started", "runtime_lease_released", "strict_stop_confirmed",
		"chrome_alive_during_execv_handoff", "runtime_process_identity_preserved",
		"runtime_db_status", "runtime_db_provider", "runtime_db_fencing_epoch",
		"controller_lease_acquired", "controller_generation", "controller_state",
		"watcher_adopted_runtime_count", "watcher_reconcile_status",
		"watcher_controller_failure_type", "node_count",
		"inventory_dispatch_attempts", "inventory_list_online", "inventory_list_generation",
		"inventory_auth_binding_generation", "inventory_sample_generation",
		"inventory_heartbeat_age_ms", "inventory_dispatch_error_type",
		"inventory_response_ok", "inventory_count",
	} {
		if value, ok := source[key]; ok {
			allowed[key] = value
		}
	}
	encoded, err := json.Marshal(allowed)
	if err != nil {
		return "invalid_allowlisted_json"
	}
	return string(encoded)
}

func p118AllowlistedJSONDiagnostics(paths ...string) string {
	parts := make([]string, 0, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		diagnostic := p118AllowlistedJSONDiagnostic(path)
		if diagnostic == "unavailable" {
			continue
		}
		parts = append(parts, filepath.Base(path)+"="+diagnostic)
	}
	if len(parts) == 0 {
		return "unavailable"
	}
	joined := strings.Join(parts, " | ")
	if len(joined) > 4096 {
		joined = joined[:4096]
	}
	return joined
}

func p118AllowlistedServerOutput(output string) string {
	lines := make([]string, 0, 2)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "Controller B failed stage=") {
			lines = append(lines, line)
		}
	}
	if len(lines) == 0 {
		return "no_allowlisted_diagnostic_lines"
	}
	joined := strings.Join(lines, " | ")
	if len(joined) > 2048 {
		joined = joined[len(joined)-2048:]
	}
	return joined
}

type p118HandoffIdentity struct {
	RuntimeUID           string `json:"runtime_uid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
	Generation           uint64 `json:"generation"`
	PID                  int    `json:"pid"`
}

// TestFarmRuntimeP118CrossRepoRealChromeHandoff is the opt-in, non-mock P1.18
// evidence path. The Python child owns an isolated Control DB and two
// production controller factories. Runtime authority must originate from the
// first controller's ensure/heartbeat path; the fixture is forbidden from
// seeding a browser_farm_runtime row before ensure.
func TestFarmRuntimeP118CrossRepoRealChromeHandoff(t *testing.T) {
	if os.Getenv("P118_CROSS_REPO_REAL_HANDOFF") != "1" {
		t.Skip("explicit P118_CROSS_REPO_REAL_HANDOFF=1 opt-in required")
	}
	serverRepo := os.Getenv("P118_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/Desktop/p18-acceptance-docs"
	}
	scenario := os.Getenv("P118_HANDOFF_SCENARIO")
	fixtureName, err := p118ScenarioFixture(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", fixtureName)
	playwrightScript := filepath.Join(serverRepo, "輔助程式", "p1_18_playwright_client.py")
	for _, path := range []string{fixtureScript, playwrightScript} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("requested P1.18 fixture dependency is unavailable: %v", err)
		}
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeUID      = "node-p118-cross"
		providerID   = "provider-p118-cross"
		profileID    = "118001"
		controllerA  = "controller-p118-a"
		controllerB  = "controller-p118-b"
		fencingEpoch = uint64(1)
	)
	root := t.TempDir()
	urlFile := filepath.Join(root, "control-wss.url")
	gatewayFile := filepath.Join(root, "controller-a.gateway.url")
	reattachRequestFile := filepath.Join(root, "controller-b.reattach.request")
	oldCDPClosedFile := filepath.Join(root, "controller-a.old-cdp-closed.json")
	reattachGatewayFile := filepath.Join(root, "controller-b.gateway.url")
	doneFile := filepath.Join(root, "playwright.done.json")
	evidenceFile := filepath.Join(root, "p118-evidence.json")
	caFile := filepath.Join(root, "p118-ca.pem")
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	serverCtx, stopServer := context.WithTimeout(context.Background(), 120*time.Second)
	defer stopServer()
	controlDBName := fmt.Sprintf("bf_p118_%x", time.Now().UnixNano())
	serverCommand := exec.CommandContext(serverCtx, "python3", fixtureScript,
		"--url-file", urlFile, "--gateway-file", gatewayFile,
		"--reattach-request-file", reattachRequestFile,
		"--old-cdp-closed-file", oldCDPClosedFile,
		"--reattach-gateway-file", reattachGatewayFile,
		"--done-file", doneFile, "--evidence-file", evidenceFile,
		"--ca-file", caFile, "--node-uid", nodeUID,
		"--public-key", publicKey, "--profile-id", profileID,
		"--provider-instance-id", providerID, "--fencing-epoch", fmt.Sprint(fencingEpoch),
		"--controller-a-id", controllerA, "--controller-b-id", controllerB)
	serverCommand.Env = append(os.Environ(), "SCRAPER_CONTROL_DB_NAME="+controlDBName)
	var serverOutput p118SynchronizedBuffer
	serverCommand.Stdout, serverCommand.Stderr = &serverOutput, &serverOutput
	if err := serverCommand.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverCommand.Wait() }()
	serverFinished := false
	defer func() {
		if serverFinished || serverCommand.Process == nil {
			return
		}
		_ = serverCommand.Process.Signal(syscall.SIGTERM)
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			_ = serverCommand.Process.Kill()
			select {
			case <-serverDone:
			case <-time.After(2 * time.Second):
			}
		}
	}()
	controlURL := waitForP118TextFileOrProcess(
		t, urlFile, 20*time.Second, &serverOutput, serverDone, &serverFinished, nil,
		evidenceFile,
		evidenceFile+".controller-a-progress.json",
		evidenceFile+".controller-b-progress.json",
		evidenceFile+".execv-phase.json",
	)

	cfg := DefaultConfig()
	cfg.Browser.UserDataRoot = filepath.Join(root, "profiles")
	cfg.Browser.StartReadyTimeoutMs = 15000
	cfg.Browser.StartStableWindowMs = 100
	cfg.Browser.DefaultStartURLs = []string{}
	coreRoot := os.Getenv("P118_REAL_CHROME_CORE")
	if coreRoot == "" {
		coreRoot = "/Applications"
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
	profile := BrowserProfile{
		ProfileId: profileID, ProfileName: "P1.18 handoff isolated", CoreId: "chrome",
		UserDataDir: filepath.Join(root, "chrome-profile"), RestoreLastSession: "never",
		LaunchArgs: []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking"},
		CreatedAt:  "2026-09-08T00:00:00Z",
	}
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
			StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
				return NewBrowserRuntimeLocalProcess(plan.Spec)
			},
			StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
			CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP, CreateTarget: createBrowserStartTarget,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer service.Shutdown()
	storeKey := sha256.Sum256(privateKey)
	ownershipStore, err := NewFileFarmRuntimeOwnershipStore(filepath.Join(root, "farm-ownership.json"), storeKey[:])
	if err != nil {
		t.Fatal(err)
	}
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: service, NodeUID: nodeUID, ProviderInstanceID: providerID,
		FencingEpoch: fencingEpoch, ControllerID: controllerA, ControllerGeneration: 1,
		OwnershipStore: ownershipStore,
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
		t.Fatal("invalid P1.18 test TLS CA")
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 15 * time.Second, HeartbeatInterval: 200 * time.Millisecond,
		AutoReconnect: true, ReconnectMinBackoff: 50 * time.Millisecond, ReconnectMaxBackoff: time.Second,
		Dialer: &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(nil); err != nil {
		t.Fatalf("P1.18 Agent initial authenticated connect: %v", err)
	}
	defer client.Close()
	waitForP118TextFileOrProcess(
		t, gatewayFile, 30*time.Second, &serverOutput, serverDone, &serverFinished, client,
	)
	playwrightCtx, cancelPlaywright := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelPlaywright()
	playwright := exec.CommandContext(playwrightCtx, "python3", playwrightScript,
		"--gateway-file", gatewayFile, "--reattach-request-file", reattachRequestFile,
		"--old-cdp-closed-file", oldCDPClosedFile,
		"--reattach-gateway-file", reattachGatewayFile, "--done-file", doneFile)
	var playwrightOutput bytes.Buffer
	playwright.Stdout, playwright.Stderr = &playwrightOutput, &playwrightOutput
	if err := playwright.Run(); err != nil {
		// Let Controller B observe the atomic done file and let the parent own
		// its DB cleanup before failing the Go test.  If it does not finish,
		// explicitly terminate and wait rather than relying on a deferred Kill.
		select {
		case <-serverDone:
			serverFinished = true
		case <-time.After(10 * time.Second):
			_ = serverCommand.Process.Signal(syscall.SIGTERM)
			select {
			case <-serverDone:
				serverFinished = true
			case <-time.After(5 * time.Second):
				_ = serverCommand.Process.Kill()
				select {
				case <-serverDone:
					serverFinished = true
				case <-time.After(2 * time.Second):
				}
			}
		}
		t.Fatalf(
			"P1.18 Playwright handoff failed: error_type=%T done=%s fixture=%s server_output=%s agent_transport={%s}",
			err, p118AllowlistedJSONDiagnostic(doneFile),
			p118AllowlistedJSONDiagnostic(evidenceFile),
			p118AllowlistedServerOutput(serverOutput.String()),
			p118TransportDiagnostic(client),
		)
	}
	if err := <-serverDone; err != nil {
		serverFinished = true
		t.Fatalf(
			"P1.18 Python fixture failed: %v output=%s agent_transport={%s}",
			err, serverOutput.String(), p118TransportDiagnostic(client),
		)
	}
	serverFinished = true
	assertP118HandoffEvidence(t, evidenceFile, scenario)
}

func waitForP118TextFileOrProcess(
	t *testing.T,
	path string,
	timeout time.Duration,
	output *p118SynchronizedBuffer,
	processDone <-chan error,
	processFinished *bool,
	client *FarmControlWSSClient,
	diagnosticPaths ...string,
) string {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-processDone:
			*processFinished = true
			t.Fatalf(
				"P1.18 fixture exited before publishing %s: %v output=%s diagnostics=%s agent_transport={%s}",
				filepath.Base(path), err, output.String(),
				p118AllowlistedJSONDiagnostics(diagnosticPaths...), p118TransportDiagnostic(client),
			)
			return ""
		case <-ticker.C:
			if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
				return strings.TrimSpace(string(raw))
			}
		case <-deadline.C:
			t.Fatalf(
				"P1.18 fixture did not publish %s: %s diagnostics=%s agent_transport={%s}",
				filepath.Base(path), output.String(),
				p118AllowlistedJSONDiagnostics(diagnosticPaths...), p118TransportDiagnostic(client),
			)
			return ""
		}
	}
}

func waitForP118TextFile(
	t *testing.T,
	path string,
	timeout time.Duration,
	output *p118SynchronizedBuffer,
	diagnosticPaths ...string,
) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf(
		"P1.18 fixture did not publish %s: %s diagnostics=%s",
		filepath.Base(path), output.String(), p118AllowlistedJSONDiagnostics(diagnosticPaths...),
	)
	return ""
}

func assertP118HandoffEvidence(t *testing.T, path, scenario string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	validate := validateP118HandoffEvidence
	if scenario == "crash_watcher" {
		validate = validateP118CrashEvidence
	} else if scenario == "execv" {
		validate = validateP118ExecvEvidence
	}
	if err := validate(raw); err != nil {
		t.Fatalf("invalid P1.18 handoff evidence: %v evidence=%s", err, raw)
	}
}

func validateP118HandoffEvidence(raw []byte) error {
	var evidence struct {
		Accepted, ControlDBCleanup, RuntimeLeaseReleased, RuntimeCreatedByEnsure bool
		ControllerAStopped, ControllerBTookOver, ChromeAliveDuringHandoff        bool
		OldCDPClosed, NewCDPConnected, NewCDPBasicIO, StrictStopConfirmed        bool
		Before, After                                                            p118HandoffIdentity
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	boolKeys := map[string]*bool{
		"accepted": &evidence.Accepted, "control_db_cleanup": &evidence.ControlDBCleanup,
		"runtime_lease_released": &evidence.RuntimeLeaseReleased, "runtime_created_by_ensure": &evidence.RuntimeCreatedByEnsure,
		"controller_a_stopped": &evidence.ControllerAStopped, "controller_b_took_over": &evidence.ControllerBTookOver,
		"chrome_alive_during_handoff": &evidence.ChromeAliveDuringHandoff, "old_cdp_closed": &evidence.OldCDPClosed,
		"new_cdp_connected": &evidence.NewCDPConnected, "new_cdp_basic_io": &evidence.NewCDPBasicIO,
		"strict_stop_confirmed": &evidence.StrictStopConfirmed,
	}
	for key, target := range boolKeys {
		if json.Unmarshal(wire[key], target) != nil || !*target {
			return fmt.Errorf("%s is missing or false", key)
		}
	}
	decodeIdentity := func(key string, target *p118HandoffIdentity) error {
		if err := json.Unmarshal(wire[key], target); err != nil {
			return fmt.Errorf("invalid %s identity: %w", key, err)
		}
		return nil
	}
	if err := decodeIdentity("before", &evidence.Before); err != nil {
		return err
	}
	if err := decodeIdentity("after", &evidence.After); err != nil {
		return err
	}
	if evidence.Before.RuntimeUID == "" || evidence.Before.Generation == 0 || evidence.Before.PID <= 0 || evidence.Before.ProcessStartIdentity == "" || evidence.Before.ProfileIncarnation == "" {
		return fmt.Errorf("before identity is incomplete")
	}
	if evidence.Before != evidence.After {
		return fmt.Errorf("runtime/process identity changed across handoff")
	}
	return nil
}

func TestP118HandoffEvidenceParserRejectsContradictions(t *testing.T) {
	identity := map[string]any{
		"runtime_uid": "runtime-1", "generation": float64(7), "pid": float64(4242),
		"process_start_identity": "start-4242", "profile_incarnation": "profile-incarnation-1",
	}
	valid := map[string]any{
		"accepted": true, "control_db_cleanup": true, "runtime_lease_released": true,
		"runtime_created_by_ensure": true, "controller_a_stopped": true, "controller_b_took_over": true,
		"chrome_alive_during_handoff": true, "old_cdp_closed": true, "new_cdp_connected": true,
		"new_cdp_basic_io": true, "strict_stop_confirmed": true,
		"before": identity, "after": map[string]any{
			"runtime_uid": "runtime-1", "generation": float64(7), "pid": float64(4242),
			"process_start_identity": "start-4242", "profile_incarnation": "profile-incarnation-1",
		},
	}
	encode := func(value map[string]any) []byte {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	if err := validateP118HandoffEvidence(encode(valid)); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "missing proof", mutate: func(value map[string]any) { delete(value, "runtime_created_by_ensure") }},
		{name: "false takeover", mutate: func(value map[string]any) { value["controller_b_took_over"] = false }},
		{name: "changed process", mutate: func(value map[string]any) { value["after"].(map[string]any)["process_start_identity"] = "replacement" }},
		{name: "missing incarnation", mutate: func(value map[string]any) { delete(value["before"].(map[string]any), "profile_incarnation") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			var mutated map[string]any
			if err := json.Unmarshal(encode(valid), &mutated); err != nil {
				t.Fatal(err)
			}
			test.mutate(mutated)
			if err := validateP118HandoffEvidence(encode(mutated)); err == nil {
				t.Fatal("contradictory evidence was accepted")
			}
		})
	}
}

func TestP118FailureDiagnosticsAreAllowlisted(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "failure.json")
	raw := []byte(`{"accepted":false,"failure_stage":"wait_successor_gateway","failure_type":"RuntimeError","scenario":"execv","stage":"production_startup","pid":4242,"boot_nonce":"image-a-nonce","runtime_db_status":"ready","runtime_db_provider":"farm","runtime_db_fencing_epoch":1,"controller_lease_acquired":true,"controller_generation":3,"controller_state":"active","watcher_reconciled":false,"watcher_adopted_runtime_count":0,"watcher_reconcile_status":"reconciled_no_adoption","watcher_controller_failure_type":"none","node_count":1,"error":"ws://127.0.0.1/private-token","controller_token":"secret"}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	diagnostic := p118AllowlistedJSONDiagnostic(path)
	if strings.Contains(diagnostic, "private-token") || strings.Contains(diagnostic, "secret") {
		t.Fatalf("failure JSON leaked a non-allowlisted value: %s", diagnostic)
	}
	if !strings.Contains(diagnostic, `"failure_stage":"wait_successor_gateway"`) {
		t.Fatalf("failure JSON omitted stage: %s", diagnostic)
	}
	for _, expected := range []string{
		`"scenario":"execv"`, `"stage":"production_startup"`, `"pid":4242`,
		`"boot_nonce":"image-a-nonce"`, `"runtime_db_status":"ready"`,
		`"runtime_db_provider":"farm"`, `"runtime_db_fencing_epoch":1`,
		`"controller_lease_acquired":true`, `"controller_generation":3`,
		`"controller_state":"active"`, `"watcher_reconciled":false`,
		`"watcher_adopted_runtime_count":0`,
		`"watcher_reconcile_status":"reconciled_no_adoption"`,
		`"watcher_controller_failure_type":"none"`, `"node_count":1`,
	} {
		if !strings.Contains(diagnostic, expected) {
			t.Fatalf("failure JSON omitted bounded fixture field %s: %s", expected, diagnostic)
		}
	}

	pathsDiagnostic := p118AllowlistedJSONDiagnostics(path, filepath.Join(directory, "missing.json"))
	if !strings.Contains(pathsDiagnostic, filepath.Base(path)+"=") ||
		strings.Contains(pathsDiagnostic, "missing.json") {
		t.Fatalf("bounded diagnostics included unavailable path or omitted evidence: %s", pathsDiagnostic)
	}
	serverDiagnostic := p118AllowlistedServerOutput(
		"sensitive raw failure ws://127.0.0.1/private-token\n" +
			"RuntimeError: Controller B failed stage=get_runtime_client error_type=FarmRuntimeControlError\n",
	)
	if strings.Contains(serverDiagnostic, "private-token") ||
		!strings.Contains(serverDiagnostic, "stage=get_runtime_client") {
		t.Fatalf("server diagnostic allowlist failed: %s", serverDiagnostic)
	}
}
