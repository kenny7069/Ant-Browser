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
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_18_handoff_fixture.py")
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
	controlURL := waitForP118TextFile(t, urlFile, 20*time.Second, &serverOutput)

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
		t, gatewayFile, 30*time.Second, &serverOutput, serverDone, &serverFinished,
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
		t.Fatalf("P1.18 Playwright handoff failed: %v output=%s", err, playwrightOutput.String())
	}
	if err := <-serverDone; err != nil {
		serverFinished = true
		t.Fatalf("P1.18 Python fixture failed: %v output=%s", err, serverOutput.String())
	}
	serverFinished = true
	assertP118HandoffEvidence(t, evidenceFile)
}

func waitForP118TextFileOrProcess(
	t *testing.T,
	path string,
	timeout time.Duration,
	output *p118SynchronizedBuffer,
	processDone <-chan error,
	processFinished *bool,
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
				"P1.18 fixture exited before publishing %s: %v output=%s",
				filepath.Base(path), err, output.String(),
			)
			return ""
		case <-ticker.C:
			if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
				return strings.TrimSpace(string(raw))
			}
		case <-deadline.C:
			t.Fatalf("P1.18 fixture did not publish %s: %s", filepath.Base(path), output.String())
			return ""
		}
	}
}

func waitForP118TextFile(t *testing.T, path string, timeout time.Duration, output *p118SynchronizedBuffer) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("P1.18 fixture did not publish %s: %s", filepath.Base(path), output.String())
	return ""
}

func assertP118HandoffEvidence(t *testing.T, path string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateP118HandoffEvidence(raw); err != nil {
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
