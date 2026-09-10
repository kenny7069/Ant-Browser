//go:build !windows

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
		"watcher_reconcile_attempts", "watcher_reconciled_connection_count",
		"runtime_lease_state", "runtime_lease_fencing_epoch",
		"runtime_lease_expires_remaining_seconds", "runtime_lease_read_error_type",
		"runtime_db_read_error_type",
		// Reconcile-stop progress is restricted to enum-like strings, booleans,
		// and typed counters. Identity objects and arbitrary error text remain
		// excluded from diagnostics.
		"controller_a_pid", "controller_b_pid", "controller_a_generation", "controller_b_generation",
		"controller_a_exit_signal", "runtime_process_identity_observed", "chrome_alive_before_stop",
		"quarantine_sent", "stop_sent", "quarantine_stop_confirmed",
		"command_observer_installed", "command_observation_count", "command_observation_order",
		"quarantine_command_observed", "quarantine_ack_observed", "stop_command_observed", "stop_ack_observed",
		"quarantine_request_identity_match", "stop_request_identity_match", "quarantine_stop_order_confirmed",
		"agent_inventory_runtime_stopped", "agent_inventory_pid_zero",
		"agent_inventory_process_identity_preserved", "agent_inventory_profile_incarnation_preserved",
		"agent_inventory_no_replacement", "agent_inventory_original_runtime_count",
		"replacement_runtime_count", "original_pid_absent", "runtime_db_row_present_before",
		"runtime_db_row_absent", "runtime_db_contradiction_preserved",
		"stale_epoch_mutation_applied", "unknown_runtime_delete_applied",
		"mutation_applied", "mutation_rowcount", "runtime_db_fencing_epoch_before",
		"runtime_db_fencing_epoch_after", "reconcile_case", "reconcile_action", "reconcile_status",
		"inventory_dispatch_attempts", "inventory_list_online", "inventory_list_generation",
		"inventory_auth_binding_generation", "inventory_sample_generation",
		"inventory_heartbeat_age_ms", "inventory_dispatch_error_type",
		"inventory_response_ok", "inventory_count",
		"configured_handoff_ttl_seconds", "execv_elapsed_seconds",
		// DB-ready/node-missing evidence is deliberately limited to enum-like
		// status, session-generation, command-count, and process-identity
		// projections.  Never pass URLs, ports, tokens, or raw errors through
		// the parent diagnostic path.
		"target_node_offline", "target_node_absent", "target_session_absent",
		"target_commands_before_reconnect", "target_commands_after_reconnect",
		"node_exit_persisted", "controller_a_sigkill", "controller_a_cleanup_skipped",
		"chrome_alive_during_missing_handoff", "runtime_db_status_before", "runtime_db_status_after",
		"runtime_db_fencing_epoch_before", "runtime_db_fencing_epoch_after",
		"missing_only_dispatched", "missing_only_inventory_requested",
		"cas_rejected", "cas_rowcount", "next_tick_inventory_reconciled",
		"next_tick_reconcile_outcome", "replacement_runtime", "replacement_identity_stable",
		"target_connection_generation_before", "target_connection_generation_after",
		"target_inventory_complete", "target_inventory_count", "target_inventory_generation",
		"before", "after",
		// Config-mismatch evidence is restricted to the authenticated command
		// projection, owner-scoped hash mutation, and fresh process identity.
		"controller_a_crashed", "controller_a_exit_signal", "controller_b_started_fresh_process",
		"runtime_process_identity_observed", "command_observer_installed", "command_observation_count",
		"reconcile_command_observed", "reconcile_ack_observed", "reconcile_request_identity_match",
		"reconcile_target_config_match", "reconcile_target_launch_mode_match",
		"replacement_ack_identity_valid", "replacement_same_node", "replacement_runtime_uid_changed",
		"replacement_generation_advanced", "replacement_pid_changed", "replacement_process_start_changed",
		"replacement_profile_incarnation_preserved", "old_process_identity_absent", "mutation_applied",
		"mutation_rowcount", "mutation_owner_scoped", "mutation_after_controller_a_exit",
		"runtime_db_old_hash_before", "runtime_db_target_hash_after",
		"replacement_persisted_by_authenticated_telemetry", "replacement_db_row_present",
		"replacement_db_target_hash", "replacement_db_status", "replacement_db_identity_match",
		"replacement_agent_inventory_match", "replacement_strict_stop_confirmed", "replacement_exact_adopted",
		"old_runtime_marked_lost", "replacement_lease_held_by_controller_b", "old_lease_not_successor",
		"runtime_lease_released", "controller_b_cleanup",
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

type p118ScenarioBudget struct {
	serverTimeout           time.Duration
	playwrightTimeout       time.Duration
	fixtureTimeout          time.Duration
	successorGatewayTimeout time.Duration
}

func p118TimeoutSeconds(duration time.Duration) string {
	return fmt.Sprint(int64(duration / time.Second))
}

func TestP118TimeoutArgumentUsesNumericSeconds(t *testing.T) {
	for duration, expected := range map[time.Duration]string{180 * time.Second: "180", 150 * time.Second: "150"} {
		if actual := p118TimeoutSeconds(duration); actual != expected {
			t.Fatalf("duration %v serialized as %q, want %q", duration, actual, expected)
		}
	}
}

func p118ScenarioBudgetFor(scenario string) (p118ScenarioBudget, error) {
	switch scenario {
	case "execv":
		return p118ScenarioBudget{
			serverTimeout:           210 * time.Second,
			playwrightTimeout:       180 * time.Second,
			fixtureTimeout:          180 * time.Second,
			successorGatewayTimeout: 150 * time.Second,
		}, nil
	case "", "graceful", "crash_watcher":
		// Keep the existing graceful/crash budgets and the Playwright client's
		// default 20-second successor wait.  These scenarios must not inherit
		// execv-only command-line overrides.
		return p118ScenarioBudget{
			serverTimeout:     120 * time.Second,
			playwrightTimeout: 60 * time.Second,
		}, nil
	case "stale_epoch_stop", "unknown_runtime_stop":
		// Stop fixtures do not launch a Playwright client or wait for a gateway.
		// Keep the existing 120-second server budget and deliberately leave both
		// the Playwright and successor-gateway budgets disabled.
		return p118ScenarioBudget{serverTimeout: 120 * time.Second}, nil
	case "db_ready_node_missing":
		return p118ScenarioBudget{serverTimeout: 200 * time.Second, fixtureTimeout: 180 * time.Second}, nil
	case "db_ready_node_missing_race":
		return p118ScenarioBudget{serverTimeout: 200 * time.Second, fixtureTimeout: 180 * time.Second}, nil
	case "config_mismatch_restart":
		return p118ScenarioBudget{serverTimeout: 180 * time.Second, fixtureTimeout: 180 * time.Second}, nil
	default:
		return p118ScenarioBudget{}, fmt.Errorf("unsupported P1.18 scenario budget: %q", scenario)
	}
}

func TestP118ScenarioBudgetMapping(t *testing.T) {
	execv, err := p118ScenarioBudgetFor("execv")
	if err != nil {
		t.Fatal(err)
	}
	wantExecv := p118ScenarioBudget{
		serverTimeout:           210 * time.Second,
		playwrightTimeout:       180 * time.Second,
		fixtureTimeout:          180 * time.Second,
		successorGatewayTimeout: 150 * time.Second,
	}
	if execv != wantExecv {
		t.Fatalf("execv budget = %#v, want %#v", execv, wantExecv)
	}
	for _, scenario := range []string{"", "graceful", "crash_watcher"} {
		budget, err := p118ScenarioBudgetFor(scenario)
		if err != nil {
			t.Fatal(err)
		}
		want := p118ScenarioBudget{serverTimeout: 120 * time.Second, playwrightTimeout: 60 * time.Second}
		if budget != want {
			t.Fatalf("scenario %q budget = %#v, want %#v", scenario, budget, want)
		}
	}
	for _, scenario := range []string{"stale_epoch_stop", "unknown_runtime_stop"} {
		budget, err := p118ScenarioBudgetFor(scenario)
		if err != nil {
			t.Fatal(err)
		}
		want := p118ScenarioBudget{serverTimeout: 120 * time.Second}
		if budget != want {
			t.Fatalf("stop scenario %q budget = %#v, want %#v", scenario, budget, want)
		}
	}
	for _, scenario := range []string{"db_ready_node_missing", "db_ready_node_missing_race"} {
		budget, err := p118ScenarioBudgetFor(scenario)
		if err != nil {
			t.Fatal(err)
		}
		want := p118ScenarioBudget{serverTimeout: 200 * time.Second, fixtureTimeout: 180 * time.Second}
		if budget != want {
			t.Fatalf("node-missing scenario %q budget = %#v, want %#v", scenario, budget, want)
		}
	}
	configMismatch, err := p118ScenarioBudgetFor("config_mismatch_restart")
	if err != nil {
		t.Fatal(err)
	}
	wantConfigMismatch := p118ScenarioBudget{serverTimeout: 180 * time.Second, fixtureTimeout: 180 * time.Second}
	if configMismatch != wantConfigMismatch {
		t.Fatalf("config mismatch budget = %#v, want %#v", configMismatch, wantConfigMismatch)
	}
	if _, err := p118ScenarioBudgetFor("unsupported"); err == nil {
		t.Fatal("unsupported scenario budget was accepted")
	}
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
		marker := "Controller B failed"
		if !strings.Contains(line, marker) {
			continue
		}
		fields := []string{marker}
		for _, field := range strings.Fields(line[strings.Index(line, marker)+len(marker):]) {
			if !strings.HasPrefix(field, "stage=") && !strings.HasPrefix(field, "error_type=") {
				continue
			}
			value := strings.TrimPrefix(strings.TrimPrefix(field, "stage="), "error_type=")
			if value == "" || len(value) > 96 {
				continue
			}
			valid := true
			for _, character := range value {
				if !((character >= 'a' && character <= 'z') ||
					(character >= 'A' && character <= 'Z') ||
					(character >= '0' && character <= '9') || character == '_' || character == '-' || character == '.') {
					valid = false
					break
				}
			}
			if valid {
				if strings.HasPrefix(field, "stage=") {
					fields = append(fields, "stage="+value)
				} else {
					fields = append(fields, "error_type="+value)
				}
			}
		}
		if len(fields) > 1 {
			lines = append(lines, strings.Join(fields, " "))
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
	if scenario == "db_ready_node_missing" || scenario == "db_ready_node_missing_race" {
		runP118NodeMissingScenario(t, scenario)
		return
	}
	if scenario == "config_mismatch_restart" {
		runP118ConfigMismatchScenario(t, scenario)
		return
	}
	stopScenario := p118StopScenario(scenario)
	fixtureName, err := p118ScenarioFixture(scenario)
	if err != nil {
		t.Fatal(err)
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", fixtureName)
	playwrightScript := filepath.Join(serverRepo, "輔助程式", "p1_18_playwright_client.py")
	dependencies := []string{fixtureScript}
	if !stopScenario {
		dependencies = append(dependencies, playwrightScript)
	}
	for _, path := range dependencies {
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
	budgets, err := p118ScenarioBudgetFor(scenario)
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithTimeout(context.Background(), budgets.serverTimeout)
	defer stopServer()
	controlDBName := fmt.Sprintf("bf_p118_%x", time.Now().UnixNano())
	serverArgs := []string{
		"--url-file", urlFile, "--evidence-file", evidenceFile,
		"--ca-file", caFile, "--node-uid", nodeUID,
		"--public-key", publicKey, "--profile-id", profileID,
		"--provider-instance-id", providerID, "--fencing-epoch", fmt.Sprint(fencingEpoch),
		"--controller-a-id", controllerA, "--controller-b-id", controllerB,
	}
	if stopScenario {
		// The reconcile-stop fixture has its own bounded CLI and deliberately
		// does not accept gateway, CDP, or Playwright marker paths.
		serverArgs = append([]string{"--scenario", scenario}, serverArgs...)
	} else {
		serverArgs = append(serverArgs,
			"--gateway-file", gatewayFile,
			"--reattach-request-file", reattachRequestFile,
			"--old-cdp-closed-file", oldCDPClosedFile,
			"--reattach-gateway-file", reattachGatewayFile,
			"--done-file", doneFile,
		)
	}
	serverCommand := exec.CommandContext(serverCtx, "python3", append([]string{fixtureScript}, serverArgs...)...)
	if budgets.fixtureTimeout > 0 {
		serverCommand.Args = append(serverCommand.Args, "--timeout", p118TimeoutSeconds(budgets.fixtureTimeout))
	}
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
	if stopScenario {
		// Controller B's stop commands are sent only after A has ensured the
		// runtime. Capture the Agent-owned running identity before B takes over;
		// the post-fixture assertion below uses a fresh InventoryWithError call
		// rather than trusting Python's projection booleans.
		beforeInventory := waitForP118RunningFarmInventory(t, farm, profileID, 30*time.Second)
		commandObservation := newP118StopCommandObservation(farm, profileID, beforeInventory)
		farm.handoffValidationHook = commandObservation.observe
		if err := waitForP118FixtureCompletion(
			t, budgets.serverTimeout, &serverOutput, serverDone, &serverFinished, client,
			evidenceFile, evidenceFile+".controller-a-progress.json", evidenceFile+".controller-b-progress.json",
		); err != nil {
			t.Fatalf(
				"P1.18 reconcile-stop fixture failed: %v output=%s diagnostics=%s agent_transport={%s}",
				err, p118AllowlistedServerOutput(serverOutput.String()), p118AllowlistedJSONDiagnostics(
					evidenceFile, evidenceFile+".controller-a-progress.json", evidenceFile+".controller-b-progress.json",
				), p118TransportDiagnostic(client),
			)
		}
		assertP118HandoffEvidence(t, evidenceFile, scenario)
		assertP118StopCommandObservation(t, commandObservation, beforeInventory)
		assertP118StoppedFarmInventory(t, farm, beforeInventory)
		return
	}
	waitForP118TextFileOrProcess(
		t, gatewayFile, 30*time.Second, &serverOutput, serverDone, &serverFinished, client,
	)
	playwrightCtx, cancelPlaywright := context.WithTimeout(context.Background(), budgets.playwrightTimeout)
	defer cancelPlaywright()
	playwright := exec.CommandContext(playwrightCtx, "python3", playwrightScript,
		"--gateway-file", gatewayFile, "--reattach-request-file", reattachRequestFile,
		"--old-cdp-closed-file", oldCDPClosedFile,
		"--reattach-gateway-file", reattachGatewayFile, "--done-file", doneFile)
	if budgets.successorGatewayTimeout > 0 {
		playwright.Args = append(playwright.Args, "--successor-gateway-timeout", p118TimeoutSeconds(budgets.successorGatewayTimeout))
	}
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
			err, p118AllowlistedServerOutput(serverOutput.String()), p118TransportDiagnostic(client),
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
				filepath.Base(path), err, p118AllowlistedServerOutput(output.String()),
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
				filepath.Base(path), p118AllowlistedServerOutput(output.String()),
				p118AllowlistedJSONDiagnostics(diagnosticPaths...), p118TransportDiagnostic(client),
			)
			return ""
		}
	}
}

func waitForP118FixtureCompletion(
	t *testing.T,
	timeout time.Duration,
	output *p118SynchronizedBuffer,
	processDone <-chan error,
	processFinished *bool,
	client *FarmControlWSSClient,
	diagnosticPaths ...string,
) error {
	t.Helper()
	if timeout <= 0 {
		return fmt.Errorf("P1.18 fixture completion timeout must be positive")
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-processDone:
		*processFinished = true
		return err
	case <-timer.C:
		t.Fatalf(
			"P1.18 fixture did not finish within %s: output=%s diagnostics=%s agent_transport={%s}",
			timeout, p118AllowlistedServerOutput(output.String()), p118AllowlistedJSONDiagnostics(diagnosticPaths...), p118TransportDiagnostic(client),
		)
		return context.DeadlineExceeded
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
		filepath.Base(path), p118AllowlistedServerOutput(output.String()), p118AllowlistedJSONDiagnostics(diagnosticPaths...),
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
	} else if p118StopScenario(scenario) {
		validate = validateP118StopEvidence
	}
	if err := validate(raw); err != nil {
		t.Fatalf("invalid P1.18 handoff evidence: %v evidence=%s", err, p118AllowlistedJSONDiagnostic(path))
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
