package backend

// P1.18 DB-ready/node-missing evidence and opt-in cross-repository runner.
// The Python fixture owns only the isolated Control DB and the two fresh
// production Controller processes.  This Go test owns the real Agent,
// BrowserRuntimeService, FarmRuntimeService, authenticated WSS client, and
// Chrome process so the fixture cannot manufacture an inventory or process
// identity result.

import (
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
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
)

const (
	p118NodeMissingStandardScenario = "db_ready_node_missing"
	p118NodeMissingRaceScenario     = "db_ready_node_missing_race"
)

var p118NodeMissingEvidenceKeys = map[string]struct{}{
	"accepted": {}, "running": {}, "actor": {}, "stage": {}, "scenario": {},
	"failure_stage": {}, "failure_type": {}, "control_db_cleanup": {},
	"controller_a_sigkill": {}, "controller_a_cleanup_skipped": {},
	"controller_a_pid": {}, "controller_a_generation": {}, "controller_b_pid": {},
	"controller_b_generation": {}, "controller_b_took_over": {},
	"controller_lease_acquired": {}, "controller_generation": {}, "controller_state": {},
	"production_startup_wiring": {}, "production_watcher_started": {},
	"watcher_reconciled": {}, "watcher_reconcile_attempts": {},
	"watcher_reconcile_status": {}, "reconcile_error_type": {}, "reconcile_outcomes": {},
	"runtime_created_by_ensure": {}, "runtime_persisted_by_authenticated_telemetry": {},
	"runtime_lease_acquired": {}, "target_node_offline": {}, "target_node_absent": {},
	"target_session_absent": {}, "node_exit_persisted": {},
	"chrome_alive_during_missing_handoff": {}, "runtime_db_status_before": {},
	"runtime_db_status_after": {}, "runtime_db_fencing_epoch_before": {},
	"runtime_db_fencing_epoch_after": {}, "missing_only_dispatched": {},
	"missing_only_inventory_requested": {}, "target_commands_before_reconnect": {},
	"target_commands_after_reconnect": {}, "cas_rejected": {}, "cas_rowcount": {},
	"next_tick_inventory_reconciled": {}, "next_tick_reconcile_outcome": {},
	"replacement_runtime": {}, "replacement_identity_stable": {},
	"target_connection_generation_before": {}, "target_connection_generation_after": {},
	"reconcile_case": {}, "reconcile_action": {}, "reconcile_status": {},
	"target_inventory_complete": {}, "target_inventory_count": {},
	"target_inventory_generation": {}, "before": {}, "after": {},
}

func p118IsNodeMissingScenario(scenario string) bool {
	return scenario == p118NodeMissingStandardScenario || scenario == p118NodeMissingRaceScenario
}

func p118NodeMissingRequiredBool(value map[string]json.RawMessage, key string) error {
	var item bool
	if raw, ok := value[key]; !ok || json.Unmarshal(raw, &item) != nil || !item {
		return fmt.Errorf("%s missing or false", key)
	}
	return nil
}

func p118NodeMissingRequiredInt(value map[string]json.RawMessage, key string, positive bool) (int64, error) {
	var item int64
	raw, ok := value[key]
	if !ok || json.Unmarshal(raw, &item) != nil || (positive && item <= 0) {
		return 0, fmt.Errorf("%s invalid", key)
	}
	return item, nil
}

func p118NodeMissingRequiredString(value map[string]json.RawMessage, key string) (string, error) {
	var item string
	raw, ok := value[key]
	if !ok || json.Unmarshal(raw, &item) != nil || strings.TrimSpace(item) == "" {
		return "", fmt.Errorf("%s invalid", key)
	}
	return item, nil
}

func p118NodeMissingIdentity(value map[string]json.RawMessage, key string) (p118HandoffIdentity, error) {
	raw, ok := value[key]
	if !ok {
		return p118HandoffIdentity{}, fmt.Errorf("%s missing", key)
	}
	var identity p118HandoffIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		return p118HandoffIdentity{}, fmt.Errorf("%s invalid", key)
	}
	if identity.RuntimeUID == "" || identity.Generation == 0 || identity.PID <= 0 ||
		identity.ProcessStartIdentity == "" || identity.ProfileIncarnation == "" {
		return p118HandoffIdentity{}, fmt.Errorf("%s incomplete", key)
	}
	return identity, nil
}

// validateP118NodeMissingEvidence accepts only the two explicit scenarios.
// It deliberately requires the failed missing-only CAS and the subsequent
// state, rather than treating a final DB status or a free-form success flag as
// proof.  No port, URL, token, password, or raw command/error field is part
// of the accepted evidence contract.
func validateP118NodeMissingEvidence(raw []byte) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	for key := range value {
		if _, ok := p118NodeMissingEvidenceKeys[key]; !ok {
			return fmt.Errorf("unexpected evidence key %q", key)
		}
	}
	scenario, err := p118NodeMissingRequiredString(value, "scenario")
	if err != nil || !p118IsNodeMissingScenario(scenario) {
		return fmt.Errorf("unsupported node-missing scenario")
	}
	for _, key := range []string{
		"accepted", "control_db_cleanup", "controller_a_sigkill", "controller_a_cleanup_skipped",
		"runtime_created_by_ensure", "runtime_persisted_by_authenticated_telemetry", "runtime_lease_acquired",
		"target_node_offline", "node_exit_persisted", "chrome_alive_during_missing_handoff",
		"controller_b_took_over", "production_startup_wiring", "production_watcher_started",
		"missing_only_dispatched",
	} {
		if err := p118NodeMissingRequiredBool(value, key); err != nil {
			return err
		}
	}
	aPID, err := p118NodeMissingRequiredInt(value, "controller_a_pid", true)
	if err != nil {
		return err
	}
	bPID, err := p118NodeMissingRequiredInt(value, "controller_b_pid", true)
	if err != nil || aPID == bPID {
		if err != nil {
			return err
		}
		return fmt.Errorf("controller process identities are not distinct")
	}
	aGeneration, err := p118NodeMissingRequiredInt(value, "controller_a_generation", true)
	if err != nil {
		return err
	}
	bGeneration, err := p118NodeMissingRequiredInt(value, "controller_b_generation", true)
	if err != nil || bGeneration <= aGeneration {
		if err != nil {
			return err
		}
		return fmt.Errorf("Controller B generation is not newer")
	}
	before, err := p118NodeMissingIdentity(value, "before")
	if err != nil {
		return err
	}
	after, err := p118NodeMissingIdentity(value, "after")
	if err != nil {
		return err
	}
	if before != after {
		return fmt.Errorf("Chrome process identity changed")
	}
	var inventoryRequested bool
	if raw, ok := value["missing_only_inventory_requested"]; !ok || json.Unmarshal(raw, &inventoryRequested) != nil || inventoryRequested {
		return fmt.Errorf("missing-only path requested inventory for the absent node")
	}
	var commandCount int64
	if raw, ok := value["target_commands_before_reconnect"]; !ok || json.Unmarshal(raw, &commandCount) != nil || commandCount != 0 {
		return fmt.Errorf("missing node received a command before reconnect")
	}
	var reconcileCase, reconcileAction, reconcileStatus, outcomes string
	for key, target := range map[string]*string{
		"reconcile_case": &reconcileCase, "reconcile_action": &reconcileAction,
		"reconcile_status": &reconcileStatus, "reconcile_outcomes": &outcomes,
	} {
		item, itemErr := p118NodeMissingRequiredString(value, key)
		if itemErr != nil {
			return itemErr
		}
		*target = item
	}
	if reconcileCase != "db_ready_node_missing" || reconcileAction != "mark_lost" {
		return fmt.Errorf("wrong reconcile case/action")
	}
	if scenario == p118NodeMissingStandardScenario {
		if reconcileStatus != "ok" || outcomes != "db_ready_node_missing:mark_lost:ok" {
			return fmt.Errorf("missing-node success outcome is not exact")
		}
		for key, want := range map[string]string{
			"runtime_db_status_after": "lost",
			"target_node_absent":      "true",
			"target_session_absent":   "true",
		} {
			if key == "runtime_db_status_after" {
				item, itemErr := p118NodeMissingRequiredString(value, key)
				if itemErr != nil || item != want {
					return fmt.Errorf("%s is not %q", key, want)
				}
				continue
			}
			var item bool
			if raw, ok := value[key]; !ok || json.Unmarshal(raw, &item) != nil || !item {
				return fmt.Errorf("%s missing or false", key)
			}
		}
		return nil
	}
	if reconcileStatus != "cas_rejected_then_adopted" || outcomes != "exact_match:adopt:ok" {
		return fmt.Errorf("race final outcome is not exact adopt")
	}
	for key := range map[string]bool{
		"cas_rejected": true, "next_tick_inventory_reconciled": true,
		"replacement_identity_stable": true, "target_inventory_complete": true,
	} {
		if err := p118NodeMissingRequiredBool(value, key); err != nil {
			return err
		}
	}
	var casRowcount int64
	if raw, ok := value["cas_rowcount"]; !ok || json.Unmarshal(raw, &casRowcount) != nil || casRowcount != 0 {
		return fmt.Errorf("race CAS rowcount was not zero")
	}
	var replacementRuntime bool
	if raw, ok := value["replacement_runtime"]; !ok || json.Unmarshal(raw, &replacementRuntime) != nil || replacementRuntime {
		return fmt.Errorf("race reported a replacement runtime")
	}
	var inventoryGeneration int64
	if raw, ok := value["target_inventory_generation"]; !ok || json.Unmarshal(raw, &inventoryGeneration) != nil || inventoryGeneration <= 0 {
		return fmt.Errorf("race inventory generation invalid")
	}
	var dbStatus string
	if dbStatus, err = p118NodeMissingRequiredString(value, "runtime_db_status_after"); err != nil || (dbStatus != "ready" && dbStatus != "idle" && dbStatus != "attached") {
		return fmt.Errorf("race runtime status is not active")
	}
	return nil
}

func TestP118NodeMissingEvidenceContract(t *testing.T) {
	identity := map[string]any{
		"runtime_uid": "runtime", "generation": 7, "pid": 4242,
		"process_start_identity": "start", "profile_incarnation": "incarnation",
	}
	baseline := func(scenario string) map[string]any {
		value := map[string]any{
			"accepted": true, "control_db_cleanup": true, "scenario": scenario,
			"controller_a_sigkill": true, "controller_a_cleanup_skipped": true,
			"controller_a_pid": 100, "controller_b_pid": 101,
			"controller_a_generation": 1, "controller_b_generation": 2,
			"runtime_created_by_ensure": true, "runtime_persisted_by_authenticated_telemetry": true,
			"runtime_lease_acquired": true, "target_node_offline": true,
			"node_exit_persisted": true, "chrome_alive_during_missing_handoff": true,
			"controller_b_took_over": true, "production_startup_wiring": true,
			"production_watcher_started": true, "missing_only_dispatched": true,
			"missing_only_inventory_requested": false, "target_commands_before_reconnect": 0,
			"reconcile_case": "db_ready_node_missing", "reconcile_action": "mark_lost",
			"before": identity, "after": identity,
		}
		if scenario == p118NodeMissingStandardScenario {
			value["reconcile_status"] = "ok"
			value["reconcile_outcomes"] = "db_ready_node_missing:mark_lost:ok"
			value["runtime_db_status_after"] = "lost"
			value["target_node_absent"] = true
			value["target_session_absent"] = true
		} else {
			value["reconcile_status"] = "cas_rejected_then_adopted"
			value["reconcile_outcomes"] = "exact_match:adopt:ok"
			value["cas_rejected"] = true
			value["cas_rowcount"] = 0
			value["next_tick_inventory_reconciled"] = true
			value["replacement_runtime"] = false
			value["replacement_identity_stable"] = true
			value["target_inventory_complete"] = true
			value["target_inventory_generation"] = 9
			value["runtime_db_status_after"] = "idle"
		}
		return value
	}
	for _, scenario := range []string{p118NodeMissingStandardScenario, p118NodeMissingRaceScenario} {
		raw, err := json.Marshal(baseline(scenario))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateP118NodeMissingEvidence(raw); err != nil {
			t.Fatalf("baseline %s rejected: %v", scenario, err)
		}
	}
	mutations := []struct {
		name string
		edit func(map[string]any)
	}{
		{"missing-only dispatch removed", func(value map[string]any) { value["missing_only_dispatched"] = false }},
		{"CAS0 reported success", func(value map[string]any) { value["cas_rowcount"] = 1 }},
		{"replacement identity changed", func(value map[string]any) {
			value["after"] = map[string]any{"runtime_uid": "replacement", "generation": 8, "pid": 4242, "process_start_identity": "start", "profile_incarnation": "incarnation"}
		}},
		{"raw secret field", func(value map[string]any) { value["controller_token"] = "secret" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			value := baseline(p118NodeMissingRaceScenario)
			mutation.edit(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateP118NodeMissingEvidence(raw); err == nil {
				t.Fatalf("mutation %q was accepted", mutation.name)
			}
		})
	}
}

func TestP118NodeMissingFixtureTerminationReapsProcessGroup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	childPIDFile := filepath.Join(t.TempDir(), "child.pid")
	command := exec.CommandContext(
		ctx,
		"sh",
		"-c",
		`trap 'kill "$child" 2>/dev/null; wait "$child" 2>/dev/null; exit 0' TERM; sleep 60 & child=$!; echo "$child" > "$1"; wait "$child"`,
		"p118-node-fixture",
		childPIDFile,
	)
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	var childPID int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(childPIDFile)
		if err == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(raw)))
			if err == nil && childPID > 0 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID <= 0 {
		cancel()
		t.Fatal("fixture child process did not start")
	}
	p118TerminateNodeMissingFixture(command, done, cancel)
	if command.ProcessState == nil || !command.ProcessState.Exited() {
		t.Fatal("fixture parent process was not reaped")
	}
	if err := syscall.Kill(childPID, 0); err == nil {
		t.Fatal("fixture child process survived parent teardown")
	}
}

func p118Write0600(t *testing.T, path string, value []byte) {
	t.Helper()
	if err := os.WriteFile(path, value, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
}

func p118ReadNodeMissingState(t *testing.T, path string) map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func p118NodeMissingStage(value map[string]json.RawMessage) string {
	var stage string
	if json.Unmarshal(value["stage"], &stage) != nil {
		return ""
	}
	return stage
}

func p118WaitNodeMissingStage(
	t *testing.T,
	path string,
	process *exec.Cmd,
	stage string,
	deadline time.Time,
	output *p118SynchronizedBuffer,
	diagnosticPaths ...string,
) map[string]json.RawMessage {
	t.Helper()
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			value := p118ReadNodeMissingState(t, path)
			if p118NodeMissingStage(value) == stage {
				return value
			}
			var running bool
			if json.Unmarshal(value["running"], &running) == nil && !running {
				t.Fatalf(
					"fixture failed before %s: output=%s diagnostics=%s",
					stage, p118AllowlistedServerOutput(output.String()),
					p118AllowlistedJSONDiagnostics(diagnosticPaths...),
				)
			}
		}
		if process != nil && process.ProcessState != nil && process.ProcessState.Exited() {
			t.Fatalf(
				"fixture exited before %s: output=%s diagnostics=%s",
				stage, p118AllowlistedServerOutput(output.String()),
				p118AllowlistedJSONDiagnostics(diagnosticPaths...),
			)
		}
		time.Sleep(30 * time.Millisecond)
	}
	t.Fatalf(
		"timed out waiting for fixture stage %s: output=%s diagnostics=%s",
		stage, p118AllowlistedServerOutput(output.String()),
		p118AllowlistedJSONDiagnostics(diagnosticPaths...),
	)
	return nil
}

func p118FarmProcessIdentity(t *testing.T, farm *FarmRuntimeService, profileID string) p118HandoffIdentity {
	t.Helper()
	record, owned := farm.currentRecord(profileID)
	if !owned {
		t.Fatal("Agent Farm service lost its owned runtime record")
	}
	snapshot, err := farm.snapshot(profileID)
	if err != nil || snapshot == nil || snapshot.Profile == nil || !snapshot.Profile.Running || !snapshot.Profile.DebugReady {
		t.Fatalf("Agent Chrome is not alive/ready after node loss: snapshot=%#v err=%v", snapshot, err)
	}
	runtime := farmRuntimeFromSnapshot(record, snapshot)
	identity := p118HandoffIdentity{
		RuntimeUID: runtime.RuntimeUID, Generation: runtime.Generation, PID: runtime.PID,
		ProcessStartIdentity: runtime.ProcessStartIdentity,
		ProfileIncarnation:   runtime.ProfileIncarnation,
	}
	if identity.RuntimeUID == "" || identity.Generation == 0 || identity.PID <= 0 || identity.ProcessStartIdentity == "" || identity.ProfileIncarnation == "" {
		t.Fatal("Agent Chrome identity is incomplete")
	}
	if err := syscall.Kill(identity.PID, 0); err != nil {
		t.Fatalf("Agent Chrome process is not alive: %v", err)
	}
	return identity
}

func p118TerminateNodeMissingFixture(command *exec.Cmd, done <-chan error, cancel context.CancelFunc) {
	if cancel != nil {
		defer cancel()
	}
	if command == nil || command.Process == nil {
		return
	}
	if command.ProcessState != nil && command.ProcessState.Exited() {
		return
	}
	_ = command.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
		return
	case <-time.After(5 * time.Second):
	}
	if cancel != nil {
		cancel()
	}
	// The Python fixture owns Controller A/B children.  If its bounded SIGTERM
	// cleanup cannot finish, kill the isolated process group so no child can
	// survive a Go test failure.  The normal path still lets the Python parent
	// verify its ownership marker and drop the unique schema first.
	_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
	_ = command.Process.Kill()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

func runP118NodeMissingScenario(t *testing.T, scenario string) {
	t.Helper()
	if !p118IsNodeMissingScenario(scenario) {
		t.Fatalf("unsupported node-missing scenario %q", scenario)
	}
	serverRepo := os.Getenv("P118_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/Desktop/p18-acceptance-docs"
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_18_node_missing_fixture.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("missing-node fixture unavailable: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeUID     = "node-p118-missing"
		providerID  = "provider-p118-missing"
		profileID   = "118901"
		controllerA = "controller-p118-missing-a"
		controllerB = "controller-p118-missing-b"
	)
	root := t.TempDir()
	urlFile := filepath.Join(root, "controller-a.url")
	bURLFile := filepath.Join(root, "controller-b.url")
	evidenceFile := filepath.Join(root, "p118-node-missing-evidence.json")
	aStateFile := filepath.Join(root, "controller-a.json")
	bStateFile := filepath.Join(root, "controller-b.json")
	nodeExitFile := filepath.Join(root, "node-exit.request")
	agentAfterFile := filepath.Join(root, "agent-after.json")
	caFile := filepath.Join(root, "p118-ca.pem")
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	controlDBName := fmt.Sprintf("bf_p118_missing_%x", time.Now().UnixNano())

	serverCtx, cancelServer := context.WithTimeout(context.Background(), 120*time.Second)
	serverArgs := []string{
		"--scenario", scenario,
		"--url-file", urlFile,
		"--b-url-file", bURLFile,
		"--evidence-file", evidenceFile,
		"--ca-file", caFile,
		"--node-uid", nodeUID,
		"--public-key", publicKey,
		"--profile-id", profileID,
		"--provider-instance-id", providerID,
		"--fencing-epoch", "1",
		"--controller-a-id", controllerA,
		"--controller-b-id", controllerB,
		"--node-exit-request-file", nodeExitFile,
		"--agent-after-file", agentAfterFile,
		"--a-state-file", aStateFile,
		"--b-state-file", bStateFile,
		"--timeout", "110",
	}
	serverCommand := exec.CommandContext(serverCtx, "python3", append([]string{fixtureScript}, serverArgs...)...)
	serverCommand.Env = append(os.Environ(), "SCRAPER_CONTROL_DB_NAME="+controlDBName)
	serverCommand.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var serverOutput p118SynchronizedBuffer
	serverCommand.Stdout, serverCommand.Stderr = &serverOutput, &serverOutput
	if err := serverCommand.Start(); err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan error, 1)
	go func() { serverDone <- serverCommand.Wait() }()
	serverFinished := false
	defer p118TerminateNodeMissingFixture(serverCommand, serverDone, cancelServer)
	controlURL := waitForP118TextFileOrProcess(t, urlFile, 20*time.Second, &serverOutput, serverDone, &serverFinished, nil, evidenceFile, aStateFile, bStateFile)

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
		ProfileId: profileID, ProfileName: "P1.18 node missing isolated", CoreId: "chrome",
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
	keyDigest := sha256.Sum256(privateKey)
	ownershipStore, err := NewFileFarmRuntimeOwnershipStore(filepath.Join(root, "farm-ownership.json"), keyDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	farm, err := NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: service, NodeUID: nodeUID, ProviderInstanceID: providerID,
		FencingEpoch: 1, ControllerID: controllerA, ControllerGeneration: 1,
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
		t.Fatal("invalid missing-node test CA")
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 15 * time.Second,
		HeartbeatInterval: 200 * time.Millisecond, AutoReconnect: false,
		Dialer: &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(nil); err != nil {
		t.Fatalf("real Agent authenticated connect failed: %v", err)
	}
	defer client.Close()
	fixtureDeadline := time.Now().Add(110 * time.Second)
	aState := p118WaitNodeMissingStage(
		t, aStateFile, serverCommand, "ready_for_node_exit", fixtureDeadline,
		&serverOutput, evidenceFile, aStateFile, bStateFile,
	)
	client.Close()
	p118Write0600(t, nodeExitFile, []byte("close-agent-session\n"))
	p118WaitNodeMissingStage(
		t, aStateFile, serverCommand, "ready_for_sigkill", fixtureDeadline,
		&serverOutput, evidenceFile, aStateFile, bStateFile,
	)

	var replacementClient *FarmControlWSSClient
	if scenario == p118NodeMissingRaceScenario {
		p118WaitNodeMissingStage(
			t, bStateFile, serverCommand, "race_offline_snapshot", fixtureDeadline,
			&serverOutput, evidenceFile, aStateFile, bStateFile,
		)
		bURLRaw, err := os.ReadFile(bURLFile)
		if err != nil {
			t.Fatal(err)
		}
		replacementClient, err = NewFarmControlWSSClient(FarmControlWSSClientConfig{
			URL: strings.TrimSpace(string(bURLRaw)), NodeUID: nodeUID, PrivateKey: privateKey,
			HandshakeTimeout: 5 * time.Second, CommandTimeout: 15 * time.Second,
			HeartbeatInterval: 200 * time.Millisecond, AutoReconnect: false,
			Dialer: &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
		}, adapter)
		if err != nil {
			t.Fatal(err)
		}
		if err := replacementClient.Connect(nil); err != nil {
			t.Fatalf("real Agent N+1 reconnect failed: %v", err)
		}
		defer replacementClient.Close()
		p118WaitNodeMissingStage(
			t, bStateFile, serverCommand, "race_generation_ready", fixtureDeadline,
			&serverOutput, evidenceFile, aStateFile, bStateFile,
		)
	}
	p118WaitNodeMissingStage(
		t, bStateFile, serverCommand, "await_agent_identity_after", fixtureDeadline,
		&serverOutput, evidenceFile, aStateFile, bStateFile,
	)
	after := p118FarmProcessIdentity(t, farm, profileID)
	beforeRaw, ok := aState["before"]
	if !ok {
		t.Fatal("Controller A did not publish process identity")
	}
	var before p118HandoffIdentity
	if err := json.Unmarshal(beforeRaw, &before); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("Chrome identity changed: before=%+v after=%+v", before, after)
	}
	p118Write0600(t, agentAfterFile, mustJSON(after))
	if err := <-serverDone; err != nil {
		t.Fatalf("missing-node fixture failed: %v output=%s diagnostics=%s", err, p118AllowlistedServerOutput(serverOutput.String()), p118AllowlistedJSONDiagnostics(evidenceFile, aStateFile, bStateFile))
	}
	serverFinished = true
	evidence, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateP118NodeMissingEvidence(evidence); err != nil {
		t.Fatalf("missing-node evidence rejected: %v diagnostics=%s", err, p118AllowlistedJSONDiagnostic(evidenceFile))
	}
	info, err := os.Stat(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence mode=%o, want 0600", info.Mode().Perm())
	}
}

func mustJSON(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return encoded
}
