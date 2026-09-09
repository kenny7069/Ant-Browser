//go:build !windows

package backend

// P1.18 config-mismatch evidence contract.  The validator is intentionally
// independent from the long-running cross-repository runner: it accepts only
// typed projections proving the production reconcile_runtime request/ACK,
// authenticated target config persistence, and the fresh replacement adopt.

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
	"strings"
	"syscall"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"github.com/gorilla/websocket"
)

const (
	p118ConfigMismatchScenario = "config_mismatch_restart"
	p118ConfigMismatchOldHash  = "1111111111111111111111111111111111111111111111111111111111111111"
	p118ConfigMismatchNewHash  = "2222222222222222222222222222222222222222222222222222222222222222"
	p118ConfigFixtureTimeout   = 170 * time.Second
	p118ConfigServerTimeout    = 190 * time.Second
)

var p118ConfigMismatchEvidenceKeys = map[string]struct{}{
	"accepted": {}, "running": {}, "actor": {}, "stage": {}, "failure_stage": {},
	"failure_type": {}, "scenario": {}, "identity": {}, "before": {}, "after": {},
	"controller_a_pid": {}, "controller_a_generation": {}, "controller_a_crashed": {},
	"controller_a_exit_signal": {}, "controller_a_cleanup_skipped": {},
	"controller_b_pid": {}, "controller_b_generation": {},
	"controller_b_started_fresh_process": {}, "controller_b_took_over": {},
	"runtime_created_by_ensure": {}, "runtime_persisted_by_authenticated_telemetry": {},
	"runtime_lease_acquired": {}, "runtime_process_identity_observed": {},
	"production_startup_wiring": {}, "production_watcher_started": {},
	"watcher_reconciled": {}, "reconcile_outcomes": {}, "reconcile_case": {},
	"reconcile_action": {}, "reconcile_status": {}, "command_observer_installed": {},
	"command_observation_count": {}, "reconcile_command_observed": {},
	"reconcile_ack_observed": {}, "reconcile_request_identity_match": {},
	"reconcile_target_config_match": {}, "reconcile_target_launch_mode_match": {},
	"replacement_ack_identity_valid": {}, "replacement_same_node": {},
	"replacement_runtime_uid_changed": {}, "replacement_generation_advanced": {},
	"replacement_pid_changed": {}, "replacement_process_start_changed": {},
	"replacement_profile_incarnation_preserved": {}, "old_process_identity_absent": {},
	"mutation_applied": {}, "mutation_rowcount": {}, "mutation_owner_scoped": {},
	"mutation_after_controller_a_exit": {}, "runtime_db_old_hash_before": {},
	"runtime_db_target_hash_after": {}, "replacement_persisted_by_authenticated_telemetry": {},
	"replacement_db_row_present": {}, "replacement_db_target_hash": {},
	"replacement_db_status": {}, "replacement_db_identity_match": {},
	"replacement_agent_inventory_match": {}, "replacement_strict_stop_confirmed": {},
	"replacement_exact_adopted": {}, "old_runtime_marked_lost": {},
	"replacement_lease_held_by_controller_b": {}, "old_lease_not_successor": {},
	"runtime_lease_released": {}, "controller_b_cleanup": {}, "control_db_cleanup": {},
}

type p118ConfigRuntimeIdentity struct {
	NodeUID            string `json:"node_uid"`
	ProfileID          string `json:"profile_id"`
	RuntimeUID         string `json:"runtime_uid"`
	ProviderInstanceID string `json:"provider_instance_id"`
	FencingEpoch       uint64 `json:"fencing_epoch"`
	Generation         uint64 `json:"generation"`
	ConfigHash         string `json:"config_hash"`
}

type p118ConfigProcessIdentity struct {
	RuntimeUID           string `json:"runtime_uid"`
	Generation           uint64 `json:"generation"`
	PID                  int64  `json:"pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
}

func p118ConfigRequiredBool(value map[string]json.RawMessage, key string) error {
	var item bool
	raw, ok := value[key]
	if !ok || json.Unmarshal(raw, &item) != nil || !item {
		return fmt.Errorf("%s missing or false", key)
	}
	return nil
}

func p118ConfigRequiredPositive(value map[string]json.RawMessage, key string) (int64, error) {
	var item int64
	raw, ok := value[key]
	if !ok || json.Unmarshal(raw, &item) != nil || item <= 0 {
		return 0, fmt.Errorf("%s invalid", key)
	}
	return item, nil
}

func p118ConfigRequiredString(value map[string]json.RawMessage, key string) (string, error) {
	var item string
	raw, ok := value[key]
	if !ok || json.Unmarshal(raw, &item) != nil || strings.TrimSpace(item) == "" {
		return "", fmt.Errorf("%s invalid", key)
	}
	return item, nil
}

func p118ConfigProcess(value map[string]json.RawMessage, key string) (p118ConfigProcessIdentity, error) {
	raw, ok := value[key]
	if !ok {
		return p118ConfigProcessIdentity{}, fmt.Errorf("%s missing", key)
	}
	var item p118ConfigProcessIdentity
	if err := json.Unmarshal(raw, &item); err != nil {
		return p118ConfigProcessIdentity{}, fmt.Errorf("%s invalid", key)
	}
	if item.RuntimeUID == "" || item.Generation == 0 || item.PID <= 0 ||
		item.ProcessStartIdentity == "" || item.ProfileIncarnation == "" {
		return p118ConfigProcessIdentity{}, fmt.Errorf("%s incomplete", key)
	}
	return item, nil
}

func p118ConfigRuntime(value map[string]json.RawMessage, key string) (p118ConfigRuntimeIdentity, error) {
	raw, ok := value[key]
	if !ok {
		return p118ConfigRuntimeIdentity{}, fmt.Errorf("%s missing", key)
	}
	var item p118ConfigRuntimeIdentity
	if err := json.Unmarshal(raw, &item); err != nil {
		return p118ConfigRuntimeIdentity{}, fmt.Errorf("%s invalid", key)
	}
	if item.NodeUID == "" || item.ProfileID == "" || item.RuntimeUID == "" ||
		item.ProviderInstanceID == "" || item.FencingEpoch == 0 || item.Generation == 0 ||
		item.ConfigHash == "" {
		return p118ConfigRuntimeIdentity{}, fmt.Errorf("%s incomplete", key)
	}
	return item, nil
}

// validateP118ConfigMismatchEvidence rejects unknown top-level keys so a
// secret-bearing token/error cannot be smuggled into an otherwise valid
// evidence object.  PID reuse is allowed; process-start/profile incarnations
// and runtime UID/generation provide the replacement proof.
func validateP118ConfigMismatchEvidence(raw []byte) error {
	var value map[string]json.RawMessage
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	for key := range value {
		if _, ok := p118ConfigMismatchEvidenceKeys[key]; !ok {
			return fmt.Errorf("unexpected evidence key %q", key)
		}
	}
	scenario, err := p118ConfigRequiredString(value, "scenario")
	if err != nil || scenario != p118ConfigMismatchScenario {
		return fmt.Errorf("unsupported config-mismatch scenario")
	}
	for _, key := range []string{
		"accepted", "control_db_cleanup", "controller_a_crashed", "controller_a_cleanup_skipped",
		"runtime_created_by_ensure", "runtime_persisted_by_authenticated_telemetry",
		"runtime_lease_acquired", "runtime_process_identity_observed",
		"mutation_applied", "mutation_owner_scoped", "mutation_after_controller_a_exit",
		"controller_b_started_fresh_process", "controller_b_took_over",
		"production_startup_wiring", "production_watcher_started", "watcher_reconciled",
		"command_observer_installed", "reconcile_command_observed", "reconcile_ack_observed",
		"reconcile_request_identity_match", "reconcile_target_config_match",
		"reconcile_target_launch_mode_match", "replacement_ack_identity_valid",
		"replacement_same_node", "replacement_runtime_uid_changed", "replacement_generation_advanced",
		"replacement_process_start_changed", "replacement_profile_incarnation_preserved",
		"old_process_identity_absent", "replacement_persisted_by_authenticated_telemetry",
		"replacement_db_row_present", "replacement_db_identity_match", "replacement_agent_inventory_match",
		"replacement_strict_stop_confirmed", "replacement_exact_adopted", "old_runtime_marked_lost",
		"replacement_lease_held_by_controller_b", "old_lease_not_successor", "runtime_lease_released",
		"controller_b_cleanup",
	} {
		if err := p118ConfigRequiredBool(value, key); err != nil {
			return err
		}
	}
	for _, key := range []string{"controller_a_pid", "controller_b_pid", "controller_a_generation", "controller_b_generation"} {
		if _, err := p118ConfigRequiredPositive(value, key); err != nil {
			return err
		}
	}
	var aPID, bPID, aGeneration, bGeneration int64
	if aPID, err = p118ConfigRequiredPositive(value, "controller_a_pid"); err != nil {
		return err
	}
	if bPID, err = p118ConfigRequiredPositive(value, "controller_b_pid"); err != nil {
		return err
	}
	if aPID == bPID {
		return fmt.Errorf("controller process identities are not distinct")
	}
	if aGeneration, err = p118ConfigRequiredPositive(value, "controller_a_generation"); err != nil {
		return err
	}
	if bGeneration, err = p118ConfigRequiredPositive(value, "controller_b_generation"); err != nil {
		return err
	}
	if bGeneration <= aGeneration {
		return fmt.Errorf("Controller B generation is not newer")
	}
	var exitSignal int64
	if raw, ok := value["controller_a_exit_signal"]; !ok || json.Unmarshal(raw, &exitSignal) != nil || exitSignal != 9 {
		return fmt.Errorf("Controller A was not SIGKILLed")
	}
	if status, _ := p118ConfigRequiredString(value, "reconcile_status"); status != "ok" {
		return fmt.Errorf("reconcile status is not ok")
	}
	for key, want := range map[string]string{
		"reconcile_outcomes":           "config_mismatch:controlled_restart:ok,exact_match:adopt:ok,db_ready_node_missing:mark_lost:ok",
		"reconcile_case":               "config_mismatch",
		"reconcile_action":             "controlled_restart",
		"runtime_db_old_hash_before":   p118ConfigMismatchOldHash,
		"runtime_db_target_hash_after": p118ConfigMismatchNewHash,
		"replacement_db_target_hash":   p118ConfigMismatchNewHash,
	} {
		item, itemErr := p118ConfigRequiredString(value, key)
		if itemErr != nil || item != want {
			return fmt.Errorf("%s is not %q", key, want)
		}
	}
	if status, err := p118ConfigRequiredString(value, "replacement_db_status"); err != nil || (status != "ready" && status != "idle") {
		return fmt.Errorf("replacement DB status is not active")
	}
	var rowcount, observationCount int64
	if raw, ok := value["mutation_rowcount"]; !ok || json.Unmarshal(raw, &rowcount) != nil || rowcount != 1 {
		return fmt.Errorf("config mutation did not affect one owned row")
	}
	if raw, ok := value["command_observation_count"]; !ok || json.Unmarshal(raw, &observationCount) != nil || observationCount != 1 {
		return fmt.Errorf("reconcile_runtime command count is not one")
	}
	before, err := p118ConfigProcess(value, "before")
	if err != nil {
		return err
	}
	after, err := p118ConfigProcess(value, "after")
	if err != nil {
		return err
	}
	identity, err := p118ConfigRuntime(value, "identity")
	if err != nil {
		return err
	}
	if before.RuntimeUID != identity.RuntimeUID || before.Generation == 0 {
		return fmt.Errorf("old process identity is not bound to old runtime")
	}
	if after.RuntimeUID == before.RuntimeUID || after.Generation <= before.Generation ||
		after.ProcessStartIdentity == before.ProcessStartIdentity ||
		after.ProfileIncarnation != before.ProfileIncarnation {
		return fmt.Errorf("replacement identity is not fresh")
	}
	if identity.ConfigHash != p118ConfigMismatchOldHash {
		return fmt.Errorf("old authenticated identity hash is not the original hash")
	}
	return nil
}

func TestP118ConfigMismatchEvidenceContract(t *testing.T) {
	identity := map[string]any{
		"node_uid": "node-p118", "profile_id": "11801", "runtime_uid": "runtime-old",
		"provider_instance_id": "provider-p118", "fencing_epoch": 1, "generation": 7,
		"config_hash": p118ConfigMismatchOldHash,
	}
	before := map[string]any{
		"runtime_uid": "runtime-old", "generation": 7, "pid": 4242,
		"process_start_identity": "start-old", "profile_incarnation": "incarnation-old",
	}
	after := map[string]any{
		"runtime_uid": "runtime-new", "generation": 8, "pid": 4242,
		"process_start_identity": "start-new", "profile_incarnation": "incarnation-old",
	}
	baseline := map[string]any{
		"accepted": true, "control_db_cleanup": true, "scenario": p118ConfigMismatchScenario,
		"controller_a_crashed": true, "controller_a_exit_signal": 9, "controller_a_cleanup_skipped": true,
		"controller_a_pid": 100, "controller_b_pid": 101, "controller_a_generation": 1, "controller_b_generation": 2,
		"runtime_created_by_ensure": true, "runtime_persisted_by_authenticated_telemetry": true,
		"runtime_lease_acquired": true, "runtime_process_identity_observed": true,
		"mutation_applied": true, "mutation_rowcount": 1, "mutation_owner_scoped": true,
		"mutation_after_controller_a_exit": true, "controller_b_started_fresh_process": true, "controller_b_took_over": true,
		"production_startup_wiring": true, "production_watcher_started": true, "watcher_reconciled": true,
		"command_observer_installed": true, "command_observation_count": 1,
		"reconcile_command_observed": true, "reconcile_ack_observed": true,
		"reconcile_request_identity_match": true, "reconcile_target_config_match": true,
		"reconcile_target_launch_mode_match": true, "replacement_ack_identity_valid": true,
		"replacement_same_node": true, "replacement_runtime_uid_changed": true, "replacement_generation_advanced": true,
		"replacement_process_start_changed": true, "replacement_profile_incarnation_preserved": true,
		"old_process_identity_absent": true, "replacement_persisted_by_authenticated_telemetry": true,
		"replacement_db_row_present": true, "replacement_db_identity_match": true,
		"replacement_agent_inventory_match": true, "replacement_strict_stop_confirmed": true,
		"replacement_exact_adopted": true, "old_runtime_marked_lost": true,
		"replacement_lease_held_by_controller_b": true, "old_lease_not_successor": true,
		"runtime_lease_released": true, "controller_b_cleanup": true,
		"reconcile_outcomes": "config_mismatch:controlled_restart:ok,exact_match:adopt:ok,db_ready_node_missing:mark_lost:ok",
		"reconcile_case":     "config_mismatch", "reconcile_action": "controlled_restart", "reconcile_status": "ok",
		"runtime_db_old_hash_before": p118ConfigMismatchOldHash, "runtime_db_target_hash_after": p118ConfigMismatchNewHash,
		"replacement_db_target_hash": p118ConfigMismatchNewHash, "replacement_db_status": "ready",
		"identity": identity, "before": before, "after": after,
	}
	raw, err := json.Marshal(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateP118ConfigMismatchEvidence(raw); err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	mutations := []struct {
		name string
		edit func(map[string]any)
	}{
		{"controlled restart removed", func(value map[string]any) { value["reconcile_action"] = "stop" }},
		{"plain quarantine accepted", func(value map[string]any) { value["reconcile_action"] = "quarantine" }},
		{"same runtime UID", func(value map[string]any) { value["after"].(map[string]any)["runtime_uid"] = "runtime-old" }},
		{"same generation", func(value map[string]any) { value["after"].(map[string]any)["generation"] = uint64(7) }},
		{"target hash not persisted", func(value map[string]any) { value["replacement_db_target_hash"] = p118ConfigMismatchOldHash }},
		{"same process start", func(value map[string]any) { value["after"].(map[string]any)["process_start_identity"] = "start-old" }},
		{"changed profile incarnation", func(value map[string]any) { value["after"].(map[string]any)["profile_incarnation"] = "incarnation-new" }},
		{"secret-bearing top-level key", func(value map[string]any) { value["controller_token"] = "secret" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			var value map[string]any
			if err := json.Unmarshal(raw, &value); err != nil {
				t.Fatal(err)
			}
			mutation.edit(value)
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateP118ConfigMismatchEvidence(raw); err == nil {
				t.Fatalf("mutation %q was accepted", mutation.name)
			}
		})
	}
}

func TestP118ConfigMismatchTimeoutHasCleanupMargin(t *testing.T) {
	if margin := p118ConfigServerTimeout - p118ConfigFixtureTimeout; margin < 15*time.Second {
		t.Fatalf("config fixture cleanup margin = %s, want at least 15s", margin)
	}
}

// runP118ConfigMismatchScenario is the opt-in production cross-repository
// branch.  It deliberately uses the same real BrowserRuntimeService,
// FarmRuntimeService, authenticated WSS client, and Chrome setup as the
// node-missing runner; Controller A/B lifecycle and the owner-scoped hash
// mutation remain owned by the Python fixture.
func runP118ConfigMismatchScenario(t *testing.T, scenario string) {
	t.Helper()
	if scenario != p118ConfigMismatchScenario {
		t.Fatalf("unsupported config-mismatch scenario %q", scenario)
	}
	serverRepo := os.Getenv("P118_SERVER_REPO")
	if serverRepo == "" {
		serverRepo = "/Users/bot/.codex/worktrees/p118-handoff"
	}
	fixtureScript := filepath.Join(serverRepo, "輔助程式", "p1_18_config_mismatch_fixture.py")
	if _, err := os.Stat(fixtureScript); err != nil {
		t.Fatalf("config-mismatch fixture unavailable: %v", err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const (
		nodeUID     = "node-p118-config"
		providerID  = "provider-p118-config"
		profileID   = "118903"
		controllerA = "controller-p118-config-a"
		controllerB = "controller-p118-config-b"
	)
	root := t.TempDir()
	urlFile := filepath.Join(root, "controller-a.url")
	evidenceFile := filepath.Join(root, "p118-config-mismatch-evidence.json")
	aStateFile := filepath.Join(root, "controller-a.json")
	bStateFile := filepath.Join(root, "controller-b.json")
	caFile := filepath.Join(root, "p118-ca.pem")
	publicKey := base64.StdEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	controlDBName := fmt.Sprintf("bf_p118_config_%x", time.Now().UnixNano())

	ctx, cancel := context.WithTimeout(context.Background(), p118ConfigServerTimeout)
	defer cancel()
	serverArgs := []string{
		"--scenario", scenario,
		"--url-file", urlFile,
		"--evidence-file", evidenceFile,
		"--ca-file", caFile,
		"--node-uid", nodeUID,
		"--public-key", publicKey,
		"--profile-id", profileID,
		"--provider-instance-id", providerID,
		"--fencing-epoch", "1",
		"--controller-a-id", controllerA,
		"--controller-b-id", controllerB,
		"--a-state-file", aStateFile,
		"--b-state-file", bStateFile,
		"--timeout", p118TimeoutSeconds(p118ConfigFixtureTimeout),
	}
	serverCommand := exec.CommandContext(ctx, "python3", append([]string{fixtureScript}, serverArgs...)...)
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
			<-serverDone
		}
	}()
	controlURL := waitForP118TextFileOrProcess(
		t, urlFile, 20*time.Second, &serverOutput, serverDone, &serverFinished, nil,
		evidenceFile, aStateFile, bStateFile,
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
		ProfileId: profileID, ProfileName: "P1.18 config mismatch isolated", CoreId: "chrome",
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
	digest := sha256.Sum256(privateKey)
	ownershipStore, err := NewFileFarmRuntimeOwnershipStore(filepath.Join(root, "farm-ownership.json"), digest[:])
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
		t.Fatal("invalid P1.18 config TLS CA")
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: controlURL, NodeUID: nodeUID, PrivateKey: privateKey,
		HandshakeTimeout: 5 * time.Second, CommandTimeout: 15 * time.Second,
		HeartbeatInterval: 200 * time.Millisecond,
		AutoReconnect:     true, ReconnectMinBackoff: 50 * time.Millisecond, ReconnectMaxBackoff: time.Second,
		Dialer: &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Connect(nil); err != nil {
		t.Fatalf("real Agent authenticated config-mismatch connect failed: %v", err)
	}
	defer client.Close()
	deadline := time.Now().Add(p118ConfigServerTimeout)
	p118WaitNodeMissingStage(
		t, aStateFile, serverCommand, "ready_for_parent_sigkill", deadline,
		&serverOutput, evidenceFile, aStateFile, bStateFile,
	)
	if err := <-serverDone; err != nil {
		serverFinished = true
		t.Fatalf("config-mismatch fixture failed: %v output=%s diagnostics=%s", err,
			p118AllowlistedServerOutput(serverOutput.String()),
			p118AllowlistedJSONDiagnostics(evidenceFile, aStateFile, bStateFile))
	}
	serverFinished = true
	raw, err := os.ReadFile(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateP118ConfigMismatchEvidence(raw); err != nil {
		t.Fatalf("config-mismatch evidence rejected: %v diagnostics=%s", err, p118AllowlistedJSONDiagnostic(evidenceFile))
	}
	info, err := os.Stat(evidenceFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("config-mismatch evidence mode=%o, want 0600", info.Mode().Perm())
	}
}
