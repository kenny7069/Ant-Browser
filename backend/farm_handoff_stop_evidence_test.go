package backend

import (
	"bytes"
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// p118StopProofs is the allowlisted proof set emitted by
// p1_18_reconcile_stop_fixture.py.  Every item is required to be the JSON
// boolean literal true; a truthy number or string is not evidence.
var p118StopProofs = []string{
	"accepted",
	"control_db_cleanup",
	"controller_a_crashed",
	"controller_a_cleanup_skipped",
	"runtime_created_by_ensure",
	"runtime_persisted_by_authenticated_telemetry",
	"runtime_lease_acquired",
	"runtime_process_identity_observed",
	"chrome_alive_before_stop",
	"controller_b_started_fresh_process",
	"controller_b_took_over",
	"production_startup_wiring",
	"production_watcher_started",
	"watcher_reconciled",
	"command_observer_installed",
	"quarantine_command_observed",
	"quarantine_ack_observed",
	"stop_command_observed",
	"stop_ack_observed",
	"quarantine_request_identity_match",
	"stop_request_identity_match",
	"quarantine_stop_order_confirmed",
	"quarantine_sent",
	"stop_sent",
	"quarantine_stop_confirmed",
	"agent_inventory_runtime_stopped",
	"agent_inventory_pid_zero",
	"agent_inventory_process_identity_preserved",
	"agent_inventory_profile_incarnation_preserved",
	"agent_inventory_no_replacement",
	"original_pid_absent",
	"runtime_db_contradiction_preserved",
	"mutation_applied",
	"controller_b_cleanup",
}

var p118StopUintCounters = []string{
	"controller_a_exit_signal",
	"controller_a_pid",
	"controller_b_pid",
	"controller_a_generation",
	"controller_b_generation",
	"command_observation_count",
	"agent_inventory_original_runtime_count",
	"replacement_runtime_count",
	"mutation_rowcount",
	"runtime_db_fencing_epoch_before",
	"runtime_db_fencing_epoch_after",
}

func p118StopScenario(scenario string) bool {
	return scenario == "stale_epoch_stop" || scenario == "unknown_runtime_stop"
}

func p118StopRequireBool(wire map[string]json.RawMessage, key string, expected bool) error {
	raw, ok := wire[key]
	if !ok || !bytes.Equal(bytes.TrimSpace(raw), []byte(strconv.FormatBool(expected))) {
		return fmt.Errorf("%s must be exactly %t", key, expected)
	}
	return nil
}

func p118StopRequireString(wire map[string]json.RawMessage, key, expected string) error {
	raw, ok := wire[key]
	if !ok {
		return fmt.Errorf("%s is missing", key)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil || value != expected {
		return fmt.Errorf("%s must be %q", key, expected)
	}
	return nil
}

func p118StopReadUint(wire map[string]json.RawMessage, key string, allowZero bool) (uint64, error) {
	raw, ok := wire[key]
	if !ok {
		return 0, fmt.Errorf("%s is missing", key)
	}
	token := bytes.TrimSpace(raw)
	if len(token) == 0 || (len(token) > 1 && token[0] == '0') {
		return 0, fmt.Errorf("%s must be a JSON uint", key)
	}
	for _, character := range token {
		if character < '0' || character > '9' {
			return 0, fmt.Errorf("%s must be a JSON uint", key)
		}
	}
	value, err := strconv.ParseUint(string(token), 10, 64)
	if err != nil || (!allowZero && value == 0) {
		if allowZero {
			return 0, fmt.Errorf("%s must be a JSON uint", key)
		}
		return 0, fmt.Errorf("%s must be a positive JSON uint", key)
	}
	return value, nil
}

func p118StopRequireUint(wire map[string]json.RawMessage, key string, expected uint64) error {
	value, err := p118StopReadUint(wire, key, true)
	if err != nil {
		return err
	}
	if value != expected {
		return fmt.Errorf("%s = %d, want %d", key, value, expected)
	}
	return nil
}

func p118StopDecodeIdentity(wire map[string]json.RawMessage, key string, allowZeroPID bool) (p118HandoffIdentity, error) {
	raw, ok := wire[key]
	if !ok {
		return p118HandoffIdentity{}, fmt.Errorf("%s identity is missing", key)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return p118HandoffIdentity{}, fmt.Errorf("%s identity must be an object", key)
	}
	for _, field := range []string{"runtime_uid", "generation", "pid", "process_start_identity", "profile_incarnation"} {
		if _, present := fields[field]; !present {
			return p118HandoffIdentity{}, fmt.Errorf("%s identity field %s is missing", key, field)
		}
	}
	var identity p118HandoffIdentity
	if err := json.Unmarshal(raw, &identity); err != nil {
		return p118HandoffIdentity{}, fmt.Errorf("invalid %s identity: %w", key, err)
	}
	if identity.RuntimeUID == "" || identity.ProcessStartIdentity == "" || identity.ProfileIncarnation == "" ||
		len(identity.RuntimeUID) > 256 || len(identity.ProcessStartIdentity) > 256 || len(identity.ProfileIncarnation) > 256 ||
		identity.Generation == 0 {
		return p118HandoffIdentity{}, fmt.Errorf("%s identity is incomplete", key)
	}
	if identity.PID < 0 || (!allowZeroPID && identity.PID == 0) || (!allowZeroPID && identity.PID <= 0) {
		return p118HandoffIdentity{}, fmt.Errorf("%s PID is invalid", key)
	}
	if allowZeroPID && identity.PID != 0 {
		return p118HandoffIdentity{}, fmt.Errorf("%s PID must be zero", key)
	}
	return identity, nil
}

// validateP118StopEvidence validates the server fixture's complete bounded
// evidence record.  It intentionally duplicates the security-relevant
// predicates in the Python validator so a Python boolean cannot turn a
// failed Agent stop into a passing Go test.
func validateP118StopEvidence(raw []byte) error {
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil || wire == nil {
		if err != nil {
			return err
		}
		return fmt.Errorf("stop evidence must be a JSON object")
	}

	var scenario string
	if err := json.Unmarshal(wire["scenario"], &scenario); err != nil || !p118StopScenario(scenario) {
		return fmt.Errorf("stop scenario missing or contradictory")
	}
	for _, key := range p118StopProofs {
		if err := p118StopRequireBool(wire, key, true); err != nil {
			return err
		}
	}
	if err := p118StopRequireBool(wire, "runtime_db_row_present_before", true); err != nil {
		return err
	}

	exitSignal, err := p118StopReadUint(wire, "controller_a_exit_signal", true)
	if err != nil {
		return err
	}
	if exitSignal != 9 {
		return fmt.Errorf("controller_a_exit_signal = %d, want SIGKILL", exitSignal)
	}
	aPID, err := p118StopReadUint(wire, "controller_a_pid", false)
	if err != nil {
		return err
	}
	bPID, err := p118StopReadUint(wire, "controller_b_pid", false)
	if err != nil {
		return err
	}
	if aPID == bPID {
		return fmt.Errorf("Controller A and B PIDs are identical")
	}
	aGeneration, err := p118StopReadUint(wire, "controller_a_generation", false)
	if err != nil {
		return err
	}
	bGeneration, err := p118StopReadUint(wire, "controller_b_generation", false)
	if err != nil {
		return err
	}
	if bGeneration <= aGeneration {
		return fmt.Errorf("Controller B generation is not newer")
	}
	if err := p118StopRequireUint(wire, "agent_inventory_original_runtime_count", 1); err != nil {
		return err
	}
	if err := p118StopRequireUint(wire, "replacement_runtime_count", 0); err != nil {
		return err
	}
	if err := p118StopRequireUint(wire, "command_observation_count", 2); err != nil {
		return err
	}
	if err := p118StopRequireString(wire, "command_observation_order", "quarantine_runtime>stop_runtime_handoff"); err != nil {
		return err
	}
	if err := p118StopRequireUint(wire, "mutation_rowcount", 1); err != nil {
		return err
	}
	oldEpoch, err := p118StopReadUint(wire, "runtime_db_fencing_epoch_before", false)
	if err != nil {
		return err
	}
	afterEpoch, err := p118StopReadUint(wire, "runtime_db_fencing_epoch_after", true)
	if err != nil {
		return err
	}

	before, err := p118StopDecodeIdentity(wire, "before", false)
	if err != nil {
		return err
	}
	after, err := p118StopDecodeIdentity(wire, "after", true)
	if err != nil {
		return err
	}
	if before.PID <= 0 || after.PID != 0 {
		return fmt.Errorf("stop process PID projection is contradictory")
	}
	if before.RuntimeUID != after.RuntimeUID || before.Generation != after.Generation ||
		before.ProcessStartIdentity != after.ProcessStartIdentity || before.ProfileIncarnation != after.ProfileIncarnation {
		return fmt.Errorf("runtime/process identity changed across stop")
	}

	expectedCase := "stale_fencing"
	expectedOutcome := "stale_fencing:quarantine_stop:ok"
	if scenario == "unknown_runtime_stop" {
		expectedCase = "unknown_runtime"
		expectedOutcome = "unknown_runtime:quarantine_stop:ok"
	}
	if err := p118StopRequireString(wire, "reconcile_case", expectedCase); err != nil {
		return err
	}
	if err := p118StopRequireString(wire, "reconcile_action", "quarantine_stop"); err != nil {
		return err
	}
	if err := p118StopRequireString(wire, "reconcile_status", "ok"); err != nil {
		return err
	}
	if err := p118StopRequireString(wire, "reconcile_outcomes", expectedOutcome); err != nil {
		return err
	}
	if scenario == "stale_epoch_stop" {
		if err := p118StopRequireBool(wire, "stale_epoch_mutation_applied", true); err != nil {
			return err
		}
		if err := p118StopRequireBool(wire, "unknown_runtime_delete_applied", false); err != nil {
			return err
		}
		if err := p118StopRequireBool(wire, "runtime_db_row_absent", false); err != nil {
			return err
		}
		if oldEpoch == ^uint64(0) || afterEpoch != oldEpoch+1 {
			return fmt.Errorf("stale fencing epoch did not advance by exactly one")
		}
	} else {
		if err := p118StopRequireBool(wire, "stale_epoch_mutation_applied", false); err != nil {
			return err
		}
		if err := p118StopRequireBool(wire, "unknown_runtime_delete_applied", true); err != nil {
			return err
		}
		if err := p118StopRequireBool(wire, "runtime_db_row_absent", true); err != nil {
			return err
		}
		if afterEpoch != 0 {
			return fmt.Errorf("unknown-runtime fencing epoch = %d, want zero", afterEpoch)
		}
	}
	return nil
}

func p118StopEvidenceBaseline(scenario string) map[string]any {
	before := map[string]any{
		"runtime_uid":            "runtime-p118-stop",
		"generation":             uint64(7),
		"pid":                    27182,
		"process_start_identity": "process-start-7",
		"profile_incarnation":    "profile-incarnation-7",
	}
	after := map[string]any{
		"runtime_uid":            "runtime-p118-stop",
		"generation":             uint64(7),
		"pid":                    0,
		"process_start_identity": "process-start-7",
		"profile_incarnation":    "profile-incarnation-7",
	}
	value := map[string]any{
		"accepted":                                      true,
		"control_db_cleanup":                            true,
		"scenario":                                      scenario,
		"controller_a_crashed":                          true,
		"controller_a_cleanup_skipped":                  true,
		"controller_a_exit_signal":                      uint64(9),
		"controller_a_pid":                              uint64(1001),
		"controller_a_generation":                       uint64(3),
		"controller_b_started_fresh_process":            true,
		"controller_b_took_over":                        true,
		"controller_b_pid":                              uint64(1002),
		"controller_b_generation":                       uint64(4),
		"production_startup_wiring":                     true,
		"production_watcher_started":                    true,
		"watcher_reconciled":                            true,
		"command_observer_installed":                    true,
		"command_observation_count":                     uint64(2),
		"command_observation_order":                     "quarantine_runtime>stop_runtime_handoff",
		"quarantine_command_observed":                   true,
		"quarantine_ack_observed":                       true,
		"stop_command_observed":                         true,
		"stop_ack_observed":                             true,
		"quarantine_request_identity_match":             true,
		"stop_request_identity_match":                   true,
		"quarantine_stop_order_confirmed":               true,
		"quarantine_sent":                               true,
		"stop_sent":                                     true,
		"quarantine_stop_confirmed":                     true,
		"runtime_created_by_ensure":                     true,
		"runtime_persisted_by_authenticated_telemetry":  true,
		"runtime_lease_acquired":                        true,
		"runtime_process_identity_observed":             true,
		"chrome_alive_before_stop":                      true,
		"agent_inventory_runtime_stopped":               true,
		"agent_inventory_pid_zero":                      true,
		"agent_inventory_process_identity_preserved":    true,
		"agent_inventory_profile_incarnation_preserved": true,
		"agent_inventory_no_replacement":                true,
		"agent_inventory_original_runtime_count":        uint64(1),
		"replacement_runtime_count":                     uint64(0),
		"original_pid_absent":                           true,
		"controller_b_cleanup":                          true,
		"runtime_db_row_present_before":                 true,
		"runtime_db_contradiction_preserved":            true,
		"mutation_applied":                              true,
		"mutation_rowcount":                             uint64(1),
		"runtime_db_fencing_epoch_before":               uint64(11),
		"runtime_db_fencing_epoch_after":                uint64(12),
		"reconcile_case":                                "stale_fencing",
		"reconcile_action":                              "quarantine_stop",
		"reconcile_status":                              "ok",
		"reconcile_outcomes":                            "stale_fencing:quarantine_stop:ok",
		"stale_epoch_mutation_applied":                  true,
		"unknown_runtime_delete_applied":                false,
		"runtime_db_row_absent":                         false,
		"before":                                        before,
		"after":                                         after,
	}
	if scenario == "unknown_runtime_stop" {
		value["stale_epoch_mutation_applied"] = false
		value["unknown_runtime_delete_applied"] = true
		value["runtime_db_row_absent"] = true
		value["runtime_db_fencing_epoch_after"] = uint64(0)
		value["reconcile_case"] = "unknown_runtime"
		value["reconcile_outcomes"] = "unknown_runtime:quarantine_stop:ok"
	}
	return value
}

func p118EncodeStopEvidence(t *testing.T, value map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestP118StopEvidenceAcceptsBothScenarios(t *testing.T) {
	for _, scenario := range []string{"stale_epoch_stop", "unknown_runtime_stop"} {
		t.Run(scenario, func(t *testing.T) {
			if err := validateP118StopEvidence(p118EncodeStopEvidence(t, p118StopEvidenceBaseline(scenario))); err != nil {
				t.Fatalf("complete stop evidence rejected: %v", err)
			}
		})
	}
}

func TestP118StopEvidenceRejectsMissingProofs(t *testing.T) {
	for _, key := range p118StopProofs {
		t.Run("missing_"+key, func(t *testing.T) {
			value := p118StopEvidenceBaseline("stale_epoch_stop")
			delete(value, key)
			if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
				t.Fatal("missing proof accepted")
			}
		})
	}
}

func TestP118StopEvidenceRejectsNonTrueProofValues(t *testing.T) {
	for _, key := range p118StopProofs {
		t.Run("false_"+key, func(t *testing.T) {
			value := p118StopEvidenceBaseline("stale_epoch_stop")
			value[key] = false
			if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
				t.Fatal("false proof accepted")
			}
		})
	}
}

func TestP118StopEvidenceRejectsSchemaAndIdentityMutations(t *testing.T) {
	baseline := p118StopEvidenceBaseline("stale_epoch_stop")
	for name, value := range map[string]any{
		"null":   nil,
		"array":  []any{},
		"string": "stop",
	} {
		t.Run("schema_"+name, func(t *testing.T) {
			raw, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if err := validateP118StopEvidence(raw); err == nil {
				t.Fatal("malformed schema accepted")
			}
		})
	}
	for _, side := range []string{"before", "after"} {
		for _, field := range []string{"runtime_uid", "generation", "pid", "process_start_identity", "profile_incarnation"} {
			t.Run("missing_"+side+"_"+field, func(t *testing.T) {
				value := p118CloneStopEvidence(t, baseline)
				delete(value[side].(map[string]any), field)
				if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
					t.Fatal("incomplete process identity accepted")
				}
			})
		}
	}
	for _, field := range []string{"runtime_uid", "generation", "process_start_identity", "profile_incarnation"} {
		t.Run("changed_after_"+field, func(t *testing.T) {
			value := p118CloneStopEvidence(t, baseline)
			switch field {
			case "generation":
				value["after"].(map[string]any)[field] = uint64(8)
			default:
				value["after"].(map[string]any)[field] = "replacement"
			}
			if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
				t.Fatal("mutated process identity accepted")
			}
		})
	}
	value := p118CloneStopEvidence(t, baseline)
	value["after"].(map[string]any)["pid"] = uint64(27182)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("nonzero stopped PID accepted")
	}
}

func TestP118StopEvidenceRejectsScenarioCaseActionStatusAndCounters(t *testing.T) {
	for key, bad := range map[string]any{
		"scenario":           "graceful",
		"reconcile_case":     "exact_match",
		"reconcile_action":   "adopt",
		"reconcile_status":   "rejected",
		"reconcile_outcomes": "unknown_runtime:quarantine_stop:ok",
	} {
		t.Run("contradictory_"+key, func(t *testing.T) {
			value := p118StopEvidenceBaseline("stale_epoch_stop")
			value[key] = bad
			if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
				t.Fatal("scenario contract contradiction accepted")
			}
		})
	}
	for _, key := range p118StopUintCounters {
		for name, bad := range map[string]any{
			"bool":     true,
			"fraction": 1.5,
			"negative": -1,
			"missing":  nil,
		} {
			t.Run(key+"_"+name, func(t *testing.T) {
				value := p118StopEvidenceBaseline("stale_epoch_stop")
				if bad == nil {
					delete(value, key)
				} else {
					value[key] = bad
				}
				if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
					t.Fatal("invalid typed uint accepted")
				}
			})
		}
	}
	value := p118StopEvidenceBaseline("stale_epoch_stop")
	value["controller_b_pid"] = uint64(1001)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("same controller PID accepted")
	}
	value = p118StopEvidenceBaseline("stale_epoch_stop")
	value["controller_b_generation"] = uint64(3)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("non-newer controller generation accepted")
	}
	value = p118StopEvidenceBaseline("stale_epoch_stop")
	value["runtime_db_fencing_epoch_after"] = uint64(13)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("stale epoch jump accepted")
	}
	value = p118StopEvidenceBaseline("unknown_runtime_stop")
	value["runtime_db_fencing_epoch_after"] = uint64(12)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("unknown runtime nonzero epoch accepted")
	}
	value = p118StopEvidenceBaseline("stale_epoch_stop")
	value["command_observation_order"] = "stop_runtime_handoff>quarantine_runtime"
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("reversed stop command order accepted")
	}
	value = p118StopEvidenceBaseline("stale_epoch_stop")
	value["command_observation_count"] = uint64(1)
	if err := validateP118StopEvidence(p118EncodeStopEvidence(t, value)); err == nil {
		t.Fatal("incomplete stop command observation accepted")
	}
}

func p118CloneStopEvidence(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	var clone map[string]any
	if err := json.Unmarshal(p118EncodeStopEvidence(t, value), &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

type p118StopCommandStep struct {
	command            string
	owned              bool
	state              string
	runtimeUID         string
	profileID          string
	providerInstance   string
	fencingEpoch       uint64
	generation         uint64
	pid                int
	processStart       string
	profileIncarnation string
}

type p118StopCommandObservation struct {
	farm      *FarmRuntimeService
	profileID string

	mu    sync.Mutex
	steps []p118StopCommandStep
}

func newP118StopCommandObservation(farm *FarmRuntimeService, profileID string, _ FarmRuntime) *p118StopCommandObservation {
	return &p118StopCommandObservation{farm: farm, profileID: profileID}
}

func (observation *p118StopCommandObservation) observe() {
	if observation == nil || observation.farm == nil {
		return
	}
	record, owned := observation.farm.currentRecord(observation.profileID)
	runtimeValue := record.runtime
	step := p118StopCommandStep{
		command:            p118StopValidationCaller(),
		owned:              owned,
		state:              runtimeValue.State,
		runtimeUID:         runtimeValue.RuntimeUID,
		profileID:          runtimeValue.ProfileID,
		providerInstance:   runtimeValue.ProviderInstanceID,
		fencingEpoch:       runtimeValue.FencingEpoch,
		generation:         runtimeValue.Generation,
		pid:                runtimeValue.PID,
		processStart:       runtimeValue.ProcessStartIdentity,
		profileIncarnation: runtimeValue.ProfileIncarnation,
	}
	observation.mu.Lock()
	observation.steps = append(observation.steps, step)
	observation.mu.Unlock()
}

func p118StopValidationCaller() string {
	pcs := make([]uintptr, 32)
	count := runtime.Callers(0, pcs)
	frames := runtime.CallersFrames(pcs[:count])
	for {
		frame, more := frames.Next()
		switch {
		case strings.HasSuffix(frame.Function, ".QuarantineRuntime"):
			return "quarantine_runtime"
		case strings.HasSuffix(frame.Function, ".StopHandoffRuntime"):
			return "stop_runtime_handoff"
		}
		if !more {
			break
		}
	}
	return "unknown"
}

func assertP118StopCommandObservation(t *testing.T, observation *p118StopCommandObservation, before FarmRuntime) {
	t.Helper()
	if observation == nil {
		t.Fatal("stop command observation is nil")
	}
	observation.mu.Lock()
	steps := append([]p118StopCommandStep(nil), observation.steps...)
	observation.mu.Unlock()
	if len(steps) != 2 {
		t.Fatalf("stop command validation count = %d, want exactly 2: %#v", len(steps), steps)
	}
	if steps[0].command != "quarantine_runtime" || steps[1].command != "stop_runtime_handoff" {
		t.Fatalf("stop command order = [%s %s], want [quarantine_runtime stop_runtime_handoff]", steps[0].command, steps[1].command)
	}
	if steps[0].state != FarmRuntimeStateIdle || steps[1].state != FarmRuntimeStateQuarantined {
		t.Fatalf("stop command states = [%s %s], want [%s %s]", steps[0].state, steps[1].state, FarmRuntimeStateIdle, FarmRuntimeStateQuarantined)
	}
	for index, step := range steps {
		if !step.owned {
			t.Fatalf("stop command %d did not validate an Agent-owned record", index)
		}
		if step.runtimeUID != before.RuntimeUID || step.profileID != before.ProfileID ||
			step.providerInstance != before.ProviderInstanceID || step.fencingEpoch != before.FencingEpoch ||
			step.generation != before.Generation || step.pid != before.PID ||
			step.processStart != before.ProcessStartIdentity || step.profileIncarnation != before.ProfileIncarnation {
			t.Fatalf("stop command %d identity changed: step=%#v before=%+v", index, step, before)
		}
	}
}

func waitForP118RunningFarmInventory(t *testing.T, farm *FarmRuntimeService, profileID string, timeout time.Duration) FarmRuntime {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last string
	for time.Now().Before(deadline) {
		inventory, err := farm.InventoryWithError()
		if err != nil {
			last = fmt.Sprintf("inventory error: %v", err)
		} else if len(inventory) == 1 {
			runtimeValue := inventory[0]
			profile := runtimeValue.Profile
			if runtimeValue.ProfileID == profileID && runtimeValue.State == FarmRuntimeStateIdle &&
				runtimeValue.RuntimeUID != "" && runtimeValue.Generation > 0 && runtimeValue.PID > 0 &&
				runtimeValue.DebugReady && runtimeValue.ProcessStartIdentity != "" &&
				runtimeValue.ProfileIncarnation != "" && profile != nil && profile.Running &&
				profile.Pid > 0 && profile.DebugReady {
				return runtimeValue
			}
			last = fmt.Sprintf("unexpected running inventory: %+v", runtimeValue)
		} else {
			last = fmt.Sprintf("inventory count=%d", len(inventory))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("Agent did not publish one complete running Farm inventory before stop: %s", last)
	return FarmRuntime{}
}

func assertP118StoppedFarmInventory(t *testing.T, farm *FarmRuntimeService, before FarmRuntime) {
	t.Helper()
	inventory, err := farm.InventoryWithError()
	if err != nil {
		t.Fatalf("Agent InventoryWithError after stop: %v", err)
	}
	if len(inventory) != 1 {
		t.Fatalf("Agent inventory after stop = %d records, want exactly one original record: %#v", len(inventory), inventory)
	}
	after := inventory[0]
	if after.RuntimeUID != before.RuntimeUID {
		t.Fatalf("Agent inventory replaced runtime UID: before=%q after=%q", before.RuntimeUID, after.RuntimeUID)
	}
	if after.NodeUID != before.NodeUID || after.ProfileID != before.ProfileID ||
		after.ProviderInstanceID != before.ProviderInstanceID || after.FencingEpoch != before.FencingEpoch ||
		after.ConfigHash != before.ConfigHash || after.Generation != before.Generation {
		t.Fatalf("Agent inventory stable runtime identity changed: before=%+v after=%+v", before, after)
	}
	if after.State != FarmRuntimeStateStopped || after.PID != 0 || after.DebugReady {
		t.Fatalf("Agent inventory did not report stopped/PID0/debug-ready false: %+v", after)
	}
	if after.ProcessStartIdentity != before.ProcessStartIdentity || after.ProfileIncarnation != before.ProfileIncarnation {
		t.Fatalf("Agent inventory process identity changed: before=%+v after=%+v", before, after)
	}
	if after.Profile == nil || after.Profile.Running || after.Profile.Pid != 0 || after.Profile.DebugReady {
		t.Fatalf("Agent inventory profile stopped projection is invalid: %+v", after.Profile)
	}
}
