package backend

import (
	"encoding/json"
	"fmt"
	"testing"
)

var p118CrashProofs = []string{
	"accepted", "control_db_cleanup", "controller_a_crashed", "controller_a_cleanup_skipped",
	"runtime_created_by_ensure", "runtime_persisted_by_authenticated_telemetry",
	"runtime_lease_acquired", "initial_cdp_published", "controller_b_started_fresh_process",
	"controller_b_took_over", "production_startup_wiring", "production_watcher_started",
	"watcher_reconciled", "runtime_lease_released", "strict_stop_confirmed",
	"chrome_alive_during_crash_handoff", "old_cdp_closed", "new_cdp_connected", "new_cdp_basic_io",
}

func validateP118CrashEvidence(raw []byte) error {
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	var scenario string
	if json.Unmarshal(wire["scenario"], &scenario) != nil || scenario != "crash_watcher" {
		return fmt.Errorf("crash scenario missing or contradictory")
	}
	for _, key := range p118CrashProofs {
		var value bool
		if json.Unmarshal(wire[key], &value) != nil || !value {
			return fmt.Errorf("%s missing or false", key)
		}
	}
	readPositive := func(key string) (uint64, error) {
		var value uint64
		if json.Unmarshal(wire[key], &value) != nil || value == 0 {
			return 0, fmt.Errorf("%s invalid", key)
		}
		return value, nil
	}
	values := map[string]uint64{}
	for _, key := range []string{"controller_a_pid", "controller_b_pid", "controller_a_generation", "controller_b_generation", "controller_a_exit_signal"} {
		value, err := readPositive(key)
		if err != nil {
			return err
		}
		values[key] = value
	}
	if values["controller_a_exit_signal"] != 9 || values["controller_a_pid"] == values["controller_b_pid"] || values["controller_b_generation"] <= values["controller_a_generation"] {
		return fmt.Errorf("crash process or takeover evidence contradictory")
	}
	var before, after p118HandoffIdentity
	if json.Unmarshal(wire["before"], &before) != nil || json.Unmarshal(wire["after"], &after) != nil {
		return fmt.Errorf("invalid process identity")
	}
	if before.RuntimeUID == "" || before.Generation == 0 || before.PID <= 0 || before.ProcessStartIdentity == "" || before.ProfileIncarnation == "" || before != after {
		return fmt.Errorf("Chrome identity missing or changed")
	}
	return nil
}

func TestP118CrashEvidenceRejectsContradictions(t *testing.T) {
	baseline := func() map[string]any {
		identity := map[string]any{"runtime_uid": "runtime", "generation": 7, "pid": 4242, "process_start_identity": "start", "profile_incarnation": "incarnation"}
		value := map[string]any{"scenario": "crash_watcher", "controller_a_pid": 100, "controller_b_pid": 101, "controller_a_generation": 1, "controller_b_generation": 2, "controller_a_exit_signal": 9, "before": identity, "after": identity}
		for _, key := range p118CrashProofs {
			value[key] = true
		}
		return value
	}
	check := func(value map[string]any) error {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return validateP118CrashEvidence(raw)
	}
	if err := check(baseline()); err != nil {
		t.Fatal(err)
	}
	for _, key := range p118CrashProofs {
		t.Run("missing_"+key, func(t *testing.T) {
			value := baseline()
			delete(value, key)
			if check(value) == nil {
				t.Fatal("missing proof accepted")
			}
		})
	}
	for key, bad := range map[string]any{"scenario": "graceful", "controller_b_pid": 100, "controller_b_generation": 1, "controller_a_exit_signal": 15, "controller_a_pid": true, "controller_a_generation": 1.5, "after": map[string]any{"runtime_uid": "replacement"}} {
		t.Run("contradictory_"+key, func(t *testing.T) {
			value := baseline()
			value[key] = bad
			if check(value) == nil {
				t.Fatal("contradiction accepted")
			}
		})
	}
}
