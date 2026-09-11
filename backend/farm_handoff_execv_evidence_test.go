package backend

import (
	"encoding/json"
	"fmt"
	"testing"
)

var p118ExecvProofs = []string{
	"accepted", "control_db_cleanup", "controller_a_execv_requested",
	"controller_b_started_new_image", "same_pid", "boot_nonce_changed",
	"runtime_created_by_ensure", "runtime_persisted_by_authenticated_telemetry",
	"runtime_lease_acquired", "initial_cdp_published", "watcher_reconciled",
	"production_startup_wiring", "production_watcher_started", "runtime_lease_released",
	"strict_stop_confirmed", "chrome_alive_during_execv_handoff",
	"runtime_process_identity_preserved", "old_cdp_closed", "new_cdp_connected",
	"new_cdp_basic_io",
}

func validateP118ExecvEvidence(raw []byte) error {
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(raw, &wire); err != nil {
		return err
	}
	var scenario string
	if err := json.Unmarshal(wire["scenario"], &scenario); err != nil || scenario != "execv" {
		return fmt.Errorf("execv scenario missing or contradictory")
	}
	for _, key := range p118ExecvProofs {
		var value bool
		if err := json.Unmarshal(wire[key], &value); err != nil || !value {
			return fmt.Errorf("%s missing or false", key)
		}
	}

	readPositiveUint := func(key string) (uint64, error) {
		var value uint64
		if err := json.Unmarshal(wire[key], &value); err != nil || value == 0 {
			return 0, fmt.Errorf("%s must be a positive uint", key)
		}
		return value, nil
	}
	controllerPIDBefore, err := readPositiveUint("controller_pid_before")
	if err != nil {
		return err
	}
	controllerPIDAfter, err := readPositiveUint("controller_pid_after")
	if err != nil {
		return err
	}
	if controllerPIDBefore != controllerPIDAfter {
		return fmt.Errorf("controller PID changed across execv")
	}

	readNonEmptyString := func(key string) (string, error) {
		var value string
		if err := json.Unmarshal(wire[key], &value); err != nil || value == "" {
			return "", fmt.Errorf("%s must be a non-empty string", key)
		}
		return value, nil
	}
	bootNonceBefore, err := readNonEmptyString("boot_nonce_before")
	if err != nil {
		return err
	}
	bootNonceAfter, err := readNonEmptyString("boot_nonce_after")
	if err != nil {
		return err
	}
	if bootNonceBefore == bootNonceAfter {
		return fmt.Errorf("controller boot nonce did not change")
	}

	var before, after p118HandoffIdentity
	if err := json.Unmarshal(wire["before"], &before); err != nil {
		return fmt.Errorf("invalid before identity: %w", err)
	}
	if err := json.Unmarshal(wire["after"], &after); err != nil {
		return fmt.Errorf("invalid after identity: %w", err)
	}
	if before.RuntimeUID == "" || before.Generation == 0 || before.PID <= 0 ||
		before.ProcessStartIdentity == "" || before.ProfileIncarnation == "" {
		return fmt.Errorf("before Chrome identity is incomplete")
	}
	if after.RuntimeUID == "" || after.Generation == 0 || after.PID <= 0 ||
		after.ProcessStartIdentity == "" || after.ProfileIncarnation == "" {
		return fmt.Errorf("after Chrome identity is incomplete")
	}
	if before != after {
		return fmt.Errorf("Chrome process identity changed across execv")
	}
	return nil
}

func p118ExecvEvidenceBaseline() map[string]any {
	identity := map[string]any{
		"runtime_uid":            "runtime-execv",
		"generation":             7,
		"pid":                    4242,
		"process_start_identity": "process-start-execv",
		"profile_incarnation":    "profile-incarnation-execv",
	}
	value := map[string]any{
		"scenario":                       "execv",
		"controller_pid_before":          uint64(100),
		"controller_pid_after":           uint64(100),
		"boot_nonce_before":              "image-a-nonce",
		"boot_nonce_after":               "image-b-nonce",
		"before":                         identity,
		"after":                          identity,
		"accepted":                       true,
		"control_db_cleanup":             true,
		"controller_a_execv_requested":   true,
		"controller_b_started_new_image": true,
		"same_pid":                       true,
		"boot_nonce_changed":             true,
		"runtime_created_by_ensure":      true,
		"runtime_persisted_by_authenticated_telemetry": true,
		"runtime_lease_acquired":                       true,
		"initial_cdp_published":                        true,
		"watcher_reconciled":                           true,
		"production_startup_wiring":                    true,
		"production_watcher_started":                   true,
		"runtime_lease_released":                       true,
		"strict_stop_confirmed":                        true,
		"chrome_alive_during_execv_handoff":            true,
		"runtime_process_identity_preserved":           true,
		"old_cdp_closed":                               true,
		"new_cdp_connected":                            true,
		"new_cdp_basic_io":                             true,
	}
	return value
}

func p118CloneExecvEvidence(t *testing.T, value map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var cloned map[string]any
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func p118EncodeExecvEvidence(t *testing.T, value map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestP118ExecvEvidenceAcceptsCompleteProof(t *testing.T) {
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, p118ExecvEvidenceBaseline())); err != nil {
		t.Fatalf("complete execv evidence rejected: %v", err)
	}
}

func TestP118ExecvEvidenceRejectsMissingProofs(t *testing.T) {
	for _, key := range p118ExecvProofs {
		t.Run("missing_"+key, func(t *testing.T) {
			value := p118ExecvEvidenceBaseline()
			delete(value, key)
			if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
				t.Fatal("missing proof accepted")
			}
		})
	}
}

func TestP118ExecvEvidenceRejectsControllerPIDContradictions(t *testing.T) {
	for _, key := range []string{"controller_pid_before", "controller_pid_after"} {
		for name, bad := range map[string]any{
			"missing":  nil,
			"zero":     uint64(0),
			"bool":     true,
			"fraction": 100.5,
			"negative": -1,
		} {
			t.Run(key+"_"+name, func(t *testing.T) {
				value := p118ExecvEvidenceBaseline()
				if bad == nil {
					delete(value, key)
				} else {
					value[key] = bad
				}
				if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
					t.Fatal("invalid controller PID accepted")
				}
			})
		}
	}

	value := p118ExecvEvidenceBaseline()
	value["controller_pid_after"] = uint64(101)
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
		t.Fatal("changed controller PID accepted")
	}
}

func TestP118ExecvEvidenceRejectsNonceContradictions(t *testing.T) {
	for _, key := range []string{"boot_nonce_before", "boot_nonce_after"} {
		t.Run("missing_"+key, func(t *testing.T) {
			value := p118ExecvEvidenceBaseline()
			delete(value, key)
			if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
				t.Fatal("missing boot nonce accepted")
			}
		})
	}
	value := p118ExecvEvidenceBaseline()
	value["boot_nonce_after"] = value["boot_nonce_before"]
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
		t.Fatal("same boot nonce accepted")
	}
	value = p118ExecvEvidenceBaseline()
	value["boot_nonce_changed"] = false
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
		t.Fatal("false boot nonce proof accepted")
	}
}

func TestP118ExecvEvidenceRejectsMissingOrChangedChromeIdentity(t *testing.T) {
	identityFields := []string{
		"runtime_uid", "generation", "pid", "process_start_identity", "profile_incarnation",
	}
	for _, side := range []string{"before", "after"} {
		for _, field := range identityFields {
			t.Run("missing_"+side+"_"+field, func(t *testing.T) {
				value := p118ExecvEvidenceBaseline()
				identity := value[side].(map[string]any)
				delete(identity, field)
				if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
					t.Fatal("missing Chrome identity accepted")
				}
			})
		}
	}

	for _, field := range identityFields {
		t.Run("changed_after_"+field, func(t *testing.T) {
			value := p118CloneExecvEvidence(t, p118ExecvEvidenceBaseline())
			identity := value["after"].(map[string]any)
			switch field {
			case "generation", "pid":
				identity[field] = float64(9999)
			default:
				identity[field] = "replacement"
			}
			if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
				t.Fatal("changed Chrome identity accepted")
			}
		})
	}
}

func TestP118ExecvEvidenceRejectsScenarioAndGracefulProofs(t *testing.T) {
	value := p118ExecvEvidenceBaseline()
	value["scenario"] = "graceful"
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
		t.Fatal("graceful scenario accepted by execv parser")
	}
	value = p118ExecvEvidenceBaseline()
	delete(value, "controller_a_execv_requested")
	value["controller_a_stopped"] = true
	if err := validateP118ExecvEvidence(p118EncodeExecvEvidence(t, value)); err == nil {
		t.Fatal("graceful stop proof substituted for execv proof")
	}
}
