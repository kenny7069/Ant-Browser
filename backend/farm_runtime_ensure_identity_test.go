package backend

import (
	"encoding/json"
	"testing"
)

func TestFarmRuntimeEnsureProjectsVerifiedProcessIdentityOnFirstResponse(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-ensure-identity")
	if err := fixture.farm.RebindController("controller-ensure-identity", 3); err != nil {
		t.Fatal(err)
	}
	fixture.farm.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		ProcessIdentity: func(pid int) (string, error) {
			if pid != 7001 {
				t.Fatalf("process identity read for pid=%d, want 7001", pid)
			}
			return "process-start-7001", nil
		},
	}

	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
		ProfileID:  "profile-ensure-identity",
		ConfigHash: "opaque-config-token",
		LaunchMode: FarmRuntimeLaunchModeDirectNoProxy,
	})
	if err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	snapshot, err := fixture.runtime.RuntimeSnapshot("profile-ensure-identity")
	if err != nil {
		t.Fatal(err)
	}
	if runtime.PID != 7001 || runtime.ProcessStartIdentity != "process-start-7001" ||
		runtime.ProfileIncarnation == "" || runtime.ProfileIncarnation != snapshot.ProfileIncarnation {
		t.Fatalf("first ensure omitted verified process identity: %+v snapshot=%+v", runtime, snapshot)
	}
	record, ok := fixture.farm.currentRecord("profile-ensure-identity")
	if !ok || record.runtime.ProcessStartIdentity != runtime.ProcessStartIdentity ||
		record.runtime.ProfileIncarnation != runtime.ProfileIncarnation {
		t.Fatalf("returned and persisted runtime projections differ: record=%+v response=%+v", record, runtime)
	}
	raw, err := json.Marshal(runtime)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["process_start_identity"] != "process-start-7001" ||
		wire["profile_incarnation"] != runtime.ProfileIncarnation {
		t.Fatalf("wire response omitted verified process identity: %s", raw)
	}
}
