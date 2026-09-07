package backend

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestFarmResourceTelemetryRTTBoundaries(t *testing.T) {
	tests := []struct {
		value float64
		want  string
	}{
		{50, FarmRTTHealthyClass},
		{50.001, FarmRTTAcceptableClass},
		{100, FarmRTTAcceptableClass},
		{100.001, FarmRTTDegradedClass},
		{200, FarmRTTDegradedClass},
		{200.001, FarmRTTNoPlacementClass},
	}
	for _, test := range tests {
		if got := ClassifyFarmRTT(test.value); got != test.want {
			t.Fatalf("ClassifyFarmRTT(%v)=%q, want %q", test.value, got, test.want)
		}
	}
	if got := ClassifyFarmRTT(-1); got != FarmRTTUnknownClass {
		t.Fatalf("negative RTT class=%q", got)
	}
}

func TestFarmResourceTelemetryUsesAgentHooksAndClosedWireProjection(t *testing.T) {
	now := time.Date(2026, 9, 8, 0, 0, 0, 123000000, time.UTC)
	service := &FarmRuntimeService{
		nodeUID:          "node-a",
		providerInstance: "farm-a",
		fencingEpoch:     7,
		records: map[string]farmRuntimeRecord{
			"profile-a": {
				runtime: FarmRuntime{
					FarmRuntimeIdentity: FarmRuntimeIdentity{
						NodeUID: "node-a", ProfileID: "profile-a", RuntimeUID: "runtime-a",
						ProviderInstanceID: "farm-a", FencingEpoch: 7, Generation: 2,
					},
					State: FarmRuntimeStateIdle, PID: 1234,
				},
			},
		},
		resourceTelemetryHooks: &FarmResourceTelemetryHooks{
			Now: func() time.Time { return now },
			NodeMemory: func() (FarmNodeMemoryTelemetry, error) {
				return FarmNodeMemoryTelemetry{TotalMB: 8192, AvailableMB: 4096, UsedPercent: 50, Health: "healthy"}, nil
			},
			ProcessRSS: func(pid int) (int64, error) {
				if pid != 1234 {
					t.Fatalf("unexpected Agent pid=%d", pid)
				}
				return 512, nil
			},
		},
	}
	telemetry, err := service.ResourceTelemetry(101)
	if err != nil {
		t.Fatalf("ResourceTelemetry: %v", err)
	}
	if telemetry.RTTClass != FarmRTTDegradedClass || telemetry.NodeUID != "node-a" || len(telemetry.Runtimes) != 1 {
		t.Fatalf("unexpected telemetry: %#v", telemetry)
	}
	if telemetry.Runtimes[0].RSSMB != 512 || telemetry.Runtimes[0].Generation != 2 {
		t.Fatalf("unexpected runtime telemetry: %#v", telemetry.Runtimes[0])
	}
	raw, err := json.Marshal(telemetry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "password") || strings.Contains(string(raw), "launch") || strings.Contains(string(raw), "proxy") {
		t.Fatalf("secret-bearing field leaked: %s", raw)
	}
	if err := ValidateFarmResourceTelemetry(telemetry); err != nil {
		t.Fatalf("wire validation: %v", err)
	}
}

func TestFarmResourceTelemetryUnknownRTTDoesNotClaimHealthy(t *testing.T) {
	service := &FarmRuntimeService{
		nodeUID: "node-a", providerInstance: "farm-a", fencingEpoch: 7,
	}
	telemetry, err := service.ResourceTelemetry(-1)
	if err != nil {
		t.Fatalf("ResourceTelemetry unknown RTT: %v", err)
	}
	if telemetry.RTTClass != FarmRTTUnknownClass || telemetry.ControlRTTMS != 0 {
		t.Fatalf("unexpected unknown RTT projection: %#v", telemetry)
	}
}

func TestFarmResourceTelemetryRejectsMutatedIdentity(t *testing.T) {
	value := FarmResourceTelemetry{
		Version: 1, NodeUID: "node-a", Provider: "farm", ProviderInstanceID: "farm-a",
		FencingEpoch: 7, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RTTClass: FarmRTTHealthyClass, NodeMemory: FarmNodeMemoryTelemetry{Health: "healthy"},
		Runtimes: []FarmRuntimeResourceTelemetry{{
			NodeUID: "node-b", ProfileID: "profile-a", RuntimeUID: "runtime-a", Provider: "farm",
			ProviderInstanceID: "farm-a", FencingEpoch: 7, Generation: 2,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Health: "healthy",
		}},
	}
	if !errors.Is(ValidateFarmResourceTelemetry(value), ErrFarmResourceTelemetryInvalid) {
		t.Fatal("mutated runtime node identity was accepted")
	}
}
