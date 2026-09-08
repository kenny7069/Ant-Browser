package backend

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestDefaultProcessTreeRSSUsesRealChildAndFailsClosedAfterExit(t *testing.T) {
	if testing.Short() {
		t.Skip("real OS process proof")
	}
	cmd := exec.Command("sh", "-c", "sleep 30 & wait")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	var rss int64
	var err error
	for time.Now().Before(deadline) {
		rss, err = defaultProcessTreeRSS(pid)
		if err == nil && rss > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil || rss <= 0 {
		t.Fatalf("real process tree RSS pid=%d rss=%d err=%v", pid, rss, err)
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	if _, err := defaultProcessTreeRSS(pid); err == nil {
		t.Fatal("exited/PID-missing process produced valid RSS")
	}
}

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
		controllerID:     "controller-a", controllerGeneration: 3,
		records: map[string]farmRuntimeRecord{
			"profile-a": {
				processStartIdentity: "start-1234",
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
			ProcessIdentity: func(pid int) (string, error) { return "start-1234", nil },
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
		controllerID: "controller-a", controllerGeneration: 3,
	}
	telemetry, err := service.ResourceTelemetry(-1)
	if err != nil {
		t.Fatalf("ResourceTelemetry unknown RTT: %v", err)
	}
	if telemetry.RTTClass != FarmRTTUnknownClass || telemetry.ControlRTTMS != 0 {
		t.Fatalf("unexpected unknown RTT projection: %#v", telemetry)
	}
}

func TestFarmResourceTelemetryPIDReuseFailsClosed(t *testing.T) {
	identityCalls := 0
	service := &FarmRuntimeService{
		nodeUID: "node-a", providerInstance: "farm-a", fencingEpoch: 7,
		controllerID: "controller-a", controllerGeneration: 3,
		records: map[string]farmRuntimeRecord{"profile-a": {processStartIdentity: "old-start", runtime: FarmRuntime{
			FarmRuntimeIdentity: FarmRuntimeIdentity{NodeUID: "node-a", ProfileID: "profile-a", RuntimeUID: "runtime-a", ProviderInstanceID: "farm-a", FencingEpoch: 7, Generation: 1},
			State:               FarmRuntimeStateIdle, PID: 1234,
		}}},
		resourceTelemetryHooks: &FarmResourceTelemetryHooks{
			NodeMemory: func() (FarmNodeMemoryTelemetry, error) { return FarmNodeMemoryTelemetry{Health: "healthy"}, nil },
			ProcessRSS: func(int) (int64, error) { return 10, nil },
			ProcessIdentity: func(int) (string, error) {
				identityCalls++
				if identityCalls == 1 {
					return "old-start", nil
				}
				return "reused-start", nil
			},
		},
	}
	if _, err := service.ResourceTelemetry(10); !errors.Is(err, ErrFarmResourceTelemetryInvalid) {
		t.Fatalf("PID reuse telemetry err=%v", err)
	}
}

func TestFarmResourceTelemetryRejectsPIDReusedBeforeSamplingAgainstLaunchBaseline(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	fixture.farm.controllerID = "controller-a"
	fixture.farm.controllerGeneration = 3
	identity := "linux-starttime:1000000001"
	rssCalls := 0
	fixture.farm.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		NodeMemory: func() (FarmNodeMemoryTelemetry, error) {
			return FarmNodeMemoryTelemetry{TotalMB: 8192, AvailableMB: 4096, UsedPercent: 50, Health: "healthy"}, nil
		},
		ProcessRSS: func(int) (int64, error) {
			rssCalls++
			return 512, nil
		},
		ProcessIdentity: func(int) (string, error) { return identity, nil },
	}
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	record, ok := fixture.farm.currentRecord("profile-1")
	if !ok || record.processStartIdentity != identity || runtime.PID != 7001 {
		t.Fatalf("launch identity was not retained: record=%#v runtime=%#v", record, runtime)
	}
	identity = "linux-starttime:1000000002" // same PID, later process incarnation
	if _, err := fixture.farm.ResourceTelemetry(10); !errors.Is(err, ErrFarmResourceTelemetryInvalid) {
		t.Fatalf("pre-sampling PID reuse err=%v", err)
	}
	if rssCalls != 0 {
		t.Fatalf("RSS read occurred after launch identity mismatch: %d", rssCalls)
	}
}

func TestFarmEnsureFailsClosedWhenLaunchIdentityUnavailable(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	fixture.farm.controllerID = "controller-a"
	fixture.farm.controllerGeneration = 3
	fixture.farm.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		ProcessIdentity: func(int) (string, error) { return "", errors.New("unavailable") },
	}
	if _, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"}); !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("missing launch identity err=%v", err)
	}
	if _, ok := fixture.farm.currentRecord("profile-1"); ok {
		t.Fatal("runtime entered Farm inventory without authenticated launch identity")
	}
}

func TestFarmStopRejectsStaleTelemetrySampleBeforeLookup(t *testing.T) {
	service := &FarmRuntimeService{
		nodeUID: "node-a", providerInstance: "farm-a", fencingEpoch: 7,
		controllerID: "controller-a", controllerGeneration: 3,
		latestResourceSequence: 9, latestResourceObservedAt: "2026-09-08T00:00:09Z",
	}
	_, err := service.StopRuntime(FarmRuntimeStopRequest{
		NodeUID: "node-a", ProfileID: "profile-a", RuntimeUID: "runtime-a",
		ProviderInstanceID: "farm-a", FencingEpoch: 7, Generation: 1,
		PID: 42, ProcessStartIdentity: "1001", ProfileIncarnation: "incarnation-a",
		ControllerID: "controller-a", ControllerGeneration: 3,
		TelemetrySequence: 8, TelemetryObservedAt: "2026-09-08T00:00:08Z",
	})
	if !errors.Is(err, ErrFarmRuntimeStale) {
		t.Fatalf("stale telemetry stop err=%v", err)
	}
}

func TestFarmStopRejectsMissingMutatedAndReusedProcessIdentityBeforeStop(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	fixture.farm.controllerID = "controller-a"
	fixture.farm.controllerGeneration = 3
	currentStart := "1000000001"
	fixture.farm.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		ProcessIdentity: func(int) (string, error) { return currentStart, nil },
	}
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1"})
	if err != nil {
		t.Fatalf("EnsureRuntime: %v", err)
	}
	record, ok := fixture.farm.currentRecord("profile-1")
	if !ok {
		t.Fatal("missing owned Farm record")
	}
	fixture.farm.latestResourceSequence = 9
	fixture.farm.latestResourceObservedAt = "2026-09-08T00:00:09Z"
	base := FarmRuntimeStopRequest{
		Provider: "farm", NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID,
		RuntimeUID: runtime.RuntimeUID, ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch: runtime.FencingEpoch, Generation: runtime.Generation,
		PID: runtime.PID, ProcessStartIdentity: record.processStartIdentity,
		ProfileIncarnation: record.profileIncarnation,
		ControllerID:       "controller-a", ControllerGeneration: 3,
		TelemetrySequence: 9, TelemetryObservedAt: "2026-09-08T00:00:09Z",
	}
	mutations := []struct {
		name   string
		mutate func(*FarmRuntimeStopRequest)
	}{
		{"missing pid", func(value *FarmRuntimeStopRequest) { value.PID = 0 }},
		{"missing start", func(value *FarmRuntimeStopRequest) { value.ProcessStartIdentity = "" }},
		{"missing incarnation", func(value *FarmRuntimeStopRequest) { value.ProfileIncarnation = "" }},
		{"mutated pid", func(value *FarmRuntimeStopRequest) { value.PID++ }},
		{"mutated start", func(value *FarmRuntimeStopRequest) { value.ProcessStartIdentity = "1000000002" }},
		{"mutated incarnation", func(value *FarmRuntimeStopRequest) { value.ProfileIncarnation = "foreign" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			request := base
			mutation.mutate(&request)
			if _, err := fixture.farm.StopRuntime(request); err == nil {
				t.Fatal("mutated stop identity was accepted")
			}
		})
	}
	currentStart = "1000000003" // PID was reused after authenticated telemetry.
	if _, err := fixture.farm.StopRuntime(base); !errors.Is(err, ErrFarmRuntimeStale) {
		t.Fatalf("PID reuse stop err=%v", err)
	}
	if fixture.stopCalls.Load() != 0 {
		t.Fatalf("runtime stop was reached for rejected process identity: %d", fixture.stopCalls.Load())
	}
}

func TestFarmResourceTelemetryRejectsMutatedIdentity(t *testing.T) {
	value := FarmResourceTelemetry{
		Version: 1, NodeUID: "node-a", Provider: "farm", ProviderInstanceID: "farm-a",
		ControllerID: "controller-a", ControllerGeneration: 3, SampleSequence: 1,
		FencingEpoch: 7, ObservedAt: time.Now().UTC().Format(time.RFC3339Nano),
		RTTClass: FarmRTTHealthyClass, NodeMemory: FarmNodeMemoryTelemetry{Health: "healthy"},
		Runtimes: []FarmRuntimeResourceTelemetry{{
			NodeUID: "node-b", ProfileID: "profile-a", RuntimeUID: "runtime-a", Provider: "farm",
			ProviderInstanceID: "farm-a", FencingEpoch: 7, Generation: 2,
			ControllerID: "controller-a", ControllerGeneration: 3, PID: 42, ProcessStartIdentity: "start-42",
			RSSMB: 1, RSSValid: true, State: FarmRuntimeStateIdle,
			ObservedAt: time.Now().UTC().Format(time.RFC3339Nano), Health: "healthy",
		}},
	}
	if !errors.Is(ValidateFarmResourceTelemetry(value), ErrFarmResourceTelemetryInvalid) {
		t.Fatal("mutated runtime node identity was accepted")
	}
}
