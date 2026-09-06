package backend

import (
	"errors"
	"os/exec"
	"strings"
	"sync"
	"testing"
)

func p112EnsureCommand(node, profile string) FarmRuntimeCommand {
	return FarmRuntimeCommand{
		Type:          "command",
		NodeUID:       node,
		CorrelationID: profile,
		Command:       "ensure_runtime",
		Payload: map[string]any{
			"profile_id":  profile,
			"launch_mode": FarmRuntimeLaunchModeDirectNoProxy,
		},
	}
}

func TestFarmRuntimeP112CommandRequiresExplicitDirectNoProxy(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"", "proxy", "direct", "DIRECT_NO_PROXY"} {
		command := p112EnsureCommand("node-test", "profile-1")
		command.Payload = map[string]any{"profile_id": "profile-1"}
		if mode != "" {
			command.Payload.(map[string]any)["launch_mode"] = mode
		}
		response, callErr := adapter.HandleCommand(command)
		if callErr != nil || response.OK || response.Error != ErrFarmRuntimeLaunchMode.Error() {
			t.Fatalf("mode %q accepted: response=%+v err=%v", mode, response, callErr)
		}
	}
	if fixture.detectCalls.Load() != 0 || fixture.startCalls.Load() != 0 {
		t.Fatal("invalid launch mode touched shared runtime")
	}

	runtime, err := adapter.HandleCommand(p112EnsureCommand("node-test", "profile-1"))
	if err != nil || !runtime.OK {
		t.Fatalf("direct/no-proxy command failed: response=%+v err=%v", runtime, err)
	}
	owned, ok := runtime.Payload.(FarmRuntime)
	if !ok || owned.LaunchMode != FarmRuntimeLaunchModeDirectNoProxy {
		t.Fatalf("direct runtime did not retain launch mode: %#v", runtime.Payload)
	}
}

func TestFarmRuntimeP112DirectModeOverridesProfileProxyInSharedLaunchPlan(t *testing.T) {
	service, manager := newRuntimeStartServiceTest(t, BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			return nil, errors.New("launch plan should be inspected before process creation")
		},
		StopProcess: func(*exec.Cmd) error { return nil },
	})
	manager.Mutex.Lock()
	profile := manager.Profiles["profile-1"]
	profile.ProxyConfig = "http://user:password@example.invalid:8080"
	manager.Mutex.Unlock()
	plan, err := service.prepareStart(BrowserRuntimeStartRequest{
		ProfileID: "profile-1",
		Options: BrowserRuntimeStartOptions{
			ForceDirectProxy: true,
		},
	}, profile)
	if err != nil {
		t.Fatal(err)
	}
	defer service.releaseStartPlan(plan)
	if plan.Spec.EffectiveProxy != "direct://" {
		t.Fatalf("effective proxy = %q, want direct://", plan.Spec.EffectiveProxy)
	}
	for _, arg := range plan.Spec.Args {
		if strings.Contains(arg, "proxy-server=") || strings.Contains(arg, "password") {
			t.Fatalf("launch args retained profile proxy: %q", arg)
		}
	}
}

func TestFarmRuntimeP112RejectsIdentityContradictionBeforeLaunch(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	command := p112EnsureCommand("other-node", "profile-1")
	response, callErr := adapter.HandleCommand(command)
	if callErr == nil || !errors.Is(callErr, ErrFarmRuntimeIdentityMismatch) {
		t.Fatalf("wrong node error = %v, want identity mismatch", callErr)
	}
	if response.OK || fixture.detectCalls.Load() != 0 || fixture.startCalls.Load() != 0 {
		t.Fatalf("wrong node touched runtime: response=%+v detect=%d start=%d", response, fixture.detectCalls.Load(), fixture.startCalls.Load())
	}
}

func TestFarmRuntimeP112CommandRaceKeepsOneDirectRuntime(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	const contenders = 16
	responses := make([]FarmRuntimeCommandResponse, contenders)
	errs := make([]error, contenders)
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			command := p112EnsureCommand("node-test", "profile-1")
			command.CorrelationID = "race-" + command.CorrelationID + "-" + string(rune('a'+index))
			responses[index], errs[index] = adapter.HandleCommand(command)
		}(i)
	}
	wg.Wait()
	var first FarmRuntime
	for i := range responses {
		if errs[i] != nil || !responses[i].OK {
			t.Fatalf("race response %d = %+v err=%v", i, responses[i], errs[i])
		}
		runtime, ok := responses[i].Payload.(FarmRuntime)
		if !ok || runtime.LaunchMode != FarmRuntimeLaunchModeDirectNoProxy {
			t.Fatalf("race runtime %d = %#v", i, responses[i].Payload)
		}
		if i == 0 {
			first = runtime
		} else if runtime.RuntimeUID != first.RuntimeUID || runtime.Generation != first.Generation {
			t.Fatalf("race adopted different runtime: first=%+v current=%+v", first, runtime)
		}
	}
	if fixture.startCalls.Load() != 0 || fixture.detectCalls.Load() != 1 {
		t.Fatalf("race lifecycle calls detect=%d start=%d; want one shared adoption", fixture.detectCalls.Load(), fixture.startCalls.Load())
	}
}

func TestFarmRuntimeP112AdapterRemovalFailsClosed(t *testing.T) {
	var adapter *FarmRuntimeControlAdapter
	if _, err := adapter.HandleCommand(p112EnsureCommand("node-test", "profile-1")); !errors.Is(err, ErrFarmRuntimeServiceUnavailable) {
		t.Fatalf("nil adapter error = %v, want unavailable", err)
	}
}
