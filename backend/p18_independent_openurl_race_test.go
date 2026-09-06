package backend

import (
	"testing"
	"time"
)

// The stale liveness observation is made before OpenUrl enters the service
// profile gate. A replacement runtime can therefore publish while the old
// transition is waiting; the old observation must fail closed without stopping
// or annotating the replacement profile.
func TestP18IndependentOpenURLStaleObservationCannotStopReplacement(t *testing.T) {
	service, manager := newRuntimeServiceTest(t)
	app := NewApp(t.TempDir())
	app.config = manager.Config
	app.browserMgr = manager
	app.runtimeService = service

	profile := manager.Profiles["profile-1"]
	_, oldCmd := newCompletedRuntimeProcess(t, nil)
	oldIdentity := service.markRunning(profile.ProfileId, profile, oldCmd, oldCmd.Process.Pid, 0, true, "")
	if oldIdentity.generation == 0 {
		t.Fatal("old runtime did not publish a generation")
	}

	// Hold the service gate after OpenUrl's stale Manager snapshot is taken. The
	// test observes the second gate reference instead of relying on a scheduler
	// sleep, then publishes N+1 while N is still waiting.
	releaseGate, err := service.acquire(profile.ProfileId)
	if err != nil {
		t.Fatal(err)
	}
	openResult := make(chan error, 1)
	go func() {
		_, openErr := app.BrowserInstanceOpenUrl(profile.ProfileId, "https://stale.example")
		openResult <- openErr
	}()

	deadline := time.Now().Add(time.Second)
	for {
		service.gatesMu.Lock()
		gate := service.gates[profile.ProfileId]
		refs := 0
		if gate != nil {
			refs = gate.refs
		}
		service.gatesMu.Unlock()
		if refs >= 2 {
			break
		}
		if time.Now().After(deadline) {
			releaseGate()
			t.Fatal("OpenUrl did not reach the service gate after stale observation")
		}
		time.Sleep(time.Millisecond)
	}

	// This is the replacement publication that would be performed by a fresh
	// Start. It is deliberately done while the stale OpenUrl transition cannot
	// yet acquire the gate, making the ABA ordering deterministic.
	newCmd := oldCmd
	newIdentity := service.markRunning(profile.ProfileId, profile, newCmd, oldCmd.Process.Pid+1, 9777, true, "")
	if newIdentity.generation <= oldIdentity.generation {
		releaseGate()
		t.Fatalf("replacement generation = %d, old = %d", newIdentity.generation, oldIdentity.generation)
	}
	releaseGate()

	select {
	case openErr := <-openResult:
		if openErr == nil {
			t.Fatal("stale OpenUrl unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stale OpenUrl did not finish after gate release")
	}

	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	manager.Mutex.Unlock()
	if !current.Running || !current.DebugReady || current.Pid != newIdentity.pid || current.DebugPort != newIdentity.debugPort {
		t.Fatalf("stale OpenUrl stopped replacement runtime: %+v", current)
	}
	if current.LastError != "" {
		t.Fatalf("stale OpenUrl annotated replacement profile: %q", current.LastError)
	}
	if got := service.Generation(profile.ProfileId); got != newIdentity.generation {
		t.Fatalf("stale OpenUrl changed replacement generation: got %d want %d", got, newIdentity.generation)
	}
}
