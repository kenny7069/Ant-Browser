package backend

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func assertHandoffRuntimeStillCurrent(t *testing.T, farm *FarmRuntimeService, request FarmRuntimeHandoffRequest) {
	t.Helper()
	snapshot, err := farm.runtimeService.RuntimeSnapshot(request.ProfileID)
	if err != nil {
		t.Fatalf("RuntimeSnapshot after rejected stop: %v", err)
	}
	if snapshot == nil || snapshot.Profile == nil || !snapshot.Profile.Running {
		t.Fatalf("rejected stop changed running state: %#v", snapshot)
	}
	if snapshot.Generation != request.Generation || snapshot.Profile.Pid != request.PID || snapshot.ProfileIncarnation != request.ProfileIncarnation {
		t.Fatalf("rejected stop changed process identity: snapshot=%#v request=%#v", snapshot, request)
	}
	record, owned := farm.currentRecord(request.ProfileID)
	if !owned || record.runtime.RuntimeUID != request.RuntimeUID || record.runtime.Generation != request.Generation {
		t.Fatalf("rejected stop changed Farm ownership: owned=%v record=%#v", owned, record)
	}
}

func TestBrowserRuntimeStopIfIdentityRejectsMissingAndMutatedProcessIdentity(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, true)

	tests := []struct {
		name    string
		mutate  func(*FarmRuntimeHandoffRequest)
		wantErr error
	}{
		{"missing pid", func(value *FarmRuntimeHandoffRequest) { value.PID = 0 }, ErrBrowserRuntimeGenerationMismatch},
		{"missing process start", func(value *FarmRuntimeHandoffRequest) { value.ProcessStartIdentity = "" }, ErrBrowserRuntimeGenerationMismatch},
		{"missing profile incarnation", func(value *FarmRuntimeHandoffRequest) { value.ProfileIncarnation = "" }, ErrBrowserRuntimeGenerationMismatch},
		{"mutated pid", func(value *FarmRuntimeHandoffRequest) { value.PID++ }, ErrBrowserRuntimeProfileMismatch},
		{"mutated process start", func(value *FarmRuntimeHandoffRequest) { value.ProcessStartIdentity += "-replacement" }, ErrBrowserRuntimeProfileMismatch},
		{"mutated profile incarnation", func(value *FarmRuntimeHandoffRequest) { value.ProfileIncarnation += "-replacement" }, ErrBrowserRuntimeProfileMismatch},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			test.mutate(&candidate)
			_, err := farm.runtimeService.StopIfIdentity(
				candidate.ProfileID,
				candidate.Generation,
				candidate.ProfileIncarnation,
				candidate.PID,
				candidate.ProcessStartIdentity,
			)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("StopIfIdentity error=%v, want %v", err, test.wantErr)
			}
			assertHandoffRuntimeStillCurrent(t, farm, request)
		})
	}
}

func TestHandoffStopRejectsMissingAndMutatedProcessIdentity(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, true)

	tests := []struct {
		name    string
		mutate  func(*FarmRuntimeHandoffRequest)
		wantErr error
	}{
		{"missing pid", func(value *FarmRuntimeHandoffRequest) { value.PID = 0 }, ErrFarmRuntimeIdentityRequired},
		{"missing process start", func(value *FarmRuntimeHandoffRequest) { value.ProcessStartIdentity = "" }, ErrFarmRuntimeIdentityRequired},
		{"missing profile incarnation", func(value *FarmRuntimeHandoffRequest) { value.ProfileIncarnation = "" }, ErrFarmRuntimeIdentityRequired},
		{"mutated pid", func(value *FarmRuntimeHandoffRequest) { value.PID++ }, ErrFarmRuntimeStale},
		{"mutated process start", func(value *FarmRuntimeHandoffRequest) { value.ProcessStartIdentity += "-replacement" }, ErrFarmRuntimeStale},
		{"mutated profile incarnation", func(value *FarmRuntimeHandoffRequest) { value.ProfileIncarnation += "-replacement" }, ErrFarmRuntimeStale},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := request
			test.mutate(&candidate)
			if _, err := farm.StopHandoffRuntime(candidate); !errors.Is(err, test.wantErr) {
				t.Fatalf("StopHandoffRuntime error=%v, want %v", err, test.wantErr)
			}
			assertHandoffRuntimeStillCurrent(t, farm, request)
		})
	}
}

func TestHandoffStopRejectsReplacementBetweenValidationAndBrowserIdentityGate(t *testing.T) {
	farm, request, _ := newProvenRestartFixture(t, true)
	validated := make(chan struct{})
	releaseValidation := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseValidation) })
	}
	defer release()
	farm.handoffValidationHook = func() {
		close(validated)
		<-releaseValidation
	}

	stopDone := make(chan error, 1)
	go func() {
		_, err := farm.StopHandoffRuntime(request)
		stopDone <- err
	}()
	select {
	case <-validated:
	case <-time.After(5 * time.Second):
		t.Fatal("handoff stop did not reach validation barrier")
	}

	if _, err := farm.runtimeService.Stop(request.ProfileID); err != nil {
		t.Fatalf("replace: stop validated runtime: %v", err)
	}
	if _, err := farm.runtimeService.Start(request.ProfileID); err != nil {
		t.Fatalf("replace: start next runtime: %v", err)
	}
	replacement, err := farm.runtimeService.RuntimeSnapshot(request.ProfileID)
	if err != nil {
		t.Fatalf("replacement snapshot: %v", err)
	}
	if replacement == nil || replacement.Profile == nil || !replacement.Profile.Running || replacement.Generation <= request.Generation || replacement.Profile.Pid == request.PID {
		t.Fatalf("replacement was not installed before old stop resumed: %#v", replacement)
	}

	release()
	select {
	case err := <-stopDone:
		if !errors.Is(err, ErrFarmRuntimeStale) {
			t.Fatalf("old handoff stop error=%v, want stale", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("old handoff stop did not finish after validation release")
	}
	current, err := farm.runtimeService.RuntimeSnapshot(request.ProfileID)
	if err != nil {
		t.Fatalf("current replacement snapshot: %v", err)
	}
	if current == nil || current.Profile == nil || !current.Profile.Running || current.Generation != replacement.Generation || current.Profile.Pid != replacement.Profile.Pid || current.ProfileIncarnation != replacement.ProfileIncarnation {
		t.Fatalf("old handoff stop changed replacement: before=%#v after=%#v", replacement, current)
	}
}
