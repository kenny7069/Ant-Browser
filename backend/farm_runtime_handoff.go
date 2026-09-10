package backend

// Authenticated controller handoff/reconcile operations.  These functions
// deliberately sit beside the existing FarmRuntimeService: they reuse the
// shared BrowserRuntimeService gates and never infer ownership from a profile's
// Running/PID/port fields alone.

import (
	"errors"
	"fmt"
	"strings"
)

// validateHandoffRequestLocked is called with both controllerOperationMu.RLock
// and the Farm per-profile gate held.  Keeping validation and publication (or
// destruction) in one critical section prevents a controller rebind or a
// replacement Farm record from crossing the authorization boundary.
func (s *FarmRuntimeService) validateHandoffRequestLocked(request FarmRuntimeHandoffRequest, requireReady bool) (farmRuntimeRecord, bool, *BrowserRuntimeServiceSnapshot, error) {
	if s == nil {
		return farmRuntimeRecord{}, false, nil, ErrFarmRuntimeServiceUnavailable
	}
	if request.Provider != "farm" || strings.TrimSpace(request.NodeUID) == "" || request.NodeUID != s.nodeUID ||
		strings.TrimSpace(request.ProfileID) == "" || strings.TrimSpace(request.RuntimeUID) == "" ||
		strings.TrimSpace(request.ProviderInstanceID) == "" || request.ProviderInstanceID != s.providerInstance ||
		request.FencingEpoch == 0 || request.FencingEpoch != s.fencingEpoch || request.Generation == 0 ||
		request.PID <= 0 || strings.TrimSpace(request.ProcessStartIdentity) == "" ||
		strings.TrimSpace(request.ProfileIncarnation) == "" || strings.TrimSpace(request.ConfigHash) == "" ||
		strings.TrimSpace(request.ControllerID) == "" || request.ControllerGeneration == 0 {
		return farmRuntimeRecord{}, false, nil, ErrFarmRuntimeIdentityRequired
	}
	currentID, currentGeneration := s.controllerBinding()
	if request.ControllerID != currentID || request.ControllerGeneration != currentGeneration {
		return farmRuntimeRecord{}, false, nil, ErrFarmRuntimeStale
	}
	if requireReady && (!request.DebugReady || request.State != "idle" && request.State != "ready" && request.State != "attached") {
		return farmRuntimeRecord{}, false, nil, ErrFarmRuntimeStale
	}
	if request.LaunchMode != "" {
		if _, err := normalizeFarmRuntimeLaunchMode(request.LaunchMode); err != nil {
			return farmRuntimeRecord{}, false, nil, err
		}
	}
	snapshot, err := s.snapshot(request.ProfileID)
	if err != nil {
		return farmRuntimeRecord{}, false, nil, err
	}
	if snapshot == nil || snapshot.Profile == nil || !snapshot.Profile.Running ||
		snapshot.Generation != request.Generation || snapshot.Profile.Pid != request.PID ||
		snapshot.ProfileIncarnation != request.ProfileIncarnation {
		return farmRuntimeRecord{}, false, snapshot, fmt.Errorf("%w: process snapshot", ErrFarmRuntimeStale)
	}
	processStartIdentity, identityErr := s.readProcessStartIdentity(request.PID)
	if identityErr != nil || processStartIdentity == "" || processStartIdentity != request.ProcessStartIdentity {
		return farmRuntimeRecord{}, false, snapshot, fmt.Errorf("%w: process start identity", ErrFarmRuntimeStale)
	}
	record, owned := s.currentRecord(request.ProfileID)
	if owned {
		identity := record.runtime.FarmRuntimeIdentity
		if identity.RuntimeUID != request.RuntimeUID || identity.ProfileID != request.ProfileID ||
			identity.NodeUID != request.NodeUID || identity.ProviderInstanceID != request.ProviderInstanceID ||
			identity.FencingEpoch != request.FencingEpoch || identity.Generation != request.Generation ||
			identity.ConfigHash != request.ConfigHash {
			return farmRuntimeRecord{}, true, snapshot, ErrFarmRuntimeIdentityMismatch
		}
		if record.processStartIdentity != request.ProcessStartIdentity || record.profileIncarnation != request.ProfileIncarnation {
			return farmRuntimeRecord{}, true, snapshot, ErrFarmRuntimeStale
		}
	}
	if s.handoffValidationHook != nil {
		s.handoffValidationHook()
	}
	return record, owned, snapshot, nil
}

// PrepareAdoptRuntime validates all identity/process evidence without changing
// the Agent record.  Server code calls this before its DB lease CAS.
func (s *FarmRuntimeService) PrepareAdoptRuntime(request FarmRuntimeHandoffRequest) (FarmRuntime, error) {
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	release, err := s.acquire(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	_, owned, snapshot, err := s.validateHandoffRequestLocked(request, true)
	if err != nil {
		return FarmRuntime{}, err
	}
	if !owned {
		return FarmRuntime{}, ErrFarmRuntimeUnknown
	}
	controllerID, controllerGeneration := s.controllerBinding()
	runtime := FarmRuntime{
		FarmRuntimeIdentity: FarmRuntimeIdentity{
			NodeUID: request.NodeUID, ProfileID: request.ProfileID, RuntimeUID: request.RuntimeUID,
			ProviderInstanceID: request.ProviderInstanceID, FencingEpoch: request.FencingEpoch,
			ConfigHash: request.ConfigHash, Generation: request.Generation,
			ControllerID: controllerID, ControllerGeneration: controllerGeneration,
		},
		State: FarmRuntimeStateIdle, DebugReady: request.DebugReady, LaunchMode: request.LaunchMode,
		PID: request.PID, ProcessStartIdentity: request.ProcessStartIdentity,
		ProfileIncarnation: request.ProfileIncarnation,
	}
	if snapshot != nil {
		runtime.Profile = farmRuntimeProfileTelemetry(snapshot.Profile)
		runtime.DebugReady = snapshot.Profile.DebugReady
	}
	return runtime, nil
}

// AdoptRuntime publishes an already validated runtime only after the Server's
// authoritative runtime-lease CAS has succeeded.
func (s *FarmRuntimeService) AdoptRuntime(request FarmRuntimeHandoffRequest) (FarmRuntime, error) {
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	release, err := s.acquire(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	record, owned, _, err := s.validateHandoffRequestLocked(request, true)
	if err != nil {
		return FarmRuntime{}, err
	}
	if !owned {
		return FarmRuntime{}, ErrFarmRuntimeUnknown
	}
	controllerID, controllerGeneration := s.controllerBinding()
	if controllerID != request.ControllerID || controllerGeneration != request.ControllerGeneration {
		return FarmRuntime{}, ErrFarmRuntimeStale
	}
	snapshot, err := s.snapshot(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	if snapshot == nil || snapshot.Profile == nil || snapshot.Generation != request.Generation ||
		snapshot.Profile.Pid != request.PID || snapshot.ProfileIncarnation != request.ProfileIncarnation ||
		!snapshot.Profile.Running || !snapshot.Profile.DebugReady {
		return FarmRuntime{}, fmt.Errorf("%w: process changed before adopt", ErrFarmRuntimeStale)
	}
	processStartIdentity, identityErr := s.readProcessStartIdentity(request.PID)
	if identityErr != nil || processStartIdentity != request.ProcessStartIdentity {
		return FarmRuntime{}, fmt.Errorf("%w: process changed before adopt", ErrFarmRuntimeStale)
	}
	runtime := FarmRuntime{
		FarmRuntimeIdentity: FarmRuntimeIdentity{
			NodeUID: request.NodeUID, ProfileID: request.ProfileID, RuntimeUID: request.RuntimeUID,
			ProviderInstanceID: request.ProviderInstanceID, FencingEpoch: request.FencingEpoch,
			ConfigHash: request.ConfigHash, Generation: request.Generation,
			ControllerID: controllerID, ControllerGeneration: controllerGeneration,
		},
		State: FarmRuntimeStateIdle, LaunchMode: request.LaunchMode,
	}
	runtime = farmRuntimeFromSnapshot(farmRuntimeRecord{
		runtime: runtime, processStartIdentity: request.ProcessStartIdentity,
		profileIncarnation: request.ProfileIncarnation, launchMode: request.LaunchMode,
	}, snapshot)
	runtime.State = FarmRuntimeStateIdle
	runtime.DebugReady = true
	record = farmRuntimeRecord{
		runtime: runtime, processStartIdentity: request.ProcessStartIdentity,
		profileIncarnation: request.ProfileIncarnation, launchMode: request.LaunchMode,
		proxyBinding: record.proxyBinding, profileCreatedAt: snapshot.Profile.CreatedAt,
	}
	s.setRecord(request.ProfileID, record)
	if err := s.persistOwnershipProvenance(); err != nil {
		return FarmRuntime{}, err
	}
	return runtime, nil
}

// QuarantineRuntime records no ownership for an unknown process.  For an
// already-owned record it only changes the local state after strict identity
// validation; StopHandoffRuntime performs the destructive operation.
func (s *FarmRuntimeService) QuarantineRuntime(request FarmRuntimeHandoffRequest) (FarmRuntime, error) {
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	release, err := s.acquire(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	record, owned, snapshot, err := s.validateHandoffRequestLocked(request, false)
	if err != nil && !errors.Is(err, ErrFarmRuntimeUnknown) {
		return FarmRuntime{}, err
	}
	if owned {
		record.runtime.State = FarmRuntimeStateQuarantined
		s.setRecord(request.ProfileID, record)
		if err := s.persistOwnershipProvenance(); err != nil {
			return FarmRuntime{}, err
		}
		return record.runtime, nil
	}
	return FarmRuntime{
		FarmRuntimeIdentity: FarmRuntimeIdentity{
			NodeUID: request.NodeUID, ProfileID: request.ProfileID, RuntimeUID: request.RuntimeUID,
			ProviderInstanceID: request.ProviderInstanceID, FencingEpoch: request.FencingEpoch,
			ConfigHash: request.ConfigHash, Generation: request.Generation,
			ControllerID: request.ControllerID, ControllerGeneration: request.ControllerGeneration,
		},
		State: FarmRuntimeStateQuarantined, PID: request.PID, DebugReady: snapshot != nil && snapshot.Profile != nil && snapshot.Profile.DebugReady,
		LaunchMode: request.LaunchMode, ProcessStartIdentity: request.ProcessStartIdentity,
		ProfileIncarnation: request.ProfileIncarnation,
	}, nil
}

// StopHandoffRuntime validates a full authenticated inventory identity and
// closes only that process generation. It never stops another profile or
// treats a port/PID match as ownership.
func (s *FarmRuntimeService) StopHandoffRuntime(request FarmRuntimeHandoffRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	return s.stopHandoffRuntimeLocked(request)
}

func (s *FarmRuntimeService) stopHandoffRuntimeLocked(request FarmRuntimeHandoffRequest) (FarmRuntime, error) {
	release, err := s.acquire(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	record, owned, _, err := s.validateHandoffRequestLocked(request, false)
	if err != nil {
		return FarmRuntime{}, err
	}
	if !owned {
		return FarmRuntime{}, ErrFarmRuntimeUnknown
	}
	s.closeCDPSessionsForRuntime(request.ProfileID, request.Generation)
	if _, err := s.runtimeService.StopIfIdentity(request.ProfileID, request.Generation, request.ProfileIncarnation, request.PID, request.ProcessStartIdentity); err != nil {
		return FarmRuntime{}, fmt.Errorf("%w: stop generation: %v", ErrFarmRuntimeStale, err)
	}
	finalSnapshot, err := s.snapshot(request.ProfileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	if finalSnapshot == nil || finalSnapshot.Profile == nil || finalSnapshot.Profile.Running ||
		finalSnapshot.ProfileIncarnation != request.ProfileIncarnation {
		return FarmRuntime{}, fmt.Errorf("%w: stop was not confirmed", ErrFarmRuntimeStale)
	}
	record.runtime = farmRuntimeFromSnapshot(record, finalSnapshot)
	record.runtime.State = FarmRuntimeStateStopped
	s.setRecord(request.ProfileID, record)
	if err := s.persistOwnershipProvenance(); err != nil {
		return FarmRuntime{}, err
	}
	return record.runtime, nil
}

// ReconcileRuntime performs a Server-authoritative controlled restart.  The
// old identity is used only for the strict stop; the replacement receives the
// target hash/mode and a fresh runtime UID from EnsureRuntime.
func (s *FarmRuntimeService) ReconcileRuntime(request FarmRuntimeReconcileRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	if request.Action != "restart" || strings.TrimSpace(request.TargetConfigHash) == "" || strings.TrimSpace(request.TargetLaunchMode) == "" {
		return FarmRuntime{}, ErrFarmRuntimeConfigMismatch
	}
	if _, err := normalizeFarmRuntimeLaunchMode(request.TargetLaunchMode); err != nil {
		return FarmRuntime{}, err
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	if _, err := s.stopHandoffRuntimeLocked(request.FarmRuntimeHandoffRequest); err != nil {
		return FarmRuntime{}, err
	}
	controllerID, controllerGeneration := s.controllerBinding()
	if controllerID != request.ControllerID || controllerGeneration != request.ControllerGeneration {
		return FarmRuntime{}, ErrFarmRuntimeStale
	}
	if s.controlledRestartEnsureHook != nil {
		s.controlledRestartEnsureHook()
	}
	return s.ensureRuntimeLocked(FarmRuntimeEnsureRequest{
		NodeUID: request.NodeUID, ProfileID: request.ProfileID,
		ProviderInstanceID: request.ProviderInstanceID, FencingEpoch: request.FencingEpoch,
		ConfigHash: request.TargetConfigHash, LaunchMode: request.TargetLaunchMode,
	}, true)
}
