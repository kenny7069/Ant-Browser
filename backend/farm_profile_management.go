package backend

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

var ErrFarmClientProfileInUseUnowned = errors.New("profile is in use by an unowned browser")
var ErrFarmClientProfileFarmOwned = errors.New("profile lifecycle is owned by an active farm runtime")

// FarmClientManagedProfile is the complete local IPC lifecycle projection. It
// deliberately excludes process IDs, debug ports, paths, launch arguments and
// profile configuration.
type FarmClientManagedProfile struct {
	FarmClientProfileProjection
	Running    bool   `json:"running"`
	Generation uint64 `json:"generation"`
}

type farmProfileManagement struct{ host *FarmClientHost }

func newFarmProfileManagement(host *FarmClientHost) (*farmProfileManagement, error) {
	if host == nil || host.manager == nil || host.runtime == nil {
		return nil, ErrFarmClientIPCUnavailable
	}
	return &farmProfileManagement{host: host}, nil
}

func (management *farmProfileManagement) List() ([]FarmClientProfileProjection, error) {
	return management.host.ProfileList()
}

func (management *farmProfileManagement) Status(profileID string) (FarmClientManagedProfile, error) {
	return management.observeOwned(profileID)
}

func (management *farmProfileManagement) Open(profileID string) (FarmClientManagedProfile, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return FarmClientManagedProfile{}, ErrFarmClientProfileNotFound
	}
	if record, farmOwned := management.farmRecord(profileID); farmOwned {
		if record.runtime.State == FarmRuntimeStateIdle || record.runtime.State == FarmRuntimeStateStarting {
			return management.Status(profileID)
		}
		return FarmClientManagedProfile{}, ErrFarmClientProfileFarmOwned
	}
	releaseAdmission, err := management.host.runtime.acquireStartAdmission()
	if err != nil {
		return FarmClientManagedProfile{}, err
	}
	defer releaseAdmission()
	var result FarmClientManagedProfile
	_, err = management.host.runtime.withProfileResult(profileID, func(host BrowserRuntimeHost) (*BrowserProfile, error) {
		if err := management.rejectUnownedLocked(profileID); err != nil {
			return nil, err
		}
		profile, err := management.host.runtime.startLocked(host, BrowserRuntimeStartRequest{ProfileID: profileID})
		if err != nil {
			return profile, err
		}
		projection, err := farmClientProjection(profile)
		if err != nil {
			return profile, err
		}
		result = FarmClientManagedProfile{FarmClientProfileProjection: projection, Running: profile.Running, Generation: management.host.runtime.Generation(profileID)}
		return profile, nil
	})
	return result, err
}

func (management *farmProfileManagement) Stop(profileID string) (FarmClientManagedProfile, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return FarmClientManagedProfile{}, ErrFarmClientProfileNotFound
	}
	if record, farmOwned := management.farmRecord(profileID); farmOwned {
		return management.stopFarmOwned(profileID, record)
	}
	var result FarmClientManagedProfile
	profile, err := management.host.runtime.withProfileResult(profileID, func(host BrowserRuntimeHost) (*BrowserProfile, error) {
		if err := management.rejectUnownedLocked(profileID); err != nil {
			return nil, err
		}
		if !management.locallyOwnedLocked(profileID) {
			return management.host.runtime.profileSnapshot(profileID)
		}
		return management.host.runtime.stopLocked(host, profileID)
	})
	if err != nil {
		return result, err
	}
	projection, err := farmClientProjection(profile)
	if err != nil {
		return result, err
	}
	result = FarmClientManagedProfile{FarmClientProfileProjection: projection, Running: profile.Running, Generation: management.host.runtime.Generation(profileID)}
	return result, nil
}

func (management *farmProfileManagement) Pair(ctx context.Context, profileID, code string) (FarmClientPairingResult, error) {
	return management.host.PairProfile(ctx, profileID, code, nil)
}

func (management *farmProfileManagement) Unpair(ctx context.Context, profileID string) (FarmClientPairingResult, error) {
	return management.host.UnpairProfile(ctx, profileID, nil)
}

func (management *farmProfileManagement) observeOwned(profileID string) (FarmClientManagedProfile, error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return FarmClientManagedProfile{}, ErrFarmClientProfileNotFound
	}
	var result FarmClientManagedProfile
	_, err := management.host.runtime.withProfileResult(profileID, func(BrowserRuntimeHost) (*BrowserProfile, error) {
		if err := management.rejectUnownedLocked(profileID); err != nil {
			return nil, err
		}
		profile, err := management.host.runtime.profileSnapshot(profileID)
		if err != nil {
			return nil, err
		}
		projection, err := farmClientProjection(profile)
		if err != nil {
			return nil, err
		}
		result = FarmClientManagedProfile{FarmClientProfileProjection: projection, Running: profile.Running, Generation: management.host.runtime.Generation(profileID)}
		return profile, nil
	})
	return result, err
}

// rejectUnownedLocked runs while BrowserRuntimeService's per-profile gate is
// held. That makes the observation and subsequent start/stop decision atomic
// with every lifecycle operation admitted by this Host.
func (management *farmProfileManagement) rejectUnownedLocked(profileID string) error {
	manager := management.host.manager
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return ErrFarmClientProfileNotFound
	}
	running := profile.Running
	userDataDir := manager.ResolveUserDataDir(profile)
	manager.Mutex.Unlock()
	if management.locallyOwnedLocked(profileID) {
		return nil
	}
	if _, ok := management.farmRecord(profileID); ok {
		return nil
	}
	if running {
		return ErrFarmClientProfileInUseUnowned
	}
	if _, ok := management.host.runtime.detectRuntime(userDataDir); ok {
		return ErrFarmClientProfileInUseUnowned
	}
	return nil
}

func (management *farmProfileManagement) locallyOwnedLocked(profileID string) bool {
	if process := management.host.runtime.processFor(profileID); process != nil && process.owner != nil {
		return true
	}
	return false
}

func (management *farmProfileManagement) farmRecord(profileID string) (farmRuntimeRecord, bool) {
	if management.host.farm == nil {
		return farmRuntimeRecord{}, false
	}
	return management.host.farm.currentRecord(profileID)
}

func (management *farmProfileManagement) stopFarmOwned(profileID string, record farmRuntimeRecord) (FarmClientManagedProfile, error) {
	farm := management.host.farm
	controllerID, controllerGeneration := farm.controllerBinding()
	farm.resourceTelemetryMu.Lock()
	telemetrySequence, telemetryObservedAt := farm.latestResourceSequence, farm.latestResourceObservedAt
	farm.resourceTelemetryMu.Unlock()
	_, err := farm.StopRuntime(FarmRuntimeStopRequest{
		Provider: "farm", NodeUID: record.runtime.NodeUID, ProfileID: profileID,
		RuntimeUID: record.runtime.RuntimeUID, ProviderInstanceID: record.runtime.ProviderInstanceID,
		FencingEpoch: record.runtime.FencingEpoch, ConfigHash: record.runtime.ConfigHash,
		Generation: record.runtime.Generation, PID: record.runtime.PID,
		ProcessStartIdentity: record.processStartIdentity, ProfileIncarnation: record.profileIncarnation,
		ControllerID: controllerID, ControllerGeneration: controllerGeneration,
		TelemetrySequence: telemetrySequence, TelemetryObservedAt: telemetryObservedAt,
	})
	if err != nil {
		return FarmClientManagedProfile{}, err
	}
	return management.observeOwned(profileID)
}

func farmClientIPCErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrFarmClientIPCInvalid):
		return "INVALID_REQUEST"
	case errors.Is(err, ErrFarmClientProfileInUseUnowned):
		return "PROFILE_IN_USE_UNOWNED"
	case errors.Is(err, ErrFarmClientProfileFarmOwned):
		return "FARM_OWNED_CONFLICT"
	case errors.Is(err, ErrFarmClientProfileNotFound):
		return "PROFILE_NOT_FOUND"
	case errors.Is(err, ErrFarmClientPairingRejected):
		return "PAIRING_REJECTED"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "DEADLINE_EXCEEDED"
	default:
		return "OPERATION_FAILED"
	}
}

func farmClientIPCRemoteError(code string) error {
	switch code {
	case "INVALID_REQUEST":
		return ErrFarmClientIPCInvalid
	case "PROFILE_IN_USE_UNOWNED":
		return ErrFarmClientProfileInUseUnowned
	case "FARM_OWNED_CONFLICT":
		return ErrFarmClientProfileFarmOwned
	case "PROFILE_NOT_FOUND":
		return ErrFarmClientProfileNotFound
	case "PAIRING_REJECTED":
		return ErrFarmClientPairingRejected
	case "DEADLINE_EXCEEDED":
		return context.DeadlineExceeded
	case "OPERATION_FAILED":
		return fmt.Errorf("%w: operation failed", ErrFarmClientIPCUnavailable)
	default:
		return ErrFarmClientIPCInvalid
	}
}
