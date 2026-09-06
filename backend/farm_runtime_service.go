package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/google/uuid"
)

// FarmRuntimeState describes the Farm-owned view of a persistent browser
// runtime. A ready runtime is idle between jobs; it is not stopped merely
// because the preceding job finished.
const (
	FarmRuntimeStateStarting = "starting"
	FarmRuntimeStateIdle     = "idle"
	FarmRuntimeStateStopped  = "stopped"
	FarmRuntimeStateCrashed  = "crashed"
	FarmRuntimeStateStale    = "stale"
)

var (
	ErrFarmRuntimeServiceUnavailable = errors.New("farm runtime service unavailable")
	ErrFarmRuntimeIdentityRequired   = errors.New("farm runtime identity is required")
	ErrFarmRuntimeIdentityMismatch   = errors.New("farm runtime identity mismatch")
	ErrFarmRuntimeUnknown            = errors.New("farm runtime is not owned by this service")
	ErrFarmRuntimeNotFound           = errors.New("farm runtime profile not found")
	// ErrFarmRuntimeConfigMismatch is reserved for an opaque server-issued
	// config hash/token mismatch. The Agent never computes or interprets it.
	ErrFarmRuntimeConfigMismatch = errors.New("farm runtime config token mismatch")
	ErrFarmRuntimeStale          = errors.New("farm runtime identity is stale")
	ErrFarmRuntimeCommand        = errors.New("invalid farm runtime command")
)

// FarmRuntimeIdentity is the strict, node-safe identity of one runtime
// instance. DebugPort is deliberately not part of this identity: ports are
// node-local locators and are telemetry only. ConfigHash is an optional,
// opaque server-issued token retained for a later attestation/reconcile
// layer; this Agent never computes or interprets it.
type FarmRuntimeIdentity struct {
	NodeUID            string `json:"node_uid"`
	ProfileID          string `json:"profile_id"`
	RuntimeUID         string `json:"runtime_uid"`
	ProviderInstanceID string `json:"provider_instance_id"`
	FencingEpoch       uint64 `json:"fencing_epoch"`
	ConfigHash         string `json:"config_hash,omitempty"`
	Generation         uint64 `json:"generation"`
}

// FarmRuntime is an immutable response snapshot. Profile is copied by the
// shared BrowserRuntimeService and is never a Manager-owned pointer.
type FarmRuntime struct {
	FarmRuntimeIdentity
	State          string          `json:"state"`
	Profile        *BrowserProfile `json:"profile,omitempty"`
	PID            int             `json:"pid"`
	DebugPort      int             `json:"debug_port"`
	DebugReady     bool            `json:"debug_ready"`
	RuntimeWarning string          `json:"runtime_warning,omitempty"`
	LastError      string          `json:"last_error,omitempty"`
	LastStartAt    string          `json:"last_start_at,omitempty"`
	LastStopAt     string          `json:"last_stop_at,omitempty"`
}

// FarmRuntimeServiceConfig constructs a farm layer around the existing
// BrowserRuntimeService. RuntimeService and NodeID are compatibility aliases
// for callers that use the older naming; if both aliases are supplied they
// must refer to the same object/value.
type FarmRuntimeServiceConfig struct {
	BrowserRuntimeService *BrowserRuntimeService
	RuntimeService        *BrowserRuntimeService
	NodeUID               string
	NodeID                string
	ProviderInstanceID    string
	FencingEpoch          uint64
}

// FarmRuntimeServiceFactoryConfig is the public, Wails-free factory boundary.
// If BrowserRuntimeService is nil, BrowserRuntimeFactory is used to construct
// the one shared lifecycle service. No Farm-specific lifecycle is duplicated.
type FarmRuntimeServiceFactoryConfig struct {
	BrowserRuntimeService *BrowserRuntimeService
	RuntimeService        *BrowserRuntimeService
	BrowserRuntimeFactory BrowserRuntimeServiceFactoryConfig
	NodeUID               string
	NodeID                string
	ProviderInstanceID    string
	FencingEpoch          uint64
}

// FarmRuntimeEnsureRequest identifies the profile and, when supplied, the
// identity expected by the caller. Empty identity fields mean "create or
// reuse the current Farm-owned instance". A non-empty RuntimeUID is always
// checked and can never cause a different runtime to be adopted. ConfigHash
// is an optional opaque server token; it is stored/compared byte-for-byte.
type FarmRuntimeEnsureRequest struct {
	NodeUID            string `json:"node_uid,omitempty"`
	ProfileID          string `json:"profile_id"`
	RuntimeUID         string `json:"runtime_uid,omitempty"`
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	FencingEpoch       uint64 `json:"fencing_epoch,omitempty"`
	ConfigHash         string `json:"config_hash,omitempty"`
	Generation         uint64 `json:"generation,omitempty"`
}

// FarmRuntimeStatusRequest is a read-only selector. Supplying identity fields
// makes the read strict; omitting them reads the currently owned profile
// record, never an arbitrary runtime found on the host.
type FarmRuntimeStatusRequest struct {
	NodeUID            string `json:"node_uid,omitempty"`
	ProfileID          string `json:"profile_id"`
	RuntimeUID         string `json:"runtime_uid,omitempty"`
	ProviderInstanceID string `json:"provider_instance_id,omitempty"`
	FencingEpoch       uint64 `json:"fencing_epoch,omitempty"`
	ConfigHash         string `json:"config_hash,omitempty"`
	Generation         uint64 `json:"generation,omitempty"`
}

// FarmRuntimeSelector is a descriptive alias used by command adapters.
type FarmRuntimeSelector = FarmRuntimeStatusRequest

// FarmRuntimeStopRequest is intentionally stricter than ensure/status. A
// stop must carry the runtime UID/provider/fencing/generation identity so a
// stale command cannot terminate a replacement runtime. ConfigHash is
// optional and, when present on both sides, is compared opaquely.
type FarmRuntimeStopRequest struct {
	NodeUID            string `json:"node_uid,omitempty"`
	ProfileID          string `json:"profile_id"`
	RuntimeUID         string `json:"runtime_uid"`
	ProviderInstanceID string `json:"provider_instance_id"`
	FencingEpoch       uint64 `json:"fencing_epoch"`
	ConfigHash         string `json:"config_hash,omitempty"`
	Generation         uint64 `json:"generation"`
}

// FarmRuntimeCommand is transport-agnostic and mirrors the command portion
// of the P1.7 Control WSS envelope. It contains no websocket or Wails type.
type FarmRuntimeCommand struct {
	Type          string `json:"type,omitempty"`
	NodeUID       string `json:"node_uid,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	Command       string `json:"command"`
	Payload       any    `json:"payload,omitempty"`
}

// FarmRuntimeCommandEnvelope is the explicit P1.7 wire-shaped input for a
// future Control WSS adapter. This service does not open a network client.
type FarmRuntimeCommandEnvelope = FarmRuntimeCommand

// FarmRuntimeCommandResponse is the explicit P1.7 wire-shaped output.
type FarmRuntimeCommandResponse struct {
	Type          string `json:"type"`
	NodeUID       string `json:"node_uid"`
	CorrelationID string `json:"correlation_id"`
	OK            bool   `json:"ok"`
	Payload       any    `json:"payload,omitempty"`
	Error         string `json:"error,omitempty"`
}

type farmRuntimeRecord struct {
	runtime FarmRuntime
}

type farmRuntimeProfileGate struct {
	mu   sync.Mutex
	refs int
}

// FarmRuntimeService owns only runtimes explicitly ensured through this
// instance. It delegates process lifecycle, readiness, crash monitoring and
// cleanup to BrowserRuntimeService. Ownership records are intentionally
// process-local in P1.10: after an Agent restart this layer returns an empty
// inventory and never adopts a runtime from profile Running/PID/port alone.
// Authenticated persistent inventory/reconcile metadata belongs to the later
// Control WSS/fencing gates.
type FarmRuntimeService struct {
	runtimeService   *BrowserRuntimeService
	nodeUID          string
	providerInstance string
	fencingEpoch     uint64

	recordsMu sync.RWMutex
	records   map[string]farmRuntimeRecord

	gatesMu sync.Mutex
	gates   map[string]*farmRuntimeProfileGate
}

// NewFarmRuntimeService constructs the Wails-free Farm lifecycle layer.
func NewFarmRuntimeService(options FarmRuntimeServiceConfig) (*FarmRuntimeService, error) {
	runtimeService := options.BrowserRuntimeService
	if runtimeService != nil && options.RuntimeService != nil && runtimeService != options.RuntimeService {
		return nil, fmt.Errorf("%w: two different BrowserRuntimeService values", ErrFarmRuntimeServiceUnavailable)
	}
	if runtimeService == nil {
		runtimeService = options.RuntimeService
	}
	if runtimeService == nil {
		return nil, fmt.Errorf("%w: BrowserRuntimeService is required", ErrFarmRuntimeServiceUnavailable)
	}
	nodeUID, err := normalizeFarmAlias(options.NodeUID, options.NodeID, "node uid")
	if err != nil {
		return nil, err
	}
	providerInstance := strings.TrimSpace(options.ProviderInstanceID)
	if providerInstance == "" {
		return nil, fmt.Errorf("%w: provider instance id is required", ErrFarmRuntimeServiceUnavailable)
	}
	if options.FencingEpoch == 0 {
		return nil, fmt.Errorf("%w: fencing epoch must be positive", ErrFarmRuntimeServiceUnavailable)
	}
	return &FarmRuntimeService{
		runtimeService:   runtimeService,
		nodeUID:          nodeUID,
		providerInstance: providerInstance,
		fencingEpoch:     options.FencingEpoch,
		records:          make(map[string]farmRuntimeRecord),
		gates:            make(map[string]*farmRuntimeProfileGate),
	}, nil
}

// NewFarmRuntimeServiceForHost creates the shared BrowserRuntimeService via
// its existing public host factory when a caller does not already have one.
func NewFarmRuntimeServiceForHost(options FarmRuntimeServiceFactoryConfig) (*FarmRuntimeService, error) {
	runtimeService := options.BrowserRuntimeService
	if runtimeService != nil && options.RuntimeService != nil && runtimeService != options.RuntimeService {
		return nil, fmt.Errorf("%w: two different BrowserRuntimeService values", ErrFarmRuntimeServiceUnavailable)
	}
	if runtimeService == nil {
		runtimeService = options.RuntimeService
	}
	if runtimeService == nil {
		var err error
		runtimeService, err = NewBrowserRuntimeServiceForHost(options.BrowserRuntimeFactory)
		if err != nil {
			return nil, err
		}
	}
	return NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService: runtimeService,
		NodeUID:               options.NodeUID,
		NodeID:                options.NodeID,
		ProviderInstanceID:    options.ProviderInstanceID,
		FencingEpoch:          options.FencingEpoch,
	})
}

func normalizeFarmAlias(primary, alias, label string) (string, error) {
	primary = strings.TrimSpace(primary)
	alias = strings.TrimSpace(alias)
	if primary != "" && alias != "" && primary != alias {
		return "", fmt.Errorf("%w: conflicting %s values", ErrFarmRuntimeServiceUnavailable, label)
	}
	if primary == "" {
		primary = alias
	}
	if primary == "" {
		return "", fmt.Errorf("%w: %s is required", ErrFarmRuntimeServiceUnavailable, label)
	}
	return primary, nil
}

// NodeUID returns the immutable node identity configured for this service.
func (s *FarmRuntimeService) NodeUID() string {
	if s == nil {
		return ""
	}
	return s.nodeUID
}

// ProviderInstanceID returns the immutable provider-instance identity.
func (s *FarmRuntimeService) ProviderInstanceID() string {
	if s == nil {
		return ""
	}
	return s.providerInstance
}

// FencingEpoch returns the immutable fencing epoch bound to this service.
func (s *FarmRuntimeService) FencingEpoch() uint64 {
	if s == nil {
		return 0
	}
	return s.fencingEpoch
}

func (s *FarmRuntimeService) acquire(profileID string) (func(), error) {
	if s == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return nil, fmt.Errorf("%w: profile id is required", ErrFarmRuntimeIdentityRequired)
	}
	s.gatesMu.Lock()
	gate := s.gates[profileID]
	if gate == nil {
		gate = &farmRuntimeProfileGate{}
		s.gates[profileID] = gate
	}
	gate.refs++
	s.gatesMu.Unlock()
	gate.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			gate.mu.Unlock()
			s.gatesMu.Lock()
			gate.refs--
			if gate.refs == 0 && s.gates[profileID] == gate {
				delete(s.gates, profileID)
			}
			s.gatesMu.Unlock()
		})
	}, nil
}

func (s *FarmRuntimeService) currentRecord(profileID string) (farmRuntimeRecord, bool) {
	s.recordsMu.RLock()
	record, ok := s.records[profileID]
	s.recordsMu.RUnlock()
	return record, ok
}

func (s *FarmRuntimeService) setRecord(profileID string, record farmRuntimeRecord) {
	s.recordsMu.Lock()
	s.records[profileID] = record
	s.recordsMu.Unlock()
}

func (s *FarmRuntimeService) deleteRecord(profileID string) {
	s.recordsMu.Lock()
	delete(s.records, profileID)
	s.recordsMu.Unlock()
}

func (s *FarmRuntimeService) snapshot(profileID string) (*BrowserRuntimeServiceSnapshot, error) {
	if s == nil || s.runtimeService == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	return s.runtimeService.RuntimeSnapshot(profileID)
}

func (s *FarmRuntimeService) validateNode(nodeUID string) error {
	nodeUID = strings.TrimSpace(nodeUID)
	if nodeUID != "" && nodeUID != s.nodeUID {
		return fmt.Errorf("%w: node uid", ErrFarmRuntimeIdentityMismatch)
	}
	return nil
}

func (s *FarmRuntimeService) validateControllerIdentity(nodeUID, provider string, epoch uint64) error {
	if err := s.validateNode(nodeUID); err != nil {
		return err
	}
	if provider != "" && strings.TrimSpace(provider) != s.providerInstance {
		return fmt.Errorf("%w: provider instance", ErrFarmRuntimeIdentityMismatch)
	}
	if epoch != 0 && epoch != s.fencingEpoch {
		return fmt.Errorf("%w: fencing epoch", ErrFarmRuntimeIdentityMismatch)
	}
	return nil
}

func validateOpaqueConfigHash(requested, stored string) error {
	if requested != "" && stored != "" && requested != stored {
		return ErrFarmRuntimeConfigMismatch
	}
	return nil
}

func (s *FarmRuntimeService) validateAgainstRecord(profileID, runtimeUID, provider string, epoch uint64, configHash string, generation uint64, record farmRuntimeRecord) error {
	if err := s.validateControllerIdentity("", provider, epoch); err != nil {
		return err
	}
	identity := record.runtime.FarmRuntimeIdentity
	if identity.ProfileID != profileID {
		return fmt.Errorf("%w: profile", ErrFarmRuntimeIdentityMismatch)
	}
	if runtimeUID != "" && runtimeUID != identity.RuntimeUID {
		return fmt.Errorf("%w: runtime uid", ErrFarmRuntimeIdentityMismatch)
	}
	if err := validateOpaqueConfigHash(configHash, identity.ConfigHash); err != nil {
		return fmt.Errorf("%w: config hash", err)
	}
	if generation != 0 && generation != identity.Generation {
		return fmt.Errorf("%w: generation", ErrFarmRuntimeStale)
	}
	return nil
}

func farmRuntimeFromSnapshot(record farmRuntimeRecord, snapshot *BrowserRuntimeServiceSnapshot) FarmRuntime {
	runtime := record.runtime
	if snapshot == nil || snapshot.Profile == nil {
		if runtime.State != FarmRuntimeStateStopped {
			runtime.State = FarmRuntimeStateCrashed
		}
		return runtime
	}
	profile := copyBrowserProfileSnapshot(snapshot.Profile)
	runtime.Profile = profile
	runtime.PID = profile.Pid
	runtime.DebugPort = profile.DebugPort
	runtime.DebugReady = profile.DebugReady
	runtime.RuntimeWarning = profile.RuntimeWarning
	runtime.LastError = profile.LastError
	runtime.LastStartAt = profile.LastStartAt
	runtime.LastStopAt = profile.LastStopAt
	switch {
	case snapshot.Generation == runtime.Generation && profile.Running:
		runtime.State = FarmRuntimeStateIdle
	case runtime.State == FarmRuntimeStateStopped && !profile.Running:
		runtime.State = FarmRuntimeStateStopped
	case snapshot.Generation == 0 && !profile.Running:
		runtime.State = FarmRuntimeStateCrashed
	default:
		runtime.State = FarmRuntimeStateStale
	}
	return runtime
}

func (s *FarmRuntimeService) refreshRecord(profileID string, record farmRuntimeRecord) (FarmRuntime, error) {
	snapshot, err := s.snapshot(profileID)
	if err != nil {
		if errors.Is(err, ErrFarmRuntimeNotFound) || strings.Contains(err.Error(), "profile not found") {
			s.deleteRecord(profileID)
			return FarmRuntime{}, fmt.Errorf("%w: %s", ErrFarmRuntimeNotFound, profileID)
		}
		return FarmRuntime{}, err
	}
	if snapshot.Profile == nil {
		return FarmRuntime{}, fmt.Errorf("%w: %s", ErrFarmRuntimeNotFound, profileID)
	}
	updated := farmRuntimeFromSnapshot(record, snapshot)
	record.runtime = updated
	s.setRecord(profileID, record)
	return updated, nil
}

// EnsureRuntime idempotently ensures a persistent Farm runtime. A matching
// idle runtime is returned without invoking BrowserRuntimeService.Start; a
// new runtime UID is minted only when the previous record is terminal and the
// caller did not present a stale UID.
func (s *FarmRuntimeService) EnsureRuntime(request FarmRuntimeEnsureRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" {
		return FarmRuntime{}, fmt.Errorf("%w: profile id", ErrFarmRuntimeIdentityRequired)
	}
	if err := s.validateControllerIdentity(request.NodeUID, request.ProviderInstanceID, request.FencingEpoch); err != nil {
		return FarmRuntime{}, err
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()

	record, owned := s.currentRecord(profileID)
	existingActiveGeneration := uint64(0)
	if request.RuntimeUID != "" && !owned {
		return FarmRuntime{}, fmt.Errorf("%w: runtime uid %s", ErrFarmRuntimeUnknown, request.RuntimeUID)
	}
	if owned {
		if err := s.validateAgainstRecord(profileID, request.RuntimeUID, request.ProviderInstanceID, request.FencingEpoch, request.ConfigHash, request.Generation, record); err != nil {
			return FarmRuntime{}, err
		}
		observed, observeErr := s.snapshot(profileID)
		if observeErr != nil {
			return FarmRuntime{}, observeErr
		}
		if observed.Profile.Running && observed.Generation == 0 {
			// A running profile without a generation was not proven by this
			// service. Do not turn it into a Farm runtime implicitly.
			record.runtime.State = FarmRuntimeStateStale
			s.setRecord(profileID, record)
			return FarmRuntime{}, fmt.Errorf("%w: running profile has no shared generation", ErrFarmRuntimeStale)
		}
		if observed.Generation != 0 && observed.Generation != record.runtime.Generation {
			// A different active generation was not created by this record. Do
			// not adopt it and, critically, do not stop it.
			record.runtime.State = FarmRuntimeStateStale
			s.setRecord(profileID, record)
			return FarmRuntime{}, fmt.Errorf("%w: generation", ErrFarmRuntimeStale)
		}
		existingActiveGeneration = observed.Generation
		if record.runtime.State == FarmRuntimeStateIdle && observed.Generation == record.runtime.Generation && observed.Profile.Running {
			return farmRuntimeFromSnapshot(record, observed), nil
		}
		if request.RuntimeUID != "" {
			return FarmRuntime{}, fmt.Errorf("%w: terminal runtime cannot be reused", ErrFarmRuntimeStale)
		}
	}

	profile, startErr := s.runtimeService.Start(profileID)
	if startErr != nil && (profile == nil || !profile.Running) {
		return FarmRuntime{}, startErr
	}
	observed, observeErr := s.snapshot(profileID)
	if observeErr != nil {
		return FarmRuntime{}, errors.Join(startErr, observeErr)
	}
	if observed.Generation == 0 || observed.Profile == nil || !observed.Profile.Running {
		return FarmRuntime{}, errors.Join(startErr, fmt.Errorf("%w: shared service returned no active generation", ErrFarmRuntimeServiceUnavailable))
	}
	if owned && existingActiveGeneration != 0 && observed.Generation == record.runtime.Generation {
		// A terminal record must not silently reuse its old UID even if the
		// shared service reported the same generation unexpectedly.
		return FarmRuntime{}, fmt.Errorf("%w: generation was not advanced", ErrFarmRuntimeStale)
	}
	if owned && existingActiveGeneration != 0 && observed.Generation != existingActiveGeneration {
		return FarmRuntime{}, fmt.Errorf("%w: replacement generation", ErrFarmRuntimeStale)
	}
	runtime := FarmRuntime{
		FarmRuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:            s.nodeUID,
			ProfileID:          profileID,
			RuntimeUID:         uuid.NewString(),
			ProviderInstanceID: s.providerInstance,
			FencingEpoch:       s.fencingEpoch,
			ConfigHash:         request.ConfigHash,
			Generation:         observed.Generation,
		},
		State: FarmRuntimeStateIdle,
	}
	runtime = farmRuntimeFromSnapshot(farmRuntimeRecord{runtime: runtime}, observed)
	s.setRecord(profileID, farmRuntimeRecord{runtime: runtime})
	if startErr != nil {
		return runtime, startErr
	}
	return runtime, nil
}

// RuntimeStatus observes only a Farm-owned runtime. It deliberately uses the
// shared service's non-adopting RuntimeSnapshot rather than Status.
func (s *FarmRuntimeService) RuntimeStatus(request FarmRuntimeStatusRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" {
		return FarmRuntime{}, fmt.Errorf("%w: profile id", ErrFarmRuntimeIdentityRequired)
	}
	if err := s.validateControllerIdentity(request.NodeUID, request.ProviderInstanceID, request.FencingEpoch); err != nil {
		return FarmRuntime{}, err
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	record, owned := s.currentRecord(profileID)
	if !owned {
		return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeUnknown, profileID)
	}
	if err := s.validateAgainstRecord(profileID, request.RuntimeUID, request.ProviderInstanceID, request.FencingEpoch, request.ConfigHash, request.Generation, record); err != nil {
		return FarmRuntime{}, err
	}
	runtime, err := s.refreshRecord(profileID, record)
	if err != nil {
		return FarmRuntime{}, err
	}
	if runtime.State == FarmRuntimeStateStale {
		return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeStale, profileID)
	}
	return runtime, nil
}

// StopRuntime is the explicit-only stop operation. It never calls the global
// BrowserRuntimeService.Shutdown and therefore cannot affect other Wails
// sessions or profiles not owned by this FarmRuntimeService.
func (s *FarmRuntimeService) StopRuntime(request FarmRuntimeStopRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" || strings.TrimSpace(request.RuntimeUID) == "" || strings.TrimSpace(request.ProviderInstanceID) == "" || request.FencingEpoch == 0 || request.Generation == 0 {
		return FarmRuntime{}, ErrFarmRuntimeIdentityRequired
	}
	if err := s.validateControllerIdentity(request.NodeUID, request.ProviderInstanceID, request.FencingEpoch); err != nil {
		return FarmRuntime{}, err
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	defer release()
	record, owned := s.currentRecord(profileID)
	if !owned {
		return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeUnknown, profileID)
	}
	if err := s.validateAgainstRecord(profileID, request.RuntimeUID, request.ProviderInstanceID, request.FencingEpoch, request.ConfigHash, request.Generation, record); err != nil {
		return FarmRuntime{}, err
	}
	if record.runtime.State == FarmRuntimeStateStopped {
		return record.runtime, nil
	}
	observed, err := s.snapshot(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	if observed.Generation != record.runtime.Generation {
		record.runtime.State = FarmRuntimeStateStale
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: generation", ErrFarmRuntimeStale)
	}
	if !observed.Profile.Running {
		record.runtime.State = FarmRuntimeStateCrashed
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: runtime is no longer running", ErrFarmRuntimeStale)
	}
	if _, err := s.runtimeService.StopIfGeneration(profileID, record.runtime.Generation); err != nil {
		if errors.Is(err, ErrBrowserRuntimeGenerationMismatch) {
			record.runtime.State = FarmRuntimeStateStale
			s.setRecord(profileID, record)
			return FarmRuntime{}, fmt.Errorf("%w: generation", ErrFarmRuntimeStale)
		}
		return FarmRuntime{}, err
	}
	finalSnapshot, err := s.snapshot(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	record.runtime = farmRuntimeFromSnapshot(record, finalSnapshot)
	record.runtime.State = FarmRuntimeStateStopped
	s.setRecord(profileID, record)
	return record.runtime, nil
}

// Stop is a short alias for callers that expose the service as a lifecycle
// object rather than a command handler.
func (s *FarmRuntimeService) Stop(request FarmRuntimeStopRequest) (FarmRuntime, error) {
	return s.StopRuntime(request)
}

// InventoryWithError lists only records created by this service's successful
// ensure path. Unknown Manager profiles and arbitrary local Chrome processes
// are never enumerated or represented as Farm runtimes.
func (s *FarmRuntimeService) InventoryWithError() ([]FarmRuntime, error) {
	if s == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	s.recordsMu.RLock()
	profileIDs := make([]string, 0, len(s.records))
	for profileID := range s.records {
		profileIDs = append(profileIDs, profileID)
	}
	s.recordsMu.RUnlock()
	sort.Strings(profileIDs)
	result := make([]FarmRuntime, 0, len(profileIDs))
	for _, profileID := range profileIDs {
		release, err := s.acquire(profileID)
		if err != nil {
			return nil, err
		}
		record, ok := s.currentRecord(profileID)
		if !ok {
			release()
			continue
		}
		runtime, err := s.refreshRecord(profileID, record)
		release()
		if errors.Is(err, ErrFarmRuntimeNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		result = append(result, runtime)
	}
	return result, nil
}

// Inventory is a convenient read-only form for UI adapters. Use
// InventoryWithError when the caller needs to distinguish service failure.
func (s *FarmRuntimeService) Inventory() []FarmRuntime {
	result, err := s.InventoryWithError()
	if err != nil {
		return nil
	}
	return result
}

// RuntimeInventory is an explicit-error alias suitable for future Agent
// inventory commands.
func (s *FarmRuntimeService) RuntimeInventory() ([]FarmRuntime, error) {
	return s.InventoryWithError()
}

func decodeFarmCommandPayload(payload any, target any) error {
	var raw []byte
	switch value := payload.(type) {
	case nil:
		raw = []byte(`{}`)
	case json.RawMessage:
		raw = append([]byte(nil), value...)
	case []byte:
		raw = append([]byte(nil), value...)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("%w: payload is not JSON-safe", ErrFarmRuntimeCommand)
		}
		raw = encoded
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: payload: %v", ErrFarmRuntimeCommand, err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("%w: payload has trailing values", ErrFarmRuntimeCommand)
		}
		return fmt.Errorf("%w: payload: %v", ErrFarmRuntimeCommand, err)
	}
	return nil
}

// HandleCommand dispatches the four P1.10 commands without knowing how the
// command arrived. Business errors are returned as ok=false so a WSS adapter
// can preserve command correlation; malformed payloads return a Go error.
func (s *FarmRuntimeService) HandleCommand(command FarmRuntimeCommand) (FarmRuntimeCommandResponse, error) {
	if s == nil {
		return FarmRuntimeCommandResponse{}, ErrFarmRuntimeServiceUnavailable
	}
	if command.Type != "" && command.Type != "command" {
		return FarmRuntimeCommandResponse{}, fmt.Errorf("%w: type", ErrFarmRuntimeCommand)
	}
	if err := s.validateNode(command.NodeUID); err != nil {
		return FarmRuntimeCommandResponse{}, err
	}
	name := strings.TrimSpace(command.Command)
	if name == "" {
		return FarmRuntimeCommandResponse{}, fmt.Errorf("%w: command is required", ErrFarmRuntimeCommand)
	}
	response := FarmRuntimeCommandResponse{Type: "command_response", NodeUID: s.nodeUID, CorrelationID: command.CorrelationID}
	switch name {
	case "ensure_runtime":
		var request FarmRuntimeEnsureRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.EnsureRuntime(request)
		if err != nil {
			response.Error = err.Error()
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "runtime_status":
		var request FarmRuntimeStatusRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.RuntimeStatus(request)
		if err != nil {
			response.Error = err.Error()
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "stop_runtime":
		var request FarmRuntimeStopRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.StopRuntime(request)
		if err != nil {
			response.Error = err.Error()
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "inventory":
		var request struct{}
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		inventory, err := s.InventoryWithError()
		if err != nil {
			response.Error = err.Error()
			return response, nil
		}
		response.OK = true
		response.Payload = inventory
	default:
		response.Error = fmt.Sprintf("%s: unknown command %q", ErrFarmRuntimeCommand, name)
	}
	return response, nil
}

// HandleCommandEnvelope is the explicit envelope-named entry point for a
// future Control WSS adapter. It intentionally has no transport dependency;
// the request and response fields remain the wire-compatible command shape.
func (s *FarmRuntimeService) HandleCommandEnvelope(envelope FarmRuntimeCommandEnvelope) (FarmRuntimeCommandResponse, error) {
	return s.HandleCommand(envelope)
}

// DispatchCommand is a response-only convenience for transports that want
// malformed commands represented as a normal failed command response.
func (s *FarmRuntimeService) DispatchCommand(command FarmRuntimeCommand) FarmRuntimeCommandResponse {
	response, err := s.HandleCommand(command)
	if err != nil {
		return FarmRuntimeCommandResponse{
			Type:          "command_response",
			NodeUID:       s.NodeUID(),
			CorrelationID: command.CorrelationID,
			Error:         err.Error(),
		}
	}
	return response
}
