package backend

import (
	"bytes"
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
	FarmRuntimeStateStarting    = "starting"
	FarmRuntimeStateIdle        = "idle"
	FarmRuntimeStateQuarantined = "quarantined"
	FarmRuntimeStateStopped     = "stopped"
	FarmRuntimeStateCrashed     = "crashed"
	FarmRuntimeStateStale       = "stale"
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
	// ErrFarmRuntimeLocalProxyBinding is a local connector-store refusal, not a
	// Server config mismatch.  In particular it must never trigger a Server
	// controlled-restart of an already-owned runtime.
	ErrFarmRuntimeLocalProxyBinding = errors.New("farm runtime local proxy binding rejected")
	ErrFarmRuntimeStale             = errors.New("farm runtime identity is stale")
	ErrFarmRuntimeCommand           = errors.New("invalid farm runtime command")
	ErrFarmRuntimeLaunchMode        = errors.New("farm runtime launch mode is invalid")
)

const (
	maxFarmRuntimeEnvelopeBytes = 64 * 1024
	maxFarmRuntimeCorrelationID = 128
	// FarmRuntimeLaunchModeDirectNoProxy is the explicit no-proxy path.
	FarmRuntimeLaunchModeDirectNoProxy = "direct_no_proxy"
	// FarmRuntimeLaunchModeProfileProxy starts the existing local profile
	// connector. Its wire binding is deliberately secret-free: the Agent reads
	// raw proxy material only from its existing local profile/config store.
	FarmRuntimeLaunchModeProfileProxy = "profile_proxy"
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
	// Controller binding is populated only when the Control Plane has issued
	// an authoritative controller lease. It is optional for older lifecycle
	// commands, but mandatory at the strict P1.14 CDP boundary when configured.
	ControllerID         string `json:"controller_id,omitempty"`
	ControllerGeneration uint64 `json:"controller_generation,omitempty"`
}

// FarmRuntimeProfile is the allowlisted profile telemetry exposed by the Farm
// boundary. LaunchArgs is retained as an in-process compatibility field for
// existing callers, but is deliberately excluded from JSON/wire output. No
// user-data path, proxy, launch code, fingerprint, or raw error is exported.
type FarmRuntimeProfile struct {
	ProfileId      string   `json:"profileId"`
	ProfileName    string   `json:"profileName"`
	CoreId         string   `json:"coreId,omitempty"`
	Running        bool     `json:"running"`
	DebugPort      int      `json:"debugPort"`
	DebugReady     bool     `json:"debugReady"`
	Pid            int      `json:"pid"`
	RuntimeWarning string   `json:"-"`
	LastStartAt    string   `json:"lastStartAt,omitempty"`
	LastStopAt     string   `json:"lastStopAt,omitempty"`
	LaunchArgs     []string `json:"-"`
}

// FarmRuntime is an immutable response snapshot. Profile is an allowlisted
// detached telemetry value and never a Manager-owned pointer.
type FarmRuntime struct {
	FarmRuntimeIdentity
	State                string              `json:"state"`
	Profile              *FarmRuntimeProfile `json:"profile,omitempty"`
	PID                  int                 `json:"pid"`
	DebugPort            int                 `json:"debug_port"`
	DebugReady           bool                `json:"debug_ready"`
	RuntimeWarning       string              `json:"runtime_warning,omitempty"`
	LastError            string              `json:"last_error,omitempty"`
	LastStartAt          string              `json:"last_start_at,omitempty"`
	LastStopAt           string              `json:"last_stop_at,omitempty"`
	LaunchMode           string              `json:"launch_mode"`
	ProcessStartIdentity string              `json:"process_start_identity,omitempty"`
	ProfileIncarnation   string              `json:"profile_incarnation,omitempty"`
}

// MarshalJSON is an additional wire fence for records assembled by older
// callers or tests. The Farm response never serializes raw lifecycle errors
// or warnings even if an internal value was populated before the telemetry
// allowlist was introduced.
func (runtime FarmRuntime) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		FarmRuntimeIdentity
		State                string              `json:"state"`
		Profile              *FarmRuntimeProfile `json:"profile,omitempty"`
		PID                  int                 `json:"pid"`
		DebugPort            int                 `json:"debug_port"`
		DebugReady           bool                `json:"debug_ready"`
		LastStartAt          string              `json:"last_start_at,omitempty"`
		LastStopAt           string              `json:"last_stop_at,omitempty"`
		LaunchMode           string              `json:"launch_mode"`
		ProcessStartIdentity string              `json:"process_start_identity,omitempty"`
		ProfileIncarnation   string              `json:"profile_incarnation,omitempty"`
	}{
		FarmRuntimeIdentity:  runtime.FarmRuntimeIdentity,
		State:                runtime.State,
		Profile:              runtime.Profile,
		PID:                  runtime.PID,
		DebugPort:            runtime.DebugPort,
		DebugReady:           runtime.DebugReady,
		LastStartAt:          runtime.LastStartAt,
		LastStopAt:           runtime.LastStopAt,
		LaunchMode:           runtime.LaunchMode,
		ProcessStartIdentity: runtime.ProcessStartIdentity,
		ProfileIncarnation:   runtime.ProfileIncarnation,
	})
}

// farmRuntimeWirePayload is the deliberately small set of values that the
// command response is allowed to put on the wire. Keep this type switch
// explicit: an exported any field is useful for compatibility with existing
// handlers, but it must not become an arbitrary JSON serialization boundary.
func farmRuntimeWirePayload(payload any) (any, error) {
	switch typed := payload.(type) {
	case nil:
		return nil, nil
	case FarmRuntime:
		return typed, nil
	case *FarmRuntime:
		if typed == nil {
			return nil, nil
		}
		return typed, nil
	case []FarmRuntime:
		return typed, nil
	case []*FarmRuntime:
		return typed, nil
	case FarmRuntimeInventorySnapshot:
		return typed, nil
	case *FarmRuntimeInventorySnapshot:
		if typed == nil {
			return nil, nil
		}
		return typed, nil
	case FarmRuntimeProfile:
		return typed, nil
	case *FarmRuntimeProfile:
		if typed == nil {
			return nil, nil
		}
		return typed, nil
	case []FarmRuntimeProfile:
		return typed, nil
	case []*FarmRuntimeProfile:
		return typed, nil
	case FarmAttestationResponse:
		return typed, nil
	case *FarmAttestationResponse:
		if typed == nil {
			return nil, nil
		}
		return typed, nil
	case FarmCDPTunnelReady:
		return typed, nil
	case *FarmCDPTunnelReady:
		if typed == nil {
			return nil, nil
		}
		return typed, nil
	default:
		return nil, fmt.Errorf("%w: response payload type is not allowlisted", ErrFarmRuntimeCommand)
	}
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
	ControllerID          string
	ControllerGeneration  uint64
	// CDPOpenHook is intentionally nil in production. Tests may use the
	// bounded stage notifications to force validate/dial/publish races without
	// changing lifecycle semantics.
	CDPOpenHook func(stage string)
	// AttestationStateProvider is a local Agent/host callback. A nil callback
	// makes the attestation command fail closed as not-ready.
	AttestationStateProvider func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error)
	// ProxyBindingVerifier is the local profile/connector fence for
	// profile_proxy. It receives no secret from the wire and must inspect the
	// existing local binding before lifecycle work starts. A nil verifier makes
	// authenticated proxy mode fail closed.
	ProxyBindingVerifier func(profileID string, binding FarmRuntimeProxyBinding) error
	// ProxyRuntimeCleanup is only supplied by the Wails-free factory that owns
	// the connector managers. It must be a no-op for App-shared services.
	ProxyRuntimeCleanup func()
	// ResourceTelemetryHooks contains only host-local measurement callbacks.
	// The wire projection is built by FarmRuntimeService and never carries the
	// callback or arbitrary host errors.
	ResourceTelemetryHooks *FarmResourceTelemetryHooks
	OwnershipStore         FarmRuntimeOwnershipStore
}

// FarmRuntimeServiceFactoryConfig is the public, Wails-free factory boundary.
// If BrowserRuntimeService is nil, BrowserRuntimeFactory is used to construct
// the one shared lifecycle service. No Farm-specific lifecycle is duplicated.
type FarmRuntimeServiceFactoryConfig struct {
	BrowserRuntimeService    *BrowserRuntimeService
	RuntimeService           *BrowserRuntimeService
	BrowserRuntimeFactory    BrowserRuntimeServiceFactoryConfig
	NodeUID                  string
	NodeID                   string
	ProviderInstanceID       string
	FencingEpoch             uint64
	ControllerID             string
	ControllerGeneration     uint64
	CDPOpenHook              func(stage string)
	AttestationStateProvider func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error)
	ProxyBindingVerifier     func(profileID string, binding FarmRuntimeProxyBinding) error
	ProxyRuntimeCleanup      func()
	ResourceTelemetryHooks   *FarmResourceTelemetryHooks
	OwnershipStore           FarmRuntimeOwnershipStore
}

// FarmRuntimeEnsureRequest identifies the profile and, when supplied, the
// identity expected by the caller. Empty identity fields mean "create or
// reuse the current Farm-owned instance". A non-empty RuntimeUID is always
// checked and can never cause a different runtime to be adopted. ConfigHash
// is an optional opaque server token; it is stored/compared byte-for-byte.
type FarmRuntimeEnsureRequest struct {
	NodeUID            string                   `json:"node_uid,omitempty"`
	ProfileID          string                   `json:"profile_id"`
	RuntimeUID         string                   `json:"runtime_uid,omitempty"`
	ProviderInstanceID string                   `json:"provider_instance_id,omitempty"`
	FencingEpoch       uint64                   `json:"fencing_epoch,omitempty"`
	ConfigHash         string                   `json:"config_hash,omitempty"`
	Generation         uint64                   `json:"generation,omitempty"`
	LaunchMode         string                   `json:"launch_mode,omitempty"`
	Proxy              *FarmRuntimeProxyBinding `json:"proxy,omitempty"`
}

// FarmRuntimeProxyBinding is the closed, secret-free Server→Agent assertion
// for a profile-owned authenticated proxy. It is never a proxy locator or a
// credential transport: raw URI, username, password, config path and Chrome
// args have no representation here.
type FarmRuntimeProxyBinding struct {
	Enabled            bool   `json:"enabled"`
	ConnectorType      string `json:"connector_type"`
	CredentialRevision string `json:"credential_revision"`
	ConfigRevision     string `json:"config_revision"`
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
	Provider             string `json:"provider"`
	NodeUID              string `json:"node_uid,omitempty"`
	ProfileID            string `json:"profile_id"`
	RuntimeUID           string `json:"runtime_uid"`
	ProviderInstanceID   string `json:"provider_instance_id"`
	FencingEpoch         uint64 `json:"fencing_epoch"`
	ConfigHash           string `json:"config_hash,omitempty"`
	Generation           uint64 `json:"generation"`
	PID                  int    `json:"pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
	ControllerID         string `json:"controller_id"`
	ControllerGeneration uint64 `json:"controller_generation"`
	TelemetrySequence    uint64 `json:"telemetry_sequence"`
	TelemetryObservedAt  string `json:"telemetry_observed_at"`
}

// FarmRuntimeHandoffRequest is the authenticated inventory evidence used by
// controller reconcile.  It is intentionally separate from
// FarmRuntimeStopRequest: stale/unknown runtimes may be stopped by a new
// controller only after complete process identity validation, without
// pretending their old fencing epoch is current or minting a lease.
type FarmRuntimeHandoffRequest struct {
	Provider             string `json:"provider"`
	NodeUID              string `json:"node_uid"`
	ProfileID            string `json:"profile_id"`
	RuntimeUID           string `json:"runtime_uid"`
	ProviderInstanceID   string `json:"provider_instance_id"`
	FencingEpoch         uint64 `json:"fencing_epoch"`
	ConfigHash           string `json:"config_hash"`
	Generation           uint64 `json:"generation"`
	PID                  int    `json:"pid"`
	ProcessStartIdentity string `json:"process_start_identity"`
	ProfileIncarnation   string `json:"profile_incarnation"`
	ControllerID         string `json:"controller_id"`
	ControllerGeneration uint64 `json:"controller_generation"`
	State                string `json:"state,omitempty"`
	DebugReady           bool   `json:"debug_ready,omitempty"`
	LaunchMode           string `json:"launch_mode,omitempty"`
}

type FarmRuntimeReconcileRequest struct {
	Action           string `json:"action"`
	TargetConfigHash string `json:"target_config_hash,omitempty"`
	TargetPolicyHash string `json:"target_policy_hash,omitempty"`
	TargetLaunchMode string `json:"target_launch_mode,omitempty"`
	FarmRuntimeHandoffRequest
}

// FarmRuntimeInventorySnapshot is used only by the handoff inventory command.
// The legacy inventory command remains a plain list for P1.12 compatibility.
type FarmRuntimeInventorySnapshot struct {
	ConnectionGeneration uint64        `json:"connection_generation"`
	Inventory            []FarmRuntime `json:"inventory"`
}

// FarmRuntimeControllerBindingRequest projects the newly authenticated
// Server controller onto the Agent before an inventory snapshot is read.
// It is deliberately a command rather than a local config update: only the
// authenticated Control WSS session may advance this binding.
type FarmRuntimeControllerBindingRequest struct {
	ControllerID         string `json:"controller_id"`
	ControllerGeneration uint64 `json:"controller_generation"`
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

func farmRuntimeStableErrorMessage(message string) string {
	switch message {
	case ErrFarmRuntimeServiceUnavailable.Error(),
		ErrFarmRuntimeIdentityRequired.Error(),
		ErrFarmRuntimeIdentityMismatch.Error(),
		ErrFarmRuntimeUnknown.Error(),
		ErrFarmRuntimeNotFound.Error(),
		ErrFarmRuntimeConfigMismatch.Error(),
		ErrFarmRuntimeStale.Error(),
		ErrFarmRuntimeCommand.Error(),
		ErrFarmRuntimeLaunchMode.Error(),
		ErrFarmAttestationInvalid.Error(),
		ErrFarmAttestationNotReady.Error(),
		ErrFarmAttestationTokenMismatch.Error(),
		ErrFarmAttestationStructuredMismatch.Error(),
		ErrFarmAttestationIdentityMismatch.Error(),
		ErrFarmAttestationUnownedRestart.Error():
		return message
	case ErrFarmCDPRequestInvalid.Error(),
		ErrFarmCDPReplay.Error(),
		ErrFarmCDPIdentity.Error(),
		ErrFarmCDPNotReady.Error():
		return message
	default:
		return ErrFarmRuntimeCommand.Error()
	}
}

// MarshalJSON prevents a direct caller from putting an arbitrary wrapped Go
// error (which may contain a path, command line, or credential) on the wire.
func (response FarmRuntimeCommandResponse) MarshalJSON() ([]byte, error) {
	payload, err := farmRuntimeWirePayload(response.Payload)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Type          string `json:"type"`
		NodeUID       string `json:"node_uid"`
		CorrelationID string `json:"correlation_id"`
		OK            bool   `json:"ok"`
		Payload       any    `json:"payload,omitempty"`
		Error         string `json:"error,omitempty"`
	}{
		Type:          "command_response",
		NodeUID:       response.NodeUID,
		CorrelationID: response.CorrelationID,
		OK:            response.OK,
		Payload:       payload,
		Error: func() string {
			if response.Error == "" {
				return ""
			}
			return farmRuntimeStableErrorMessage(response.Error)
		}(),
	})
}

type farmRuntimeRecord struct {
	runtime              FarmRuntime
	profileIncarnation   string
	processStartIdentity string
	launchMode           string
	proxyBinding         *FarmRuntimeProxyBinding
	profileCreatedAt     string
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
	runtimeService       *BrowserRuntimeService
	nodeUID              string
	providerInstance     string
	fencingEpoch         uint64
	controllerID         string
	controllerGeneration uint64
	controllerMu         sync.RWMutex
	// Rebind is a controller projection operation, not a local metadata
	// setter. Lifecycle and CDP side effects hold the read side until their
	// final generation check and record publication; Rebind takes the write
	// side so an old controller cannot cross the handoff boundary.
	controllerOperationMu      sync.RWMutex
	connectionOperationMu      sync.RWMutex
	cdpOpenHook                func(stage string)
	attestationStateProvider   func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error)
	proxyBindingVerifier       func(profileID string, binding FarmRuntimeProxyBinding) error
	proxyRuntimeCleanup        func()
	resourceTelemetryHooks     *FarmResourceTelemetryHooks
	connectionMu               sync.Mutex
	connectionGeneration       uint64
	activeConnectionGeneration uint64
	ownershipStore             FarmRuntimeOwnershipStore
	ownershipMu                sync.Mutex
	resourceTelemetrySequence  uint64
	resourceTelemetryMu        sync.Mutex
	latestResourceSequence     uint64
	latestResourceObservedAt   string
	stopRequestHook            func(FarmRuntimeStopRequest)
	handoffValidationHook      func()

	recordsMu sync.RWMutex
	records   map[string]farmRuntimeRecord

	attestation *FarmAttestationAgent

	gatesMu sync.Mutex
	gates   map[string]*farmRuntimeProfileGate

	cdpSessionsMu      sync.Mutex
	cdpSessions        map[string]*farmCDPSession
	cdpTombstones      map[string]farmCDPTombstone
	cdpTokenTombstones map[string]farmCDPTombstone
}

func (s *FarmRuntimeService) controllerBinding() (string, uint64) {
	if s == nil {
		return "", 0
	}
	s.controllerMu.RLock()
	id, generation := s.controllerID, s.controllerGeneration
	s.controllerMu.RUnlock()
	return id, generation
}

// ControllerBinding returns the current authenticated controller generation.
func (s *FarmRuntimeService) ControllerBinding() (string, uint64) {
	return s.controllerBinding()
}

// RebindController is only used after a Server has authenticated inventory
// and supplied a strictly newer controller generation.  It updates existing
// records' controller projection but never creates a runtime or infers
// ownership from a local profile/PID/port.
func (s *FarmRuntimeService) RebindController(controllerID string, generation uint64) error {
	if s == nil {
		return ErrFarmRuntimeServiceUnavailable
	}
	controllerID = strings.TrimSpace(controllerID)
	if controllerID == "" || generation == 0 {
		return ErrFarmRuntimeIdentityRequired
	}
	s.controllerOperationMu.Lock()
	defer s.controllerOperationMu.Unlock()
	s.controllerMu.Lock()
	if generation < s.controllerGeneration || (generation == s.controllerGeneration && controllerID != s.controllerID) {
		s.controllerMu.Unlock()
		return ErrFarmRuntimeStale
	}
	s.controllerID, s.controllerGeneration = controllerID, generation
	s.controllerMu.Unlock()
	s.recordsMu.Lock()
	for profileID, record := range s.records {
		record.runtime.ControllerID = controllerID
		record.runtime.ControllerGeneration = generation
		s.records[profileID] = record
	}
	s.recordsMu.Unlock()
	return nil
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
	controllerID := strings.TrimSpace(options.ControllerID)
	if (controllerID == "") != (options.ControllerGeneration == 0) {
		return nil, fmt.Errorf("%w: controller id and generation must be supplied together", ErrFarmRuntimeServiceUnavailable)
	}
	service := &FarmRuntimeService{
		runtimeService:           runtimeService,
		nodeUID:                  nodeUID,
		providerInstance:         providerInstance,
		fencingEpoch:             options.FencingEpoch,
		controllerID:             controllerID,
		controllerGeneration:     options.ControllerGeneration,
		cdpOpenHook:              options.CDPOpenHook,
		records:                  make(map[string]farmRuntimeRecord),
		gates:                    make(map[string]*farmRuntimeProfileGate),
		cdpSessions:              make(map[string]*farmCDPSession),
		cdpTombstones:            make(map[string]farmCDPTombstone),
		cdpTokenTombstones:       make(map[string]farmCDPTombstone),
		attestation:              NewFarmAttestationAgent(),
		attestationStateProvider: options.AttestationStateProvider,
		proxyBindingVerifier:     options.ProxyBindingVerifier,
		proxyRuntimeCleanup:      options.ProxyRuntimeCleanup,
		resourceTelemetryHooks:   options.ResourceTelemetryHooks,
		ownershipStore:           options.OwnershipStore,
		connectionGeneration:     1,
	}
	if err := service.restoreOwnershipProvenance(); err != nil {
		return nil, err
	}
	return service, nil
}

// BeginControlConnection advances the authenticated Agent connection fence.
// A fresh WSS session must obtain a new generation before inventory can be
// used to mark absent runtimes lost.
func (s *FarmRuntimeService) BeginControlConnection() uint64 {
	if s == nil {
		return 0
	}
	s.connectionMu.Lock()
	s.connectionGeneration++
	generation := s.connectionGeneration
	s.activeConnectionGeneration = generation
	s.connectionMu.Unlock()
	return generation
}

// BeginAuthenticatedControlConnection binds controller authority to the
// authenticated transport session, before that session may dispatch commands.
// A business command cannot create or advance this binding.
func (s *FarmRuntimeService) BeginAuthenticatedControlConnection(controllerID string, controllerGeneration uint64) (uint64, error) {
	if s == nil {
		return 0, ErrFarmRuntimeServiceUnavailable
	}
	s.connectionOperationMu.Lock()
	defer s.connectionOperationMu.Unlock()
	if err := s.RebindController(controllerID, controllerGeneration); err != nil {
		return 0, err
	}
	return s.BeginControlConnection(), nil
}

func (s *FarmRuntimeService) EndControlConnection(generation uint64) {
	if s == nil || generation == 0 {
		return
	}
	s.connectionOperationMu.Lock()
	s.connectionMu.Lock()
	if s.activeConnectionGeneration == generation {
		s.activeConnectionGeneration = 0
	}
	s.connectionMu.Unlock()
	s.connectionOperationMu.Unlock()
}

func (s *FarmRuntimeService) connectionIsCurrent(generation uint64) bool {
	s.connectionMu.Lock()
	current := s.activeConnectionGeneration
	s.connectionMu.Unlock()
	return generation != 0 && current == generation
}

func (s *FarmRuntimeService) ConnectionGeneration() uint64 {
	if s == nil {
		return 0
	}
	s.connectionMu.Lock()
	generation := s.connectionGeneration
	s.connectionMu.Unlock()
	return generation
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
	verifier := options.ProxyBindingVerifier
	if verifier == nil {
		// The Wails-free production host owns no second connector path: it
		// verifies through the same shared BrowserRuntimeService resolver that
		// will later acquire the Xray/Mihomo bridge for Chrome.
		verifier = runtimeService.VerifyLocalProfileProxyBinding
	}
	return NewFarmRuntimeService(FarmRuntimeServiceConfig{
		BrowserRuntimeService:    runtimeService,
		NodeUID:                  options.NodeUID,
		NodeID:                   options.NodeID,
		ProviderInstanceID:       options.ProviderInstanceID,
		FencingEpoch:             options.FencingEpoch,
		ControllerID:             options.ControllerID,
		ControllerGeneration:     options.ControllerGeneration,
		CDPOpenHook:              options.CDPOpenHook,
		AttestationStateProvider: options.AttestationStateProvider,
		ProxyBindingVerifier:     verifier,
		ProxyRuntimeCleanup:      runtimeService.CleanupOwnedProxyRuntimes,
		ResourceTelemetryHooks:   options.ResourceTelemetryHooks,
		OwnershipStore:           options.OwnershipStore,
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

func (s *FarmRuntimeService) hasActiveRecord() bool {
	if s == nil {
		return false
	}
	s.recordsMu.RLock()
	defer s.recordsMu.RUnlock()
	for _, record := range s.records {
		if record.runtime.State == FarmRuntimeStateIdle || record.runtime.State == FarmRuntimeStateStarting {
			return true
		}
	}
	return false
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

func normalizeFarmRuntimeLaunchMode(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if value != FarmRuntimeLaunchModeDirectNoProxy && value != FarmRuntimeLaunchModeProfileProxy {
		return "", fmt.Errorf("%w: %q", ErrFarmRuntimeLaunchMode, value)
	}
	return value, nil
}

func cloneFarmRuntimeProxyBinding(value *FarmRuntimeProxyBinding) *FarmRuntimeProxyBinding {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func equalFarmRuntimeProxyBinding(left, right *FarmRuntimeProxyBinding) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func validateFarmRuntimeProxyBinding(value *FarmRuntimeProxyBinding, required bool) error {
	if value == nil {
		if required {
			return fmt.Errorf("%w: proxy binding is required", ErrFarmRuntimeLaunchMode)
		}
		return nil
	}
	if !value.Enabled {
		return fmt.Errorf("%w: proxy binding must be enabled", ErrFarmRuntimeLaunchMode)
	}
	connector := strings.TrimSpace(value.ConnectorType)
	if connector != "xray" && connector != "mihomo" {
		return fmt.Errorf("%w: proxy connector", ErrFarmRuntimeLaunchMode)
	}
	if strings.TrimSpace(value.CredentialRevision) == "" || strings.TrimSpace(value.ConfigRevision) == "" {
		return fmt.Errorf("%w: proxy revision", ErrFarmRuntimeLaunchMode)
	}
	for _, token := range []string{value.ConnectorType, value.CredentialRevision, value.ConfigRevision} {
		if err := validateAttestationToken(token, true); err != nil {
			return fmt.Errorf("%w: proxy binding", ErrFarmRuntimeLaunchMode)
		}
	}
	return nil
}

func farmRuntimeProfileTelemetry(profile *BrowserProfile) *FarmRuntimeProfile {
	if profile == nil {
		return nil
	}
	return &FarmRuntimeProfile{
		ProfileId:   profile.ProfileId,
		ProfileName: profile.ProfileName,
		CoreId:      profile.CoreId,
		Running:     profile.Running,
		DebugPort:   profile.DebugPort,
		DebugReady:  profile.DebugReady,
		Pid:         profile.Pid,
		// RuntimeWarning is produced by the lifecycle service and may contain a
		// host-derived error. Do not forward it across the Farm boundary.
		LastStartAt: profile.LastStartAt,
		LastStopAt:  profile.LastStopAt,
		// Keep this only for in-process compatibility; FarmRuntimeProfile's
		// JSON representation excludes it.
		LaunchArgs: cloneBrowserProfileStrings(profile.LaunchArgs),
	}
}

func farmRuntimeIncarnationMatches(record farmRuntimeRecord, snapshot *BrowserRuntimeServiceSnapshot) bool {
	return record.profileIncarnation != "" && snapshot != nil &&
		snapshot.ProfileIncarnation != "" && record.profileIncarnation == snapshot.ProfileIncarnation
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
	profile := snapshot.Profile
	telemetry := farmRuntimeProfileTelemetry(profile)
	runtime.Profile = telemetry
	runtime.PID = profile.Pid
	runtime.DebugPort = profile.DebugPort
	runtime.DebugReady = profile.DebugReady
	// Raw lifecycle errors/warnings may include paths, command arguments, or
	// credentials. They are intentionally not part of Farm telemetry.
	runtime.RuntimeWarning = ""
	runtime.LastError = ""
	runtime.LastStartAt = profile.LastStartAt
	runtime.LastStopAt = profile.LastStopAt
	runtime.ProcessStartIdentity = record.processStartIdentity
	runtime.ProfileIncarnation = record.profileIncarnation
	switch {
	case snapshot.Generation == runtime.Generation && profile.Running && !profile.DebugReady:
		runtime.State = FarmRuntimeStateStarting
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
	if !farmRuntimeIncarnationMatches(record, snapshot) {
		record.runtime.State = FarmRuntimeStateStale
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: profile incarnation", ErrFarmRuntimeStale)
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
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" {
		return FarmRuntime{}, fmt.Errorf("%w: profile id", ErrFarmRuntimeIdentityRequired)
	}
	if err := s.validateControllerIdentity(request.NodeUID, request.ProviderInstanceID, request.FencingEpoch); err != nil {
		return FarmRuntime{}, err
	}
	launchMode, err := normalizeFarmRuntimeLaunchMode(request.LaunchMode)
	if err != nil {
		return FarmRuntime{}, err
	}
	if err := validateFarmRuntimeProxyBinding(request.Proxy, launchMode == FarmRuntimeLaunchModeProfileProxy); err != nil {
		return FarmRuntime{}, err
	}
	if launchMode == FarmRuntimeLaunchModeDirectNoProxy && request.Proxy != nil {
		return FarmRuntime{}, fmt.Errorf("%w: direct mode cannot carry proxy binding", ErrFarmRuntimeLaunchMode)
	}
	if launchMode == FarmRuntimeLaunchModeProfileProxy {
		if s.proxyBindingVerifier == nil {
			return FarmRuntime{}, ErrFarmRuntimeLocalProxyBinding
		}
		if err := s.proxyBindingVerifier(profileID, *cloneFarmRuntimeProxyBinding(request.Proxy)); err != nil {
			// Local verifier errors may include a path or a credential-bearing
			// connector error. Do not return them to the command boundary.
			return FarmRuntime{}, ErrFarmRuntimeLocalProxyBinding
		}
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
	var expectedIncarnation string
	if !owned {
		// A newly-created Farm service has no proof that an already-running
		// shared runtime belongs to this Agent. Start would intentionally reuse
		// that runtime, so calling it here would mint a second Farm UID for an
		// unproven process. Leave the runtime untouched until authenticated
		// reconcile supplies ownership evidence.
		observed, observeErr := s.snapshot(profileID)
		if observeErr != nil {
			return FarmRuntime{}, observeErr
		}
		if observed == nil || observed.Profile == nil {
			return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeNotFound, profileID)
		}
		expectedIncarnation = observed.ProfileIncarnation
		if observed.Profile.Running || observed.Generation != 0 {
			return FarmRuntime{}, fmt.Errorf("%w: unproven shared runtime", ErrFarmRuntimeStale)
		}
		if expectedIncarnation == "" {
			return FarmRuntime{}, fmt.Errorf("%w: profile incarnation is unavailable", ErrFarmRuntimeStale)
		}
	}
	if owned {
		if err := s.validateAgainstRecord(profileID, request.RuntimeUID, request.ProviderInstanceID, request.FencingEpoch, request.ConfigHash, request.Generation, record); err != nil {
			return FarmRuntime{}, err
		}
		if launchMode != "" && record.launchMode != launchMode &&
			(record.runtime.State == FarmRuntimeStateIdle || record.runtime.State == FarmRuntimeStateStarting) {
			return FarmRuntime{}, fmt.Errorf("%w: owned runtime launch mode", ErrFarmRuntimeLaunchMode)
		}
		if !equalFarmRuntimeProxyBinding(record.proxyBinding, request.Proxy) &&
			(record.runtime.State == FarmRuntimeStateIdle || record.runtime.State == FarmRuntimeStateStarting) {
			return FarmRuntime{}, fmt.Errorf("%w: owned runtime proxy binding", ErrFarmRuntimeConfigMismatch)
		}
		observed, observeErr := s.snapshot(profileID)
		if observeErr != nil {
			return FarmRuntime{}, observeErr
		}
		if observed == nil || observed.Profile == nil {
			return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeNotFound, profileID)
		}
		if !farmRuntimeIncarnationMatches(record, observed) {
			record.runtime.State = FarmRuntimeStateStale
			s.setRecord(profileID, record)
			return FarmRuntime{}, fmt.Errorf("%w: profile incarnation", ErrFarmRuntimeStale)
		}
		expectedIncarnation = record.profileIncarnation
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
		if (record.runtime.State == FarmRuntimeStateIdle || record.runtime.State == FarmRuntimeStateStarting) && observed.Generation == record.runtime.Generation && observed.Profile.Running {
			return farmRuntimeFromSnapshot(record, observed), nil
		}
		if request.RuntimeUID != "" {
			return FarmRuntime{}, fmt.Errorf("%w: terminal runtime cannot be reused", ErrFarmRuntimeStale)
		}
	}

	startOptions := BrowserRuntimeStartOptions{}
	if launchMode == FarmRuntimeLaunchModeDirectNoProxy {
		startOptions.ForceDirectProxy = true
	}
	profile, startErr := s.runtimeService.StartIfGenerationWithOptions(profileID, existingActiveGeneration, expectedIncarnation, startOptions)
	if errors.Is(startErr, ErrBrowserRuntimeProfileMismatch) {
		return FarmRuntime{}, fmt.Errorf("%w: profile changed before start", ErrFarmRuntimeStale)
	}
	if startErr != nil && (profile == nil || !profile.Running) {
		return FarmRuntime{}, startErr
	}
	observed, observeErr := s.snapshot(profileID)
	if observeErr != nil {
		return FarmRuntime{}, errors.Join(startErr, observeErr)
	}
	if observed == nil || observed.Profile == nil || !farmRuntimeIncarnationMatches(farmRuntimeRecord{profileIncarnation: expectedIncarnation}, observed) {
		return FarmRuntime{}, errors.Join(startErr, fmt.Errorf("%w: profile incarnation changed during ensure", ErrFarmRuntimeStale))
	}
	if observed.Generation == 0 || !observed.Profile.Running {
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
	controllerID, controllerGeneration := s.controllerBinding()
	runtime := FarmRuntime{
		FarmRuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:              s.nodeUID,
			ProfileID:            profileID,
			RuntimeUID:           uuid.NewString(),
			ProviderInstanceID:   s.providerInstance,
			FencingEpoch:         s.fencingEpoch,
			ConfigHash:           request.ConfigHash,
			Generation:           observed.Generation,
			ControllerID:         controllerID,
			ControllerGeneration: controllerGeneration,
		},
		State:      FarmRuntimeStateIdle,
		LaunchMode: launchMode,
	}
	runtime = farmRuntimeFromSnapshot(farmRuntimeRecord{runtime: runtime}, observed)
	processStartIdentity := ""
	if controllerID != "" {
		processStartIdentity, err = s.readProcessStartIdentity(observed.Profile.Pid)
		if err != nil || processStartIdentity == "" {
			return FarmRuntime{}, fmt.Errorf("%w: process start identity", ErrFarmRuntimeServiceUnavailable)
		}
	}
	record = farmRuntimeRecord{runtime: runtime, profileIncarnation: observed.ProfileIncarnation, processStartIdentity: processStartIdentity, launchMode: launchMode, proxyBinding: cloneFarmRuntimeProxyBinding(request.Proxy), profileCreatedAt: observed.Profile.CreatedAt}
	// Re-project from the same generation/incarnation-fenced BrowserRuntime
	// snapshot only after the OS process-start identity has been verified.
	// The earlier projection intentionally could not carry these record-owned
	// fields and returning it would make the first ensure response weaker than
	// the immediately following inventory/heartbeat for the same runtime.
	runtime = farmRuntimeFromSnapshot(record, observed)
	record.runtime = runtime
	s.setRecord(profileID, record)
	if err := s.persistOwnershipProvenance(); err != nil {
		return FarmRuntime{}, err
	}
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
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
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

// ApplyAttestation binds a structured attestation to a runtime explicitly
// owned by this service.  The shared BrowserRuntimeService readiness snapshot
// is required as an additional launch-state fence; a caller cannot mark an
// arbitrary or unowned profile as applied by setting Ready in a request.
func (s *FarmRuntimeService) ApplyAttestation(
	request FarmAttestationRequest,
	state FarmAttestationLaunchState,
) (FarmAttestationResponse, error) {
	if s == nil {
		return FarmAttestationResponse{}, ErrFarmRuntimeServiceUnavailable
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	if err := request.validate(); err != nil {
		return FarmAttestationResponse{}, err
	}
	if err := s.validateControllerIdentity(request.RuntimeIdentity.NodeUID, request.RuntimeIdentity.ProviderInstanceID, request.RuntimeIdentity.FencingEpoch); err != nil {
		return FarmAttestationResponse{}, err
	}
	release, err := s.acquire(request.RuntimeIdentity.ProfileID)
	if err != nil {
		return FarmAttestationResponse{}, err
	}
	defer release()
	record, owned := s.currentRecord(request.RuntimeIdentity.ProfileID)
	if !owned {
		return FarmAttestationResponse{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeUnknown, request.RuntimeIdentity.ProfileID)
	}
	identity := record.runtime.FarmRuntimeIdentity
	if identity.NodeUID != request.RuntimeIdentity.NodeUID ||
		identity.ProfileID != request.RuntimeIdentity.ProfileID ||
		identity.RuntimeUID != request.RuntimeIdentity.RuntimeUID ||
		identity.ProviderInstanceID != request.RuntimeIdentity.ProviderInstanceID ||
		identity.FencingEpoch != request.RuntimeIdentity.FencingEpoch ||
		identity.Generation != request.RuntimeIdentity.Generation ||
		identity.ConfigHash != request.RuntimeIdentity.ConfigHash ||
		identity.ConfigHash != request.ConfigHash {
		return FarmAttestationResponse{}, ErrFarmAttestationIdentityMismatch
	}
	snapshot, err := s.snapshot(request.RuntimeIdentity.ProfileID)
	if err != nil {
		return FarmAttestationResponse{}, err
	}
	if snapshot == nil || snapshot.Profile == nil || !snapshot.Profile.Running || !snapshot.Profile.DebugReady || snapshot.Generation != identity.Generation || !farmRuntimeIncarnationMatches(record, snapshot) {
		return FarmAttestationResponse{}, ErrFarmAttestationNotReady
	}
	if s.attestation == nil {
		return FarmAttestationResponse{}, ErrFarmAttestationInvalid
	}
	return s.attestation.ApplyAttestation(request, state)
}

// AttestRuntime is a concise compatibility alias for runtime adapters.
func (s *FarmRuntimeService) AttestRuntime(request FarmAttestationRequest, state FarmAttestationLaunchState) (FarmAttestationResponse, error) {
	return s.ApplyAttestation(request, state)
}

// AttestRuntimeFromLocalState is the transport-facing entry point. The
// remote command supplies only the Server request; launch state must come from
// a local Agent/host callback and is therefore not forgeable on the wire.
func (s *FarmRuntimeService) AttestRuntimeFromLocalState(request FarmAttestationRequest) (FarmAttestationResponse, error) {
	if s == nil {
		return FarmAttestationResponse{}, ErrFarmRuntimeServiceUnavailable
	}
	if err := request.validate(); err != nil {
		return FarmAttestationResponse{}, err
	}
	if err := s.validateControllerIdentity(request.RuntimeIdentity.NodeUID, request.RuntimeIdentity.ProviderInstanceID, request.RuntimeIdentity.FencingEpoch); err != nil {
		return FarmAttestationResponse{}, err
	}
	if s.attestationStateProvider == nil {
		return FarmAttestationResponse{}, ErrFarmAttestationNotReady
	}
	state, err := s.attestationStateProvider(request.RuntimeIdentity)
	if err != nil {
		// Do not propagate a provider's arbitrary local error into a transport
		// response; it may contain a path, command line, or proxy credential.
		// Preserve only the small set of stable attestation classifications.
		switch {
		case errors.Is(err, ErrFarmAttestationIdentityMismatch):
			return FarmAttestationResponse{}, ErrFarmAttestationIdentityMismatch
		case errors.Is(err, ErrFarmAttestationInvalid):
			return FarmAttestationResponse{}, ErrFarmAttestationInvalid
		case errors.Is(err, ErrFarmAttestationNotReady):
			return FarmAttestationResponse{}, ErrFarmAttestationNotReady
		default:
			return FarmAttestationResponse{}, ErrFarmAttestationNotReady
		}
	}
	return s.ApplyAttestation(request, state)
}

// StopRuntime is the explicit-only stop operation. It never calls the global
// BrowserRuntimeService.Shutdown and therefore cannot affect other Wails
// sessions or profiles not owned by this FarmRuntimeService.
func (s *FarmRuntimeService) StopRuntime(request FarmRuntimeStopRequest) (FarmRuntime, error) {
	if s == nil {
		return FarmRuntime{}, ErrFarmRuntimeServiceUnavailable
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	profileID := strings.TrimSpace(request.ProfileID)
	controllerID, controllerGeneration := s.controllerBinding()
	if s.stopRequestHook != nil {
		s.stopRequestHook(request)
	}
	if strings.TrimSpace(request.NodeUID) == "" || profileID == "" || strings.TrimSpace(request.RuntimeUID) == "" || strings.TrimSpace(request.ProviderInstanceID) == "" || request.FencingEpoch == 0 || request.Generation == 0 {
		return FarmRuntime{}, ErrFarmRuntimeIdentityRequired
	}
	if controllerID != "" && (request.PID <= 0 || strings.TrimSpace(request.ProcessStartIdentity) == "" || strings.TrimSpace(request.ProfileIncarnation) == "") {
		return FarmRuntime{}, ErrFarmRuntimeIdentityRequired
	}
	if controllerID != "" && (request.Provider != "farm" || request.ControllerID != controllerID || request.ControllerGeneration != controllerGeneration) {
		return FarmRuntime{}, fmt.Errorf("%w: controller generation", ErrFarmRuntimeStale)
	}
	if controllerID != "" {
		s.resourceTelemetryMu.Lock()
		latestSequence, latestObserved := s.latestResourceSequence, s.latestResourceObservedAt
		s.resourceTelemetryMu.Unlock()
		if request.TelemetrySequence == 0 || request.TelemetrySequence != latestSequence || request.TelemetryObservedAt == "" || request.TelemetryObservedAt != latestObserved {
			return FarmRuntime{}, fmt.Errorf("%w: telemetry sample", ErrFarmRuntimeStale)
		}
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
	if controllerID != "" && (request.PID != record.runtime.PID || request.ProcessStartIdentity != record.processStartIdentity || request.ProfileIncarnation != record.profileIncarnation) {
		return FarmRuntime{}, fmt.Errorf("%w: process identity", ErrFarmRuntimeStale)
	}
	observed, err := s.snapshot(profileID)
	if err != nil {
		return FarmRuntime{}, err
	}
	if observed == nil || observed.Profile == nil {
		return FarmRuntime{}, fmt.Errorf("%w: profile %s", ErrFarmRuntimeNotFound, profileID)
	}
	if !farmRuntimeIncarnationMatches(record, observed) {
		record.runtime.State = FarmRuntimeStateStale
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: profile incarnation", ErrFarmRuntimeStale)
	}
	if record.runtime.State == FarmRuntimeStateStopped {
		return record.runtime, nil
	}
	if observed.Generation != record.runtime.Generation {
		record.runtime.State = FarmRuntimeStateStale
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: generation", ErrFarmRuntimeStale)
	}
	if controllerID != "" {
		if observed.Profile.Pid != request.PID || observed.ProfileIncarnation != request.ProfileIncarnation {
			return FarmRuntime{}, fmt.Errorf("%w: current process identity", ErrFarmRuntimeStale)
		}
		currentStartIdentity, identityErr := s.readProcessStartIdentity(request.PID)
		if identityErr != nil || currentStartIdentity == "" || currentStartIdentity != request.ProcessStartIdentity {
			return FarmRuntime{}, fmt.Errorf("%w: process start identity", ErrFarmRuntimeStale)
		}
	}
	if !observed.Profile.Running {
		record.runtime.State = FarmRuntimeStateCrashed
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: runtime is no longer running", ErrFarmRuntimeStale)
	}
	// An explicit strict stop owns the whole runtime lifecycle. Close any
	// browser-level CDP sessions first so relay goroutines cannot keep a
	// stopped Chrome target alive or retain a replayable session identity.
	s.closeCDPSessionsForRuntime(profileID, record.runtime.Generation)
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
	if finalSnapshot == nil || finalSnapshot.Profile == nil || !farmRuntimeIncarnationMatches(record, finalSnapshot) {
		record.runtime.State = FarmRuntimeStateStale
		s.setRecord(profileID, record)
		return FarmRuntime{}, fmt.Errorf("%w: profile incarnation changed during stop", ErrFarmRuntimeStale)
	}
	record.runtime = farmRuntimeFromSnapshot(record, finalSnapshot)
	record.runtime.State = FarmRuntimeStateStopped
	s.setRecord(profileID, record)
	if err := s.persistOwnershipProvenance(); err != nil {
		return FarmRuntime{}, err
	}
	if s.proxyRuntimeCleanup != nil && !s.hasActiveRecord() {
		s.proxyRuntimeCleanup()
	}
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
	raw, err := farmRuntimeJSONBytes(payload, true)
	if err != nil {
		return err
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return fmt.Errorf("%w: payload JSON", ErrFarmRuntimeCommand)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%w: payload must be an object", ErrFarmRuntimeCommand)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
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

func farmRuntimeJSONBytes(value any, nilAsObject bool) ([]byte, error) {
	if value == nil {
		if nilAsObject {
			return []byte(`{}`), nil
		}
		return nil, fmt.Errorf("%w: empty command body", ErrFarmRuntimeCommand)
	}
	var raw []byte
	switch typed := value.(type) {
	case io.Reader:
		// The limit is installed before any read. This keeps a malicious or
		// stalled transport from handing an unbounded body to io.ReadAll.
		limited := io.LimitReader(typed, maxFarmRuntimeEnvelopeBytes+1)
		var err error
		raw, err = io.ReadAll(limited)
		if err != nil {
			return nil, fmt.Errorf("%w: body read failed", ErrFarmRuntimeCommand)
		}
	case json.RawMessage:
		raw = append([]byte(nil), typed...)
	case []byte:
		raw = append([]byte(nil), typed...)
	case string:
		raw = []byte(typed)
	default:
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, fmt.Errorf("%w: body is not JSON-safe", ErrFarmRuntimeCommand)
		}
		raw = encoded
	}
	if len(raw) > maxFarmRuntimeEnvelopeBytes {
		return nil, fmt.Errorf("%w: body exceeds limit", ErrFarmRuntimeCommand)
	}
	return raw, nil
}

// validateFarmRuntimeJSON walks every object and array before decoding into a
// typed request. encoding/json otherwise silently keeps the last duplicate
// key, which makes an authenticated command ambiguous (including nested
// payload objects).
func validateFarmRuntimeJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkFarmRuntimeJSON(decoder); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func walkFarmRuntimeJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return fmt.Errorf("object key is not a string")
				}
				// encoding/json matches struct fields case-insensitively. Reject
				// both exact duplicates and aliases before decoding so a second
				// spelling cannot overwrite an authenticated field (including in
				// recursively nested payload objects).
				canonical := strings.ToLower(key)
				if key != canonical {
					return fmt.Errorf("object key is a case alias")
				}
				if _, exists := seen[canonical]; exists {
					return fmt.Errorf("duplicate object key")
				}
				seen[canonical] = struct{}{}
				if err := walkFarmRuntimeJSON(decoder); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim('}') {
				return fmt.Errorf("invalid object")
			}
		case '[':
			for decoder.More() {
				if err := walkFarmRuntimeJSON(decoder); err != nil {
					return err
				}
			}
			closing, err := decoder.Token()
			if err != nil || closing != json.Delim(']') {
				return fmt.Errorf("invalid array")
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
	}
	return nil
}

func decodeFarmRuntimeEnvelope(raw []byte) (FarmRuntimeCommand, error) {
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return FarmRuntimeCommand{}, fmt.Errorf("%w: invalid JSON", ErrFarmRuntimeCommand)
	}
	var wire struct {
		Type          string          `json:"type"`
		NodeUID       string          `json:"node_uid"`
		CorrelationID string          `json:"correlation_id"`
		Command       string          `json:"command"`
		Payload       json.RawMessage `json:"payload"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return FarmRuntimeCommand{}, fmt.Errorf("%w: invalid envelope", ErrFarmRuntimeCommand)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FarmRuntimeCommand{}, fmt.Errorf("%w: trailing envelope value", ErrFarmRuntimeCommand)
	}
	return FarmRuntimeCommand{
		Type:          wire.Type,
		NodeUID:       wire.NodeUID,
		CorrelationID: wire.CorrelationID,
		Command:       wire.Command,
		Payload:       wire.Payload,
	}, nil
}

func (s *FarmRuntimeService) validateCommand(command FarmRuntimeCommand) error {
	if command.Type != "command" {
		return fmt.Errorf("%w: type", ErrFarmRuntimeCommand)
	}
	if strings.TrimSpace(command.NodeUID) == "" {
		return fmt.Errorf("%w: node uid is required", ErrFarmRuntimeIdentityRequired)
	}
	if err := s.validateNode(command.NodeUID); err != nil {
		return err
	}
	correlationID := strings.TrimSpace(command.CorrelationID)
	if correlationID == "" || len(correlationID) > maxFarmRuntimeCorrelationID {
		return fmt.Errorf("%w: correlation id", ErrFarmRuntimeCommand)
	}
	if strings.TrimSpace(command.Command) == "" {
		return fmt.Errorf("%w: command is required", ErrFarmRuntimeCommand)
	}
	switch strings.TrimSpace(command.Command) {
	case "ensure_runtime", "runtime_status", "stop_runtime", "inventory", "inventory_handoff", "attest_runtime", "prepare_adopt_runtime", "adopt_runtime", "quarantine_runtime", "stop_runtime_handoff", "reconcile_runtime":
		return nil
	default:
		return fmt.Errorf("%w: unknown command", ErrFarmRuntimeCommand)
	}
}

func farmRuntimeWireError(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, ErrFarmRuntimeIdentityRequired):
		return ErrFarmRuntimeIdentityRequired.Error()
	case errors.Is(err, ErrFarmRuntimeIdentityMismatch):
		return ErrFarmRuntimeIdentityMismatch.Error()
	case errors.Is(err, ErrFarmRuntimeUnknown):
		return ErrFarmRuntimeUnknown.Error()
	case errors.Is(err, ErrFarmRuntimeNotFound):
		return ErrFarmRuntimeNotFound.Error()
	case errors.Is(err, ErrFarmRuntimeStale):
		return ErrFarmRuntimeStale.Error()
	case errors.Is(err, ErrFarmRuntimeLaunchMode):
		return ErrFarmRuntimeLaunchMode.Error()
	case errors.Is(err, ErrFarmRuntimeLocalProxyBinding):
		return ErrFarmRuntimeLocalProxyBinding.Error()
	case errors.Is(err, ErrFarmRuntimeConfigMismatch):
		return ErrFarmRuntimeConfigMismatch.Error()
	case errors.Is(err, ErrFarmRuntimeServiceUnavailable):
		return ErrFarmRuntimeServiceUnavailable.Error()
	case errors.Is(err, ErrFarmAttestationInvalid):
		return ErrFarmAttestationInvalid.Error()
	case errors.Is(err, ErrFarmAttestationNotReady):
		return ErrFarmAttestationNotReady.Error()
	case errors.Is(err, ErrFarmAttestationTokenMismatch):
		return ErrFarmAttestationTokenMismatch.Error()
	case errors.Is(err, ErrFarmAttestationStructuredMismatch):
		return ErrFarmAttestationStructuredMismatch.Error()
	case errors.Is(err, ErrFarmAttestationIdentityMismatch):
		return ErrFarmAttestationIdentityMismatch.Error()
	case errors.Is(err, ErrFarmAttestationUnownedRestart):
		return ErrFarmAttestationUnownedRestart.Error()
	default:
		return ErrFarmRuntimeCommand.Error()
	}
}

// HandleCommand dispatches the P1.10 lifecycle commands and P1.11 attestation
// without knowing how the
// command arrived. Business errors are returned as ok=false so a WSS adapter
// can preserve command correlation; malformed payloads return a Go error.
func (s *FarmRuntimeService) HandleCommand(command FarmRuntimeCommand) (FarmRuntimeCommandResponse, error) {
	if s == nil {
		return FarmRuntimeCommandResponse{}, ErrFarmRuntimeServiceUnavailable
	}
	if err := s.validateCommand(command); err != nil {
		return FarmRuntimeCommandResponse{}, err
	}
	name := strings.TrimSpace(command.Command)
	response := FarmRuntimeCommandResponse{Type: "command_response", NodeUID: s.nodeUID, CorrelationID: strings.TrimSpace(command.CorrelationID)}
	switch name {
	case "ensure_runtime":
		var request FarmRuntimeEnsureRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		// The command surface is the Control WSS boundary. It accepts only an
		// explicit direct mode or an explicit secret-free binding to the local
		// profile connector; raw proxy material has no decodable field.
		if request.LaunchMode != FarmRuntimeLaunchModeDirectNoProxy && request.LaunchMode != FarmRuntimeLaunchModeProfileProxy {
			err := fmt.Errorf("%w: command ensure requires explicit mode", ErrFarmRuntimeLaunchMode)
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		runtime, err := s.EnsureRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
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
			response.Error = farmRuntimeWireError(err)
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
			response.Error = farmRuntimeWireError(err)
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
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = inventory
	case "inventory_handoff":
		var request struct{}
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		inventory, err := s.InventoryWithError()
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = FarmRuntimeInventorySnapshot{
			ConnectionGeneration: s.ConnectionGeneration(),
			Inventory:            inventory,
		}
	case "prepare_adopt_runtime":
		var request FarmRuntimeHandoffRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.PrepareAdoptRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "adopt_runtime":
		var request FarmRuntimeHandoffRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.AdoptRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "quarantine_runtime":
		var request FarmRuntimeHandoffRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.QuarantineRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "stop_runtime_handoff":
		var request FarmRuntimeHandoffRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.StopHandoffRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "reconcile_runtime":
		var request FarmRuntimeReconcileRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		runtime, err := s.ReconcileRuntime(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = runtime
	case "attest_runtime":
		var request FarmAttestationRequest
		if err := decodeFarmCommandPayload(command.Payload, &request); err != nil {
			return FarmRuntimeCommandResponse{}, err
		}
		attestation, err := s.AttestRuntimeFromLocalState(request)
		if err != nil {
			response.Error = farmRuntimeWireError(err)
			return response, nil
		}
		response.OK = true
		response.Payload = attestation
	default:
		response.Error = ErrFarmRuntimeCommand.Error()
	}
	return response, nil
}

// FarmRuntimeControlAdapter is the Wails-free Agent seam used by a Control
// WSS transport. It deliberately delegates all lifecycle work to the shared
// FarmRuntimeService; the adapter owns no process, CDP, or proxy state.
type FarmRuntimeControlAdapter struct {
	service *FarmRuntimeService
}

func NewFarmRuntimeControlAdapter(service *FarmRuntimeService) (*FarmRuntimeControlAdapter, error) {
	if service == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	return &FarmRuntimeControlAdapter{service: service}, nil
}

func (adapter *FarmRuntimeControlAdapter) HandleCommand(command FarmRuntimeCommand) (FarmRuntimeCommandResponse, error) {
	if adapter == nil || adapter.service == nil {
		return FarmRuntimeCommandResponse{}, ErrFarmRuntimeServiceUnavailable
	}
	return adapter.service.HandleCommand(command)
}

func (adapter *FarmRuntimeControlAdapter) DispatchCommand(command FarmRuntimeCommand) FarmRuntimeCommandResponse {
	if adapter == nil || adapter.service == nil {
		return FarmRuntimeCommandResponse{Type: "command_response", Error: farmRuntimeWireError(ErrFarmRuntimeServiceUnavailable)}
	}
	return adapter.service.DispatchCommand(command)
}

// DispatchCommandForConnection keeps the authenticated connection fence held
// across the complete command. Reconnect/rebind waits for an admitted command,
// while queued work from an invalidated connection fails before any side effect.
func (adapter *FarmRuntimeControlAdapter) DispatchCommandForConnection(command FarmRuntimeCommand, connectionGeneration uint64) FarmRuntimeCommandResponse {
	if adapter == nil || adapter.service == nil {
		return FarmRuntimeCommandResponse{Type: "command_response", Error: farmRuntimeWireError(ErrFarmRuntimeServiceUnavailable)}
	}
	service := adapter.service
	name := strings.TrimSpace(command.Command)
	mutatesRuntime := name != "inventory" && name != "inventory_handoff" && name != "runtime_status"
	if mutatesRuntime {
		service.connectionOperationMu.RLock()
		defer service.connectionOperationMu.RUnlock()
	}
	if !service.connectionIsCurrent(connectionGeneration) {
		return FarmRuntimeCommandResponse{Type: "command_response", NodeUID: service.nodeUID, CorrelationID: command.CorrelationID, Error: farmRuntimeWireError(ErrFarmRuntimeStale)}
	}
	return adapter.DispatchCommand(command)
}

// ResourceTelemetry is the authenticated heartbeat projection used by the
// Control WSS transport. It does not dispatch through the command surface and
// therefore cannot be confused with a lifecycle response or locator payload.
func (adapter *FarmRuntimeControlAdapter) ResourceTelemetry(controlRTTMS float64) (FarmResourceTelemetry, error) {
	if adapter == nil || adapter.service == nil {
		return FarmResourceTelemetry{}, ErrFarmRuntimeServiceUnavailable
	}
	return adapter.service.ResourceTelemetry(controlRTTMS)
}

// BeginControlConnection is called only after the WSS authentication ACK.
// It is intentionally not exposed as a command payload: a remote caller
// cannot mint a connection generation without authenticating the node.
func (adapter *FarmRuntimeControlAdapter) BeginControlConnection() uint64 {
	if adapter == nil || adapter.service == nil {
		return 0
	}
	return adapter.service.BeginControlConnection()
}

func (adapter *FarmRuntimeControlAdapter) BeginAuthenticatedControlConnection(controllerID string, controllerGeneration uint64) (uint64, error) {
	if adapter == nil || adapter.service == nil {
		return 0, ErrFarmRuntimeServiceUnavailable
	}
	return adapter.service.BeginAuthenticatedControlConnection(controllerID, controllerGeneration)
}

func (adapter *FarmRuntimeControlAdapter) EndControlConnection(connectionGeneration uint64) {
	if adapter != nil && adapter.service != nil {
		adapter.service.EndControlConnection(connectionGeneration)
	}
}

// HandleCommandEnvelope is the explicit envelope-named entry point for a
// future Control WSS adapter. It intentionally has no transport dependency;
// the request and response fields remain the wire-compatible command shape.
func (s *FarmRuntimeService) HandleCommandEnvelope(envelope any) (FarmRuntimeCommandResponse, error) {
	var command FarmRuntimeCommand
	switch typed := envelope.(type) {
	case FarmRuntimeCommandEnvelope:
		command = typed
	case *FarmRuntimeCommandEnvelope:
		if typed == nil {
			err := fmt.Errorf("%w: nil envelope", ErrFarmRuntimeCommand)
			return FarmRuntimeCommandResponse{Type: "command_response", NodeUID: s.NodeUID(), Error: farmRuntimeWireError(err)}, err
		}
		command = *typed
	default:
		raw, err := farmRuntimeJSONBytes(envelope, false)
		if err != nil {
			return FarmRuntimeCommandResponse{Type: "command_response", NodeUID: s.NodeUID(), Error: farmRuntimeWireError(err)}, err
		}
		command, err = decodeFarmRuntimeEnvelope(raw)
		if err != nil {
			return FarmRuntimeCommandResponse{Type: "command_response", NodeUID: s.NodeUID(), Error: farmRuntimeWireError(err)}, err
		}
	}
	response, err := s.HandleCommand(command)
	if err != nil {
		return FarmRuntimeCommandResponse{
			Type:          "command_response",
			NodeUID:       s.NodeUID(),
			CorrelationID: strings.TrimSpace(command.CorrelationID),
			Error:         farmRuntimeWireError(err),
		}, err
	}
	return response, nil
}

// DispatchCommand is a response-only convenience for transports that want
// malformed commands represented as a normal failed command response.
func (s *FarmRuntimeService) DispatchCommand(command FarmRuntimeCommand) FarmRuntimeCommandResponse {
	response, err := s.HandleCommand(command)
	if err != nil {
		return FarmRuntimeCommandResponse{
			Type:          "command_response",
			NodeUID:       s.NodeUID(),
			CorrelationID: strings.TrimSpace(command.CorrelationID),
			Error:         farmRuntimeWireError(err),
		}
	}
	return response
}
