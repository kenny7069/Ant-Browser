package backend

import (
	"errors"
	"sync"
)

var ErrFarmProfileCapabilityNotAcknowledged = errors.New("profile.create.v1 capability not acknowledged")

// FarmProfileControlAdapter is the narrow authenticated WSS seam for profile
// management. Runtime lifecycle commands remain owned by
// FarmRuntimeControlAdapter; this adapter only admits the closed create
// command and delegates the durable operation to the resident management
// coordinator shared with local IPC.
type FarmProfileControlAdapter struct {
	management *farmProfileManagement
	nodeUID    string

	mu                   sync.RWMutex
	controllerID         string
	controllerGeneration uint64
	connectionGeneration uint64
	capabilityReady      bool
}

type farmProfileCreateManagementPayload struct {
	OperationUID         string                   `json:"operation_uid"`
	RequestUID           string                   `json:"request_uid"`
	Command              string                   `json:"command"`
	NodeUID              string                   `json:"node_uid"`
	ControllerGeneration uint64                   `json:"controller_generation"`
	ConnectionGeneration uint64                   `json:"connection_generation"`
	PayloadDigest        string                   `json:"payload_digest"`
	Payload              farmProfileCreatePayload `json:"payload"`
}

func NewFarmProfileControlAdapter(management *farmProfileManagement) (*FarmProfileControlAdapter, error) {
	if management == nil || management.host == nil || management.host.manager == nil {
		return nil, ErrFarmClientIPCUnavailable
	}
	return &FarmProfileControlAdapter{management: management, nodeUID: management.host.identity.NodeUID}, nil
}

func (adapter *FarmProfileControlAdapter) Handles(command string) bool {
	return adapter != nil && command == farmProfileCreateCommand
}

func (adapter *FarmProfileControlAdapter) BeginAuthenticatedControlConnection(controllerID string, controllerGeneration, connectionGeneration uint64) error {
	if adapter == nil || adapter.management == nil {
		return ErrFarmClientIPCUnavailable
	}
	if controllerID == "" || controllerGeneration == 0 || connectionGeneration == 0 {
		return ErrFarmRuntimeStale
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	adapter.controllerID = controllerID
	adapter.controllerGeneration = controllerGeneration
	adapter.connectionGeneration = connectionGeneration
	adapter.capabilityReady = false
	return nil
}

func (adapter *FarmProfileControlAdapter) AcknowledgeCapabilities(connectionGeneration uint64) error {
	if adapter == nil {
		return ErrFarmRuntimeStale
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if adapter.connectionGeneration == 0 || adapter.connectionGeneration != connectionGeneration {
		return ErrFarmRuntimeStale
	}
	adapter.capabilityReady = true
	return nil
}

func (adapter *FarmProfileControlAdapter) EndControlConnection(connectionGeneration uint64) {
	if adapter == nil {
		return
	}
	adapter.mu.Lock()
	if adapter.connectionGeneration == connectionGeneration {
		adapter.controllerID = ""
		adapter.controllerGeneration = 0
		adapter.connectionGeneration = 0
		adapter.capabilityReady = false
	}
	adapter.mu.Unlock()
}

func (adapter *FarmProfileControlAdapter) DispatchCommandForConnection(command FarmRuntimeCommand, connectionGeneration uint64) FarmRuntimeCommandResponse {
	if adapter == nil {
		return FarmRuntimeCommandResponse{Type: "command_response", Error: ErrFarmClientIPCUnavailable.Error()}
	}
	response := FarmRuntimeCommandResponse{Type: "command_response", NodeUID: adapter.nodeUID, CorrelationID: command.CorrelationID}
	if adapter.management == nil {
		response.Error = ErrFarmClientIPCUnavailable.Error()
		return response
	}
	if command.Type != "command" || command.NodeUID != adapter.nodeUID || command.Command != farmProfileCreateCommand {
		response.Error = ErrFarmRuntimeCommand.Error()
		return response
	}
	var managementPayload farmProfileCreateManagementPayload
	if err := decodeFarmCommandPayload(command.Payload, &managementPayload); err != nil ||
		managementPayload.Command != farmProfileCreateCommand ||
		managementPayload.NodeUID != adapter.nodeUID ||
		managementPayload.ControllerGeneration == 0 ||
		managementPayload.ConnectionGeneration == 0 ||
		managementPayload.PayloadDigest == "" {
		response.Error = ErrFarmRuntimeCommand.Error()
		return response
	}
	digest, err := FarmProfileCreatePayloadDigest(managementPayload.Payload.DisplayName, managementPayload.Payload.CoreRef)
	if err != nil || digest != managementPayload.PayloadDigest {
		response.Error = ErrFarmRuntimeCommand.Error()
		return response
	}
	request := FarmProfileCreateRequest{
		OperationUID: managementPayload.OperationUID, RequestUID: managementPayload.RequestUID,
		PayloadDigest: managementPayload.PayloadDigest, DisplayName: managementPayload.Payload.DisplayName,
		CoreRef: managementPayload.Payload.CoreRef,
	}
	if !validFarmProfileCreateRequest(request) {
		response.Error = ErrFarmRuntimeCommand.Error()
		return response
	}

	// Hold the read fence through the durable create. Begin/End take the write
	// lock, so reconnect waits for an admitted mutation and cannot invalidate
	// the identity half-way through it.
	adapter.mu.RLock()
	if adapter.controllerID == "" || adapter.controllerGeneration == 0 ||
		adapter.connectionGeneration == 0 || adapter.connectionGeneration != connectionGeneration ||
		managementPayload.ControllerGeneration != adapter.controllerGeneration ||
		managementPayload.ConnectionGeneration != adapter.connectionGeneration {
		adapter.mu.RUnlock()
		response.Error = ErrFarmRuntimeStale.Error()
		return response
	}
	if !adapter.capabilityReady {
		adapter.mu.RUnlock()
		response.Error = ErrFarmProfileCapabilityNotAcknowledged.Error()
		return response
	}
	result, err := adapter.management.Create(request)
	adapter.mu.RUnlock()
	if err != nil {
		if errors.Is(err, ErrFarmProfileCreateConflict) {
			response.Error = ErrFarmProfileCreateConflict.Error()
		} else {
			response.Error = ErrFarmRuntimeCommand.Error()
		}
		return response
	}
	response.OK = true
	response.Payload = result
	return response
}
