package backend

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

func farmProfileManagementCommandPayload(request FarmProfileCreateRequest, nodeUID string, controllerGeneration, connectionGeneration uint64) map[string]any {
	return map[string]any{
		"operation_uid": request.OperationUID, "request_uid": request.RequestUID,
		"command": farmProfileCreateCommand, "node_uid": nodeUID,
		"controller_generation": controllerGeneration, "connection_generation": connectionGeneration,
		"payload_digest": request.PayloadDigest,
		"payload":        map[string]any{"display_name": request.DisplayName, "core_ref": request.CoreRef},
	}
}

func TestFarmProfileControlAdapterUsesClosedCreateAndCurrentFence(t *testing.T) {
	management, _, _ := newFarmProfileCreateFixture(t)
	adapter, err := NewFarmProfileControlAdapter(management)
	if err != nil {
		t.Fatal(err)
	}
	connectionGeneration := uint64(7)
	if err := adapter.BeginAuthenticatedControlConnection("controller-a", 3, connectionGeneration); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AcknowledgeCapabilities(connectionGeneration); err != nil {
		t.Fatal(err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "WSS Profile")
	response := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
		Type: "command", NodeUID: management.host.identity.NodeUID, CorrelationID: "create-1",
		Command: farmProfileCreateCommand, Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 3, connectionGeneration),
	}, connectionGeneration)
	if !response.OK || response.Error != "" || response.CorrelationID != "create-1" {
		t.Fatalf("response=%+v", response)
	}
	result, ok := response.Payload.(FarmProfileCreateResult)
	if !ok || result.RequestUID != request.RequestUID {
		t.Fatalf("payload=%T %+v", response.Payload, response.Payload)
	}

	adapter.EndControlConnection(connectionGeneration)
	stale := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
		Type: "command", NodeUID: management.host.identity.NodeUID, CorrelationID: "create-2",
		Command: farmProfileCreateCommand, Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 3, connectionGeneration),
	}, connectionGeneration)
	if stale.OK || stale.Error != ErrFarmRuntimeStale.Error() {
		t.Fatalf("stale response=%+v", stale)
	}
}

func TestFarmProfileControlAdapterRejectsStaleNestedControllerAndConnection(t *testing.T) {
	management, _, _ := newFarmProfileCreateFixture(t)
	adapter, err := NewFarmProfileControlAdapter(management)
	if err != nil {
		t.Fatal(err)
	}
	if response := (*FarmProfileControlAdapter)(nil).DispatchCommandForConnection(FarmRuntimeCommand{}, 1); response.Error != ErrFarmClientIPCUnavailable.Error() {
		t.Fatalf("nil response=%+v", response)
	}
	if err := adapter.BeginAuthenticatedControlConnection("controller-a", 3, 7); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AcknowledgeCapabilities(7); err != nil {
		t.Fatal(err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Fence")
	for _, test := range []struct {
		name       string
		controller uint64
		connection uint64
	}{
		{name: "controller", controller: 2, connection: 7},
		{name: "connection", controller: 3, connection: 6},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
				Type: "command", NodeUID: management.host.identity.NodeUID, Command: farmProfileCreateCommand,
				Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, test.controller, test.connection),
			}, 7)
			if response.OK || response.Error != ErrFarmRuntimeStale.Error() {
				t.Fatalf("response=%+v", response)
			}
		})
	}
	if err := adapter.BeginAuthenticatedControlConnection("controller-b", 4, 8); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AcknowledgeCapabilities(8); err != nil {
		t.Fatal(err)
	}
	late := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
		Type: "command", NodeUID: management.host.identity.NodeUID, Command: farmProfileCreateCommand,
		Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 3, 7),
	}, 7)
	if late.OK || late.Error != ErrFarmRuntimeStale.Error() {
		t.Fatalf("late old command response=%+v", late)
	}
}

func TestFarmProfileControlAdapterRejectsUnknownCommandAndPayload(t *testing.T) {
	management, _, _ := newFarmProfileCreateFixture(t)
	adapter, err := NewFarmProfileControlAdapter(management)
	if err != nil {
		t.Fatal(err)
	}
	if adapter.Handles("ensure_runtime") || !adapter.Handles(farmProfileCreateCommand) {
		t.Fatal("profile adapter command allowlist is not exact")
	}
	if err := adapter.BeginAuthenticatedControlConnection("controller-a", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := adapter.AcknowledgeCapabilities(2); err != nil {
		t.Fatal(err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Safe")
	raw, err := json.Marshal(map[string]any{
		"operation_uid": request.OperationUID, "request_uid": request.RequestUID,
		"command": farmProfileCreateCommand, "node_uid": management.host.identity.NodeUID,
		"controller_generation": uint64(1), "connection_generation": uint64(2),
		"payload_digest": request.PayloadDigest,
		"payload":        map[string]any{"display_name": request.DisplayName, "core_ref": request.CoreRef, "unknown": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	bad := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
		Type: "command", NodeUID: management.host.identity.NodeUID, CorrelationID: "bad-1",
		Command: farmProfileCreateCommand, Payload: json.RawMessage(raw),
	}, 2)
	if bad.OK || bad.Error != ErrFarmRuntimeCommand.Error() {
		t.Fatalf("unknown field response=%+v", bad)
	}

	wrong := adapter.DispatchCommandForConnection(FarmRuntimeCommand{
		Type: "command", NodeUID: "other-node", CorrelationID: "bad-2",
		Command: farmProfileCreateCommand, Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 1, 2),
	}, 2)
	if wrong.OK || wrong.Error != ErrFarmRuntimeCommand.Error() {
		t.Fatalf("wrong node response=%+v", wrong)
	}
}

func TestFarmControlCapabilitiesAreClosedAndProfileCreateIsGated(t *testing.T) {
	if !validFarmControlCapabilities(farmControlCapabilities{Type: "capabilities", Capabilities: FarmClientProfileCreateCapabilities()}) {
		t.Fatal("existing profile capability primitive was not accepted")
	}
	for _, message := range []farmControlCapabilities{
		{Type: "capabilities", Capabilities: []string{"profile.create.v1", "profile.create.v1"}},
		{Type: "capabilities", Capabilities: []string{"profile.list.v1"}},
		{Type: "other", Capabilities: []string{"profile.create.v1"}},
	} {
		if validFarmControlCapabilities(message) {
			t.Fatalf("invalid capabilities accepted: %+v", message)
		}
	}
	var ack farmControlCapabilitiesAck
	if err := strictFarmControlDecode([]byte(`{"type":"capabilities_ack"}`), &ack, maxFarmControlMessageBytes); err != nil || ack.Type != "capabilities_ack" {
		t.Fatalf("valid capabilities ack rejected: %v %+v", err, ack)
	}
	if err := strictFarmControlDecode([]byte(`{"type":"capabilities_ack","extra":true}`), &ack, maxFarmControlMessageBytes); err == nil {
		t.Fatal("capabilities ack accepted unknown field")
	}
	management, _, _ := newFarmProfileCreateFixture(t)
	adapter, err := NewFarmProfileControlAdapter(management)
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.BeginAuthenticatedControlConnection("controller-a", 1, 1); err != nil {
		t.Fatal(err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Gated")
	blocked := adapter.DispatchCommandForConnection(FarmRuntimeCommand{Type: "command", NodeUID: management.host.identity.NodeUID, Command: farmProfileCreateCommand, Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 1, 1)}, 1)
	if blocked.OK || blocked.Error != ErrFarmProfileCapabilityNotAcknowledged.Error() {
		t.Fatalf("pre-ack response=%+v", blocked)
	}
	if err := adapter.AcknowledgeCapabilities(1); err != nil {
		t.Fatal(err)
	}
	ready := adapter.DispatchCommandForConnection(FarmRuntimeCommand{Type: "command", NodeUID: management.host.identity.NodeUID, Command: farmProfileCreateCommand, Payload: farmProfileManagementCommandPayload(request, management.host.identity.NodeUID, 1, 1)}, 1)
	if !ready.OK || ready.Error != "" {
		t.Fatalf("post-ack response=%+v", ready)
	}
}

func TestFarmProfileControlAdapterAndIPCShareCoordinator(t *testing.T) {
	management, _, _ := newFarmProfileCreateFixture(t)
	management.host.management = management
	server, err := StartFarmClientIPCServer(management.host)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if server.management != management {
		t.Fatal("IPC server created a second management coordinator")
	}
	profileAdapter, err := NewFarmProfileControlAdapter(management)
	if err != nil {
		t.Fatal(err)
	}
	if profileAdapter.management != server.management {
		t.Fatal("WSS and IPC do not share management coordinator")
	}
}
