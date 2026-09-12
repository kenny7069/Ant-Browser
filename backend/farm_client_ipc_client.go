package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

type FarmClientIPCClient struct {
	stateRoot string
	timeout   time.Duration
}

func NewFarmClientIPCClient(configPath string) (*FarmClientIPCClient, error) {
	config, err := LoadFarmClientConfig(configPath)
	if err != nil {
		return nil, err
	}
	if err := config.ValidateFarmClientConfig(); err != nil {
		return nil, err
	}
	timeout := config.commandTimeout()
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	return &FarmClientIPCClient{stateRoot: config.StateRoot, timeout: timeout}, nil
}

func (client *FarmClientIPCClient) ProfileList(ctx context.Context) ([]FarmClientProfileProjection, error) {
	var result []FarmClientProfileProjection
	err := client.call(ctx, farmClientIPCProfileList, struct{}{}, &result)
	return result, err
}

func (client *FarmClientIPCClient) ProfileOpen(ctx context.Context, profileID string) (FarmClientManagedProfile, error) {
	var result FarmClientManagedProfile
	err := client.call(ctx, farmClientIPCProfileOpen, farmClientIPCProfilePayload{ProfileID: profileID}, &result)
	return result, err
}

func (client *FarmClientIPCClient) ProfileStop(ctx context.Context, profileID string) (FarmClientManagedProfile, error) {
	var result FarmClientManagedProfile
	err := client.call(ctx, farmClientIPCProfileStop, farmClientIPCProfilePayload{ProfileID: profileID}, &result)
	return result, err
}

func (client *FarmClientIPCClient) ProfileStatus(ctx context.Context, profileID string) (FarmClientManagedProfile, error) {
	var result FarmClientManagedProfile
	err := client.call(ctx, farmClientIPCProfileState, farmClientIPCProfilePayload{ProfileID: profileID}, &result)
	return result, err
}

func (client *FarmClientIPCClient) PairProfile(ctx context.Context, profileID, pairingCode string) (FarmClientPairingResult, error) {
	var result FarmClientPairingResult
	err := client.call(ctx, farmClientIPCProfilePair, farmClientIPCPairPayload{ProfileID: profileID, PairingCode: pairingCode}, &result)
	pairingCode = ""
	return result, err
}

func (client *FarmClientIPCClient) UnpairProfile(ctx context.Context, profileID string) (FarmClientPairingResult, error) {
	var result FarmClientPairingResult
	err := client.call(ctx, farmClientIPCProfileUnpair, farmClientIPCProfilePayload{ProfileID: profileID}, &result)
	return result, err
}

func (client *FarmClientIPCClient) call(ctx context.Context, operation string, payload, destination any) error {
	if client == nil || client.stateRoot == "" {
		return ErrFarmClientIPCUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		return ErrFarmClientIPCInvalid
	}
	requestUID := uuid.NewString()
	request := farmClientIPCRequest{ProtocolVersion: FarmClientIPCProtocolVersion, RequestUID: requestUID, Operation: operation, Payload: payloadRaw}
	if err := validateFarmClientIPCRequest(request); err != nil {
		return err
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return ErrFarmClientIPCInvalid
	}
	connection, err := dialFarmClientIPC(ctx, client.stateRoot)
	if err != nil {
		return fmt.Errorf("%w: connect", ErrFarmClientIPCUnavailable)
	}
	defer connection.Close()
	stopClose := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stopClose()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err := writeFarmClientIPCFrame(connection, raw); err != nil {
		return fmt.Errorf("%w: write", ErrFarmClientIPCUnavailable)
	}
	responseRaw, err := readFarmClientIPCFrame(connection)
	if err != nil {
		return fmt.Errorf("%w: read", ErrFarmClientIPCUnavailable)
	}
	response, err := decodeFarmClientIPCResponse(responseRaw)
	if err != nil || response.RequestUID != requestUID {
		return ErrFarmClientIPCInvalid
	}
	if !response.OK {
		return farmClientIPCRemoteError(response.Error.Code)
	}
	decoderErr := decodeFarmClientIPCResult(operation, response.Result, destination)
	if decoderErr != nil {
		return errors.Join(ErrFarmClientIPCInvalid, decoderErr)
	}
	return nil
}

func decodeFarmClientIPCResult(operation string, raw json.RawMessage, destination any) error {
	switch operation {
	case farmClientIPCProfileList:
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return ErrFarmClientIPCInvalid
		}
		for _, item := range items {
			var object map[string]json.RawMessage
			if err := json.Unmarshal(item, &object); err != nil || !exactFarmClientIPCKeys(object, []string{"profile_id", "display_name", "login_readiness", "provider", "profile_incarnation"}) {
				return ErrFarmClientIPCInvalid
			}
		}
	case farmClientIPCProfileOpen, farmClientIPCProfileStop, farmClientIPCProfileState:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || !exactFarmClientIPCKeys(object, []string{"profile_id", "display_name", "login_readiness", "provider", "profile_incarnation", "running", "generation"}) {
			return ErrFarmClientIPCInvalid
		}
	case farmClientIPCProfilePair, farmClientIPCProfileUnpair:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(raw, &object); err != nil || !exactFarmClientIPCKeys(object, []string{"success", "node_uid", "profile_id", "server_profile_id", "status"}) {
			return ErrFarmClientIPCInvalid
		}
	default:
		return ErrFarmClientIPCInvalid
	}
	return decodeStrictJSON(raw, destination)
}
