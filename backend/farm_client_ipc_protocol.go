package backend

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/google/uuid"
)

const (
	FarmClientIPCProtocolVersion = 1
	farmClientIPCMaxFrameBytes   = 64 << 10

	farmClientIPCHealth        = "health_v1"
	farmClientIPCProfileList   = "profile_list_v1"
	farmClientIPCProfileOpen   = "management_runtime_open_v1"
	farmClientIPCProfileStop   = "management_runtime_stop_v1"
	farmClientIPCProfileState  = "management_runtime_status_v1"
	farmClientIPCProfilePair   = "profile_pair_v1"
	farmClientIPCProfileUnpair = "profile_unpair_v1"
	farmClientIPCServiceStop   = "service_stop_v1"
)

var (
	ErrFarmClientIPCInvalid     = errors.New("invalid farm client IPC message")
	ErrFarmClientIPCUnavailable = errors.New("farm client IPC unavailable")
)

type farmClientIPCRequest struct {
	ProtocolVersion int             `json:"protocol_version"`
	RequestUID      string          `json:"request_uid"`
	Operation       string          `json:"operation"`
	Payload         json.RawMessage `json:"payload"`
}

type farmClientIPCError struct {
	Code string `json:"code"`
}

type farmClientIPCResponse struct {
	ProtocolVersion int                 `json:"protocol_version"`
	RequestUID      string              `json:"request_uid"`
	OK              bool                `json:"ok"`
	Result          json.RawMessage     `json:"result,omitempty"`
	Error           *farmClientIPCError `json:"error,omitempty"`
}

type farmClientIPCProfilePayload struct {
	ProfileID string `json:"profile_id"`
}

type farmClientIPCPairPayload struct {
	ProfileID   string `json:"profile_id"`
	PairingCode string `json:"pairing_code"`
}

type farmClientIPCServiceStopResult struct {
	Accepted bool `json:"accepted"`
}

func validateFarmClientIPCRequest(request farmClientIPCRequest) error {
	if request.ProtocolVersion != FarmClientIPCProtocolVersion || uuid.Validate(request.RequestUID) != nil || uuid.MustParse(request.RequestUID).String() != request.RequestUID {
		return ErrFarmClientIPCInvalid
	}
	switch request.Operation {
	case farmClientIPCHealth, farmClientIPCProfileList, farmClientIPCServiceStop:
		var payload struct{}
		return decodeFarmClientIPCObject(request.Payload, &payload, nil)
	case farmClientIPCProfileOpen, farmClientIPCProfileStop, farmClientIPCProfileState, farmClientIPCProfileUnpair:
		var payload farmClientIPCProfilePayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id"}); err != nil || strings.TrimSpace(payload.ProfileID) == "" || len(payload.ProfileID) > 128 {
			return ErrFarmClientIPCInvalid
		}
	case farmClientIPCProfilePair:
		var payload farmClientIPCPairPayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id", "pairing_code"}); err != nil || strings.TrimSpace(payload.ProfileID) == "" || len(payload.ProfileID) > 128 || strings.TrimSpace(payload.PairingCode) == "" || len(payload.PairingCode) > 4096 {
			return ErrFarmClientIPCInvalid
		}
	default:
		return ErrFarmClientIPCInvalid
	}
	return nil
}

func decodeFarmClientIPCRequest(raw []byte) (farmClientIPCRequest, error) {
	var request farmClientIPCRequest
	if err := decodeFarmClientIPCObject(raw, &request, []string{"protocol_version", "request_uid", "operation", "payload"}); err != nil {
		return request, err
	}
	return request, validateFarmClientIPCRequest(request)
}

func decodeFarmClientIPCResponse(raw []byte) (farmClientIPCResponse, error) {
	var response farmClientIPCResponse
	if err := rejectFarmClientIPCDuplicateKeys(raw); err != nil {
		return response, err
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return response, ErrFarmClientIPCInvalid
	}
	want := []string{"protocol_version", "request_uid", "ok"}
	if value, ok := keys["ok"]; ok && bytes.Equal(bytes.TrimSpace(value), []byte("true")) {
		want = append(want, "result")
	} else {
		want = append(want, "error")
	}
	if !exactFarmClientIPCKeys(keys, want) {
		return response, ErrFarmClientIPCInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil || requireJSONEOF(decoder) != nil {
		return response, ErrFarmClientIPCInvalid
	}
	if response.ProtocolVersion != FarmClientIPCProtocolVersion || uuid.Validate(response.RequestUID) != nil || response.OK == (response.Error != nil) || response.OK == (len(response.Result) == 0) {
		return response, ErrFarmClientIPCInvalid
	}
	return response, nil
}

func decodeFarmClientIPCObject(raw []byte, destination any, allowed []string) error {
	if len(raw) == 0 || len(raw) > farmClientIPCMaxFrameBytes {
		return ErrFarmClientIPCInvalid
	}
	if err := rejectFarmClientIPCDuplicateKeys(raw); err != nil {
		return err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || !exactFarmClientIPCKeys(object, allowed) {
		return ErrFarmClientIPCInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || requireJSONEOF(decoder) != nil {
		return ErrFarmClientIPCInvalid
	}
	return nil
}

func exactFarmClientIPCKeys(object map[string]json.RawMessage, allowed []string) bool {
	if object == nil || len(object) != len(allowed) {
		return false
	}
	for _, key := range allowed {
		if _, ok := object[key]; !ok {
			return false
		}
	}
	return true
}

func rejectFarmClientIPCDuplicateKeys(raw []byte) error {
	if err := rejectSuiteReleaseDuplicateJSONKeys(raw); err != nil {
		return ErrFarmClientIPCInvalid
	}
	return nil
}

func readFarmClientIPCFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > farmClientIPCMaxFrameBytes {
		return nil, ErrFarmClientIPCInvalid
	}
	raw := make([]byte, size)
	if _, err := io.ReadFull(reader, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func writeFarmClientIPCFrame(writer io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > farmClientIPCMaxFrameBytes {
		return ErrFarmClientIPCInvalid
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	if written, err := writer.Write(header[:]); err != nil {
		return err
	} else if written != len(header) {
		return io.ErrShortWrite
	}
	if written, err := writer.Write(raw); err != nil {
		return err
	} else if written != len(raw) {
		return io.ErrShortWrite
	}
	return nil
}

func marshalFarmClientIPCResult(value any) (json.RawMessage, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > farmClientIPCMaxFrameBytes/2 {
		return nil, fmt.Errorf("%w: result", ErrFarmClientIPCInvalid)
	}
	return raw, nil
}
