package backend

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestFarmClientIPCRequestStrictClosedSchema(t *testing.T) {
	requestUID := uuid.NewString()
	valid := `{"protocol_version":1,"request_uid":"` + requestUID + `","operation":"profile_list_v1","payload":{}}`
	if _, err := decodeFarmClientIPCRequest([]byte(valid)); err != nil {
		t.Fatalf("valid request rejected: %v", err)
	}
	invalid := []string{
		`{"protocol_version":1,"protocol_version":1,"request_uid":"` + requestUID + `","operation":"profile_list_v1","payload":{}}`,
		`{"Protocol_Version":1,"request_uid":"` + requestUID + `","operation":"profile_list_v1","payload":{}}`,
		`{"protocol_version":1,"request_uid":"` + requestUID + `","operation":"profile_list_v1","payload":{"extra":true}}`,
		`{"protocol_version":1,"request_uid":"` + requestUID + `","operation":"shell","payload":{}}`,
		valid + `{}`,
	}
	for _, raw := range invalid {
		if _, err := decodeFarmClientIPCRequest([]byte(raw)); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("invalid request accepted or wrong error: %q: %v", raw, err)
		}
	}
}

func TestFarmClientIPCServiceStopRequiresExactEmptyPayload(t *testing.T) {
	requestUID := uuid.NewString()
	request := func(payload string) string {
		return `{"protocol_version":1,"request_uid":"` + requestUID + `","operation":"service_stop_v1","payload":` + payload + `}`
	}
	if _, err := decodeFarmClientIPCRequest([]byte(request(`{}`))); err != nil {
		t.Fatalf("empty service stop rejected: %v", err)
	}
	for _, payload := range []string{
		`null`, `[]`, `""`, `{"unknown":true}`, `{"unknown":true,"unknown":false}`,
		`{"value":"` + strings.Repeat("x", farmClientIPCMaxFrameBytes) + `"}`,
	} {
		if _, err := decodeFarmClientIPCRequest([]byte(request(payload))); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("service stop payload accepted: %.80q: %v", payload, err)
		}
	}
}

func TestFarmClientIPCFramingBoundsAndTruncation(t *testing.T) {
	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], farmClientIPCMaxFrameBytes+1)
	oversized.Write(header[:])
	if _, err := readFarmClientIPCFrame(&oversized); !errors.Is(err, ErrFarmClientIPCInvalid) {
		t.Fatalf("oversized frame error=%v", err)
	}
	var truncated bytes.Buffer
	binary.BigEndian.PutUint32(header[:], 4)
	truncated.Write(header[:])
	truncated.WriteString("{}")
	if _, err := readFarmClientIPCFrame(&truncated); err == nil {
		t.Fatal("truncated frame accepted")
	}
	if err := writeFarmClientIPCFrame(&bytes.Buffer{}, []byte(strings.Repeat("x", farmClientIPCMaxFrameBytes+1))); !errors.Is(err, ErrFarmClientIPCInvalid) {
		t.Fatalf("oversized write error=%v", err)
	}
}
