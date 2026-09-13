package backend

import (
	"encoding/json"
	"testing"
)

func TestFarmClientIPCServiceStopResultIsClosed(t *testing.T) {
	var result farmClientIPCServiceStopResult
	if err := decodeFarmClientIPCResult(farmClientIPCServiceStop, json.RawMessage(`{"accepted":true}`), &result); err != nil || !result.Accepted {
		t.Fatalf("valid service stop result rejected: result=%+v err=%v", result, err)
	}
	for _, raw := range []string{
		`{}`,
		`{"accepted":false,"extra":true}`,
		`{"accepted":true,"accepted":true}`,
		`{"accepted":"true"}`,
		`true`,
	} {
		result = farmClientIPCServiceStopResult{}
		if err := decodeFarmClientIPCResult(farmClientIPCServiceStop, json.RawMessage(raw), &result); err == nil {
			t.Fatalf("invalid service stop result accepted: %s: %v", raw, err)
		}
	}
}
