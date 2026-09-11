package backend

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFarmClientDiagnosticsIsSecretAndIdentityFree(t *testing.T) {
	canaries := []string{
		"private-key-canary",
		"enrollment-code-canary",
		"node-secret-canary",
		"https://user:password@example.invalid/enroll",
		"/secret/state/path",
	}
	config := FarmClientConfig{
		ApplicationRoot: canaries[4],
		StateRoot:       canaries[4],
		ControlURL:      "wss://controller.example.invalid/control?token=" + canaries[2],
		EnrollmentURL:   canaries[3],
		Identity: FarmClientIdentityConfig{
			NodeUID:       canaries[2],
			PrivateKey:    canaries[0],
			PrivateKeyRef: canaries[2],
		},
	}
	raw, err := json.Marshal(FarmClientDiagnosticsValue(config))
	if err != nil {
		t.Fatal(err)
	}
	for _, canary := range canaries {
		if strings.Contains(string(raw), canary) {
			t.Fatalf("diagnostics leaked canary %q: %s", canary, raw)
		}
	}
	if !FarmClientDiagnosticsValue(config).SecureIdentity {
		t.Fatal("diagnostics did not report secure identity capability")
	}
}
