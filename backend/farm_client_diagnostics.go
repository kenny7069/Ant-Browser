package backend

import (
	"runtime"
	"strings"
)

// FarmClientDiagnostics is an intentionally small allowlist. It contains no
// node identity, endpoint, filesystem path, enrollment code, or key material.
// New diagnostic fields must be added explicitly instead of serializing the
// client config or a native-store error.
type FarmClientDiagnostics struct {
	Version              string `json:"version"`
	Platform             string `json:"platform"`
	Architecture         string `json:"architecture"`
	ControlConfigured    bool   `json:"control_configured"`
	EnrollmentConfigured bool   `json:"enrollment_configured"`
	PairingConfigured    bool   `json:"pairing_configured"`
	SecureIdentity       bool   `json:"secure_identity"`
}

func FarmClientDiagnosticsValue(config FarmClientConfig) FarmClientDiagnostics {
	identity := config.identityConfig()
	return FarmClientDiagnostics{
		Version:              FarmClientVersion,
		Platform:             runtime.GOOS,
		Architecture:         runtime.GOARCH,
		ControlConfigured:    strings.TrimSpace(config.ControlURL) != "" || strings.TrimSpace(config.WSSURL) != "",
		EnrollmentConfigured: strings.TrimSpace(config.EnrollmentURL) != "",
		PairingConfigured:    strings.TrimSpace(config.PairingURL) != "",
		SecureIdentity:       strings.TrimSpace(identity.PrivateKeyRef) != "",
	}
}
