package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"reflect"
	"time"
)

const (
	suiteDoctorTotalProbeTimeout = 20 * time.Second
	suiteDoctorPhaseTimeout      = 5 * time.Second
)

type suiteDoctorProbeResult struct {
	Status    string
	Code      string
	Retryable bool
}

type suiteDoctorProbeDependencies struct {
	SessionDisplay func(context.Context) suiteDoctorProbeResult
	LookupIP       func(context.Context, string, string) ([]net.IP, error)
	DialContext    func(context.Context, string, string) (net.Conn, error)
	TLSDialContext func(context.Context, string, string, *tls.Config) (net.Conn, error)
	FetchDiscovery func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error)
}

func newSuiteDoctorProbeDependencies() suiteDoctorProbeDependencies {
	resolver := net.DefaultResolver
	dialer := &net.Dialer{}
	return suiteDoctorProbeDependencies{
		SessionDisplay: probeSuiteDoctorSessionDisplay,
		LookupIP:       resolver.LookupIP,
		DialContext:    dialer.DialContext,
		TLSDialContext: func(ctx context.Context, network, address string, config *tls.Config) (net.Conn, error) {
			return (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, network, address)
		},
		FetchDiscovery: FetchSuiteBootstrapDiscovery,
	}
}

func deferredSuiteDoctorProbeDependencies() suiteDoctorProbeDependencies {
	return suiteDoctorProbeDependencies{
		SessionDisplay: func(context.Context) suiteDoctorProbeResult {
			return suiteDoctorProbeResult{Status: "UNKNOWN", Code: "CHECK_NOT_IMPLEMENTED"}
		},
	}
}

func suiteDoctorProbeContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return context.WithTimeout(parent, suiteDoctorTotalProbeTimeout)
}

func suiteDoctorPhaseContext(parent context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, suiteDoctorPhaseTimeout)
}

func probeSuiteDoctorNetwork(ctx context.Context, roots SuiteUserRoots, handoff SuiteOwnershipHandoff, deps suiteDoctorProbeDependencies) []suiteDoctorProbeResult {
	blocked := suiteDoctorProbeResult{Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}
	failEvidence := []suiteDoctorProbeResult{blocked, blocked, blocked, {Status: "FAIL", Code: "DISCOVERY_EVIDENCE_INVALID"}}
	if deps.LookupIP == nil || deps.DialContext == nil || deps.TLSDialContext == nil || deps.FetchDiscovery == nil {
		return []suiteDoctorProbeResult{
			{Status: "UNKNOWN", Code: "CHECK_NOT_IMPLEMENTED"},
			{Status: "UNKNOWN", Code: "CHECK_NOT_IMPLEMENTED"},
			{Status: "UNKNOWN", Code: "CHECK_NOT_IMPLEMENTED"},
			{Status: "UNKNOWN", Code: "CHECK_NOT_IMPLEMENTED"},
		}
	}
	bootstrap, exists, err := loadBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName))
	preparation, preparationErr := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
	if err != nil || !exists || bootstrap == nil || preparationErr != nil || preparation == nil || preparation.Stage != SetupBootstrapDrafted ||
		preparation.RequestUID != handoff.SetupRequestUID {
		return failEvidence
	}
	bootstrapDigest, err := bootstrapConfigDigest(*bootstrap)
	if err != nil || bootstrapDigest != preparation.BootstrapSHA256 {
		return failEvidence
	}
	receipt, err := LoadSuiteTransportReceipt(roots, *bootstrap)
	if err != nil || receipt == nil || receipt.RequestUID != handoff.SetupRequestUID || receipt.SetupStageID != handoff.SetupStageID ||
		receipt.BootstrapSHA256 != preparation.BootstrapSHA256 || receipt.ManifestSHA256 != handoff.ManifestSHA256 ||
		receipt.Target != handoff.ReleaseTarget || receipt.Version != filepath.Base(handoff.SuiteBinaryRoot) {
		return failEvidence
	}
	clientConfig, digest, err := loadSuiteHandoffClientConfig(handoff.ClientConfigPath)
	if err != nil || digest != handoff.ClientConfigSHA256 || !suiteDoctorConfigMatchesDiscovery(clientConfig, receipt.discovery(), *bootstrap) {
		return failEvidence
	}
	origin, err := url.Parse(bootstrap.ServerURL)
	if err != nil || origin.Hostname() == "" {
		return failEvidence
	}
	port := origin.Port()
	if port == "" {
		port = "443"
	}
	dnsCtx, cancelDNS := suiteDoctorPhaseContext(ctx)
	addresses, err := deps.LookupIP(dnsCtx, "ip", origin.Hostname())
	dnsContextErr := dnsCtx.Err()
	cancelDNS()
	if err != nil || len(addresses) == 0 {
		if dnsContextErr != nil {
			return []suiteDoctorProbeResult{{Status: "FAIL", Code: "DNS_TIMEOUT", Retryable: true}, blocked, blocked, blocked}
		}
		return []suiteDoctorProbeResult{{Status: "FAIL", Code: "DNS_RESOLUTION_FAILED", Retryable: true}, blocked, blocked, blocked}
	}
	dns := suiteDoctorProbeResult{Status: "PASS", Code: "DNS_RESOLVED"}

	tcpCtx, cancelTCP := suiteDoctorPhaseContext(ctx)
	selectedAddress := ""
	for _, resolved := range addresses {
		if resolved == nil {
			continue
		}
		candidate := net.JoinHostPort(resolved.String(), port)
		connection, dialErr := deps.DialContext(tcpCtx, "tcp", candidate)
		if dialErr == nil && connection != nil {
			selectedAddress = candidate
			_ = connection.Close()
			break
		}
		if connection != nil {
			_ = connection.Close()
		}
	}
	tcpContextErr := tcpCtx.Err()
	cancelTCP()
	if selectedAddress == "" {
		code := "TCP_CONNECT_FAILED"
		if tcpContextErr != nil {
			code = "TCP_TIMEOUT"
		}
		return []suiteDoctorProbeResult{dns, {Status: "FAIL", Code: code, Retryable: true}, blocked, blocked}
	}
	tcp := suiteDoctorProbeResult{Status: "PASS", Code: "TCP_CONNECTED"}

	tlsCtx, cancelTLS := suiteDoctorPhaseContext(ctx)
	tlsConnection, err := deps.TLSDialContext(tlsCtx, "tcp", selectedAddress, &tls.Config{MinVersion: tls.VersionTLS12, ServerName: origin.Hostname()})
	tlsContextErr := tlsCtx.Err()
	cancelTLS()
	if err != nil || tlsConnection == nil {
		if tlsConnection != nil {
			_ = tlsConnection.Close()
		}
		code := "TLS_VERIFY_FAILED"
		if tlsContextErr != nil {
			code = "TLS_TIMEOUT"
		}
		return []suiteDoctorProbeResult{dns, tcp, {Status: "FAIL", Code: code, Retryable: true}, blocked}
	}
	_ = tlsConnection.Close()
	tlsResult := suiteDoctorProbeResult{Status: "PASS", Code: "TLS_VERIFIED"}

	fresh, err := deps.FetchDiscovery(ctx, *bootstrap)
	if err != nil {
		if ctx.Err() != nil {
			return []suiteDoctorProbeResult{dns, tcp, tlsResult, {Status: "FAIL", Code: "DISCOVERY_TIMEOUT", Retryable: true}}
		}
		if errors.Is(err, ErrSuiteBootstrapTLS) {
			return []suiteDoctorProbeResult{dns, tcp, {Status: "FAIL", Code: "TLS_VERIFY_FAILED", Retryable: true}, blocked}
		}
		if errors.Is(err, ErrSuiteBootstrapTransport) {
			return []suiteDoctorProbeResult{dns, {Status: "FAIL", Code: "TCP_CONNECT_FAILED", Retryable: true}, blocked, blocked}
		}
		if errors.Is(err, ErrSuiteBootstrapCompatibility) {
			return []suiteDoctorProbeResult{dns, tcp, tlsResult, {Status: "FAIL", Code: "DISCOVERY_INCOMPATIBLE"}}
		}
		return []suiteDoctorProbeResult{dns, tcp, tlsResult, {Status: "FAIL", Code: "DISCOVERY_REJECTED"}}
	}
	if !reflect.DeepEqual(fresh, receipt.discovery()) {
		return []suiteDoctorProbeResult{dns, tcp, tlsResult, {Status: "FAIL", Code: "DISCOVERY_DRIFT"}}
	}
	return []suiteDoctorProbeResult{dns, tcp, tlsResult, {Status: "PASS", Code: "DISCOVERY_VERIFIED"}}
}

func suiteDoctorConfigMatchesDiscovery(config FarmClientConfig, discovery SuiteBootstrapDiscovery, bootstrap BootstrapConfig) bool {
	if config.ControlURL != discovery.ControlEndpoint || config.WSSURL != discovery.ControlEndpoint || config.EnrollmentURL != discovery.EnrollmentEndpoint {
		return false
	}
	origin, err := canonicalSuiteBootstrapOrigin(bootstrap.ServerURL, "https")
	if err != nil || config.PairingURL != origin+"/api/farm/pair" {
		return false
	}
	if discovery.Update == nil {
		return config.UpdateManifestURL == "" && config.UpdatePublicKey == "" && config.UpdateChannel == ""
	}
	return config.UpdateManifestURL == discovery.Update.ManifestURL && config.UpdatePublicKey == discovery.Update.PublicKeyEd25519Base64 && config.UpdateChannel == discovery.Update.Channel
}
