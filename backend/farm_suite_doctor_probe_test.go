package backend

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func suiteDoctorProbeFixture(t *testing.T) (suiteIdentityFixture, SuiteOwnershipHandoff) {
	t.Helper()
	fixture := newSuiteEnrollmentFinalizeFixture(t, strings.Repeat("a", 128))
	deps := suiteEnrollmentFinalizeTestDependencies(fixture)
	if _, err := runSuiteCanonicalEnrollmentFinalizeWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
		t.Fatal(err)
	}
	versionRoot := filepath.Join(filepath.Dir(fixture.source), "versions", filepath.Base(fixture.source))
	if err := os.MkdirAll(filepath.Dir(versionRoot), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fixture.source, versionRoot); err != nil {
		t.Fatal(err)
	}
	fixture.source = versionRoot
	if _, err := FinalizeSuiteOwnershipHandoff(fixture.roots, fixture.preparation.RequestUID, fixture.source, filepath.Join(fixture.source, "AntBrowser.exe")); err != nil {
		t.Fatal(err)
	}
	handoff, err := LoadSuiteOwnershipHandoff(fixture.roots)
	if err != nil || handoff == nil {
		t.Fatalf("handoff=%+v err=%v", handoff, err)
	}
	return fixture, *handoff
}

func connectedSuiteDoctorProbeDependencies(discovery SuiteBootstrapDiscovery) suiteDoctorProbeDependencies {
	return suiteDoctorProbeDependencies{
		SessionDisplay: func(context.Context) suiteDoctorProbeResult {
			return suiteDoctorProbeResult{Status: "PASS", Code: "SESSION_DISPLAY_READY"}
		},
		LookupIP: func(context.Context, string, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("192.0.2.10")}, nil
		},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
		TLSDialContext: func(context.Context, string, string, *tls.Config) (net.Conn, error) {
			client, server := net.Pipe()
			_ = server.Close()
			return client, nil
		},
		FetchDiscovery: func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
			return discovery, nil
		},
	}
}

func TestSuiteDoctorNetworkProbeUsesBoundEvidenceAndFixedLayers(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	deps := connectedSuiteDoctorProbeDependencies(fixture.discovery)
	deps.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		if address != "192.0.2.10:8443" {
			return nil, errors.New("dial target was not resolver evidence")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	results := probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, deps)
	want := []suiteDoctorProbeResult{
		{Status: "PASS", Code: "DNS_RESOLVED"},
		{Status: "PASS", Code: "TCP_CONNECTED"},
		{Status: "PASS", Code: "TLS_VERIFIED"},
		{Status: "PASS", Code: "DISCOVERY_VERIFIED"},
	}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("results=%+v", results)
	}
	report := doctorSuiteWithDependencies(context.Background(), fixture.roots, &fakeSuiteServicePlatform{}, deps)
	for _, name := range []string{"session_display", "dns_tcp", "tls", "discovery"} {
		layer := suiteDoctorLayerNamed(report, name)
		if layer == nil || layer.Status != "PASS" {
			t.Fatalf("layer %s=%+v report=%+v", name, layer, report)
		}
	}
}

func TestSuiteDoctorNetworkProbeStopsAtFailedBoundary(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	cases := []struct {
		name string
		edit func(*suiteDoctorProbeDependencies)
		want []suiteDoctorProbeResult
	}{
		{name: "dns", edit: func(deps *suiteDoctorProbeDependencies) {
			deps.LookupIP = func(context.Context, string, string) ([]net.IP, error) { return nil, errors.New("secret dns detail") }
		}, want: []suiteDoctorProbeResult{{Status: "FAIL", Code: "DNS_RESOLUTION_FAILED", Retryable: true}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}}},
		{name: "tcp", edit: func(deps *suiteDoctorProbeDependencies) {
			deps.DialContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("secret tcp detail") }
		}, want: []suiteDoctorProbeResult{{Status: "PASS", Code: "DNS_RESOLVED"}, {Status: "FAIL", Code: "TCP_CONNECT_FAILED", Retryable: true}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}}},
		{name: "tls", edit: func(deps *suiteDoctorProbeDependencies) {
			deps.TLSDialContext = func(context.Context, string, string, *tls.Config) (net.Conn, error) {
				return nil, errors.New("certificate secret detail")
			}
		}, want: []suiteDoctorProbeResult{{Status: "PASS", Code: "DNS_RESOLVED"}, {Status: "PASS", Code: "TCP_CONNECTED"}, {Status: "FAIL", Code: "TLS_VERIFY_FAILED", Retryable: true}, {Status: "BLOCKED", Code: "PREREQUISITE_BLOCKED"}}},
		{name: "discovery", edit: func(deps *suiteDoctorProbeDependencies) {
			deps.FetchDiscovery = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
				return SuiteBootstrapDiscovery{}, ErrSuiteBootstrapResponse
			}
		}, want: []suiteDoctorProbeResult{{Status: "PASS", Code: "DNS_RESOLVED"}, {Status: "PASS", Code: "TCP_CONNECTED"}, {Status: "PASS", Code: "TLS_VERIFIED"}, {Status: "FAIL", Code: "DISCOVERY_REJECTED"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deps := connectedSuiteDoctorProbeDependencies(fixture.discovery)
			tc.edit(&deps)
			if got := probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, deps); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got=%+v want=%+v", got, tc.want)
			}
		})
	}
}

func TestSuiteDoctorNetworkProbeRejectsDiscoveryAndLocalEvidenceDrift(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	changed := fixture.discovery
	changed.SupportedCapabilities = append(append([]string(nil), changed.SupportedCapabilities...), "unexpected")
	deps := connectedSuiteDoctorProbeDependencies(changed)
	results := probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, deps)
	if results[3].Status != "FAIL" || results[3].Code != "DISCOVERY_DRIFT" {
		t.Fatalf("discovery drift=%+v", results)
	}
	bootstrapPath := filepath.Join(fixture.roots.Config, suiteBootstrapDraftName)
	if err := writeOwnerAtomic(bootstrapPath, []byte("{}\n")); err != nil {
		t.Fatal(err)
	}
	results = probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, connectedSuiteDoctorProbeDependencies(fixture.discovery))
	if results[0].Status != "BLOCKED" || results[3].Status != "FAIL" || results[3].Code != "DISCOVERY_EVIDENCE_INVALID" {
		t.Fatalf("local evidence drift=%+v", results)
	}
}

func TestSuiteDoctorNetworkProbeBindsReceiptToBootstrapDigest(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	receipt, err := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap)
	if err != nil || receipt == nil {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	receipt.BootstrapSHA256 = strings.Repeat("b", 64)
	raw, err := marshalSuiteTransportReceipt(*receipt, fixture.bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerAtomic(filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName), raw); err != nil {
		t.Fatal(err)
	}
	results := probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, connectedSuiteDoctorProbeDependencies(fixture.discovery))
	if results[0].Status != "BLOCKED" || results[3].Status != "FAIL" || results[3].Code != "DISCOVERY_EVIDENCE_INVALID" {
		t.Fatalf("receipt binding=%+v", results)
	}
}

func TestSuiteDoctorProbeCodesCannotLeakUnderlyingErrors(t *testing.T) {
	fixture, _ := suiteDoctorProbeFixture(t)
	deps := connectedSuiteDoctorProbeDependencies(fixture.discovery)
	deps.LookupIP = func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("https://secret.example/ 203.0.113.9 private certificate")
	}
	report := doctorSuiteWithDependencies(context.Background(), fixture.roots, &fakeSuiteServicePlatform{}, deps)
	raw := strings.ToLower(toJSON(report))
	for _, forbidden := range []string{"secret.example", "203.0.113.9", "private certificate", fixture.roots.Config} {
		if strings.Contains(raw, strings.ToLower(forbidden)) {
			t.Fatalf("report leaked %q: %s", forbidden, raw)
		}
	}
	if report.ExitClass != "NETWORK_TLS" || SuiteDoctorExitCode(report) != 3 {
		t.Fatalf("classification=%+v", report)
	}
	if layer := suiteDoctorLayerNamed(report, "enrollment"); layer == nil || layer.Status != "PASS" {
		t.Fatalf("network failure suppressed local diagnosis: %+v", report)
	}
}

func TestSuiteDoctorTLSProbePinsSystemPolicyAndSessionDominates(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	deps := connectedSuiteDoctorProbeDependencies(fixture.discovery)
	deps.SessionDisplay = func(context.Context) suiteDoctorProbeResult {
		return suiteDoctorProbeResult{Status: "FAIL", Code: "DISPLAY_UNAVAILABLE", Retryable: true}
	}
	deps.TLSDialContext = func(_ context.Context, _, _ string, config *tls.Config) (net.Conn, error) {
		if config == nil || config.MinVersion != tls.VersionTLS12 || config.ServerName != "farm.example.test" || config.InsecureSkipVerify || config.RootCAs != nil {
			return nil, errors.New("unsafe TLS policy")
		}
		client, server := net.Pipe()
		_ = server.Close()
		return client, nil
	}
	if results := probeSuiteDoctorNetwork(context.Background(), fixture.roots, handoff, deps); results[2].Status != "PASS" {
		t.Fatalf("tls policy=%+v", results)
	}
	report := doctorSuiteWithDependencies(context.Background(), fixture.roots, &fakeSuiteServicePlatform{}, deps)
	if report.ExitClass != "USER_SESSION" || report.DominantCode != "DISPLAY_UNAVAILABLE" || SuiteDoctorExitCode(report) != 7 {
		t.Fatalf("session classification=%+v", report)
	}
}

func TestSuiteDoctorNetworkProbeHonorsCancelledParentBudget(t *testing.T) {
	fixture, handoff := suiteDoctorProbeFixture(t)
	deps := connectedSuiteDoctorProbeDependencies(fixture.discovery)
	dialed := false
	deps.LookupIP = func(ctx context.Context, _, _ string) ([]net.IP, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	deps.DialContext = func(context.Context, string, string) (net.Conn, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	results := probeSuiteDoctorNetwork(ctx, fixture.roots, handoff, deps)
	if results[0].Code != "DNS_TIMEOUT" || !results[0].Retryable || dialed {
		t.Fatalf("cancelled probe=%+v dialed=%v", results, dialed)
	}
}

func suiteDoctorLayerNamed(report SuiteDoctorReport, name string) *SuiteDoctorLayer {
	for index := range report.Layers {
		if report.Layers[index].Name == name {
			return &report.Layers[index]
		}
	}
	return nil
}
