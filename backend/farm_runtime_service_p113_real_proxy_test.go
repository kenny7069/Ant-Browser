package backend

import (
	"ant-chrome/backend/internal/browser"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFarmRuntimeP113RealXrayProxyChrome is the opt-in authenticated-proxy
// evidence path.  It starts a loopback Xray SOCKS5 server with credentials,
// then asks the public Farm factory to use the existing XrayManager bridge.
// No test pre-creates that bridge and no secret is written to test output.
func TestFarmRuntimeP113RealXrayProxyChrome(t *testing.T) {
	if os.Getenv("P113_REAL_XRAY_PROXY") != "1" {
		t.Skip("explicit P113_REAL_XRAY_PROXY=1 opt-in required")
	}
	xrayPath := "/tmp/bf-p113-xray-v26.7.11/xray"
	if _, err := os.Stat(xrayPath); err != nil {
		t.Fatal("approved local Xray fixture is unavailable")
	}
	initialRoots := p113XrayRoots()

	var upstreamHits atomic.Int64
	var probeBaseline atomic.Int64
	target := httptestP113Target(t, &upstreamHits)
	upstream := startP113AuthenticatedXrayWithAccessLog(t, xrayPath)
	defer upstream.stop()

	cfg := DefaultConfig()
	cfg.Browser.XrayBinaryPath = xrayPath
	cfg.Browser.DefaultConnectorType = "xray"
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.StartReadyTimeoutMs = 15000
	cfg.Browser.StartStableWindowMs = 100
	cfg.Browser.DefaultStartURLs = []string{target.url}
	coreRoot := "/Applications"
	cfg.Browser.Cores = []browser.Core{{CoreId: "chrome", CorePath: coreRoot, IsDefault: true}}
	profileID := "p113-real-proxy"
	// This is local profile-store material.  It is intentionally not included
	// in a Farm request, attestation, assertion, or t.Log output.
	profile := BrowserProfile{ProfileId: profileID, ProfileName: "P1.13 isolated", CoreId: "chrome", UserDataDir: filepath.Join(t.TempDir(), "profile"), RestoreLastSession: "never", ProxyConfig: "socks5://p113-user:p113-password@" + upstream.address, LaunchArgs: []string{"--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-background-networking", "--proxy-bypass-list=<-loopback>"}}

	var mu sync.Mutex
	var launch *BrowserRuntimeLaunchSpec
	var farm *FarmRuntimeService
	var err error
	farm, err = NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		NodeUID: "node-p113", ProviderInstanceID: "provider-p113", FencingEpoch: 1,
		BrowserRuntimeFactory: BrowserRuntimeServiceFactoryConfig{AppRoot: t.TempDir(), Config: cfg, Profiles: []BrowserProfile{profile}, Host: BrowserRuntimeHost{
			StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
				process, startErr := NewBrowserRuntimeLocalProcess(plan.Spec)
				mu.Lock()
				spec := plan.Spec
				spec.Args = append([]string(nil), plan.Spec.Args...)
				launch = &spec
				mu.Unlock()
				return process, startErr
			},
			StopProcess: func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
			CanConnect:  canConnectDebugPort, TryCloseCDP: tryCloseBrowserViaCDP, CreateTarget: createBrowserStartTarget,
		}},
		AttestationStateProvider: func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
			if upstreamHits.Load() <= probeBaseline.Load() || !p113XrayAccessedTarget(upstream.accessLog, target) {
				return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
			}
			binding, bindingErr := farm.runtimeService.LocalProfileProxyBinding(profileID)
			if bindingErr != nil {
				return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
			}
			policy := FarmAttestationPolicy{AllowedDomains: []string{}, WebRTCMode: "disable_non_proxied_udp"}
			return FarmAttestationLaunchState{Ready: true, Policy: policy, AppliedRuntime: FarmAttestationRuntime{AllowedDomains: []string{}, WebRTCMode: policy.WebRTCMode, Proxy: FarmAttestationProxy{Enabled: true, ConnectorType: binding.ConnectorType, CredentialRevision: binding.CredentialRevision, ConfigRevision: binding.ConfigRevision}}}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer farm.runtimeService.Shutdown()
	binding, err := farm.runtimeService.LocalProfileProxyBinding(profileID)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := farm.EnsureRuntime(FarmRuntimeEnsureRequest{NodeUID: "node-p113", ProfileID: profileID, ConfigHash: "p113-safe-config-hash", LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: &binding})
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	effectiveProxy := ""
	if launch != nil {
		effectiveProxy = launch.EffectiveProxy
	}
	mu.Unlock()
	if !strings.HasPrefix(effectiveProxy, "socks5://127.0.0.1:") || effectiveProxy == "direct://" || strings.Contains(effectiveProxy, "p113-") {
		t.Fatal("production launch did not receive a masked loopback Xray bridge")
	}
	assertP113SecureRoots(t, initialRoots)
	if !waitP113(func() bool { return upstreamHits.Load() > 0 }, 5*time.Second) {
		t.Fatal("real Chrome did not reach controlled endpoint through authenticated upstream")
	}
	request := FarmAttestationRequest{Version: FarmAttestationVersion, RuntimeIdentity: runtime.FarmRuntimeIdentity, PolicyHash: "p113-policy", ConfigHash: runtime.ConfigHash, Policy: FarmAttestationPolicy{AllowedDomains: []string{}, WebRTCMode: "disable_non_proxied_udp"}, RuntimeConfig: FarmAttestationRuntime{AllowedDomains: []string{}, WebRTCMode: "disable_non_proxied_udp", Proxy: FarmAttestationProxy{Enabled: true, ConnectorType: binding.ConnectorType, CredentialRevision: binding.CredentialRevision, ConfigRevision: binding.ConfigRevision}}}
	if _, err := farm.AttestRuntimeFromLocalState(request); err != nil {
		t.Fatal(err)
	}
	if _, err := farm.StopRuntime(FarmRuntimeStopRequest{NodeUID: runtime.NodeUID, ProfileID: runtime.ProfileID, RuntimeUID: runtime.RuntimeUID, ProviderInstanceID: runtime.ProviderInstanceID, FencingEpoch: runtime.FencingEpoch, ConfigHash: runtime.ConfigHash, Generation: runtime.Generation}); err != nil {
		t.Fatal(err)
	}

	// Rotate only the local connector-store password.  The Server-facing
	// binding remains revisions/hash, while real SOCKS I/O must reject it.
	probeBaseline.Store(upstreamHits.Load())
	manager := farm.runtimeService.Manager()
	manager.Mutex.Lock()
	manager.Profiles[profileID].ProxyConfig = strings.Replace(manager.Profiles[profileID].ProxyConfig, "p113-password", "p113-wrong", 1)
	manager.Mutex.Unlock()
	wrongBinding, bindingErr := farm.runtimeService.LocalProfileProxyBinding(profileID)
	if bindingErr != nil {
		t.Fatal(bindingErr)
	}
	var wrongFarm *FarmRuntimeService
	wrongFarm, err = NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		BrowserRuntimeService: farm.runtimeService, NodeUID: "node-p113", ProviderInstanceID: "provider-p113", FencingEpoch: 1,
		AttestationStateProvider: func(FarmRuntimeIdentity) (FarmAttestationLaunchState, error) {
			return FarmAttestationLaunchState{}, ErrFarmAttestationNotReady
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong, ensureErr := wrongFarm.EnsureRuntime(FarmRuntimeEnsureRequest{NodeUID: "node-p113", ProfileID: profileID, ConfigHash: "p113-safe-config-hash-rotated", LaunchMode: FarmRuntimeLaunchModeProfileProxy, Proxy: &wrongBinding})
	if ensureErr != nil {
		t.Fatalf("wrong credential must fail at ready connectivity/attestation, not bridge construction: %v", ensureErr)
	}
	time.Sleep(500 * time.Millisecond)
	wrongRequest := request
	wrongRequest.RuntimeIdentity = wrong.FarmRuntimeIdentity
	wrongRequest.ConfigHash = wrong.ConfigHash
	wrongRequest.RuntimeConfig.Proxy = FarmAttestationProxy{Enabled: true, ConnectorType: wrongBinding.ConnectorType, CredentialRevision: wrongBinding.CredentialRevision, ConfigRevision: wrongBinding.ConfigRevision}
	if _, err := wrongFarm.AttestRuntimeFromLocalState(wrongRequest); !errors.Is(err, ErrFarmAttestationNotReady) {
		t.Fatalf("wrong credential attestation = %v, want connectivity fail closed", err)
	}
	if upstreamHits.Load() != probeBaseline.Load() {
		t.Fatal("wrong credential unexpectedly reached controlled endpoint")
	}
	if _, err := wrongFarm.StopRuntime(FarmRuntimeStopRequest{NodeUID: wrong.NodeUID, ProfileID: wrong.ProfileID, RuntimeUID: wrong.RuntimeUID, ProviderInstanceID: wrong.ProviderInstanceID, FencingEpoch: wrong.FencingEpoch, ConfigHash: wrong.ConfigHash, Generation: wrong.Generation}); err != nil {
		t.Fatal(err)
	}
	if !waitP113(func() bool { return p113SameRoots(initialRoots, p113XrayRoots()) }, 3*time.Second) {
		t.Fatal("strict stop did not clean released Xray bridge configs")
	}
}

type p113HTTPServer struct {
	server *http.Server
	url    string
}

func httptestP113Target(t *testing.T, hits *atomic.Int64) p113HTTPServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte("ok")) })}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return p113HTTPServer{server: server, url: "http://" + listener.Addr().String()}
}

type p113XrayUpstream struct {
	address   string
	accessLog string
	stop      func()
}

func startP113AuthenticatedXray(t *testing.T, binary string) (string, func()) {
	t.Helper()
	upstream := startP113AuthenticatedXrayWithAccessLog(t, binary)
	return upstream.address, upstream.stop
}

func startP113AuthenticatedXrayWithAccessLog(t *testing.T, binary string) p113XrayUpstream {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	accessLog := filepath.Join(dir, "access.log")
	errorLog := filepath.Join(dir, "error.log")
	config := map[string]any{"log": map[string]any{"access": accessLog, "error": errorLog, "loglevel": "warning"}, "inbounds": []any{map[string]any{"listen": host, "port": mustP113Port(t, port), "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": "p113-user", "pass": "p113-password"}}}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "upstream.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	if !waitP113(func() bool {
		c, e := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if e == nil {
			_ = c.Close()
			return true
		}
		return false
	}, 5*time.Second) {
		_ = cmd.Process.Kill()
		t.Fatal("authenticated upstream did not start")
	}
	return p113XrayUpstream{address: addr, accessLog: accessLog, stop: func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	}}
}

func mustP113Port(t *testing.T, value string) int {
	var port int
	if _, err := fmt.Sscan(value, &port); err != nil || port < 1 {
		t.Fatal("invalid test port")
	}
	return port
}
func waitP113(check func() bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return check()
}

func p113XrayRoots() map[string]struct{} {
	roots, _ := filepath.Glob(filepath.Join(os.TempDir(), "ant-proxy-xray-*"))
	result := make(map[string]struct{}, len(roots))
	for _, root := range roots {
		result[root] = struct{}{}
	}
	return result
}

func p113SameRoots(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for root := range left {
		if _, ok := right[root]; !ok {
			return false
		}
	}
	return true
}

func p113XrayAccessedTarget(logPath string, target p113HTTPServer) bool {
	return p113XrayAccessedTargetAfter(logPath, target, 0)
}

func p113XrayAccessLogSize(logPath string) int64 {
	info, err := os.Stat(logPath)
	if err != nil {
		return 0
	}
	return info.Size()
}

func p113XrayAccessedTargetAfter(logPath string, target p113HTTPServer, offset int64) bool {
	raw, err := os.ReadFile(logPath)
	if err != nil {
		return false
	}
	if offset < 0 || offset > int64(len(raw)) {
		offset = 0
	}
	return strings.Contains(string(raw[offset:]), strings.TrimPrefix(target.url, "http://"))
}

func assertP113SecureRoots(t *testing.T, initial map[string]struct{}) {
	t.Helper()
	if err := p113SecureRootsError(initial); err != nil {
		t.Fatal(err)
	}
}

func p113SecureRootsError(initial map[string]struct{}) error {
	for root := range p113XrayRoots() {
		if _, existed := initial[root]; existed {
			continue
		}
		info, err := os.Stat(root)
		if err != nil || info.Mode().Perm() != 0700 {
			return fmt.Errorf("Xray temporary root does not satisfy Unix private-directory contract")
		}
		err = filepath.Walk(root, func(_ string, entry os.FileInfo, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Mode().IsRegular() && entry.Mode().Perm() != 0600 {
				return fmt.Errorf("temporary Xray file mode is not private")
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("Xray temporary config permission audit failed")
		}
		return nil
	}
	return fmt.Errorf("production Xray bridge did not create an isolated temporary config root")
}
