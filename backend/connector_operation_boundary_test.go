package backend

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/proxy"
)

const p113MihomoOnlyOperationNode = `
name: p113-mieru
type: mieru
server: proxy.example.com
port: 40001
username: user
password: pass
transport: TCP
`

func TestP113OperationBoundariesRejectCrossStack(t *testing.T) {
	proxyID := "p113-mieru"
	proxies := []config.BrowserProxy{{ProxyId: proxyID, ProxyConfig: p113MihomoOnlyOperationNode}}

	if _, err := proxy.BuildProxyHTTPClient("", proxyID, proxies, nil, nil, nil, config.BrowserConnectorXray, time.Second); err == nil {
		t.Fatal("xray HTTP client accepted a Mihomo-only node")
	}
	connectivity := proxy.TestRealConnectivityWithRuntimeConfig(proxyID, proxies, nil, nil, nil, config.BrowserConnectorXray, nil)
	if connectivity.Ok || !strings.Contains(connectivity.Error, "connector xray") {
		t.Fatalf("xray real connectivity did not fail closed: %+v", connectivity)
	}
	tcpConnectivity := proxy.TestConnectivityWithConnector(proxyID, "", proxies, config.BrowserConnectorXray)
	if tcpConnectivity.Ok || !strings.Contains(tcpConnectivity.Error, "connector xray") {
		t.Fatalf("xray TCP connectivity did not fail closed: %+v", tcpConnectivity)
	}
	ipHealth, err := proxy.FetchIPHealthInfo(proxyID, proxies, nil, nil, nil, config.BrowserConnectorXray, nil)
	if err == nil || !strings.Contains(fmt.Sprint(ipHealth["error"]), "connector xray") {
		t.Fatalf("xray IP health did not fail closed: data=%v err=%v", ipHealth, err)
	}
	page := proxy.ProbeBrowserPageConnectivity(proxyID, proxies, nil, nil, nil, config.BrowserConnectorXray, nil)
	if page.Ok || !strings.Contains(page.Error, "connector xray") {
		t.Fatalf("xray page probe did not fail closed: %+v", page)
	}
	diagnostic := proxy.BuildProxyDiagnostic(p113MihomoOnlyOperationNode, nil, "", proxy.BuildDiagnosticOptions{ConnectorType: config.BrowserConnectorXray})
	if diagnostic.Ok || !strings.Contains(strings.Join(diagnostic.Errors, " "), "connector xray") {
		t.Fatalf("xray diagnostics did not fail closed: %+v", diagnostic)
	}
	app := &App{config: config.DefaultConfig()}
	if _, _, err := app.proxyCoreHTTPClient(time.Second, p113MihomoOnlyOperationNode, config.BrowserConnectorXray); err == nil {
		t.Fatal("xray core download client accepted a Mihomo-only node")
	}
}

func TestP113WarmupOperationMatrix(t *testing.T) {
	app := &App{}
	wrong := app.warmupProxyBridge("p113-mieru", p113MihomoOnlyOperationNode, nil, config.BrowserConnectorXray)
	if wrong.Ok || !strings.Contains(wrong.Error, "connector xray") {
		t.Fatalf("xray warmup did not fail closed: %+v", wrong)
	}

	singBox := app.warmupProxyBridge("", "hysteria2://pass@example.com:443", nil, config.BrowserConnectorXray)
	if singBox.Ok || singBox.Engine != proxy.ProxyKernelSingBox || !strings.Contains(singBox.Error, "sing-box") {
		t.Fatalf("xray hysteria2 warmup did not stay in sing-box boundary: %+v", singBox)
	}

	mihomo := app.warmupProxyBridge("", "vless://00000000-0000-0000-0000-000000000000@example.com:443", nil, config.BrowserConnectorMihomo)
	if mihomo.Ok || mihomo.Engine != proxy.ProxyKernelMihomo || !strings.Contains(strings.ToLower(mihomo.Error), "mihomo") {
		t.Fatalf("mihomo warmup did not stay in Mihomo boundary: %+v", mihomo)
	}

	direct := app.warmupProxyBridge("", "direct://", nil, config.BrowserConnectorXray)
	if !direct.Ok || direct.Engine != "direct" {
		t.Fatalf("literal direct warmup was not the sole native exception: %+v", direct)
	}
	empty := app.warmupProxyBridge("", "", nil, config.BrowserConnectorXray)
	if empty.Ok || !strings.Contains(empty.Error, "代理配置为空") {
		t.Fatalf("empty warmup config was accepted: %+v", empty)
	}
}

func TestP113DownloadOperationBoundaryRejectsEmptyAndSystemFallback(t *testing.T) {
	app := &App{config: config.DefaultConfig()}
	if _, _, err := app.proxyCoreHTTPClient(time.Second, "", config.BrowserConnectorXray); err == nil {
		t.Fatal("empty core download config was accepted")
	}
	if _, _, err := app.proxyCoreHTTPClient(time.Second, "__system__", config.BrowserConnectorXray); err == nil {
		t.Fatal("system proxy fallback was accepted")
	}
	if client, label, err := app.proxyCoreHTTPClient(time.Second, "direct://", config.BrowserConnectorXray); err != nil || client == nil || !strings.Contains(label, "直连") {
		t.Fatalf("literal direct download exception failed: client=%v label=%q err=%v", client, label, err)
	}
	if client, label, err := app.proxyCoreHTTPClient(time.Second, "direct://", config.BrowserConnectorXray); err != nil || client == nil || !strings.Contains(label, "xray") {
		t.Fatalf("direct download did not retain explicit connector label: client=%v label=%q err=%v", client, label, err)
	} else if transport, ok := client.Transport.(*http.Transport); !ok || transport.Proxy != nil {
		proxyConfigured := ok && transport.Proxy != nil
		t.Fatalf("direct download unexpectedly consults a system proxy: transport=%T proxy_configured=%t", client.Transport, proxyConfigured)
	}
	if _, _, err := app.proxyCoreHTTPClient(time.Second, "vless://00000000-0000-0000-0000-000000000000@example.com:443", config.BrowserConnectorXray); err == nil || !strings.Contains(err.Error(), "xray 管理器") {
		t.Fatalf("xray configured download did not stay in xray stack: %v", err)
	}
	if _, _, err := app.proxyCoreHTTPClient(time.Second, "vless://00000000-0000-0000-0000-000000000000@example.com:443", config.BrowserConnectorMihomo); err == nil || !strings.Contains(strings.ToLower(err.Error()), "mihomo") {
		t.Fatalf("mihomo configured download did not stay in Mihomo stack: %v", err)
	}
}

func TestP113DiagnosticsRejectUnknownConnectorEvenForDirect(t *testing.T) {
	result := proxy.BuildProxyDiagnostic("direct://", nil, "", proxy.BuildDiagnosticOptions{ConnectorType: ""})
	if result.Ok || !strings.Contains(strings.Join(result.Errors, " "), "connector type") {
		t.Fatalf("diagnostics accepted direct config without explicit connector: %+v", result)
	}
}
