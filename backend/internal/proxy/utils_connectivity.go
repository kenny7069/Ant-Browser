package proxy

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"ant-chrome/backend/internal/config"
)

// TestConnectivity is retained for source compatibility but cannot safely
// infer a connector. It deliberately performs no network operation.
func TestConnectivity(proxyId string, proxyConfig string, proxies []config.BrowserProxy, _ interface{}) TestResult {
	return connectorRequiredTestResult(proxyId)
}

// TestConnectivityWithConnector 通过 TCP 握手测试代理服务器的可达性和延迟。
// TCP probe 本身不启动 bridge，但仍先经 connector-aware resolver 验证协议属于
// 当前 stack；因此它不能把 Mihomo-only 节点当成 xray operation 的有效输入。
func TestConnectivityWithConnector(proxyId string, proxyConfig string, proxies []config.BrowserProxy, connectorType string) TestResult {
	src := strings.TrimSpace(proxyConfig)
	if proxyId != "" {
		for _, item := range proxies {
			if strings.EqualFold(item.ProxyId, proxyId) {
				src = strings.TrimSpace(item.ProxyConfig)
				break
			}
		}
	}
	if src == "" {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: "tcp", Error: "代理配置为空"}
	}
	if _, err := ResolveProxyKernelForConnector(src, proxies, proxyId, connectorType); err != nil {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: strings.TrimSpace(connectorType), Error: safeProxyError(err)}
	}

	endpoint, err := proxyEndpoint(src)
	if err != nil {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: "tcp", Error: "地址解析失败: " + safeProxyError(err)}
	}

	start := time.Now()
	conn, err := net.DialTimeout("tcp", endpoint, 10*time.Second)
	latency := time.Since(start).Milliseconds()

	if err != nil {
		return TestResult{ProxyId: proxyId, Ok: false, LatencyMs: latency, Engine: "tcp", Error: safeProxyError(err)}
	}
	conn.Close()
	return TestResult{ProxyId: proxyId, Ok: true, LatencyMs: latency, Engine: "tcp"}
}

// TestRealConnectivity is a compatibility wrapper with no connector and is
// deliberately fail-closed without starting a bridge or making a request.
func TestRealConnectivity(
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
) TestResult {
	return connectorRequiredTestResult(proxyId)
}

// TestRealConnectivityWithSingBox is retained for source compatibility only;
// use TestRealConnectivityWithRuntimeConfig with an explicit connector.
func TestRealConnectivityWithSingBox(
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
) TestResult {
	return connectorRequiredTestResult(proxyId)
}

// TestRealConnectivityWithConfig is retained for source compatibility only.
func TestRealConnectivityWithConfig(
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
	cfg *SpeedTestConfig,
) TestResult {
	return connectorRequiredTestResult(proxyId)
}

func connectorRequiredTestResult(proxyId string) TestResult {
	return TestResult{ProxyId: proxyId, Engine: "connector", Error: ErrConnectorTypeRequired.Error()}
}

func TestRealConnectivityWithRuntimeConfig(
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
	clashMgr *ClashManager,
	connectorType string,
	cfg *SpeedTestConfig,
) TestResult {
	src := resolveProxyConfig("", proxies, proxyId)
	engine := speedTestProbeEngine(src, proxies, proxyId, connectorType)
	if src == "" {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: engine, Error: "代理配置为空"}
	}

	targetURLs := defaultRealConnectivityTargets()
	timeout := 15 * time.Second
	if cfg != nil {
		if len(cfg.URLs) > 0 {
			configuredURLs := normalizeSpeedTestURLs(cfg.URLs)
			if len(configuredURLs) > 0 {
				targetURLs = append(configuredURLs, targetURLs...)
			}
		}
		if cfg.Timeout > 0 {
			timeout = cfg.Timeout
		}
	}
	targetURLs = uniqueSpeedTestURLs(targetURLs)
	if len(targetURLs) == 0 {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: engine, Error: "真实连通性测试目标 URL 为空"}
	}

	client, err := buildProxyHTTPClient(src, proxyId, proxies, xrayMgr, singboxMgr, clashMgr, connectorType, timeout)
	if err != nil {
		return TestResult{ProxyId: proxyId, Ok: false, Engine: engine, Error: safeProxyError(err)}
	}

	var lastErr error
	var lastLatency int64
	for _, targetURL := range targetURLs {
		start := time.Now()
		resp, err := client.Get(targetURL)
		latency := time.Since(start).Milliseconds()
		lastLatency = latency
		if err != nil {
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if isSpeedTestSuccessStatus(resp.StatusCode) {
			return TestResult{ProxyId: proxyId, Ok: true, LatencyMs: latency, Engine: engine}
		}
		lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	if lastErr != nil {
		return TestResult{ProxyId: proxyId, Ok: false, LatencyMs: lastLatency, Engine: engine, Error: "真实访问失败: " + safeProxyError(lastErr)}
	}
	return TestResult{ProxyId: proxyId, Ok: false, LatencyMs: lastLatency, Engine: engine, Error: "真实连通性测试失败"}
}

func defaultRealConnectivityTargets() []string {
	return []string{
		DefaultSpeedTestURL,
		"https://cp.cloudflare.com/generate_204",
		"https://www.cloudflare.com/cdn-cgi/trace",
		"http://www.msftconnecttest.com/connecttest.txt",
	}
}

func normalizeSpeedTestURLs(urls []string) []string {
	result := make([]string, 0, len(urls))
	for _, item := range urls {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func uniqueSpeedTestURLs(urls []string) []string {
	result := make([]string, 0, len(urls))
	seen := map[string]struct{}{}
	for _, item := range normalizeSpeedTestURLs(urls) {
		key := strings.ToLower(item)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, item)
	}
	return result
}

func isSpeedTestSuccessStatus(statusCode int) bool {
	return statusCode == http.StatusNoContent || (statusCode >= 200 && statusCode < 300)
}
