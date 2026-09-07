package proxy

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/logger"

	xproxy "golang.org/x/net/proxy"
)

// buildProxyHTTPClient 根据代理配置构建 HTTP 客户端，统一用于测速/健康检测场景。
func BuildProxyHTTPClient(
	src string,
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
	clashMgr *ClashManager,
	connectorType string,
	timeout time.Duration,
) (*http.Client, error) {
	return buildProxyHTTPClient(src, proxyId, proxies, xrayMgr, singboxMgr, clashMgr, connectorType, timeout)
}

func buildProxyHTTPClient(
	src string,
	proxyId string,
	proxies []config.BrowserProxy,
	xrayMgr *XrayManager,
	singboxMgr *SingBoxManager,
	clashMgr *ClashManager,
	connectorType string,
	timeout time.Duration,
) (*http.Client, error) {
	src = strings.TrimSpace(resolveProxyConfig(src, proxies, proxyId))
	log := logger.New("ProxyHTTPClient")
	resolution, err := ResolveProxyKernelForConnector(src, proxies, proxyId, connectorType)
	if err != nil {
		log.Warn("代理内核解析失败",
			logger.F("proxy_id", proxyId),
			logger.F("error", safeProxyError(err)),
		)
		return nil, err
	}
	log.Info("代理 HTTP 客户端内核选择",
		logger.F("proxy_id", proxyId),
		logger.F("protocol", resolution.Protocol),
		logger.F("kernel", resolution.Kernel),
		logger.F("preferred_kernel", resolution.PreferredKernel),
		logger.F("supported_kernels", strings.Join(resolution.SupportedKernels, ",")),
		logger.F("reason", resolution.Reason),
	)
	l := strings.ToLower(strings.TrimSpace(src))
	if l == "direct://" {
		return BuildDirectHTTPClient(timeout), nil
	}

	switch resolution.Kernel {
	case ProxyKernelMihomo:
		if clashMgr == nil {
			log.Warn("Mihomo 管理器未初始化", logger.F("proxy_id", proxyId))
			return nil, fmt.Errorf("Mihomo 管理器未初始化")
		}
		proxyAddr, err := clashMgr.EnsureNodeBridge(src, proxies, proxyId)
		if err != nil {
			log.Warn("Mihomo 桥接启动失败", logger.F("proxy_id", proxyId), logger.F("error", safeProxyError(err)))
			return nil, fmt.Errorf("Mihomo 桥接启动失败: %w", err)
		}
		log.Info("Mihomo 桥接已就绪", logger.F("proxy_id", proxyId), logger.F("proxy_addr", safeProxyURI(proxyAddr)))
		return buildHTTPProxyClient(proxyAddr, timeout)
	case ProxyKernelSingBox:
		if singboxMgr == nil {
			log.Warn("sing-box 管理器未初始化", logger.F("proxy_id", proxyId))
			return nil, fmt.Errorf("sing-box 管理器未初始化")
		}
		socks5Addr, err := singboxMgr.EnsureBridge(src, proxies, proxyId)
		if err != nil {
			log.Warn("sing-box 桥接启动失败", logger.F("proxy_id", proxyId), logger.F("error", safeProxyError(err)))
			return nil, fmt.Errorf("sing-box 桥接启动失败: %w", err)
		}
		log.Info("sing-box 桥接已就绪", logger.F("proxy_id", proxyId), logger.F("socks5_addr", safeProxyURI(socks5Addr)))
		return buildSocks5HTTPClient(strings.TrimPrefix(socks5Addr, "socks5://"), timeout)
	case ProxyKernelXray:
		if xrayMgr == nil {
			log.Warn("xray 管理器未初始化", logger.F("proxy_id", proxyId))
			return nil, fmt.Errorf("xray 管理器未初始化")
		}
		socks5Addr, err := xrayMgr.EnsureBridge(src, proxies, proxyId)
		if err != nil {
			log.Warn("xray 桥接启动失败", logger.F("proxy_id", proxyId), logger.F("error", safeProxyError(err)))
			return nil, fmt.Errorf("xray 桥接启动失败: %w", err)
		}
		log.Info("xray 桥接已就绪", logger.F("proxy_id", proxyId), logger.F("socks5_addr", safeProxyURI(socks5Addr)))
		return buildSocks5HTTPClient(strings.TrimPrefix(socks5Addr, "socks5://"), timeout)
	default:
		return nil, fmt.Errorf("无法为协议 %s 选择代理内核", resolution.Protocol)
	}
}

// BuildDirectHTTPClient is the only non-stack HTTP client exception. It does
// not consult HTTP(S)_PROXY or any system proxy configuration.
func BuildDirectHTTPClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return &http.Client{
		Transport: &http.Transport{DialContext: dialer.DialContext},
		Timeout:   timeout,
	}
}

func buildHTTPProxyClient(proxyAddr string, timeout time.Duration) (*http.Client, error) {
	proxyURL, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("HTTP 代理地址解析失败: %w", err)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

func buildSocks5HTTPClient(socks5Host string, timeout time.Duration) (*http.Client, error) {
	dialer, err := xproxy.SOCKS5("tcp", socks5Host, nil, xproxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("SOCKS5 dialer 创建失败: %w", err)
	}
	contextDialer, ok := dialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("SOCKS5 dialer 不支持 ContextDialer")
	}
	transport := &http.Transport{DialContext: contextDialer.DialContext}
	return &http.Client{Transport: transport, Timeout: timeout}, nil
}
