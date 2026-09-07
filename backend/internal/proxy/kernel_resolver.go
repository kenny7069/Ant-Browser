package proxy

import (
	"errors"
	"fmt"
	"strings"

	"ant-chrome/backend/internal/config"
)

// ErrConnectorTypeRequired is returned by connectorless compatibility APIs
// before they can start a bridge or perform network I/O.
var ErrConnectorTypeRequired = errors.New("connector type is required")

const (
	ProxyKernelAuto    = "auto"
	ProxyKernelNative  = "native"
	ProxyKernelXray    = "xray"
	ProxyKernelSingBox = "sing-box"
	ProxyKernelMihomo  = "mihomo"
)

type ProxyKernelResolution struct {
	ConnectorType    string   `json:"connectorType"`
	Protocol         string   `json:"protocol"`
	PreferredKernel  string   `json:"preferredKernel"`
	Kernel           string   `json:"kernel"`
	SupportedKernels []string `json:"supportedKernels"`
	MissingCore      string   `json:"missingCore,omitempty"`
	Reason           string   `json:"reason"`
}

func NormalizePreferredKernel(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ProxyKernelAuto:
		return ""
	case ProxyKernelXray:
		return ProxyKernelXray
	case ProxyKernelSingBox, "singbox", "sing_box":
		return ProxyKernelSingBox
	case ProxyKernelMihomo, "clash", "clash-meta":
		return ProxyKernelMihomo
	case ProxyKernelNative:
		return ProxyKernelNative
	default:
		return strings.ToLower(strings.TrimSpace(value))
	}
}

func ResolveProxyKernel(proxyConfig string, proxies []config.BrowserProxy, proxyId string, preferredKernel string) (ProxyKernelResolution, error) {
	// Keep the historical symbol for source compatibility, but do not allow an
	// operation to silently select a stack. Every production caller must carry
	// an explicit connector through ResolveProxyKernelForConnector.
	_ = proxyConfig
	_ = proxies
	_ = proxyId
	_ = preferredKernel
	return ProxyKernelResolution{}, fmt.Errorf("connector type is required; use ResolveProxyKernelForConnector")
}

func ResolveProxyKernelForConnector(proxyConfig string, proxies []config.BrowserProxy, proxyId string, connectorType string) (ProxyKernelResolution, error) {
	src := strings.TrimSpace(resolveProxyConfig(proxyConfig, proxies, proxyId))
	connector, err := RequireConnectorType(connectorType)
	resolution := ProxyKernelResolution{ConnectorType: connector, PreferredKernel: ProxyKernelAuto}
	if err != nil {
		return resolution, err
	}
	if src == "" {
		return resolution, fmt.Errorf("代理配置为空")
	}
	protocol := DetectProxyProtocol(src)
	supported := SupportedKernelsForProtocol(protocol, src, proxies, proxyId)
	resolution.Protocol = protocol
	resolution.SupportedKernels = supported
	if len(supported) == 0 {
		return resolution, fmt.Errorf("不支持的代理协议: %s", protocol)
	}
	if preferred := explicitPreferredKernel(proxies, proxyId); preferred != "" {
		resolution.PreferredKernel = preferred
		if !containsKernel(supported, preferred) {
			return resolution, fmt.Errorf("协议 %s 不支持指定内核 %s", protocol, preferred)
		}
		if protocol == "direct" {
			resolution.Kernel = ProxyKernelNative
			resolution.Reason = "直连无需代理内核"
			return resolution, nil
		}
		if !connectorAllowsKernel(connector, preferred) {
			return resolution, fmt.Errorf("connector %s 不允许指定内核 %s", connector, preferred)
		}
		resolution.Kernel = preferred
		resolution.Reason = "使用代理指定内核"
		return resolution, nil
	}
	if protocol == "direct" {
		resolution.Kernel = ProxyKernelNative
		resolution.Reason = "直连无需代理内核"
		return resolution, nil
	}
	for _, candidate := range connectorKernelPriority(connector) {
		if containsKernel(supported, candidate) {
			resolution.Kernel = candidate
			resolution.Reason = "按连接栈策略选择内核"
			return resolution, nil
		}
	}
	return resolution, fmt.Errorf("connector %s 不支持代理协议 %s", connector, protocol)
}

func DetectProxyProtocol(proxyConfig string) string {
	src := strings.TrimSpace(proxyConfig)
	l := strings.ToLower(src)
	if src == "" || strings.EqualFold(src, "direct://") {
		return "direct"
	}
	if strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") {
		return "http"
	}
	if strings.HasPrefix(l, "socks5://") {
		return "socks5"
	}
	if IsChainSocks5Proxy(src) {
		return "chain+socks5"
	}
	if nodeType := clashNodeType(src); nodeType != "" {
		return nodeType
	}
	for _, prefix := range []string{"vmess://", "vless://", "trojan://", "ss://", "ssr://", "hysteria2://", "hysteria://", "tuic://", "anytls://"} {
		if strings.HasPrefix(l, prefix) {
			return strings.TrimSuffix(prefix, "://")
		}
	}
	return "unknown"
}

func SupportedKernelsForProtocol(protocol string, proxyConfig string, proxies []config.BrowserProxy, proxyId string) []string {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case "direct":
		return []string{ProxyKernelNative}
	case "http", "https", "socks5":
		// Every non-direct proxy is stack-owned. Xray and Mihomo can both bridge
		// standard HTTP/SOCKS5 upstreams; the connector policy chooses one.
		return []string{ProxyKernelXray, ProxyKernelMihomo}
	case "vmess", "vless", "trojan", "chain+socks5":
		return []string{ProxyKernelXray, ProxyKernelMihomo}
	case "ss", "shadowsocks":
		if IsMihomoOnlyProtocol(proxyConfig) {
			return []string{ProxyKernelMihomo}
		}
		return []string{ProxyKernelXray, ProxyKernelMihomo}
	case "hysteria", "hysteria2", "tuic", "anytls":
		return []string{ProxyKernelSingBox, ProxyKernelMihomo}
	case "mieru", "wireguard":
		return []string{ProxyKernelMihomo}
	default:
		_ = proxyConfig
		_ = proxies
		_ = proxyId
		return nil
	}
}

func containsKernel(kernels []string, kernel string) bool {
	kernel = NormalizePreferredKernel(kernel)
	for _, item := range kernels {
		if item == kernel {
			return true
		}
	}
	return false
}

// RequireConnectorType is the operation-boundary connector validator. Alias
// normalization belongs to browser configuration compatibility code; an
// operation must receive the canonical xray/mihomo value explicitly.
func RequireConnectorType(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case config.BrowserConnectorXray:
		return config.BrowserConnectorXray, nil
	case config.BrowserConnectorMihomo:
		return config.BrowserConnectorMihomo, nil
	case "":
		return "", ErrConnectorTypeRequired
	default:
		return "", fmt.Errorf("未知连接栈: %s", strings.TrimSpace(value))
	}
}

func explicitPreferredKernel(proxies []config.BrowserProxy, proxyId string) string {
	proxyId = strings.TrimSpace(proxyId)
	if proxyId == "" {
		return ""
	}
	for _, item := range proxies {
		if strings.EqualFold(strings.TrimSpace(item.ProxyId), proxyId) {
			return NormalizePreferredKernel(item.PreferredKernel)
		}
	}
	return ""
}

func connectorKernelPriority(connector string) []string {
	switch connector {
	case config.BrowserConnectorMihomo:
		return []string{ProxyKernelMihomo}
	default:
		return []string{ProxyKernelXray, ProxyKernelSingBox}
	}
}

func connectorAllowsKernel(connector string, kernel string) bool {
	return containsKernel(connectorKernelPriority(connector), kernel)
}
