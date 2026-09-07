package proxy

import (
	"testing"

	"ant-chrome/backend/internal/config"
)

func TestResolveProxyKernelDefaultPriority(t *testing.T) {
	cases := []struct {
		name       string
		proxy      string
		wantKernel string
	}{
		{name: "vless uses xray", proxy: "vless://00000000-0000-0000-0000-000000000000@example.com:443", wantKernel: ProxyKernelXray},
		{name: "hysteria2 uses sing-box", proxy: "hysteria2://pass@example.com:443", wantKernel: ProxyKernelSingBox},
		{name: "anytls URI uses sing-box", proxy: "anytls://pass@example.com:443?sni=example.com", wantKernel: ProxyKernelSingBox},
		{name: "mieru uses mihomo", proxy: mieruClashNode, wantKernel: ProxyKernelMihomo},
		{name: "http uses native", proxy: "http://127.0.0.1:8080", wantKernel: ProxyKernelNative},
		{name: "socks5 without auth uses native", proxy: "socks5://127.0.0.1:1080", wantKernel: ProxyKernelNative},
		{name: "socks5 with auth uses xray", proxy: "socks5://user:pass@127.0.0.1:1080", wantKernel: ProxyKernelXray},
		{name: "http with auth uses xray", proxy: "http://user:pass@127.0.0.1:8080", wantKernel: ProxyKernelXray},
		{name: "https with auth uses xray", proxy: "https://user:pass@127.0.0.1:8443", wantKernel: ProxyKernelXray},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveProxyKernel(tc.proxy, nil, "", "")
			if err != nil {
				t.Fatalf("ResolveProxyKernel returned error: %v", err)
			}
			if got.Kernel != tc.wantKernel {
				t.Fatalf("kernel = %q, want %q; resolution=%+v", got.Kernel, tc.wantKernel, got)
			}
		})
	}
}

func TestResolveProxyKernelRejectsUnsupportedPreferredKernel(t *testing.T) {
	_, err := ResolveProxyKernel(mieruClashNode, nil, "", ProxyKernelXray)
	if err == nil {
		t.Fatal("expected mieru + xray preference to be rejected")
	}
}

func TestResolveProxyKernelReadsPreferredKernelFromProxy(t *testing.T) {
	proxyID := "p1"
	got, err := ResolveProxyKernel("", []config.BrowserProxy{{ProxyId: proxyID, ProxyConfig: mieruClashNode, PreferredKernel: ProxyKernelMihomo}}, proxyID, "")
	if err != nil {
		t.Fatalf("ResolveProxyKernel returned error: %v", err)
	}
	if got.Kernel != ProxyKernelMihomo || got.PreferredKernel != ProxyKernelMihomo {
		t.Fatalf("unexpected resolution: %+v", got)
	}
}

func TestResolveProxyKernelForConnectorPrefersMihomoStack(t *testing.T) {
	got, err := ResolveProxyKernelForConnector("vless://00000000-0000-0000-0000-000000000000@example.com:443", nil, "", config.BrowserConnectorMihomo)
	if err != nil {
		t.Fatalf("ResolveProxyKernelForConnector returned error: %v", err)
	}
	if got.Kernel != ProxyKernelMihomo {
		t.Fatalf("kernel = %q, want %q; resolution=%+v", got.Kernel, ProxyKernelMihomo, got)
	}
}

func TestResolveProxyKernelForConnectorKeepsSingBoxOnlyProtocols(t *testing.T) {
	got, err := ResolveProxyKernelForConnector("hysteria2://pass@example.com:443", nil, "", config.BrowserConnectorXray)
	if err != nil {
		t.Fatalf("ResolveProxyKernelForConnector returned error: %v", err)
	}
	if got.Kernel != ProxyKernelSingBox {
		t.Fatalf("kernel = %q, want %q; resolution=%+v", got.Kernel, ProxyKernelSingBox, got)
	}
}

func TestResolveProxyKernelForConnectorRejectsCrossStackPreference(t *testing.T) {
	proxyID := "p1"
	proxies := []config.BrowserProxy{{
		ProxyId:         proxyID,
		ProxyConfig:     "vless://00000000-0000-0000-0000-000000000000@example.com:443",
		PreferredKernel: ProxyKernelXray,
	}}
	resolution, err := ResolveProxyKernelForConnector("", proxies, proxyID, config.BrowserConnectorMihomo)
	if err == nil {
		t.Fatalf("cross-stack preferred kernel was accepted: %+v", resolution)
	}
}

func TestResolveProxyKernelForConnectorRejectsMihomoOnlyProtocolOnXrayStack(t *testing.T) {
	resolution, err := ResolveProxyKernelForConnector(mieruClashNode, nil, "", config.BrowserConnectorXray)
	if err == nil {
		t.Fatalf("xray connector selected mihomo-only protocol: %+v", resolution)
	}
	if resolution.Kernel != "" {
		t.Fatalf("kernel = %q, want none on cross-stack rejection; resolution=%+v", resolution.Kernel, resolution)
	}
}

func TestResolveProxyKernelForConnectorRejectsUnknownConnector(t *testing.T) {
	resolution, err := ResolveProxyKernelForConnector("socks5://user:pass@127.0.0.1:1080", nil, "", "surprise")
	if err == nil {
		t.Fatalf("unknown connector was accepted: %+v", resolution)
	}
}

func TestResolveProxyKernelForConnectorValidatesDirectPreferredKernel(t *testing.T) {
	proxyID := "direct-profile"
	proxies := []config.BrowserProxy{{
		ProxyId:         proxyID,
		ProxyConfig:     "direct://",
		PreferredKernel: ProxyKernelXray,
	}}
	resolution, err := ResolveProxyKernelForConnector("", proxies, proxyID, config.BrowserConnectorXray)
	if err == nil {
		t.Fatalf("direct proxy accepted incompatible preferred kernel: %+v", resolution)
	}
	if resolution.Protocol != "direct" || resolution.PreferredKernel != ProxyKernelXray {
		t.Fatalf("direct resolution lost explicit preference: %+v", resolution)
	}
}
