package proxy

import (
	"testing"

	"ant-chrome/backend/internal/config"
)

func TestResolveProxyKernelDefaultPriority(t *testing.T) {
	cases := []struct {
		name       string
		proxy      string
		connector  string
		wantKernel string
	}{
		{name: "vless uses xray", proxy: "vless://00000000-0000-0000-0000-000000000000@example.com:443", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelXray},
		{name: "hysteria2 uses sing-box", proxy: "hysteria2://pass@example.com:443", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelSingBox},
		{name: "anytls URI uses sing-box", proxy: "anytls://pass@example.com:443?sni=example.com", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelSingBox},
		{name: "mieru uses mihomo", proxy: mieruClashNode, connector: config.BrowserConnectorMihomo, wantKernel: ProxyKernelMihomo},
		{name: "http uses xray bridge", proxy: "http://127.0.0.1:8080", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelXray},
		{name: "socks5 without auth uses xray bridge", proxy: "socks5://127.0.0.1:1080", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelXray},
		{name: "socks5 with auth uses mihomo", proxy: "socks5://user:pass@127.0.0.1:1080", connector: config.BrowserConnectorMihomo, wantKernel: ProxyKernelMihomo},
		{name: "http with auth uses xray", proxy: "http://user:pass@127.0.0.1:8080", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelXray},
		{name: "https with auth uses xray", proxy: "https://user:pass@127.0.0.1:8443", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelXray},
		{name: "literal direct uses native", proxy: "direct://", connector: config.BrowserConnectorXray, wantKernel: ProxyKernelNative},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveProxyKernelForConnector(tc.proxy, nil, "", tc.connector)
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
	got, err := ResolveProxyKernelForConnector("", []config.BrowserProxy{{ProxyId: proxyID, ProxyConfig: mieruClashNode, PreferredKernel: ProxyKernelMihomo}}, proxyID, config.BrowserConnectorMihomo)
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

func TestResolveProxyKernelForConnectorRejectsEmptyConfig(t *testing.T) {
	resolution, err := ResolveProxyKernelForConnector("", nil, "", config.BrowserConnectorXray)
	if err == nil {
		t.Fatalf("empty proxy config was accepted: %+v", resolution)
	}
}

func TestResolveProxyKernelForConnectorRejectsSingBoxAlias(t *testing.T) {
	resolution, err := ResolveProxyKernelForConnector("vless://00000000-0000-0000-0000-000000000000@example.com:443", nil, "", "sing-box")
	if err == nil {
		t.Fatalf("sing-box alias was accepted as an operation connector: %+v", resolution)
	}
}

func TestResolveProxyKernelForConnectorOperationMatrix(t *testing.T) {
	cases := []struct {
		name      string
		connector string
		proxy     string
		want      string
		wantErr   bool
	}{
		{name: "xray vless", connector: config.BrowserConnectorXray, proxy: "vless://00000000-0000-0000-0000-000000000000@example.com:443", want: ProxyKernelXray},
		{name: "xray hysteria2", connector: config.BrowserConnectorXray, proxy: "hysteria2://pass@example.com:443", want: ProxyKernelSingBox},
		{name: "xray mieru rejected", connector: config.BrowserConnectorXray, proxy: mieruClashNode, wantErr: true},
		{name: "mihomo vless", connector: config.BrowserConnectorMihomo, proxy: "vless://00000000-0000-0000-0000-000000000000@example.com:443", want: ProxyKernelMihomo},
		{name: "mihomo hysteria2", connector: config.BrowserConnectorMihomo, proxy: "hysteria2://pass@example.com:443", want: ProxyKernelMihomo},
		{name: "mihomo xray preference rejected", connector: config.BrowserConnectorMihomo, proxy: "vless://00000000-0000-0000-0000-000000000000@example.com:443", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxies := []config.BrowserProxy{{ProxyId: "p1", ProxyConfig: tc.proxy}}
			if tc.name == "mihomo xray preference rejected" {
				proxies[0].PreferredKernel = ProxyKernelXray
			}
			resolution, err := ResolveProxyKernelForConnector("", proxies, "p1", tc.connector)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("cross-stack operation was accepted: %+v", resolution)
				}
				return
			}
			if err != nil || resolution.Kernel != tc.want {
				t.Fatalf("resolution=%+v err=%v want kernel %q", resolution, err, tc.want)
			}
			if resolution.ConnectorType != tc.connector {
				t.Fatalf("connector=%q want %q", resolution.ConnectorType, tc.connector)
			}
		})
	}
}
