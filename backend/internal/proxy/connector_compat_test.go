package proxy

import (
	"errors"
	"testing"

	"ant-chrome/backend/internal/config"
)

func TestConnectorlessCompatibilityWrappersFailClosed(t *testing.T) {
	const proxyID = "compat-proxy"
	want := ErrConnectorTypeRequired.Error()
	testResults := map[string]TestResult{
		"speed":        SpeedTest(proxyID, nil, nil, nil, nil),
		"tcp":          TestConnectivity(proxyID, "socks5://127.0.0.1:1", nil, nil),
		"real":         TestRealConnectivity(proxyID, nil, nil),
		"real-singbox": TestRealConnectivityWithSingBox(proxyID, nil, nil, nil),
		"real-config":  TestRealConnectivityWithConfig(proxyID, nil, nil, nil, nil),
	}
	for name, result := range testResults {
		if result.Ok || result.Error != want {
			t.Errorf("%s wrapper result = %+v, want stable connector-required failure", name, result)
		}
	}
	if _, err := FetchDefaultIPHealthInfo(proxyID, nil, nil, nil); !errors.Is(err, ErrConnectorTypeRequired) {
		t.Fatalf("FetchDefaultIPHealthInfo error = %v, want ErrConnectorTypeRequired", err)
	}
	if ok, message := ValidateProxyConfig("vless://user@example.com:443", nil, proxyID); ok || message != want {
		t.Fatalf("ValidateProxyConfig result = %v, %q; want stable connector-required failure", ok, message)
	}
}

func TestExplicitConnectorWrappersRemainAvailable(t *testing.T) {
	result := SpeedTestWithConnector("", nil, nil, nil, nil, config.BrowserConnectorXray, nil)
	if result.Ok || result.Error == "" {
		t.Fatalf("explicit speed wrapper did not fail at input/config boundary: %+v", result)
	}
	result = TestRealConnectivityWithRuntimeConfig("", nil, nil, nil, nil, config.BrowserConnectorXray, nil)
	if result.Ok || result.Error == "" {
		t.Fatalf("explicit real-connectivity wrapper did not fail at input/config boundary: %+v", result)
	}
	if _, err := FetchIPHealthInfo("", nil, nil, nil, nil, config.BrowserConnectorXray, nil); err == nil {
		t.Fatal("explicit IP health wrapper accepted missing proxy config")
	}
}
