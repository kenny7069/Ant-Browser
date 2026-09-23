package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type suiteBootstrapRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip suiteBootstrapRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func suiteBootstrapFixture(origin string) map[string]any {
	return map[string]any{
		"schema_version":           3,
		"deployment_uid":           "123e4567-e89b-12d3-a456-426614174000",
		"minimum_suite_version":    "3.0.0",
		"minimum_protocol_version": "3.0.0",
		"enrollment_endpoint":      origin + "/api/farm/v3/bootstrap/enroll",
		"control_endpoint":         "wss" + strings.TrimPrefix(origin, "https") + "/control/ws",
		"supported_capabilities":   []string{"browser.manage", "profile.list"},
		"endpoint_allowlist":       []string{origin},
	}
}

func trustedSuiteBootstrapClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, MaxResponseHeaderBytes: maxSuiteBootstrapHeaderBytes}}
}

func suiteBootstrapConfig(t *testing.T, origin string) BootstrapConfig {
	t.Helper()
	return BootstrapConfig{ServerURL: origin, StatePath: filepath.Join(t.TempDir(), "setup.json"), NodeName: "Farmer"}
}

func TestFetchSuiteBootstrapDiscoveryTrustedTLSFixedPathAndHost(t *testing.T) {
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.RequestURI() != suiteBootstrapDiscoveryPath || request.Host != strings.TrimPrefix(server.URL, "https://") || request.Header.Get("X-Forwarded-Host") != "" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("request method=%s uri=%s host=%s", request.Method, request.URL.RequestURI(), request.Host)
		}
		response.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(response).Encode(suiteBootstrapFixture(server.URL))
	}))
	defer server.Close()
	discovery, err := fetchSuiteBootstrapDiscoveryWithClient(context.Background(), suiteBootstrapConfig(t, server.URL), "3.2.0+signed.7", "3.0.0", trustedSuiteBootstrapClient(t, server))
	if err != nil || discovery.DeploymentUID != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("discovery=%+v err=%v", discovery, err)
	}
}

func TestFetchSuiteBootstrapDiscoveryRejectsExpiredCertificate(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired discovery test"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     time.Now().Add(-time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("expired TLS request reached handler")
	}))
	server.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: certificate}}}
	server.StartTLS()
	defer server.Close()
	client := trustedSuiteBootstrapClient(t, server)
	_, err = fetchSuiteBootstrapDiscoveryWithClient(context.Background(), suiteBootstrapConfig(t, server.URL), "3.0.0", "3.0.0", client)
	if !errors.Is(err, ErrSuiteBootstrapTLS) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("expired certificate error=%v", err)
	}
}

func TestFetchSuiteBootstrapDiscoveryProductionRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{}`))
	}))
	defer server.Close()
	_, err := FetchSuiteBootstrapDiscovery(context.Background(), suiteBootstrapConfig(t, server.URL))
	if !errors.Is(err, ErrSuiteBootstrapTLS) || strings.Contains(err.Error(), server.URL) {
		t.Fatalf("TLS error=%v", err)
	}
}

func TestFetchSuiteBootstrapDiscoveryRejectsWrongSANAndTLS11(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*httptest.Server, *http.Client)
	}{
		{"wrong SAN", func(_ *httptest.Server, client *http.Client) {
			client.Transport.(*http.Transport).TLSClientConfig.ServerName = "wrong.example.test"
		}},
		{"TLS 1.1", func(server *httptest.Server, _ *http.Client) {
			server.TLS.MaxVersion = tls.VersionTLS11
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			reached := false
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				reached = true
			}))
			server.StartTLS()
			defer server.Close()
			client := trustedSuiteBootstrapClient(t, server)
			test.configure(server, client)
			_, err := fetchSuiteBootstrapDiscoveryWithClient(context.Background(), suiteBootstrapConfig(t, server.URL), "3.0.0", "3.0.0", client)
			if !errors.Is(err, ErrSuiteBootstrapTLS) || strings.Contains(err.Error(), server.URL) || reached {
				t.Fatalf("error=%v reached=%t", err, reached)
			}
		})
	}
}

func TestFetchSuiteBootstrapDiscoveryRejectsRedirectStatusTypeAndOversize(t *testing.T) {
	for _, test := range []struct {
		name    string
		handler http.HandlerFunc
		want    error
	}{
		{"redirect", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://example.test/elsewhere", http.StatusFound)
		}, ErrSuiteBootstrapRedirect},
		{"status", func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("secret-body"))
		}, ErrSuiteBootstrapHTTPStatus},
		{"content type", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write([]byte(`{}`))
		}, ErrSuiteBootstrapResponse},
		{"oversize", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, maxSuiteBootstrapBodyBytes+1))
		}, ErrSuiteBootstrapResponse},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(test.handler)
			defer server.Close()
			_, err := fetchSuiteBootstrapDiscoveryWithClient(context.Background(), suiteBootstrapConfig(t, server.URL), "3.0.0", "3.0.0", trustedSuiteBootstrapClient(t, server))
			if !errors.Is(err, test.want) || strings.Contains(strings.ToLower(err.Error()), "secret") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestFetchSuiteBootstrapDiscoveryRejectsOversizedHeadersFromSuppliedTransport(t *testing.T) {
	origin := "https://farm.example.test"
	raw, _ := json.Marshal(suiteBootstrapFixture(origin))
	client := &http.Client{Transport: suiteBootstrapRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"X-Fill":       []string{strings.Repeat("x", maxSuiteBootstrapHeaderBytes)},
			},
			Body: io.NopCloser(strings.NewReader(string(raw))),
		}, nil
	})}
	_, err := fetchSuiteBootstrapDiscoveryWithClient(context.Background(), suiteBootstrapConfig(t, origin), "3.0.0", "3.0.0", client)
	if !errors.Is(err, ErrSuiteBootstrapResponse) {
		t.Fatalf("oversized header error=%v", err)
	}
}

func TestFetchSuiteBootstrapDiscoveryRejectsOversizedRequestOriginBeforeTransport(t *testing.T) {
	client := &http.Client{Transport: suiteBootstrapRoundTripper(func(*http.Request) (*http.Response, error) {
		t.Fatal("transport called for oversized request origin")
		return nil, nil
	})}
	config := suiteBootstrapConfig(t, "https://"+strings.Repeat("a", maxSuiteBootstrapURLBytes))
	_, err := fetchSuiteBootstrapDiscoveryWithClient(context.Background(), config, "3.0.0", "3.0.0", client)
	if !errors.Is(err, ErrSuiteBootstrapConfig) {
		t.Fatalf("oversized request origin error=%v", err)
	}
}

func TestParseSuiteBootstrapDiscoveryClosedSchemaAndEndpointPolicy(t *testing.T) {
	origin := "https://farm.example.test"
	valid := suiteBootstrapFixture(origin)
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	valid["update"] = map[string]any{"manifest_url": origin + "/updates/manifest.json?channel=stable", "public_key_ed25519_b64": key, "channel": "stable"}
	validRaw, _ := json.Marshal(valid)
	if _, err := parseSuiteBootstrapDiscovery(validRaw, origin, "3.0.0+build.1", "3.0.0+protocol.9"); err != nil {
		t.Fatalf("valid discovery=%v", err)
	}
	originOnlyUpdate := suiteBootstrapFixture(origin)
	originOnlyUpdate["update"] = map[string]any{"manifest_url": origin, "public_key_ed25519_b64": key, "channel": "beta"}
	originOnlyRaw, _ := json.Marshal(originOnlyUpdate)
	if _, err := parseSuiteBootstrapDiscovery(originOnlyRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("origin-only update URL rejected: %v", err)
	}
	asciiUpdate := suiteBootstrapFixture(origin)
	asciiUpdate["update"] = map[string]any{"manifest_url": origin + "/releases/@manifest.json", "public_key_ed25519_b64": key, "channel": "stable"}
	asciiUpdateRaw, _ := json.Marshal(asciiUpdate)
	if _, err := parseSuiteBootstrapDiscovery(asciiUpdateRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("visible ASCII update URL rejected: %v", err)
	}
	rfc3986Update := suiteBootstrapFixture(origin)
	rfc3986Update["update"] = map[string]any{
		"manifest_url":           origin + "/r/Az09-._~!$&'()*+,;=:@manifest?q=Az09-._~!$&'()*+,;=:@/?next",
		"public_key_ed25519_b64": key,
		"channel":                "stable",
	}
	rfc3986UpdateRaw, _ := json.Marshal(rfc3986Update)
	if _, err := parseSuiteBootstrapDiscovery(rfc3986UpdateRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("RFC3986 update URL rejected: %v", err)
	}
	maximumUpdate := suiteBootstrapFixture(origin)
	maximumUpdateURL := origin + "/" + strings.Repeat("a", maxSuiteBootstrapURLBytes-len(origin)-1)
	maximumUpdate["update"] = map[string]any{"manifest_url": maximumUpdateURL, "public_key_ed25519_b64": key, "channel": "stable"}
	maximumUpdateRaw, _ := json.Marshal(maximumUpdate)
	if len(maximumUpdateURL) != maxSuiteBootstrapURLBytes {
		t.Fatalf("maximum update URL size=%d", len(maximumUpdateURL))
	}
	if _, err := parseSuiteBootstrapDiscovery(maximumUpdateRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("maximum update URL rejected: %v", err)
	}
	maxCapability := suiteBootstrapFixture(origin)
	maxCapability["supported_capabilities"] = []string{"a" + strings.Repeat("b", 79)}
	maxCapabilityRaw, _ := json.Marshal(maxCapability)
	if _, err := parseSuiteBootstrapDiscovery(maxCapabilityRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("80-byte capability rejected: %v", err)
	}
	emptyCapabilities := suiteBootstrapFixture(origin)
	emptyCapabilities["supported_capabilities"] = []string{}
	emptyCapabilitiesRaw, _ := json.Marshal(emptyCapabilities)
	if _, err := parseSuiteBootstrapDiscovery(emptyCapabilitiesRaw, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("empty capability array rejected: %v", err)
	}
	mutations := map[string]func(map[string]any){
		"schema":               func(v map[string]any) { v["schema_version"] = 2 },
		"uuid":                 func(v map[string]any) { v["deployment_uid"] = strings.ToUpper(v["deployment_uid"].(string)) },
		"capability order":     func(v map[string]any) { v["supported_capabilities"] = []string{"z", "a"} },
		"capability duplicate": func(v map[string]any) { v["supported_capabilities"] = []string{"a", "a"} },
		"capability long":      func(v map[string]any) { v["supported_capabilities"] = []string{"a" + strings.Repeat("b", 80)} },
		"capability null":      func(v map[string]any) { v["supported_capabilities"] = nil },
		"capability count": func(v map[string]any) {
			values := make([]string, maxSuiteBootstrapCapabilities+1)
			for index := range values {
				values[index] = "a"
			}
			v["supported_capabilities"] = values
		},
		"allowlist slash": func(v map[string]any) { v["endpoint_allowlist"] = []string{origin + "/"} },
		"allowlist null":  func(v map[string]any) { v["endpoint_allowlist"] = nil },
		"allowlist count": func(v map[string]any) {
			values := make([]string, maxSuiteBootstrapAllowlist+1)
			for index := range values {
				values[index] = origin
			}
			v["endpoint_allowlist"] = values
		},
		"allowlist missing request": func(v map[string]any) { v["endpoint_allowlist"] = []string{"https://other.example.test"} },
		"enrollment not allowlisted": func(v map[string]any) {
			v["enrollment_endpoint"] = "https://other.example.test/api/farm/v3/bootstrap/enroll"
		},
		"enrollment query": func(v map[string]any) { v["enrollment_endpoint"] = origin + "/api/farm/v3/bootstrap/enroll?x=1" },
		"control path":     func(v map[string]any) { v["control_endpoint"] = "wss://farm.example.test/other" },
		"endpoint userinfo": func(v map[string]any) {
			v["enrollment_endpoint"] = "https://u@farm.example.test/api/farm/v3/bootstrap/enroll"
		},
		"update fragment": func(v map[string]any) { v["update"].(map[string]any)["manifest_url"] = origin + "/m#x" },
		"update query space": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=a b"
		},
		"update query tab": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=a\tb"
		},
		"update escaped path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/releases%2Fmanifest.json"
		},
		"update escaped query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=a%20b"
		},
		"update Unicode path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/releases/café.json"
		},
		"update Unicode query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=café"
		},
		"update backslash path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/a\\b"
		},
		"update brace path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/a{b"
		},
		"update brace query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q={"
		},
		"update pipe query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=|"
		},
		"update caret query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=^"
		},
		"update backtick query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=`"
		},
		"update angle query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?q=<x>"
		},
		"update empty query": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/m?"
		},
		"update root path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/"
		},
		"update directory path": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + "/releases/"
		},
		"update URL too long": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = maximumUpdateURL + "a"
		},
		"enrollment URL too long": func(v map[string]any) {
			v["enrollment_endpoint"] = origin + "/" + strings.Repeat("a", maxSuiteBootstrapURLBytes)
		},
		"control URL too long": func(v map[string]any) {
			v["control_endpoint"] = "wss://farm.example.test/" + strings.Repeat("a", maxSuiteBootstrapURLBytes)
		},
		"allowlist URL too long": func(v map[string]any) {
			v["endpoint_allowlist"] = []string{"https://" + strings.Repeat("a", maxSuiteBootstrapURLBytes), origin}
		},
		"update uppercase host": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = "https://FARM.example.test/m"
		},
		"update default port": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = origin + ":443/m"
		},
		"update not allowlisted": func(v map[string]any) {
			v["update"].(map[string]any)["manifest_url"] = "https://other.example.test/m"
		},
		"update key":     func(v map[string]any) { v["update"].(map[string]any)["public_key_ed25519_b64"] = "bad" },
		"update channel": func(v map[string]any) { v["update"].(map[string]any)["channel"] = "dev" },
		"update partial": func(v map[string]any) { v["update"] = map[string]any{"channel": "stable"} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var value map[string]any
			_ = json.Unmarshal(validRaw, &value)
			mutate(value)
			raw, _ := json.Marshal(value)
			if _, err := parseSuiteBootstrapDiscovery(raw, origin, "3.0.0", "3.0.0"); !errors.Is(err, ErrSuiteBootstrapResponse) {
				t.Fatalf("mutation accepted: %v", err)
			}
		})
	}
	closed := [][]byte{
		append(append([]byte{}, validRaw...), []byte(" true")...),
		[]byte(strings.Replace(string(validRaw), `"schema_version":3`, `"schema_version":3,"schema_version":3`, 1)),
		[]byte(strings.Replace(string(validRaw), `"channel":"stable"`, `"channel":"stable","secret":"x"`, 1)),
		[]byte(strings.Replace(string(validRaw), `"deployment_uid"`, `"unknown"`, 1)),
		[]byte(`{"schema_version":NaN}`),
	}
	for index, raw := range closed {
		if _, err := parseSuiteBootstrapDiscovery(raw, origin, "3.0.0", "3.0.0"); !errors.Is(err, ErrSuiteBootstrapResponse) {
			t.Fatalf("closed mutation %d accepted: %v", index, err)
		}
	}
}

func TestParseSuiteBootstrapDiscoveryBodyLimitIsInclusive(t *testing.T) {
	origin := "https://farm.example.test"
	raw, _ := json.Marshal(suiteBootstrapFixture(origin))
	maximum := append(append([]byte{}, raw...), bytes.Repeat([]byte{' '}, maxSuiteBootstrapBodyBytes-len(raw))...)
	if len(maximum) != maxSuiteBootstrapBodyBytes {
		t.Fatalf("fixture size=%d", len(maximum))
	}
	if _, err := parseSuiteBootstrapDiscovery(maximum, origin, "3.0.0", "3.0.0"); err != nil {
		t.Fatalf("maximum legal body rejected: %v", err)
	}
	if _, err := parseSuiteBootstrapDiscovery(append(maximum, ' '), origin, "3.0.0", "3.0.0"); !errors.Is(err, ErrSuiteBootstrapResponse) {
		t.Fatalf("oversized body accepted: %v", err)
	}
}

func TestSuiteBootstrapOriginRejectsMalformedDNSAndPorts(t *testing.T) {
	for _, raw := range []string{
		"https://farm.example.test",
		"https://farm.example.test:8443",
		"https://192.0.2.1",
		"https://[2001:db8::1]",
		"https://[2001:db8::1]:8443",
	} {
		canonical, err := canonicalSuiteBootstrapOrigin(raw, "https")
		if err != nil || canonical != raw {
			t.Fatalf("canonical origin %s => %s, %v", raw, canonical, err)
		}
	}
	for _, raw := range []string{
		"https://bad..example.test",
		"https://-bad.example.test",
		"https://bad-.example.test",
		"https://bad_example.test",
		"https://farm.example.test:bad",
		"https://farm.example.test:0443",
		"https://farm.example.test:65536",
		"https://farm.example.test:443",
		"https://farm.example.test/",
		"https://farm.example.test?",
		"https://farm.example.test#",
		"https://192.168.001.001",
		"https://[2001:0db8:0:0:0:0:0:1]",
		"https://[::ffff:192.0.2.1]",
		"https://[0:0:0:0:0:ffff:c000:201]",
		"https://" + strings.Repeat("a", maxSuiteBootstrapURLBytes),
	} {
		if _, err := canonicalSuiteBootstrapOrigin(raw, "https"); err == nil {
			t.Fatalf("origin accepted: %s", raw)
		}
	}
}

func TestParseSuiteBootstrapDiscoveryRejectsEquivalentIPv6AllowlistEntries(t *testing.T) {
	origin := "https://[2001:db8::1]"
	fixture := suiteBootstrapFixture(origin)
	fixture["endpoint_allowlist"] = []string{
		"https://[2001:0db8:0:0:0:0:0:1]",
		origin,
	}
	raw, _ := json.Marshal(fixture)
	if _, err := parseSuiteBootstrapDiscovery(raw, origin, "3.0.0", "3.0.0"); !errors.Is(err, ErrSuiteBootstrapResponse) {
		t.Fatalf("equivalent IPv6 allowlist entries accepted: %v", err)
	}
}

func TestSuiteBootstrapSemverCompatibilityIgnoresBuildWithoutIntegerOverflow(t *testing.T) {
	origin := "https://farm.example.test"
	fixture := suiteBootstrapFixture(origin)
	matrix := []struct {
		current, minimum string
		compatible       bool
	}{
		{"3.0.0+client.9", "3.0.0+server.1", true},
		{"3.0.0", "3.0.1", false},
		{"3.0.0-rc.2", "3.0.0-rc.10", false},
		{"3.0.0", "3.0.0-rc.999999999999999999999999999999999999", true},
		{"999999999999999999999999999999999999.0.0", "999999999999999999999999999999999998.9.9", true},
	}
	for _, test := range matrix {
		fixture["minimum_suite_version"] = test.minimum
		raw, _ := json.Marshal(fixture)
		_, err := parseSuiteBootstrapDiscovery(raw, origin, test.current, "3.0.0")
		if test.compatible && err != nil || !test.compatible && !errors.Is(err, ErrSuiteBootstrapCompatibility) {
			t.Fatalf("current=%s minimum=%s err=%v", test.current, test.minimum, err)
		}
	}
}

func TestSuiteBootstrapProtocolCompatibilityAndFixedProductionVersion(t *testing.T) {
	if FarmSuiteBootstrapProtocolVersion != "3.0.0" {
		t.Fatalf("protocol version=%q", FarmSuiteBootstrapProtocolVersion)
	}
	origin := "https://farm.example.test"
	fixture := suiteBootstrapFixture(origin)
	fixture["minimum_protocol_version"] = "3.0.1"
	raw, _ := json.Marshal(fixture)
	if _, err := parseSuiteBootstrapDiscovery(raw, origin, "99.0.0", FarmSuiteBootstrapProtocolVersion); !errors.Is(err, ErrSuiteBootstrapCompatibility) {
		t.Fatalf("newer protocol accepted: %v", err)
	}
	fixture["minimum_protocol_version"] = "3.0.0-01"
	raw, _ = json.Marshal(fixture)
	if _, err := parseSuiteBootstrapDiscovery(raw, origin, "3.0.0", FarmSuiteBootstrapProtocolVersion); !errors.Is(err, ErrSuiteBootstrapResponse) {
		t.Fatalf("invalid prerelease accepted: %v", err)
	}
}
