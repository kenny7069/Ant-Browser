package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestExtensionCompatEntrypointsRejectNilClientWithoutEnvironmentProxy(t *testing.T) {
	var proxyHits atomic.Int64
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer trap.Close()
	t.Setenv("HTTP_PROXY", trap.URL)
	t.Setenv("HTTPS_PROXY", trap.URL)
	t.Setenv("NO_PROXY", "")

	manager := &Manager{}
	extensionID := strings.Repeat("a", 32)
	if _, err := manager.LookupExtension(extensionID); err == nil || !strings.Contains(err.Error(), "explicit HTTP client") {
		t.Fatalf("LookupExtension nil-client result = %v, want explicit-client error", err)
	}
	if _, err := manager.InstallExtensionFromWebStore(context.Background(), extensionID); err == nil || !strings.Contains(err.Error(), "explicit HTTP client") {
		t.Fatalf("InstallExtensionFromWebStore nil-client result = %v, want explicit-client error", err)
	}
	if got := proxyHits.Load(); got != 0 {
		t.Fatalf("nil-client compatibility path reached HTTP_PROXY trap %d times", got)
	}
}

func TestExtensionDownloadHelperRejectsNilClient(t *testing.T) {
	_, err := downloadChromeExtensionCRX(context.Background(), strings.Repeat("a", 32), nil)
	if err == nil || !strings.Contains(err.Error(), "explicit HTTP client") {
		t.Fatalf("downloadChromeExtensionCRX nil client error = %v", err)
	}
}
