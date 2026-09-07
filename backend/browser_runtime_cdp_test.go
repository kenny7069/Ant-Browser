package backend

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBrowserLevelCDPURLRequiresOwnedBrowserTarget(t *testing.T) {
	var response string
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(fmt.Sprintf(`{"webSocketDebuggerUrl":%q}`, response)))
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port

	tests := []struct {
		name string
		url  string
		want bool
	}{
		{name: "browser-level", url: fmt.Sprintf("ws://127.0.0.1:%d/devtools/browser/owned", port), want: true},
		{name: "page-target", url: fmt.Sprintf("ws://127.0.0.1:%d/devtools/page/not-owned", port)},
		{name: "missing-port", url: "ws://127.0.0.1/devtools/browser/owned"},
		{name: "query", url: fmt.Sprintf("ws://127.0.0.1:%d/devtools/browser/owned?target=page", port)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response = test.url
			got, err := browserLevelCDPURL(port)
			if test.want {
				if err != nil || got != test.url {
					t.Fatalf("browserLevelCDPURL = %q, %v; want %q", got, err, test.url)
				}
				return
			}
			if err == nil {
				t.Fatalf("browserLevelCDPURL accepted %q", test.url)
			}
		})
	}
}
