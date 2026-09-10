package backend

import (
	"strings"
	"testing"

	"ant-chrome/backend/internal/proxy"
)

func TestBrowserStartProxyLogMaskDoesNotExposeCredentials(t *testing.T) {
	raw := `vless://user:password-value@example.test:443?token=token-value`
	masked := proxy.MaskProxySensitiveText(raw)
	for _, secret := range []string{"user:password-value@example.test:443", "token-value"} {
		if strings.Contains(masked, secret) {
			t.Fatalf("masked browser-start proxy value contains %q: %s", secret, masked)
		}
	}
	if !strings.Contains(masked, "vless://<redacted>") {
		t.Fatalf("masked browser-start proxy value = %q, want redacted URI", masked)
	}
}
