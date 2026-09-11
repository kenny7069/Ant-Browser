package backend

import (
	"strings"
	"testing"

	"ant-chrome/backend/internal/config"
)

func TestSaveBrowserSettingsRequiresExactCanonicalConnector(t *testing.T) {
	for _, input := range []string{"", "sing-box", "singbox", "clash", "surprise", "Xray", " xray "} {
		app := NewApp(t.TempDir())
		app.config = config.DefaultConfig()
		before := app.config.Browser.DefaultConnectorType
		err := app.SaveBrowserSettings(BrowserSettings{DefaultConnectorType: input})
		if err == nil {
			t.Fatalf("SaveBrowserSettings(%q) accepted non-canonical connector", input)
		}
		if app.config.Browser.DefaultConnectorType != before {
			t.Fatalf("SaveBrowserSettings(%q) mutated connector on rejection: %q -> %q", input, before, app.config.Browser.DefaultConnectorType)
		}
		if !strings.Contains(strings.ToLower(err.Error()), "connector") {
			t.Fatalf("SaveBrowserSettings(%q) error = %v, want connector validation", input, err)
		}
	}
}

func TestSaveBrowserSettingsAcceptsCanonicalConnectors(t *testing.T) {
	for _, input := range []string{config.BrowserConnectorXray, config.BrowserConnectorMihomo} {
		app := NewApp(t.TempDir())
		app.config = config.DefaultConfig()
		if err := app.SaveBrowserSettings(BrowserSettings{DefaultConnectorType: input}); err != nil {
			t.Fatalf("SaveBrowserSettings(%q) failed: %v", input, err)
		}
		if app.config.Browser.DefaultConnectorType != input {
			t.Fatalf("saved connector = %q, want %q", app.config.Browser.DefaultConnectorType, input)
		}
	}
}
