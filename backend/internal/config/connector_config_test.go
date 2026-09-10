package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeBrowserConnectorTypeDoesNotAcceptLegacyAliases(t *testing.T) {
	for _, value := range []string{"sing-box", "singbox", "sing_box", "clash", "", "surprise"} {
		if got := NormalizeBrowserConnectorType(value); got != strings.ToLower(strings.TrimSpace(value)) {
			t.Fatalf("NormalizeBrowserConnectorType(%q) = %q, want strict spelling only", value, got)
		}
	}
}

func TestMigrateLegacyBrowserConnectorTypeIsExplicitAndBounded(t *testing.T) {
	cases := map[string]string{
		"xray":     BrowserConnectorXray,
		"mihomo":   BrowserConnectorMihomo,
		"sing-box": BrowserConnectorXray,
		"singbox":  BrowserConnectorXray,
		"clash":    BrowserConnectorMihomo,
	}
	for input, want := range cases {
		got, err := MigrateLegacyBrowserConnectorType(input)
		if err != nil || got != want {
			t.Fatalf("MigrateLegacyBrowserConnectorType(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	for _, input := range []string{"", "unknown"} {
		if _, err := MigrateLegacyBrowserConnectorType(input); err == nil {
			t.Fatalf("MigrateLegacyBrowserConnectorType(%q) accepted invalid value", input)
		}
	}
}

func TestLoadConnectorPresenceAndLegacyMigration(t *testing.T) {
	tests := []struct {
		name       string
		yaml       string
		want       string
		wantErr    bool
		wantReason string
	}{
		{name: "omitted uses default", yaml: "browser:\n  user_data_root: data\n", want: BrowserConnectorXray},
		{name: "legacy alias migrates", yaml: "browser:\n  default_connector_type: sing-box\n", want: BrowserConnectorXray},
		{name: "explicit empty rejects", yaml: "browser:\n  default_connector_type: \"\"\n", wantErr: true, wantReason: "不可为空"},
		{name: "unknown rejects", yaml: "browser:\n  default_connector_type: mystery\n", wantErr: true, wantReason: "无效"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := Load(path)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), tc.wantReason) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantReason)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Browser.DefaultConnectorType != tc.want {
				t.Fatalf("DefaultConnectorType = %q, want %q", cfg.Browser.DefaultConnectorType, tc.want)
			}
		})
	}
}
