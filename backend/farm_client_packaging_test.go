package backend

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func farmClientRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime caller unavailable")
	}
	return filepath.Dir(filepath.Dir(file))
}

func TestFarmClientPackagingIsDedicatedAndOwnershipScoped(t *testing.T) {
	root := farmClientRepositoryRoot(t)
	required := []string{
		"publish/farm-client/windows/installer.nsi",
		"publish/farm-client/windows/publish-windows.ps1",
		"publish/farm-client/linux/package.sh",
		"publish/farm-client/macos/package.sh",
		".github/workflows/publish-farm-client-windows.yml",
		".github/workflows/publish-farm-client-linux.yml",
		".github/workflows/publish-farm-client-macos.yml",
	}
	for _, relative := range required {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative))); err != nil {
			t.Fatalf("dedicated Farm Client packaging file missing: %s: %v", relative, err)
		}
	}
	installer, err := os.ReadFile(filepath.Join(root, "publish", "farm-client", "windows", "installer.nsi"))
	if err != nil {
		t.Fatal(err)
	}
	value := strings.ToLower(string(installer))
	for _, forbidden := range []string{"taskkill.exe", "/im xray", "/im sing-box", "killall", "pkill", "antbrowser-setup"} {
		if strings.Contains(value, forbidden) {
			t.Fatalf("Farm Client installer contains forbidden Desktop/global cleanup %q", forbidden)
		}
	}
	for _, requiredText := range []string{
		`$programfiles64\ant farm client`, `$localappdata\antfarmclient`,
		"exactexecutable", "per-user state and ant browser profiles are intentionally preserved",
	} {
		if !strings.Contains(value, requiredText) {
			t.Fatalf("Farm Client installer missing %q", requiredText)
		}
	}
}

func TestFarmClientUnixPackagingInjectsVersionAndKeepsOutputsIsolated(t *testing.T) {
	root := farmClientRepositoryRoot(t)
	for _, relative := range []string{
		"publish/farm-client/linux/package.sh",
		"publish/farm-client/macos/package.sh",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		value := string(raw)
		for _, requiredText := range []string{
			"ant-chrome/backend.FarmClientVersion=$VERSION",
			`OUTPUT_DIR="$SCRIPT_DIR/dist"`,
			`STAGING_ROOT="$SCRIPT_DIR/.staging"`,
			".update.bin",
		} {
			if !strings.Contains(value, requiredText) {
				t.Fatalf("%s missing %q", relative, requiredText)
			}
		}
		for _, forbidden := range []string{"publish/output", "publish/staging", "taskkill", "killall", "pkill"} {
			if strings.Contains(strings.ToLower(value), forbidden) {
				t.Fatalf("%s contains shared or global cleanup %q", relative, forbidden)
			}
		}
	}
}

func TestFarmClientWindowsPackagingInjectsVersionAndKeepsOutputsIsolated(t *testing.T) {
	root := farmClientRepositoryRoot(t)
	relative := "publish/farm-client/windows/publish-windows.ps1"
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	value := string(raw)
	for _, requiredText := range []string{
		"ant-chrome/backend.FarmClientVersion=$Version",
		`Join-Path $PSScriptRoot "dist"`,
		`Join-Path $PSScriptRoot ".staging\windows-$Arch"`,
		".update.exe",
	} {
		if !strings.Contains(value, requiredText) {
			t.Fatalf("%s missing %q", relative, requiredText)
		}
	}
	for _, forbidden := range []string{"publish\\output", "publish\\staging", "taskkill", "killall", "pkill"} {
		if strings.Contains(strings.ToLower(value), forbidden) {
			t.Fatalf("%s contains shared or global cleanup %q", relative, forbidden)
		}
	}
}

func TestFarmClientPackageExamplesUseStrictKnownConfigFields(t *testing.T) {
	root := farmClientRepositoryRoot(t)
	for _, relative := range []string{
		"publish/farm-client/windows/config.example.yaml",
		"publish/farm-client/linux/config.example.yaml",
		"publish/farm-client/macos/config.example.yaml",
	} {
		config, err := LoadFarmClientConfig(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("package example %s does not match strict config schema: %v", relative, err)
		}
		if strings.TrimSpace(config.Identity.PrivateKeyRef) == "" || config.Identity.PrivateKey != "" || config.Identity.PrivateKeyEnv != "" {
			t.Fatalf("package example %s must use only a secure identity reference", relative)
		}
	}
}

func TestFarmClientReleaseWorkflowsCannotMatchDesktopTags(t *testing.T) {
	root := farmClientRepositoryRoot(t)
	for _, name := range []string{
		"publish-farm-client-windows.yml", "publish-farm-client-linux.yml", "publish-farm-client-macos.yml",
	} {
		raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", name))
		if err != nil {
			t.Fatal(err)
		}
		value := string(raw)
		if !strings.Contains(value, `farm-client-v*`) || strings.Contains(value, `- "v*"`) {
			t.Fatalf("%s is not isolated from Desktop release tags", name)
		}
		if !strings.Contains(value, "AntFarmClient-") && !strings.Contains(value, "ant-farm-client_") {
			t.Fatalf("%s does not publish a dedicated Farm Client artifact", name)
		}
	}
}
