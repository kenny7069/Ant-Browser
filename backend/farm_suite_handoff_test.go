package backend

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func suiteHandoffFixture(t *testing.T) (SuiteUserRoots, SetupPreparationCheckpoint, string, string) {
	t.Helper()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	roots := SuiteUserRoots{
		Config: filepath.Join(base, "config"), BrowserData: filepath.Join(base, "browser-data"),
		AgentState: filepath.Join(base, "agent-state"), Logs: filepath.Join(base, "logs"),
	}
	if err := ensureSuiteOwnerRoots(roots); err != nil {
		t.Fatal(err)
	}
	suiteBinaryRoot := filepath.Join(base, "versions", "1.2.3")
	if err := os.MkdirAll(suiteBinaryRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	guiPath := filepath.Join(suiteBinaryRoot, "Ant Browser.exe")
	if err := os.WriteFile(guiPath, []byte("signed-gui-fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := FarmClientConfig{
		ApplicationRoot: filepath.Join(roots.BrowserData, "ant-application"), StateRoot: roots.AgentState,
		ControlURL: "wss://farm.example.test/control/ws", NodeName: "Farm One",
		Identity: FarmClientIdentityConfig{NodeUID: "node-one", PrivateKeyRef: "device-node-one"},
	}
	if err := ensureOwnerDirectory(config.ApplicationRoot); err != nil {
		t.Fatal(err)
	}
	raw, err := yaml.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeOwnerAtomic(filepath.Join(roots.Config, SuiteClientConfigName), raw); err != nil {
		t.Fatal(err)
	}
	checkpoint := SetupPreparationCheckpoint{
		SchemaVersion: 1, Stage: SetupInputValidated, RequestUID: "8a064666-42a6-4f0c-b023-f12393c25674",
		BootstrapSHA256: strings.Repeat("a", 64),
	}
	path := filepath.Join(roots.AgentState, suitePreparationStateName)
	for _, stage := range []SetupStage{SetupInputValidated, SetupUserRootsReady, SetupBootstrapDrafted} {
		checkpoint.Stage = stage
		if err := saveSetupPreparationCheckpoint(path, checkpoint); err != nil {
			t.Fatal(err)
		}
	}
	return roots, checkpoint, suiteBinaryRoot, guiPath
}

func TestSuiteOwnershipHandoffFinalizeLoadAndGUIInvocation(t *testing.T) {
	roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
	first, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath)
	if err != nil {
		t.Fatal(err)
	}
	second, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath)
	if err != nil || second != first {
		t.Fatalf("idempotent finalize = %+v, %v", second, err)
	}
	loaded, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || loaded == nil || *loaded != first {
		t.Fatalf("loaded handoff = %+v, %v", loaded, err)
	}
	invocation, err := LoadSuiteGUIInvocation(roots)
	if err != nil || invocation.Executable != guiPath || len(invocation.Arguments) != 2 ||
		invocation.Arguments[0] != "--farm-client-config" || invocation.Arguments[1] != filepath.Join(roots.Config, SuiteClientConfigName) {
		t.Fatalf("GUI invocation = %+v, %v", invocation, err)
	}
	raw, err := os.ReadFile(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"private_key", "enrollment", "pairing_code", "cookie", "password"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("handoff contains forbidden %q: %s", forbidden, raw)
		}
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("handoff mode = %o", info.Mode().Perm())
		}
	}
}

func TestSuiteGUIInvocationRequiresDurableHandoff(t *testing.T) {
	roots, _, _, _ := suiteHandoffFixture(t)
	if invocation, err := LoadSuiteGUIInvocation(roots); !errors.Is(err, ErrSuiteOwnershipHandoff) || invocation.Executable != "" {
		t.Fatalf("missing handoff invocation = %+v, %v", invocation, err)
	}
	if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName), []byte("{")); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteGUIInvocation(roots); !errors.Is(err, ErrSuiteOwnershipHandoff) {
		t.Fatalf("corrupt handoff invocation = %v", err)
	}
}

func TestSuiteOwnershipHandoffFailsClosedOnMismatchAndUnsafePaths(t *testing.T) {
	t.Run("request mismatch", func(t *testing.T) {
		roots, _, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if _, err := FinalizeSuiteOwnershipHandoff(roots, "3ab595c5-768f-48f7-842a-1d53a924970e", suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("request mismatch = %v", err)
		}
	})
	t.Run("state root mismatch", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		configPath := filepath.Join(roots.Config, SuiteClientConfigName)
		raw, _ := os.ReadFile(configPath)
		replaced := strings.Replace(string(raw), roots.AgentState, filepath.Join(filepath.Dir(roots.AgentState), "other-state"), 1)
		if err := writeOwnerAtomic(configPath, []byte(replaced)); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("state mismatch = %v", err)
		}
	})
	t.Run("redirected GUI", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		link := filepath.Join(filepath.Dir(guiPath), "linked-gui.exe")
		if err := os.Symlink(guiPath, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, link); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("redirected GUI = %v", err)
		}
	})
	t.Run("world readable config", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mode assertion is Unix-specific")
		}
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if err := os.Chmod(filepath.Join(roots.Config, SuiteClientConfigName), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("unsafe config = %v", err)
		}
	})
}

func TestSuiteOwnershipHandoffRejectsCorruptExistingAndConfigDrift(t *testing.T) {
	for _, raw := range []string{
		`{"schema_version":1}`,
		`{"schema_version":1,"schema_version":1}`,
		`{"Schema_Version":1}`,
	} {
		t.Run(raw, func(t *testing.T) {
			roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
			if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteOwnershipHandoffName), []byte(raw)); err != nil {
				t.Fatal(err)
			}
			if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
				t.Fatalf("corrupt handoff = %v", err)
			}
		})
	}
	roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
	if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(roots.Config, SuiteClientConfigName)
	raw, _ := os.ReadFile(configPath)
	if err := writeOwnerAtomic(configPath, append(raw, '\n')); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteOwnershipHandoff(roots); !errors.Is(err, ErrSuiteOwnershipHandoff) {
		t.Fatalf("config drift = %v", err)
	}
}

func TestSuiteWindowsPackageScaffoldFailsClosedAndSeparatesRoots(t *testing.T) {
	repositoryRoot := farmClientRepositoryRoot(t)
	paths := []string{
		"publish/suite/windows/installer.nsi",
		"publish/suite/windows/publish-windows.ps1",
		"publish/suite/windows/README.md",
		"publish/suite/LICENSES.json",
	}
	contents := make(map[string]string, len(paths))
	for _, relative := range paths {
		raw, err := os.ReadFile(filepath.Join(repositoryRoot, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatalf("package contract file %s: %v", relative, err)
		}
		contents[relative] = string(raw)
	}
	script := strings.ToLower(contents["publish/suite/windows/publish-windows.ps1"])
	for _, required := range []string{
		"makensis.exe", "signtool.exe", "get-authenticodesignature", "get-filehash",
		"release-manifest.json", "release-manifest.envelope.json", "manifest_sha256",
		"suite verify-release", "releasekeyid", "releasepublickey", "ed25519 release envelope verification failed",
		"ant browser.exe", "ant-farm-client.exe", "runtime/xray.exe", "runtime/sing-box.exe",
		"sha256 mismatch", "size mismatch", "license manifest", "suite installer signing failed",
		"unexpected or uncovered file", "foreach ($relative in $allowed.keys)",
		"manifest does not cover licenses.json",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("publish preflight missing %q", required)
		}
	}
	preflightEnd := strings.Index(script, "$stage =")
	for _, check := range []string{"require-tool", "assert-authenticode", "sha256 mismatch", "license manifest"} {
		if index := strings.Index(script, check); index < 0 || index > preflightEnd {
			t.Fatalf("preflight %q occurs after staging mutation", check)
		}
	}
	installer := strings.ToLower(contents["publish/suite/windows/installer.nsi"])
	for _, required := range []string{
		`$programfiles64\ant browser suite`, `\versions\${version}`,
		`$localappdata\antsuite`, "suite launch-gui", "ownership-handoff.json", "--farm-client-config",
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer missing %q", required)
		}
	}
	for _, forbidden := range []string{"taskkill", "stop-process", `rmdir /r "${user_root}`, `file "${user_root}`} {
		if strings.Contains(installer, forbidden) {
			t.Fatalf("installer contains unsafe mutable/global operation %q", forbidden)
		}
	}
	var licenses struct {
		SchemaVersion int `json:"schema_version"`
		Artifacts     []struct {
			Name              string `json:"name"`
			LicenseExpression string `json:"license_expression"`
			NoticeFile        string `json:"notice_file"`
		} `json:"artifacts"`
	}
	decoder := json.NewDecoder(strings.NewReader(contents["publish/suite/LICENSES.json"]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&licenses); err != nil || licenses.SchemaVersion != 1 || len(licenses.Artifacts) < 3 {
		t.Fatalf("license contract invalid: %+v, %v", licenses, err)
	}
	for _, artifact := range licenses.Artifacts {
		if artifact.Name == "" || artifact.LicenseExpression == "" || !strings.HasPrefix(artifact.NoticeFile, "licenses/") {
			t.Fatalf("incomplete license contract: %+v", artifact)
		}
	}
}
