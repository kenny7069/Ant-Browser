package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
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
	guiPath := filepath.Join(suiteBinaryRoot, filepath.FromSlash(suiteCurrentReleaseLayout().GUI))
	config := FarmClientConfig{
		ApplicationRoot: filepath.Join(roots.BrowserData, "ant-application"), StateRoot: roots.AgentState,
		ControlURL: "wss://farm.example.test/control/ws", NodeName: "Farm One",
		Identity: FarmClientIdentityConfig{NodeUID: "node-one", PrivateKeyRef: "device-node-one"},
	}
	if err := ensureOwnerDirectory(config.ApplicationRoot); err != nil {
		t.Fatal(err)
	}
	config.AntConfigPath = filepath.Join(config.ApplicationRoot, "config.yaml")
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
	files := map[string][]byte{
		suiteCurrentReleaseLayout().GUI:      []byte("signed-gui-fixture"),
		suiteCurrentReleaseLayout().Client:   []byte("signed-agent-fixture"),
		suiteCurrentReleaseLayout().Xray:     []byte("signed-xray-fixture"),
		suiteCurrentReleaseLayout().SingBox:  []byte("signed-sing-box-fixture"),
		suiteCurrentReleaseLayout().Chromium: []byte("signed-chromium-fixture"),
		"LICENSES.json":                      []byte("license-manifest-fixture"),
		"licenses/Ant-LICENSE.txt":           []byte("Ant license fixture"),
		"licenses/Xray-LICENSE.txt":          []byte("Xray license fixture"),
		"licenses/SingBox-LICENSE.txt":       []byte("Sing-box license fixture"),
		"licenses/Chromium-LICENSE.txt":      []byte("Chromium license fixture"),
	}
	entries := make([]SuiteReleaseEntry, 0, len(files))
	for relative, content := range files {
		path := filepath.Join(suiteBinaryRoot, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, content, 0o755); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		role, executable := SuiteReleaseEntryLegal, false
		if suiteTestIsLayoutBinary(relative) {
			role, executable = SuiteReleaseEntryBinary, true
		}
		entries = append(entries, SuiteReleaseEntry{Path: relative, Role: role, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Executable: executable})
	}
	commit := strings.Repeat("a", 40)
	manifest := SuiteReleaseManifest{
		SchemaVersion: 1, Version: "1.2.3", Target: SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH},
		Commits: SuiteReleaseCommits{AntBrowser: commit, FarmAgent: commit, FarmControl: commit}, ConfigSchema: 1,
		Capabilities: []string{"setup-plan", "signed-release"}, CoreVersions: map[string]string{"chromium": "128.0.0"},
		Dependencies: []SuiteReleaseDependency{
			{Name: "Ant-Browser-Suite", Version: "1.2.3", LicenseRef: "licenses/Ant-LICENSE.txt"},
			{Name: "Xray-core", Version: "25.1.1", LicenseRef: "licenses/Xray-LICENSE.txt"},
			{Name: "sing-box", Version: "1.11.0", LicenseRef: "licenses/SingBox-LICENSE.txt"},
			{Name: "Chromium", Version: "128.0.0", LicenseRef: "licenses/Chromium-LICENSE.txt"},
		}, Entries: entries,
	}
	manifestRaw, err := MarshalSuiteReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(suiteBinaryRoot, "release-manifest.json"), manifestRaw, 0o644); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignSuiteReleaseManifest(manifestRaw, "suite-test-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(suiteBinaryRoot, "release-manifest.envelope.json"), envelope, 0o644); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySuiteReleaseManifest(manifestRaw, envelope, SuiteReleaseTrustAnchor{KeyID: "suite-test-key", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewSuiteSetupPlan(checkpoint, verified)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveSuiteSetupPlan(roots, plan); err != nil {
		t.Fatalf("save setup plan: %+v, %v", plan, err)
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
	t.Run("missing setup plan", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if err := os.Remove(filepath.Join(roots.AgentState, suiteSetupPlanName)); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("missing plan = %v", err)
		}
	})
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
	t.Run("non-canonical Ant config path", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		configPath := filepath.Join(roots.Config, SuiteClientConfigName)
		raw, _ := os.ReadFile(configPath)
		var config FarmClientConfig
		if err := yaml.Unmarshal(raw, &config); err != nil {
			t.Fatal(err)
		}
		config.AntConfigPath = filepath.Join(roots.BrowserData, "escaped-config.yaml")
		raw, err := yaml.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if err := writeOwnerAtomic(configPath, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("non-canonical Ant config path = %v", err)
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

func TestSuiteOwnershipHandoffBindsInstalledReleaseBytesAndRoot(t *testing.T) {
	t.Run("cross target", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		otherTarget := SuiteReleaseTarget{OS: "windows", Arch: "amd64"}
		if otherTarget == (SuiteReleaseTarget{OS: runtime.GOOS, Arch: runtime.GOARCH}) {
			otherTarget = SuiteReleaseTarget{OS: "linux", Arch: "arm64"}
		}
		if runtime.GOOS == "darwin" {
			// macOS bundle paths only validate for darwin; cross the arch instead.
			otherTarget = SuiteReleaseTarget{OS: "darwin", Arch: map[string]string{"arm64": "amd64", "amd64": "arm64"}[runtime.GOARCH]}
		}
		rewriteSuiteHandoffReleaseTarget(t, roots, checkpoint, suiteBinaryRoot, otherTarget)
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("cross target = %v", err)
		}
	})
	t.Run("manifest mismatch", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		manifestPath := filepath.Join(suiteBinaryRoot, "release-manifest.json")
		raw, _ := os.ReadFile(manifestPath)
		raw = []byte(strings.Replace(string(raw), `"version":"1.2.3"`, `"version":"1.2.4"`, 1))
		if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("manifest mismatch = %v", err)
		}
	})
	t.Run("tampered GUI revalidated on load", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(guiPath, []byte("tampered GUI"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSuiteOwnershipHandoff(roots); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("tampered GUI load = %v", err)
		}
	})
	t.Run("tampered non-GUI entry", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if err := os.WriteFile(filepath.Join(suiteBinaryRoot, filepath.FromSlash(suiteCurrentReleaseLayout().Xray)), []byte("tampered runtime"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("tampered entry = %v", err)
		}
	})
	t.Run("unexpected regular file", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if err := os.WriteFile(filepath.Join(suiteBinaryRoot, "evil.dll"), []byte("not manifest covered"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("unexpected file = %v", err)
		}
	})
	t.Run("unexpected symlink", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, guiPath := suiteHandoffFixture(t)
		if err := os.Symlink(guiPath, filepath.Join(suiteBinaryRoot, "gui-link.exe")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, suiteBinaryRoot, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("unexpected symlink = %v", err)
		}
	})
	t.Run("unplanned version root", func(t *testing.T) {
		roots, checkpoint, suiteBinaryRoot, originalGUIPath := suiteHandoffFixture(t)
		unplanned := filepath.Join(filepath.Dir(suiteBinaryRoot), "unplanned")
		if err := os.Rename(suiteBinaryRoot, unplanned); err != nil {
			t.Fatal(err)
		}
		guiPath := filepath.Join(unplanned, filepath.Base(originalGUIPath))
		if _, err := FinalizeSuiteOwnershipHandoff(roots, checkpoint.RequestUID, unplanned, guiPath); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("unplanned root = %v", err)
		}
	})
}

func rewriteSuiteHandoffReleaseTarget(t *testing.T, roots SuiteUserRoots, checkpoint SetupPreparationCheckpoint, suiteBinaryRoot string, target SuiteReleaseTarget) {
	t.Helper()
	manifestPath := filepath.Join(suiteBinaryRoot, "release-manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseSuiteReleaseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	manifest.Target = target
	raw, err = MarshalSuiteReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SignSuiteReleaseManifest(raw, "cross-target-key", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(suiteBinaryRoot, "release-manifest.envelope.json"), envelope, 0o644); err != nil {
		t.Fatal(err)
	}
	verified, err := VerifySuiteReleaseManifest(raw, envelope, SuiteReleaseTrustAnchor{KeyID: "cross-target-key", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewSuiteSetupPlan(checkpoint, verified)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(roots.AgentState, suiteSetupPlanName)); err != nil {
		t.Fatal(err)
	}
	if err := SaveSuiteSetupPlan(roots, plan); err != nil {
		t.Fatal(err)
	}
}

func TestStreamSuiteInstalledEntryDigestDoesNotRequireWholeFileBuffer(t *testing.T) {
	const size = int64(16 << 20)
	path := filepath.Join(t.TempDir(), "sparse-runtime.bin")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(size); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	expectedHasher := sha256.New()
	if _, err := io.CopyN(expectedHasher, zeroReader{}, size); err != nil {
		t.Fatal(err)
	}
	digest, err := streamSuiteInstalledEntryDigest(path, size)
	if err != nil || digest != hex.EncodeToString(expectedHasher.Sum(nil)) {
		t.Fatalf("streamed digest=%q err=%v", digest, err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(buffer []byte) (int, error) {
	clear(buffer)
	return len(buffer), nil
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
	scriptSource := contents["publish/suite/windows/publish-windows.ps1"]
	for _, required := range []string{
		"makensis.exe", "signtool.exe", "get-authenticodesignature", "get-filehash",
		"release-manifest.json", "release-manifest.envelope.json", "manifest_sha256",
		"suite verify-release", "releasekeyid", "releasepublickey", "ed25519 release envelope verification failed",
		"antbrowser.exe", "ant-farm-client.exe", "runtime/xray.exe", "runtime/sing-box.exe", "runtime/chrome/chrome.exe",
		"sha256 mismatch", "size mismatch", "license manifest", "suite installer signing failed",
		"unexpected or uncovered file", "foreach ($key in $allowed.keys)",
		"manifest does not cover licenses.json", "signed dependency does not have one exact license artifact",
		"license artifact does not exactly match a signed dependency", "exact signed legal entry",
		"version-agnostic policy contract", "license policy artifact is missing from the payload",
		"product license notice is not an exact signed legal entry", "manifest does not cover the product license notice",
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
	executableCheck := strings.Index(script, "if ([bool]$entry.executable)")
	requiredCoverage := strings.Index(script, `foreach ($relative in @("antbrowser.exe"`)
	if executableCheck < 0 || requiredCoverage < 0 || executableCheck > requiredCoverage ||
		!strings.Contains(script[executableCheck:requiredCoverage], "assert-authenticode $path") {
		t.Fatal("publisher does not Authenticode-check every manifest executable before required-file coverage")
	}
	for _, required := range []string{"numeric prerelease identifier with a leading zero", "$identifier -match '^[0-9]+$'"} {
		if !strings.Contains(script, required) {
			t.Fatalf("publisher SemVer validation missing %q", required)
		}
	}
	for _, required := range []string{
		`$seen[$key] = [string]$entry.path`,
		`$allowed[$key] = [string]$seen[$key]`,
		`$allowed[$relative.ToLowerInvariant()] = $relative`,
		`if ($relative -cne [string]$allowed[$key])`,
		`payload path casing differs from its signed canonical path`,
		`foreach ($key in $allowed.Keys)`,
		`$relative = [string]$allowed[$key]`,
		`Join-Path $stage ($relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))`,
	} {
		if !strings.Contains(scriptSource, required) {
			t.Fatalf("publisher loses signed path casing: missing %q", required)
		}
	}
	for _, canonicalPath := range []string{"AntBrowser.exe", "LICENSES.json", "licenses/Ant-Browser-Suite-LICENSE.txt", "release-manifest.envelope.json"} {
		if !strings.Contains(scriptSource, canonicalPath) && !strings.Contains(contents["publish/suite/LICENSES.json"], canonicalPath) {
			t.Fatalf("package contract omits canonical mixed-case path %q", canonicalPath)
		}
	}
	installer := strings.ToLower(contents["publish/suite/windows/installer.nsi"])
	for _, required := range []string{
		`$programfiles64\ant browser suite`, `\versions\${version}`,
		`iffileexists "${version_dir}\*.*"`, "immutable suite version is already installed",
	} {
		if !strings.Contains(installer, required) {
			t.Fatalf("installer missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"taskkill", "stop-process", "$localappdata", "createdirectory", "user_root",
		"createshortcut", "launch-gui", "writeuninstaller", `section "uninstall"`, "rmdir /r", "uninstallstring",
	} {
		if strings.Contains(installer, forbidden) {
			t.Fatalf("installer contains unsafe mutable/global operation %q", forbidden)
		}
	}
	var licenses struct {
		SchemaVersion  int `json:"schema_version"`
		ProductLicense struct {
			Name              string `json:"name"`
			LicenseExpression string `json:"license_expression"`
			NoticeFile        string `json:"notice_file"`
		} `json:"product_license"`
		AllowedArtifacts []struct {
			Name              string `json:"name"`
			LicenseExpression string `json:"license_expression"`
			NoticeFile        string `json:"notice_file"`
		} `json:"allowed_artifacts"`
	}
	decoder := json.NewDecoder(strings.NewReader(contents["publish/suite/LICENSES.json"]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&licenses); err != nil || licenses.SchemaVersion != 1 || len(licenses.AllowedArtifacts) != 3 {
		t.Fatalf("license contract invalid: %+v, %v", licenses, err)
	}
	if licenses.ProductLicense.Name != "Ant-Browser-Suite" || licenses.ProductLicense.NoticeFile != "licenses/Ant-Browser-Suite-LICENSE.txt" || licenses.ProductLicense.LicenseExpression == "" {
		t.Fatalf("product license contract invalid: %+v", licenses.ProductLicense)
	}
	seenChromium := false
	for _, artifact := range licenses.AllowedArtifacts {
		if artifact.Name == "Chromium" {
			seenChromium = true
		}
		if artifact.Name == "" || artifact.LicenseExpression == "" || !strings.HasPrefix(artifact.NoticeFile, "licenses/") {
			t.Fatalf("incomplete license contract: %+v", artifact)
		}
	}
	if !seenChromium {
		t.Fatal("Chromium license artifact missing")
	}
	for _, forbiddenVersion := range []string{`"version"`, "1.2.3", "25.1.1", "1.11.0", "128.0.0"} {
		if strings.Contains(contents["publish/suite/LICENSES.json"], forbiddenVersion) || strings.Contains(contents["publish/suite/windows/publish-windows.ps1"], forbiddenVersion) {
			t.Fatalf("version-agnostic license policy is pinned to %q", forbiddenVersion)
		}
	}
}

func suiteTestIsLayoutBinary(relative string) bool {
	layout := suiteCurrentReleaseLayout()
	for _, binary := range []string{layout.GUI, layout.Client, layout.Xray, layout.SingBox, layout.Chromium} {
		if relative == binary {
			return true
		}
	}
	return false
}
