package main

import (
	"ant-chrome/backend"
	"ant-chrome/backend/internal/database"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDiagnosticsCLIUsesAllowlist(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	secret := "PRIVATE_KEY_AND_ENROLLMENT_CODE_CANARY"
	config := "application_root: " + root + "\nstate_root: " + filepath.Join(root, "state") +
		"\ncontrol_url: ws://127.0.0.1:1\nenrollment_url: http://127.0.0.1:2/enroll\nallow_loopback_http_enrollment: true\n" +
		"identity:\n  node_uid: node-a\n  private_key: " + secret + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := protectedMain([]string{"-config", configPath, "-diagnostics"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), "node-a") || strings.Contains(stdout.String(), root) {
		t.Fatalf("diagnostics leaked configured value: %s", stdout.String())
	}
}

func TestProfileCLIUsesResidentIPCForListAndStatus(t *testing.T) {
	root, err := os.MkdirTemp("", "af-cli-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	antConfigPath := filepath.Join(root, "ant.yaml")
	antConfig := backend.DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDB(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.GetConn().Exec(`INSERT INTO browser_profiles
		(profile_id, incarnation_id, profile_name, created_at, updated_at)
		VALUES ('profile-1', 'incarnation-1', 'Safe profile', '2026-09-12T00:00:00Z', '2026-09-12T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	clientConfig := backend.FarmClientConfig{
		ApplicationRoot: root,
		StateRoot:       filepath.Join(root, "state"),
		AntConfigPath:   antConfigPath,
		ControlURL:      "ws://127.0.0.1:1",
		Identity: backend.FarmClientIdentityConfig{
			NodeUID:    "node-ipc-test",
			PrivateKey: base64.StdEncoding.EncodeToString(key),
		},
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := backend.NewFarmClientHost(configPath)
	if err != nil {
		t.Fatal(err)
	}
	server, err := backend.StartFarmClientIPCServer(host)
	if err != nil {
		_ = host.Shutdown()
		t.Fatal(err)
	}
	defer func() {
		_ = server.Close()
		_ = host.Shutdown()
	}()
	for _, args := range [][]string{{"profiles", "list"}, {"profiles", "status", "profile-1"}} {
		var stdout, stderr bytes.Buffer
		if code := runProfileCommand(configPath, args, strings.NewReader(""), &stdout, &stderr); code != 0 {
			t.Fatalf("args=%v exit=%d stderr=%q", args, code, stderr.String())
		}
		if !strings.Contains(stdout.String(), "profile-1") {
			t.Fatalf("args=%v output=%q", args, stdout.String())
		}
		for _, forbidden := range []string{root, "debugPort", "proxyConfig", "private_key"} {
			if strings.Contains(stdout.String(), forbidden) {
				t.Fatalf("args=%v leaked %q: %s", args, forbidden, stdout.String())
			}
		}
	}
}

func TestProtectedMainDoesNotPrintPanicValue(t *testing.T) {
	secret := "PANIC_PRIVATE_KEY_CANARY"
	var stderr bytes.Buffer
	code := protectedRun(&stderr, func() int {
		panic(secret)
	})
	if code != 1 || strings.Contains(stderr.String(), secret) {
		t.Fatalf("panic output=%q code=%d", stderr.String(), code)
	}
}

func TestEnrollmentCodeReaderIsBoundedAndTrims(t *testing.T) {
	code, err := readEnrollmentCode(strings.NewReader("  code-value  \nignored"), &bytes.Buffer{})
	if err != nil || code != "code-value" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}

func TestFarmAgentControlDistinguishesStopFromPreserve(t *testing.T) {
	if farmAgentControlPreservesRuntimes(strings.NewReader("S")) {
		t.Fatal("ordinary service stop unexpectedly preserved runtimes")
	}
	if !farmAgentControlPreservesRuntimes(strings.NewReader("P")) {
		t.Fatal("update rollback did not preserve runtimes")
	}
	if !farmAgentControlPreservesRuntimes(strings.NewReader("")) {
		t.Fatal("launcher death EOF did not preserve runtimes")
	}
}

func TestSuiteGUILaunchUsesOnlyDurableAbsoluteInvocation(t *testing.T) {
	originalLoad, originalStart := loadSuiteGUIInvocation, startSuiteGUIProcess
	t.Cleanup(func() {
		loadSuiteGUIInvocation, startSuiteGUIProcess = originalLoad, originalStart
	})
	wantExecutable := filepath.Join(t.TempDir(), "versions", "1.2.3", "Ant Browser.exe")
	wantConfig := filepath.Join(t.TempDir(), "config", "client.yaml")
	loadSuiteGUIInvocation = func(backend.SuiteUserRoots) (backend.SuiteGUIInvocation, error) {
		return backend.SuiteGUIInvocation{Executable: wantExecutable, Arguments: []string{"--farm-client-config", wantConfig}}, nil
	}
	var executable string
	var arguments []string
	startSuiteGUIProcess = func(path string, args ...string) error {
		executable, arguments = path, append([]string(nil), args...)
		return nil
	}
	var stdout, stderr bytes.Buffer
	if code := runSuiteCommand(backend.SuiteUserRoots{}, []string{"launch-gui"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if executable != wantExecutable || len(arguments) != 2 || arguments[0] != "--farm-client-config" || arguments[1] != wantConfig {
		t.Fatalf("launch=%q %#v", executable, arguments)
	}
}

func TestSuiteGUILaunchRejectsNonAbsoluteDurableInvocation(t *testing.T) {
	originalLoad, originalStart := loadSuiteGUIInvocation, startSuiteGUIProcess
	t.Cleanup(func() {
		loadSuiteGUIInvocation, startSuiteGUIProcess = originalLoad, originalStart
	})
	loadSuiteGUIInvocation = func(backend.SuiteUserRoots) (backend.SuiteGUIInvocation, error) {
		return backend.SuiteGUIInvocation{Executable: "Ant Browser.exe", Arguments: []string{"--farm-client-config", "client.yaml"}}, nil
	}
	called := false
	startSuiteGUIProcess = func(string, ...string) error { called = true; return nil }
	if code := runSuiteCommand(backend.SuiteUserRoots{}, []string{"launch-gui"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 || called {
		t.Fatalf("exit=%d start_called=%v", code, called)
	}
}

func TestSuiteGUILaunchFailsClosedOnMissingHandoffAndStartError(t *testing.T) {
	originalLoad, originalStart := loadSuiteGUIInvocation, startSuiteGUIProcess
	t.Cleanup(func() {
		loadSuiteGUIInvocation, startSuiteGUIProcess = originalLoad, originalStart
	})
	loadSuiteGUIInvocation = func(backend.SuiteUserRoots) (backend.SuiteGUIInvocation, error) {
		return backend.SuiteGUIInvocation{}, backend.ErrSuiteOwnershipHandoff
	}
	if code := protectedRun(&bytes.Buffer{}, func() int {
		return runSuiteCommand(backend.SuiteUserRoots{}, []string{"launch-gui"}, &bytes.Buffer{}, &bytes.Buffer{})
	}); code != 1 {
		t.Fatalf("missing handoff exit=%d", code)
	}
	loadSuiteGUIInvocation = func(backend.SuiteUserRoots) (backend.SuiteGUIInvocation, error) {
		return backend.SuiteGUIInvocation{Executable: filepath.Join(t.TempDir(), "Ant Browser.exe"), Arguments: []string{"--farm-client-config", filepath.Join(t.TempDir(), "client.yaml")}}, nil
	}
	startSuiteGUIProcess = func(string, ...string) error { return errors.New("injected start failure") }
	if code := runSuiteCommand(backend.SuiteUserRoots{}, []string{"launch-gui"}, &bytes.Buffer{}, &bytes.Buffer{}); code != 1 {
		t.Fatalf("start failure exit=%d", code)
	}
}

func TestSuiteReleaseVerificationUsesCallerPinnedTrustAnchor(t *testing.T) {
	manifest := []byte(`{"schema_version":1,"version":"1.2.3","target":{"os":"windows","arch":"amd64"},"commits":{"ant_browser":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","farm_agent":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","farm_control":"cccccccccccccccccccccccccccccccccccccccc"},"config_schema":1,"capabilities":["setup-plan"],"core_versions":{"chromium":"120.0.0"},"dependencies":[{"name":"Ant-Suite","version":"1.2.3","license_ref":"LICENSE"}],"entries":[{"path":"Ant.exe","role":"binary","size":1,"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","executable":true},{"path":"LICENSE","role":"legal","size":1,"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","executable":false}]}`)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := backend.SignSuiteReleaseManifest(manifest, "suite-key-1", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	manifestPath, envelopePath := filepath.Join(root, "release.json"), filepath.Join(root, "release-envelope.json")
	if err := os.WriteFile(manifestPath, manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(envelopePath, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	arguments := []string{"verify-release", "-manifest", manifestPath, "-envelope", envelopePath, "-key-id", "suite-key-1", "-public-key", base64.StdEncoding.EncodeToString(publicKey)}
	var stdout, stderr bytes.Buffer
	if code := runSuiteCommand(backend.SuiteUserRoots{}, arguments, &stdout, &stderr); code != 0 || strings.TrimSpace(stdout.String()) != `{"verified":true}` {
		t.Fatalf("verify exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	arguments[6] = "wrong-key"
	stdout.Reset()
	stderr.Reset()
	if code := runSuiteCommand(backend.SuiteUserRoots{}, arguments, &stdout, &stderr); code != 1 || strings.Contains(stderr.String(), base64.StdEncoding.EncodeToString(publicKey)) {
		t.Fatalf("wrong trust anchor exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestSuiteReleaseVerificationRejectsSymlinkAndOversize(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "manifest.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := readSuiteReleaseVerificationFile(link, 1024); err == nil {
			t.Fatal("symlinked release input accepted")
		}
	}
	large := filepath.Join(root, "large.json")
	if err := os.WriteFile(large, make([]byte, 1025), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSuiteReleaseVerificationFile(large, 1024); err == nil {
		t.Fatal("oversized release input accepted")
	}
}
