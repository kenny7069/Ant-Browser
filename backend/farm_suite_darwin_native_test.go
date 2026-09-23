//go:build darwin

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestSuiteDarwinLaunchAgentNativeOptIn drives the real per-user launchd with
// a test-only label.  It never touches the production label, and removes its
// plist and loaded job afterwards.  Run with ANT_SUITE_DARWIN_NATIVE_LAUNCHD=1
// from a logged-in GUI session.
func TestSuiteDarwinLaunchAgentNativeOptIn(t *testing.T) {
	if os.Getenv("ANT_SUITE_DARWIN_NATIVE_LAUNCHD") != "1" {
		t.Skip("native launchd test is opt-in")
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	testLabel := func(uid int) string {
		hash := sha256.Sum256([]byte("native-test:" + strconv.Itoa(uid) + ":" + strconv.FormatInt(time.Now().UnixNano(), 10)))
		return "com.antbrowser.suite.agent." + hex.EncodeToString(hash[:8])
	}
	label := testLabel(os.Getuid())
	platform := darwinSuiteServicePlatform{
		uid: os.Getuid(), home: account.HomeDir,
		labelFor: func(int) string { return label }, run: runSuiteDarwinLaunchctl,
		validateInstallRoot: func(SuiteOwnershipHandoff) error { return nil },
	}
	root := t.TempDir()
	root, _ = filepath.EvalSymlinks(root)
	marker := filepath.Join(root, "launched")
	script := "#!/bin/sh\nprintf '%s' \"$2\" > '" + marker + "'\nexec /bin/sleep 30\n"
	if err := os.WriteFile(filepath.Join(root, "ant-farm-client"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, SuiteClientConfigName)
	handoff := SuiteOwnershipHandoff{SuiteBinaryRoot: root, ClientConfigPath: config}
	plist, _ := platform.plistPath(label)
	domain := platform.domain()
	t.Cleanup(func() {
		_ = runSuiteDarwinLaunchctl("bootout", domain+"/"+label)
		_ = os.Remove(plist)
		_ = runSuiteDarwinLaunchctl("enable", domain+"/"+label)
	})

	if identity, err := platform.ValidateInstall(handoff); err != nil || identity != label {
		t.Fatalf("identity = %q, %v", identity, err)
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationAbsent {
		t.Fatalf("before register = %s, %v", state, err)
	}
	if err := platform.RegisterDisabled(handoff, label); err != nil {
		t.Fatal(err)
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationExactDisabled {
		t.Fatalf("registered = %s, %v", state, err)
	}
	// A disabled job must not load even if bootstrapped by hand.
	if result := runSuiteDarwinLaunchctl("bootstrap", domain, plist); result.Err == nil {
		t.Fatal("launchd bootstrapped a disabled job")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("disabled job ran")
	}
	if err := platform.Enable(handoff, label); err != nil {
		t.Fatal(err)
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationExactEnabled {
		t.Fatalf("enabled = %s, %v", state, err)
	}
	if err := platform.Start(handoff, label); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, err := os.ReadFile(marker)
		if err == nil && string(raw) == config {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("launchd did not run the Agent with the canonical config: %q %v", raw, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if result := runSuiteDarwinLaunchctl("print", domain+"/"+label); result.Err != nil {
		t.Fatalf("started job is not loaded: %s", result.Output)
	}
	// Starting again kickstarts the loaded job instead of failing.
	if err := platform.Start(handoff, label); err != nil {
		t.Fatalf("second start = %v", err)
	}
}

// TestSuiteDarwinInstalledRootNativeOptIn validates a pkg-installed version
// root with the production rules (root ownership up to "/", no user write,
// exact manifest tree, real codesign) and smoke-runs the installed Chromium.
// Set ANT_SUITE_DARWIN_NATIVE_INSTALLED_ROOT to the installed version root.
// The test binary carries no signing policy, so it opts into the ad-hoc test
// policy explicitly, exactly as a test-built ant-farm-client does.
func TestSuiteDarwinInstalledRootNativeOptIn(t *testing.T) {
	root := os.Getenv("ANT_SUITE_DARWIN_NATIVE_INSTALLED_ROOT")
	if root == "" {
		t.Skip("native installed-root test is opt-in")
	}
	raw, err := os.ReadFile(filepath.Join(root, "release-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := ParseSuiteReleaseManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	handoff := SuiteOwnershipHandoff{SuiteBinaryRoot: root, ManifestSHA256: hex.EncodeToString(digest[:]), ReleaseTarget: manifest.Target}
	validator := productionSuiteDarwinInstallValidator()
	validator.policy = suiteDarwinSigningPolicy{AllowAdhoc: true}
	started := time.Now()
	if err := validator.validate(handoff); err != nil {
		t.Fatalf("installed root rejected: %v", err)
	}
	t.Logf("installed root validated in %s (%d entries)", time.Since(started).Round(time.Millisecond), len(manifest.Entries))
	previousAdhoc := suiteDarwinAllowAdhocCodeSigning
	suiteDarwinAllowAdhocCodeSigning = "1" // as linked into a test-built client
	t.Cleanup(func() { suiteDarwinAllowAdhocCodeSigning = previousAdhoc })
	if _, err := validateSuiteStagePlatformInstall(root, SuiteSetupPlan{ManifestSHA256: handoff.ManifestSHA256, Target: manifest.Target}, manifest.Version); err != nil {
		t.Fatalf("stage install evidence rejected: %v", err)
	}
	// The Agent user cannot add or replace anything in the immutable tree.
	for _, path := range []string{filepath.Join(root, "probe"), filepath.Join(root, "ant-farm-client")} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err == nil {
			t.Fatalf("user wrote %s", path)
		}
	}
	// A team-pinned policy rejects the ad-hoc test signatures.
	pinned := validator
	pinned.policy = suiteDarwinSigningPolicy{TeamID: "ABCDE12345"}
	if err := pinned.validate(handoff); err == nil {
		t.Fatal("ad-hoc payload passed a Developer ID team policy")
	}
	// Installed Chromium runs from the immutable root and answers CDP.
	profile := t.TempDir()
	chromium := filepath.Join(root, filepath.FromSlash(suiteDarwinReleaseLayout.Chromium))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, chromium, "--headless=new", "--no-first-run", "--use-mock-keychain",
		"--remote-debugging-port=0", "--user-data-dir="+profile, "about:blank")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	var port string
	for port == "" && ctx.Err() == nil {
		if raw, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort")); err == nil {
			port = strings.SplitN(string(raw), "\n", 2)[0]
		}
		time.Sleep(100 * time.Millisecond)
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodPut,
		"http://127.0.0.1:"+port+"/json/new?data:text/html,<title>suite-native-ok</title>", nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("installed Chromium CDP unavailable: %v", err)
	}
	response.Body.Close()
	for {
		list, err := http.Get("http://127.0.0.1:" + port + "/json/list")
		if err == nil {
			body, _ := io.ReadAll(list.Body)
			list.Body.Close()
			if strings.Contains(string(body), `"title": "suite-native-ok"`) {
				break
			}
		}
		if ctx.Err() != nil {
			t.Fatal("installed Chromium never rendered the CDP page")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
