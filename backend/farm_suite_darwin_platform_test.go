//go:build darwin

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSuiteDarwinSigningPolicyArguments(t *testing.T) {
	if _, err := (suiteDarwinSigningPolicy{}).codesignArguments("/x"); !errors.Is(err, ErrSuiteDarwinCodeSignature) {
		t.Fatalf("build without signing policy accepted: %v", err)
	}
	if _, err := (suiteDarwinSigningPolicy{TeamID: "abc"}).codesignArguments("/x"); !errors.Is(err, ErrSuiteDarwinCodeSignature) {
		t.Fatalf("malformed team accepted: %v", err)
	}
	adhoc, err := (suiteDarwinSigningPolicy{AllowAdhoc: true}).codesignArguments("/x")
	if err != nil || !reflect.DeepEqual(adhoc, []string{"--verify", "--deep", "--strict", "--", "/x"}) {
		t.Fatalf("ad-hoc arguments = %v, %v", adhoc, err)
	}
	// A pinned team wins over the ad-hoc test switch.
	team, err := (suiteDarwinSigningPolicy{TeamID: "ABCDE12345", AllowAdhoc: true}).codesignArguments("/x")
	if err != nil || len(team) != 6 || team[3] != `-R=anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"` {
		t.Fatalf("team arguments = %v, %v", team, err)
	}
	if current := currentSuiteDarwinSigningPolicy(); current.TeamID != "" || current.AllowAdhoc {
		t.Fatalf("test binary unexpectedly carries a signing policy: %+v", current)
	}
}

func TestSuiteDarwinCodeObjectsUseOutermostBundle(t *testing.T) {
	manifest := SuiteReleaseManifest{Entries: []SuiteReleaseEntry{
		{Path: "ant-farm-client", Role: SuiteReleaseEntryBinary},
		{Path: "AntBrowser.app/Contents/MacOS/AntBrowser", Role: SuiteReleaseEntryBinary},
		{Path: "runtime/chrome/C.app/Contents/MacOS/C", Role: SuiteReleaseEntryBinary},
		{Path: "runtime/chrome/C.app/Contents/Frameworks/F.framework/Helpers/H.app/Contents/MacOS/H", Role: SuiteReleaseEntryBinary},
		{Path: "runtime/chrome/C.app/Contents/Frameworks/F.framework/Versions/1/F", Role: SuiteReleaseEntryLibrary},
		{Path: "LICENSES.json", Role: SuiteReleaseEntryLegal},
	}}
	want := []string{"ant-farm-client", "AntBrowser.app", "runtime/chrome/C.app"}
	if got := suiteDarwinCodeObjects(manifest); !reflect.DeepEqual(got, want) {
		t.Fatalf("code objects = %v, want %v", got, want)
	}
}

type suiteDarwinTreeFixture struct {
	base, root string
	handoff    SuiteOwnershipHandoff
	validator  suiteDarwinInstallValidator
	verified   []string
}

func newSuiteDarwinTreeFixture(t *testing.T) *suiteDarwinTreeFixture {
	t.Helper()
	base := t.TempDir()
	base, _ = filepath.EvalSymlinks(base)
	root := filepath.Join(base, "versions", "3.1.0")
	files := map[string][]byte{
		"ant-farm-client": []byte("agent"),
		"runtime/chrome/C C.app/Contents/Frameworks/F.framework/Versions/1/F": []byte("framework"),
		"runtime/chrome/C C.app/Contents/MacOS/C C":                           []byte("chromium"),
		"LICENSES.json": []byte("licenses"),
	}
	links := map[string]string{
		"runtime/chrome/C C.app/Contents/Frameworks/F.framework/Versions/Current": "1",
		"runtime/chrome/C C.app/Contents/Frameworks/F.framework/F":                "Versions/Current/F",
	}
	manifest := suiteReleaseManifestFixture()
	manifest.Version = "3.1.0"
	manifest.Target = SuiteReleaseTarget{OS: "darwin", Arch: runtime.GOARCH}
	manifest.Dependencies = []SuiteReleaseDependency{}
	manifest.Entries = nil
	for path, content := range files {
		full := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, content, 0o755); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		role, executable := SuiteReleaseEntryBinary, true
		if path == "LICENSES.json" {
			role, executable = SuiteReleaseEntryLegal, false
		} else if strings.Contains(path, "Versions/1/") {
			role, executable = SuiteReleaseEntryLibrary, false
		}
		manifest.Entries = append(manifest.Entries, SuiteReleaseEntry{Path: path, Role: role, Size: int64(len(content)), SHA256: hex.EncodeToString(digest[:]), Executable: executable})
	}
	for path, target := range links {
		if err := os.Symlink(target, filepath.Join(root, filepath.FromSlash(path))); err != nil {
			t.Fatal(err)
		}
		manifest.Entries = append(manifest.Entries, suiteDarwinLinkEntry(path, target))
	}
	raw, err := MarshalSuiteReleaseManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-manifest.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release-manifest.envelope.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	fixture := &suiteDarwinTreeFixture{base: base, root: root}
	fixture.handoff = SuiteOwnershipHandoff{SuiteBinaryRoot: root, ManifestSHA256: hex.EncodeToString(digest[:]), ReleaseTarget: manifest.Target}
	fixture.validator = suiteDarwinInstallValidator{
		base: base, chainTop: base, euid: func() int { return 501 }, owner: uint32(os.Getuid()),
		policy: suiteDarwinSigningPolicy{AllowAdhoc: true},
		codesign: func(_ context.Context, arguments ...string) error {
			fixture.verified = append(fixture.verified, arguments[len(arguments)-1])
			return nil
		},
	}
	fixture.lock(t)
	t.Cleanup(func() { fixture.unlock() })
	return fixture
}

// lock removes every write bit, the owner-level stand-in for a root-owned tree.
func (f *suiteDarwinTreeFixture) lock(t *testing.T) {
	t.Helper()
	var directories []string
	err := filepath.WalkDir(f.base, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			return nil
		}
		if entry.IsDir() {
			directories = append(directories, path)
			return nil
		}
		return os.Chmod(path, 0o555)
	})
	if err != nil {
		t.Fatal(err)
	}
	for index := len(directories) - 1; index >= 0; index-- {
		if err := os.Chmod(directories[index], 0o555); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *suiteDarwinTreeFixture) unlock() {
	_ = filepath.WalkDir(f.base, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.Type()&fs.ModeSymlink == 0 {
			_ = os.Chmod(path, 0o755)
		}
		return nil
	})
}

func (f *suiteDarwinTreeFixture) mutate(t *testing.T, change func()) {
	t.Helper()
	f.unlock()
	change()
	f.lock(t)
}

func TestSuiteDarwinInstallValidatorAcceptsLockedSignedTree(t *testing.T) {
	fixture := newSuiteDarwinTreeFixture(t)
	if err := fixture.validator.validate(fixture.handoff); err != nil {
		t.Fatalf("locked tree rejected: %v", err)
	}
	want := []string{filepath.Join(fixture.root, "ant-farm-client"), filepath.Join(fixture.root, "runtime/chrome/C C.app")}
	got := append([]string(nil), fixture.verified...)
	if len(got) != 2 || !((got[0] == want[0] && got[1] == want[1]) || (got[0] == want[1] && got[1] == want[0])) {
		t.Fatalf("codesign verified %v, want %v", got, want)
	}
}

func TestSuiteDarwinInstallValidatorRejectsEveryDrift(t *testing.T) {
	cases := map[string]func(t *testing.T, f *suiteDarwinTreeFixture){
		"root user": func(t *testing.T, f *suiteDarwinTreeFixture) { f.validator.euid = func() int { return 0 } },
		"noncanonical root": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.validator.base = filepath.Join(f.base, "elsewhere")
		},
		"writable file": func(t *testing.T, f *suiteDarwinTreeFixture) {
			if err := os.Chmod(filepath.Join(f.root, "ant-farm-client"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"group writable directory": func(t *testing.T, f *suiteDarwinTreeFixture) {
			if err := os.Chmod(filepath.Join(f.root, "runtime"), 0o575); err != nil {
				t.Fatal(err)
			}
		},
		"writable ancestor": func(t *testing.T, f *suiteDarwinTreeFixture) {
			if err := os.Chmod(filepath.Join(f.base, "versions"), 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"wrong owner": func(t *testing.T, f *suiteDarwinTreeFixture) { f.validator.owner = 0 },
		"retargeted link": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.mutate(t, func() {
				link := filepath.Join(f.root, "runtime/chrome/C C.app/Contents/Frameworks/F.framework/Versions/Current")
				_ = os.Remove(link)
				_ = os.Symlink("../../../../../../../ant-farm-client", link)
			})
		},
		"tampered bytes": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.mutate(t, func() { _ = os.WriteFile(filepath.Join(f.root, "ant-farm-client"), []byte("agenT"), 0o755) })
		},
		"extra file": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.mutate(t, func() { _ = os.WriteFile(filepath.Join(f.root, "runtime", "extra"), []byte("x"), 0o755) })
		},
		"uncovered symlink": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.mutate(t, func() { _ = os.Symlink("ant-farm-client", filepath.Join(f.root, "alias")) })
		},
		"signature rejected": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.validator.codesign = func(context.Context, ...string) error { return ErrSuiteDarwinCodeSignature }
		},
		"no signing policy": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.validator.policy = suiteDarwinSigningPolicy{}
		},
		"manifest digest": func(t *testing.T, f *suiteDarwinTreeFixture) { f.handoff.ManifestSHA256 = strings.Repeat("0", 64) },
		"cross arch": func(t *testing.T, f *suiteDarwinTreeFixture) {
			f.handoff.ReleaseTarget.Arch = map[string]string{"arm64": "amd64", "amd64": "arm64"}[runtime.GOARCH]
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fixture := newSuiteDarwinTreeFixture(t)
			mutate(t, fixture)
			if err := fixture.validator.validate(fixture.handoff); !errors.Is(err, ErrSuiteServiceActivation) {
				t.Fatalf("drift %q accepted: %v", name, err)
			}
		})
	}
}

type suiteDarwinFakeLaunchd struct {
	disabled map[string]bool
	loaded   map[string]bool
	calls    [][]string
	plist    string
	fail     string
}

func (f *suiteDarwinFakeLaunchd) run(arguments ...string) suiteDarwinLaunchctlResult {
	f.calls = append(f.calls, append([]string(nil), arguments...))
	if len(arguments) > 0 && arguments[0] == f.fail {
		return suiteDarwinLaunchctlResult{Err: errors.New("launchctl failed")}
	}
	switch arguments[0] {
	case "print-disabled":
		output := "\tdisabled services = {\n"
		for label, disabled := range f.disabled {
			state := "enabled"
			if disabled {
				state = "disabled"
			}
			output += "\t\t\"" + label + "\" => " + state + "\n"
		}
		return suiteDarwinLaunchctlResult{Output: []byte(output + "\t}\n")}
	case "disable", "enable":
		label := arguments[1][strings.LastIndex(arguments[1], "/")+1:]
		if arguments[0] == "disable" {
			if _, err := os.Stat(f.plist); err == nil {
				return suiteDarwinLaunchctlResult{Err: errors.New("plist written before disable")}
			}
		}
		f.disabled[label] = arguments[0] == "disable"
	case "print":
		label := arguments[1][strings.LastIndex(arguments[1], "/")+1:]
		if !f.loaded[label] {
			return suiteDarwinLaunchctlResult{Err: errors.New("not loaded")}
		}
	case "bootstrap":
		label := strings.TrimSuffix(filepath.Base(arguments[2]), ".plist")
		f.loaded[label] = true
	}
	return suiteDarwinLaunchctlResult{}
}

func TestSuiteDarwinLaunchAgentRegistrationChain(t *testing.T) {
	home := t.TempDir()
	uid := os.Getuid()
	label := suiteDarwinLaunchAgentLabel(uid)
	fake := &suiteDarwinFakeLaunchd{disabled: map[string]bool{}, loaded: map[string]bool{},
		plist: filepath.Join(home, "Library", "LaunchAgents", label+".plist")}
	rootChecks := 0
	platform := darwinSuiteServicePlatform{uid: uid, home: home, labelFor: suiteDarwinLaunchAgentLabel, run: fake.run,
		validateInstallRoot: func(SuiteOwnershipHandoff) error { rootChecks++; return nil }}
	handoff := SuiteOwnershipHandoff{
		SuiteBinaryRoot:  "/Library/Application Support/Ant Browser Suite/versions/3.1.0",
		ClientConfigPath: filepath.Join(home, "Library", "Application Support", "AntSuite", SuiteClientConfigName),
	}
	identity, err := platform.ValidateInstall(handoff)
	if err != nil || identity != label {
		t.Fatalf("identity = %q, %v", identity, err)
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationAbsent {
		t.Fatalf("before register = %s, %v", state, err)
	}
	if err := platform.RegisterDisabled(handoff, label); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(fake.plist)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("plist mode = %v, %v", info, err)
	}
	raw, _ := os.ReadFile(fake.plist)
	for _, required := range []string{"<string>/Library/Application Support/Ant Browser Suite/versions/3.1.0/ant-farm-client</string>",
		"<string>-config</string>", "<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>", "<key>SuccessfulExit</key>\n\t\t<false/>"} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("plist lacks %q:\n%s", required, raw)
		}
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationExactDisabled {
		t.Fatalf("after register = %s, %v", state, err)
	}
	if err := platform.Enable(handoff, label); err != nil {
		t.Fatal(err)
	}
	if state, err := platform.InspectRegistration(handoff, label); err != nil || state != suiteServiceRegistrationExactEnabled {
		t.Fatalf("after enable = %s, %v", state, err)
	}
	if err := platform.Start(handoff, label); err != nil || !fake.loaded[label] {
		t.Fatalf("start bootstrap = %v", err)
	}
	if err := platform.Start(handoff, label); err != nil || fake.calls[len(fake.calls)-1][0] != "kickstart" {
		t.Fatalf("second start must kickstart the loaded service: %v %v", err, fake.calls)
	}
	if rootChecks == 0 {
		t.Fatal("install root was never revalidated")
	}

	// Drift: foreign bytes, a group-writable plist, an unlisted label, a wrong label.
	if err := os.WriteFile(fake.plist, append(raw, ' '), 0o644); err != nil {
		t.Fatal(err)
	}
	if state, _ := platform.InspectRegistration(handoff, label); state != suiteServiceRegistrationDrift {
		t.Fatalf("modified plist = %s", state)
	}
	if err := os.WriteFile(fake.plist, raw, 0o664); err != nil || os.Chmod(fake.plist, 0o664) != nil {
		t.Fatal(err)
	}
	if _, err := platform.InspectRegistration(handoff, label); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("group-writable plist accepted: %v", err)
	}
	_ = os.Chmod(fake.plist, 0o644)
	delete(fake.disabled, label)
	if state, _ := platform.InspectRegistration(handoff, label); state != suiteServiceRegistrationDrift {
		t.Fatalf("unlisted label = %s", state)
	}
	if err := platform.Enable(handoff, "com.antbrowser.suite.agent.0000000000000000"); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("foreign label accepted: %v", err)
	}
	bad := handoff
	bad.ClientConfigPath = filepath.Join(home, "other.yaml")
	if err := platform.RegisterDisabled(bad, label); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("noncanonical config accepted: %v", err)
	}
	fake.fail = "disable"
	_ = os.Remove(fake.plist)
	if err := platform.RegisterDisabled(handoff, label); err == nil {
		t.Fatal("register continued after launchctl disable failed")
	}
	if _, err := os.Stat(fake.plist); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("plist written although it could not be disabled first")
	}
}
