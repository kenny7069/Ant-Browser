//go:build darwin

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const suiteDarwinLaunchctlPath = "/bin/launchctl"

var suiteDarwinLabelPattern = regexp.MustCompile(`^com\.antbrowser\.suite\.agent\.[0-9a-f]{16}$`)

type suiteDarwinLaunchctlResult struct {
	Output []byte
	Err    error
}

// darwinSuiteServicePlatform registers the resident Agent as a per-user
// LaunchAgent.  launchd's per-user disabled database is the enable switch,
// so the plist can be written and audited while the service stays disabled,
// mirroring the Windows "register disabled -> audit -> enable -> start" chain.
type darwinSuiteServicePlatform struct {
	uid                 int
	home                string
	labelFor            func(int) string
	run                 func(...string) suiteDarwinLaunchctlResult
	validateInstallRoot func(SuiteOwnershipHandoff) error
}

func newSuiteServicePlatform() suiteServicePlatform {
	uid := os.Getuid()
	home := ""
	// The account database, not $HOME, decides where launchd reads agents.
	if account, err := user.LookupId(strconv.Itoa(uid)); err == nil {
		home = account.HomeDir
	}
	return darwinSuiteServicePlatform{uid: uid, home: home, labelFor: suiteDarwinLaunchAgentLabel, run: runSuiteDarwinLaunchctl, validateInstallRoot: validateCanonicalSuiteInstallRoot}
}

func runSuiteDarwinLaunchctl(arguments ...string) suiteDarwinLaunchctlResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, suiteDarwinLaunchctlPath, arguments...)
	var output suiteBoundedCommandBuffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil || output.exceeded {
		return suiteDarwinLaunchctlResult{Err: ErrSuiteServiceActivation}
	}
	return suiteDarwinLaunchctlResult{Output: output.Bytes(), Err: err}
}

func suiteDarwinLaunchAgentLabel(uid int) string {
	hash := sha256.Sum256([]byte("uid:" + strconv.Itoa(uid)))
	return "com.antbrowser.suite.agent." + hex.EncodeToString(hash[:8])
}

func (p darwinSuiteServicePlatform) validateRoot(h SuiteOwnershipHandoff) error {
	if p.validateInstallRoot == nil {
		return validateCanonicalSuiteInstallRoot(h)
	}
	return p.validateInstallRoot(h)
}

func (p darwinSuiteServicePlatform) domain() string { return "gui/" + strconv.Itoa(p.uid) }

func (p darwinSuiteServicePlatform) label() string {
	if p.labelFor == nil {
		return suiteDarwinLaunchAgentLabel(p.uid)
	}
	return p.labelFor(p.uid)
}

func (p darwinSuiteServicePlatform) plistPath(label string) (string, error) {
	if p.uid <= 0 || !filepath.IsAbs(p.home) || !suiteDarwinLabelPattern.MatchString(label) || label != p.label() {
		return "", ErrSuiteServiceActivation
	}
	return filepath.Join(p.home, "Library", "LaunchAgents", label+".plist"), nil
}

func buildSuiteDarwinLaunchAgentPlist(label string, h SuiteOwnershipHandoff) ([]byte, error) {
	program := filepath.Join(h.SuiteBinaryRoot, filepath.FromSlash(suiteDarwinReleaseLayout.Client))
	for _, value := range []string{program, h.ClientConfigPath} {
		if !filepath.IsAbs(value) || filepath.Clean(value) != value || strings.ContainsAny(value, "\x00\r\n") {
			return nil, ErrSuiteServiceActivation
		}
	}
	if filepath.Base(h.ClientConfigPath) != SuiteClientConfigName || !suiteDarwinLabelPattern.MatchString(label) {
		return nil, ErrSuiteServiceActivation
	}
	escape := func(value string) string {
		var output bytes.Buffer
		_ = xml.EscapeText(&output, []byte(value))
		return output.String()
	}
	return []byte(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + escape(label) + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>` + escape(program) + `</string>
		<string>-config</string>
		<string>` + escape(h.ClientConfigPath) + `</string>
	</array>
	<key>LimitLoadToSessionType</key>
	<string>Aqua</string>
	<key>ProcessType</key>
	<string>Interactive</string>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<dict>
		<key>SuccessfulExit</key>
		<false/>
	</dict>
	<key>ThrottleInterval</key>
	<integer>10</integer>
</dict>
</plist>
`), nil
}

func (p darwinSuiteServicePlatform) ValidateInstall(h SuiteOwnershipHandoff) (string, error) {
	if err := p.validateRoot(h); err != nil {
		return "", err
	}
	label := p.label()
	if _, err := p.plistPath(label); err != nil {
		return "", err
	}
	return label, nil
}

func (p darwinSuiteServicePlatform) disabledState(label string) (disabled, listed bool, err error) {
	result := p.run("print-disabled", p.domain())
	if result.Err != nil {
		return false, false, ErrSuiteServiceActivation
	}
	marker := `"` + label + `" => `
	for _, line := range strings.Split(string(result.Output), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, marker) {
			continue
		}
		switch strings.TrimSpace(strings.TrimPrefix(line, marker)) {
		case "disabled", "true":
			return true, true, nil
		case "enabled", "false":
			return false, true, nil
		default:
			return false, false, ErrSuiteServiceActivation
		}
	}
	return false, false, nil
}

// readOwnedPlist returns the plist only if it is a regular file owned by this
// user and not writable by anyone else; launchd would refuse it otherwise.
func (p darwinSuiteServicePlatform) readOwnedPlist(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxSuiteWindowsTaskXMLBytes {
		return nil, true, ErrSuiteServiceActivation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != p.uid || info.Mode().Perm()&0o022 != 0 {
		return nil, true, ErrSuiteServiceActivation
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, true, ErrSuiteServiceActivation
	}
	return raw, true, nil
}

func (p darwinSuiteServicePlatform) RegisterDisabled(h SuiteOwnershipHandoff, label string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	path, err := p.plistPath(label)
	if err != nil {
		return err
	}
	raw, err := buildSuiteDarwinLaunchAgentPlist(label, h)
	if err != nil {
		return err
	}
	// Disable before the plist exists, so a login in between cannot start it.
	if result := p.run("disable", p.domain()+"/"+label); result.Err != nil {
		return ErrSuiteServiceActivation
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return ErrSuiteServiceActivation
	}
	if err := farmClientAtomicWrite(path, raw, 0o644); err != nil {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}

func (p darwinSuiteServicePlatform) InspectRegistration(h SuiteOwnershipHandoff, label string) (suiteServiceRegistrationState, error) {
	if err := p.validateRoot(h); err != nil {
		return suiteServiceRegistrationDrift, err
	}
	path, err := p.plistPath(label)
	if err != nil {
		return suiteServiceRegistrationDrift, err
	}
	raw, exists, err := p.readOwnedPlist(path)
	if err != nil {
		return suiteServiceRegistrationDrift, err
	}
	if !exists {
		return suiteServiceRegistrationAbsent, nil
	}
	expected, err := buildSuiteDarwinLaunchAgentPlist(label, h)
	if err != nil || !bytes.Equal(raw, expected) {
		return suiteServiceRegistrationDrift, nil
	}
	disabled, listed, err := p.disabledState(label)
	if err != nil {
		return suiteServiceRegistrationDrift, err
	}
	if !listed {
		// Never registered through RegisterDisabled: cannot prove its state.
		return suiteServiceRegistrationDrift, nil
	}
	if err := p.validateRoot(h); err != nil {
		return suiteServiceRegistrationDrift, err
	}
	if disabled {
		return suiteServiceRegistrationExactDisabled, nil
	}
	return suiteServiceRegistrationExactEnabled, nil
}

func (p darwinSuiteServicePlatform) Enable(h SuiteOwnershipHandoff, label string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	if _, err := p.plistPath(label); err != nil {
		return err
	}
	if result := p.run("enable", p.domain()+"/"+label); result.Err != nil {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}

func (p darwinSuiteServicePlatform) Start(h SuiteOwnershipHandoff, label string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	path, err := p.plistPath(label)
	if err != nil {
		return err
	}
	target := p.domain() + "/" + label
	if p.run("print", target).Err == nil {
		if result := p.run("kickstart", target); result.Err != nil {
			return ErrSuiteServiceActivation
		}
	} else if result := p.run("bootstrap", p.domain(), path); result.Err != nil {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}
