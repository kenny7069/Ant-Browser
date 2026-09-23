//go:build windows

package backend

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func windowsSuitePlatformFixture(t *testing.T) (SuiteOwnershipHandoff, string, suiteWindowsTaskContract) {
	t.Helper()
	sid, err := currentSuiteWindowsSID()
	if err != nil {
		t.Fatal(err)
	}
	root := `C:\Program Files\Ant Browser Suite\versions\1.2.3`
	handoff := SuiteOwnershipHandoff{SuiteBinaryRoot: root, ClientConfigPath: `C:\Users\farmer\AppData\Local\AntSuite\config\client.yaml`, AgentStateRoot: t.TempDir()}
	name := suiteWindowsTaskName(sid)
	contract := suiteWindowsTaskContract{TaskName: name, UserSID: sid, Command: filepath.Join(root, "ant-farm-client.exe"), ConfigPath: handoff.ClientConfigPath}
	return handoff, name, contract
}

func TestWindowsSuiteTaskRegisterHasNoForceAndInspectIsExact(t *testing.T) {
	handoff, name, contract := windowsSuitePlatformFixture(t)
	var calls [][]string
	platform := windowsSuiteServicePlatform{validateInstallRoot: func(SuiteOwnershipHandoff) error { return nil }, run: func(command string, args ...string) suiteWindowsTaskCommandResult {
		calls = append(calls, append([]string{command}, args...))
		return suiteWindowsTaskCommandResult{}
	}}
	if err := platform.RegisterDisabled(handoff, name); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || slices.Contains(calls[0], "/F") || !slices.Contains(calls[0], "/Create") {
		t.Fatalf("unsafe create call: %v", calls)
	}
	if !filepath.IsAbs(calls[0][0]) || !strings.EqualFold(filepath.Base(calls[0][0]), "schtasks.exe") {
		t.Fatalf("noncanonical task scheduler command: %q", calls[0][0])
	}
	raw, _ := buildSuiteWindowsTaskXML(contract)
	platform.run = func(string, ...string) suiteWindowsTaskCommandResult {
		return suiteWindowsTaskCommandResult{Output: suiteWindowsTaskUTF16LE(raw)}
	}
	state, err := platform.InspectRegistration(handoff, name)
	if err != nil || state != suiteServiceRegistrationExactDisabled {
		t.Fatalf("state=%s err=%v", state, err)
	}
}

func TestWindowsSuiteTaskQueryErrorsDoNotBecomeAbsent(t *testing.T) {
	handoff, name, _ := windowsSuitePlatformFixture(t)
	for _, code := range []uint32{0x80070005, 0x8004130d, 1} {
		platform := windowsSuiteServicePlatform{validateInstallRoot: func(SuiteOwnershipHandoff) error { return nil }, run: func(string, ...string) suiteWindowsTaskCommandResult {
			return suiteWindowsTaskCommandResult{ExitCode: code, Err: errors.New("query failed")}
		}}
		state, err := platform.InspectRegistration(handoff, name)
		if err == nil || state != suiteServiceRegistrationDrift {
			t.Fatalf("code=%#x state=%s err=%v", code, state, err)
		}
	}
	platform := windowsSuiteServicePlatform{validateInstallRoot: func(SuiteOwnershipHandoff) error { return nil }, run: func(string, ...string) suiteWindowsTaskCommandResult {
		return suiteWindowsTaskCommandResult{ExitCode: suiteWindowsTaskQueryNotFound, Err: &os.PathError{Op: "query", Path: "task", Err: errors.New("not found")}}
	}}
	state, err := platform.InspectRegistration(handoff, name)
	if err != nil || state != suiteServiceRegistrationAbsent {
		t.Fatalf("not-found state=%s err=%v", state, err)
	}
}

func TestWindowsSuiteTaskMutationCommandsAreSeparatedAndNonzeroFails(t *testing.T) {
	handoff, name, _ := windowsSuitePlatformFixture(t)
	var calls [][]string
	platform := windowsSuiteServicePlatform{validateInstallRoot: func(SuiteOwnershipHandoff) error { return nil }, run: func(command string, args ...string) suiteWindowsTaskCommandResult {
		calls = append(calls, append([]string{command}, args...))
		return suiteWindowsTaskCommandResult{}
	}}
	if err := platform.Enable(handoff, name); err != nil {
		t.Fatal(err)
	}
	if err := platform.Start(handoff, name); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 2 || !slices.Equal(calls[0][1:], []string{"/Change", "/TN", name, "/ENABLE"}) || !slices.Equal(calls[1][1:], []string{"/Run", "/TN", name}) {
		t.Fatalf("mutation calls=%v", calls)
	}
	for _, call := range calls {
		if slices.Contains(call, "/HRESULT") {
			t.Fatalf("unsupported HRESULT switch on mutation call: %v", call)
		}
	}
	platform.run = func(string, ...string) suiteWindowsTaskCommandResult {
		return suiteWindowsTaskCommandResult{ExitCode: 1}
	}
	if err := platform.RegisterDisabled(handoff, name); !errors.Is(err, ErrSuiteServiceActivation) {
		t.Fatalf("nonzero create accepted: %v", err)
	}
}
