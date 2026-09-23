//go:build windows

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows"
)

type suiteWindowsTaskCommandResult struct {
	Output   []byte
	ExitCode uint32
	Err      error
}

type windowsSuiteServicePlatform struct {
	run                 func(string, ...string) suiteWindowsTaskCommandResult
	validateInstallRoot func(SuiteOwnershipHandoff) error
}

func newSuiteServicePlatform() suiteServicePlatform {
	return windowsSuiteServicePlatform{run: runSuiteWindowsTaskCommand, validateInstallRoot: validateCanonicalSuiteInstallRoot}
}

func (p windowsSuiteServicePlatform) validateRoot(h SuiteOwnershipHandoff) error {
	if p.validateInstallRoot == nil {
		return validateCanonicalSuiteInstallRoot(h)
	}
	return p.validateInstallRoot(h)
}

func runSuiteWindowsTaskCommand(name string, args ...string) suiteWindowsTaskCommandResult {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, args...)
	var output suiteBoundedCommandBuffer
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if ctx.Err() != nil || output.exceeded {
		return suiteWindowsTaskCommandResult{Err: ErrSuiteServiceActivation}
	}
	result := suiteWindowsTaskCommandResult{Output: output.Bytes(), Err: err}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = uint32(exitErr.ExitCode())
	}
	return result
}

func (p windowsSuiteServicePlatform) taskContract(h SuiteOwnershipHandoff, taskName string, enabled bool) (suiteWindowsTaskContract, error) {
	userSID, err := currentSuiteWindowsSID()
	if err != nil || taskName != suiteWindowsTaskName(userSID) {
		return suiteWindowsTaskContract{}, ErrSuiteServiceActivation
	}
	contract := suiteWindowsTaskContract{
		TaskName: taskName, UserSID: userSID,
		Command:    filepath.Join(h.SuiteBinaryRoot, "ant-farm-client.exe"),
		ConfigPath: h.ClientConfigPath, Enabled: enabled,
	}
	if err := contract.validate(); err != nil {
		return suiteWindowsTaskContract{}, err
	}
	return contract, nil
}

func (p windowsSuiteServicePlatform) ValidateInstall(h SuiteOwnershipHandoff) (string, error) {
	if err := p.validateRoot(h); err != nil {
		return "", err
	}
	userSID, err := currentSuiteWindowsSID()
	if err != nil {
		return "", err
	}
	return suiteWindowsTaskName(userSID), nil
}

func currentSuiteWindowsSID() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", ErrSuiteServiceActivation
	}
	return user.User.Sid.String(), nil
}

func suiteWindowsTaskName(userSID string) string {
	hash := sha256.Sum256([]byte(userSID))
	return `\AntBrowserSuite-Agent-` + hex.EncodeToString(hash[:8])
}

func suiteWindowsSchtasksPath() (string, error) {
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		return "", ErrSuiteServiceActivation
	}
	path := filepath.Clean(filepath.Join(systemDirectory, "schtasks.exe"))
	if !suiteWindowsAbsolutePath(path) || !strings.EqualFold(filepath.Base(path), "schtasks.exe") || !strings.EqualFold(filepath.Dir(path), filepath.Clean(systemDirectory)) {
		return "", ErrSuiteServiceActivation
	}
	return path, nil
}

func (p windowsSuiteServicePlatform) RegisterDisabled(h SuiteOwnershipHandoff, taskName string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	contract, err := p.taskContract(h, taskName, false)
	if err != nil {
		return err
	}
	raw, err := buildSuiteWindowsTaskXML(contract)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(h.AgentStateRoot, ".suite-task-*.xml")
	if err != nil {
		return ErrSuiteServiceActivation
	}
	path := temporary.Name()
	defer os.Remove(path)
	if temporary.Chmod(0o600) != nil || func() error { _, err := temporary.Write(suiteWindowsTaskUTF16LE(raw)); return err }() != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return ErrSuiteServiceActivation
	}
	schtasksPath, err := suiteWindowsSchtasksPath()
	if err != nil {
		return err
	}
	result := p.run(schtasksPath, "/Create", "/TN", taskName, "/XML", path, "/HRESULT")
	if result.Err != nil || result.ExitCode != 0 {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}

func (p windowsSuiteServicePlatform) InspectRegistration(h SuiteOwnershipHandoff, taskName string) (suiteServiceRegistrationState, error) {
	if err := p.validateRoot(h); err != nil {
		return suiteServiceRegistrationDrift, err
	}
	disabled, err := p.taskContract(h, taskName, false)
	if err != nil {
		return suiteServiceRegistrationDrift, err
	}
	schtasksPath, err := suiteWindowsSchtasksPath()
	if err != nil {
		return suiteServiceRegistrationDrift, err
	}
	result := p.run(schtasksPath, "/Query", "/TN", taskName, "/XML", "/HRESULT")
	if result.Err != nil {
		if suiteWindowsTaskQueryIsAbsent(result.ExitCode, result.Err) {
			return suiteServiceRegistrationAbsent, nil
		}
		return suiteServiceRegistrationDrift, ErrSuiteServiceActivation
	}
	if result.ExitCode != suiteWindowsTaskQueryOK {
		return suiteServiceRegistrationDrift, ErrSuiteServiceActivation
	}
	queryXML, decodeErr := decodeSuiteWindowsTaskCommandXML(result.Output)
	if decodeErr != nil {
		return suiteServiceRegistrationDrift, ErrSuiteServiceActivation
	}
	if matchSuiteWindowsTaskXML(queryXML, disabled) == nil {
		if err := p.validateRoot(h); err != nil {
			return suiteServiceRegistrationDrift, err
		}
		return suiteServiceRegistrationExactDisabled, nil
	}
	enabled := disabled
	enabled.Enabled = true
	if matchSuiteWindowsTaskXML(queryXML, enabled) == nil {
		if err := p.validateRoot(h); err != nil {
			return suiteServiceRegistrationDrift, err
		}
		return suiteServiceRegistrationExactEnabled, nil
	}
	return suiteServiceRegistrationDrift, nil
}

func (p windowsSuiteServicePlatform) Enable(h SuiteOwnershipHandoff, taskName string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	if _, err := p.taskContract(h, taskName, false); err != nil {
		return err
	}
	schtasksPath, err := suiteWindowsSchtasksPath()
	if err != nil {
		return err
	}
	result := p.run(schtasksPath, "/Change", "/TN", taskName, "/ENABLE")
	if result.Err != nil || result.ExitCode != 0 {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}

func (p windowsSuiteServicePlatform) Start(h SuiteOwnershipHandoff, taskName string) error {
	if err := p.validateRoot(h); err != nil {
		return err
	}
	if _, err := p.taskContract(h, taskName, true); err != nil {
		return err
	}
	schtasksPath, err := suiteWindowsSchtasksPath()
	if err != nil {
		return err
	}
	result := p.run(schtasksPath, "/Run", "/TN", taskName)
	if result.Err != nil || result.ExitCode != 0 {
		return ErrSuiteServiceActivation
	}
	return p.validateRoot(h)
}
