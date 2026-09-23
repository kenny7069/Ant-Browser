package backend

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const farmClientAutostartName = "Ant Farm Client"

var ErrFarmClientAutostart = errors.New("ant farm client autostart failed")

// FarmClientAutostartStatus is safe for CLI diagnostics. Paths and command
// lines are deliberately excluded because they can disclose user names and
// local installation layout.
type FarmClientAutostartStatus struct {
	Installed bool   `json:"installed"`
	Active    bool   `json:"active"`
	Method    string `json:"method"`
}

type farmClientAutostartManager interface {
	Install(executablePath, configPath string) error
	Remove() error
	Status() (FarmClientAutostartStatus, error)
}

func farmClientAutostartInputs(executablePath, configPath string) (string, string, error) {
	executablePath = filepath.Clean(strings.TrimSpace(executablePath))
	configPath = filepath.Clean(strings.TrimSpace(configPath))
	for name, path := range map[string]string{"executable": executablePath, "config": configPath} {
		if path == "." || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
			return "", "", fmt.Errorf("%w: %s path invalid", ErrFarmClientAutostart, name)
		}
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() {
			return "", "", fmt.Errorf("%w: %s file unavailable", ErrFarmClientAutostart, name)
		}
	}
	return executablePath, configPath, nil
}

func InstallFarmClientAutostart(executablePath, configPath string) error {
	executablePath, configPath, err := farmClientAutostartInputs(executablePath, configPath)
	if err != nil {
		return err
	}
	if err := rejectRawAutostartForSuiteFootprint(configPath); err != nil {
		return err
	}
	return newFarmClientAutostartManager().Install(executablePath, configPath)
}

func rejectRawAutostartForSuiteFootprint(configPath string) error {
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		return fmt.Errorf("%w: resolve Suite roots", ErrFarmClientAutostart)
	}
	return rejectRawAutostartForSuiteFootprintAtRoots(configPath, roots)
}

func rejectRawAutostartForSuiteFootprintAtRoots(configPath string, roots SuiteUserRoots) error {
	configPath = filepath.Clean(configPath)
	suitePath := suitePathWithin(configPath, roots.Config) || suitePathWithin(configPath, roots.AgentState) || suitePathWithin(configPath, roots.BrowserData)
	config, err := LoadFarmClientConfig(configPath)
	if err != nil {
		if suitePath {
			return fmt.Errorf("%w: suspicious Suite config", ErrFarmClientAutostart)
		}
		return nil
	}
	isSuite := suitePath || sameSuiteHandoffPath(config.StateRoot, roots.AgentState) || suitePathWithin(config.ApplicationRoot, roots.BrowserData) || suitePathWithin(config.AntConfigPath, roots.BrowserData)
	if isSuite {
		return fmt.Errorf("%w: Suite activation requires the durable coordinator", ErrFarmClientAutostart)
	}
	return nil
}

func suitePathWithin(path, root string) bool {
	if !filepath.IsAbs(path) || !filepath.IsAbs(root) {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func RemoveFarmClientAutostartForConfig(configPath string) error {
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		return fmt.Errorf("%w: resolve Suite roots", ErrFarmClientAutostart)
	}
	return removeFarmClientAutostartForConfigAtRoots(configPath, roots, newFarmClientAutostartManager())
}

func FarmClientAutostartStatusForConfig(configPath string) (FarmClientAutostartStatus, error) {
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		return FarmClientAutostartStatus{}, fmt.Errorf("%w: resolve Suite roots", ErrFarmClientAutostart)
	}
	return farmClientAutostartStatusForConfigAtRoots(configPath, roots, newFarmClientAutostartManager())
}

func removeFarmClientAutostartForConfigAtRoots(configPath string, roots SuiteUserRoots, manager farmClientAutostartManager) error {
	if err := rejectRawAutostartForSuiteFootprintAtRoots(configPath, roots); err != nil {
		return err
	}
	return manager.Remove()
}

func farmClientAutostartStatusForConfigAtRoots(configPath string, roots SuiteUserRoots, manager farmClientAutostartManager) (FarmClientAutostartStatus, error) {
	if err := rejectRawAutostartForSuiteFootprintAtRoots(configPath, roots); err != nil {
		return FarmClientAutostartStatus{}, err
	}
	return manager.Status()
}

func RemoveFarmClientAutostart() error {
	return newFarmClientAutostartManager().Remove()
}

func FarmClientAutostartStatusValue() (FarmClientAutostartStatus, error) {
	return newFarmClientAutostartManager().Status()
}

func farmClientAtomicWrite(path string, value []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("%w: create autostart directory", ErrFarmClientAutostart)
	}
	if info, err := os.Lstat(directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: autostart directory invalid", ErrFarmClientAutostart)
	}
	temporary, err := os.CreateTemp(directory, ".ant-farm-client-*")
	if err != nil {
		return fmt.Errorf("%w: create autostart staging file", ErrFarmClientAutostart)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: secure autostart staging file", ErrFarmClientAutostart)
	}
	if _, err := temporary.Write(value); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: write autostart staging file", ErrFarmClientAutostart)
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("%w: sync autostart staging file", ErrFarmClientAutostart)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("%w: close autostart staging file", ErrFarmClientAutostart)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("%w: publish autostart file", ErrFarmClientAutostart)
	}
	return nil
}
