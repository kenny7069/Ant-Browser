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
	return newFarmClientAutostartManager().Install(executablePath, configPath)
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
