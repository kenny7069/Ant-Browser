package backend

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SuiteUserRoots separates immutable suite binaries from data owned by the
// account that will run the Agent. Resolving paths never creates directories.
type SuiteUserRoots struct {
	Config      string
	BrowserData string
	AgentState  string
	Logs        string
}

func ResolveSuiteUserRoots() (SuiteUserRoots, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return SuiteUserRoots{}, fmt.Errorf("resolve suite user home: %w", err)
	}
	return resolveSuiteUserRoots(runtime.GOOS, home, os.Getenv)
}

// resolveSuiteUserRoots is injectable so platform layouts can be verified on
// any test runner. XDG overrides must be absolute; an invalid override does
// not silently redirect mutable data into the current directory.
func resolveSuiteUserRoots(goos, home string, getenv func(string) string) (SuiteUserRoots, error) {
	var configBase, dataBase, stateBase, logBase string
	switch goos {
	case "windows":
		base := strings.TrimSpace(getenv("LOCALAPPDATA"))
		if !filepath.IsAbs(base) {
			return SuiteUserRoots{}, fmt.Errorf("%w: LOCALAPPDATA must be absolute", ErrFarmClientRoots)
		}
		root := filepath.Join(base, "AntSuite")
		return SuiteUserRoots{
			Config: filepath.Join(root, "config"), BrowserData: filepath.Join(root, "browser-data"),
			AgentState: filepath.Join(root, "agent-state"), Logs: filepath.Join(root, "logs"),
		}, nil
	case "linux":
		if !filepath.IsAbs(home) {
			return SuiteUserRoots{}, fmt.Errorf("%w: user home must be absolute", ErrFarmClientRoots)
		}
		configBase = suiteXDGBase(getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config"))
		dataBase = suiteXDGBase(getenv("XDG_DATA_HOME"), filepath.Join(home, ".local", "share"))
		stateBase = suiteXDGBase(getenv("XDG_STATE_HOME"), filepath.Join(home, ".local", "state"))
		logBase = stateBase
	case "darwin":
		if !filepath.IsAbs(home) {
			return SuiteUserRoots{}, fmt.Errorf("%w: user home must be absolute", ErrFarmClientRoots)
		}
		configBase = filepath.Join(home, "Library", "Application Support")
		dataBase, stateBase = configBase, configBase
		logBase = filepath.Join(home, "Library", "Logs")
	default:
		return SuiteUserRoots{}, fmt.Errorf("%w: unsupported OS", ErrFarmClientRoots)
	}
	for _, base := range []string{configBase, dataBase, stateBase, logBase} {
		if !filepath.IsAbs(base) {
			return SuiteUserRoots{}, fmt.Errorf("%w: suite user base must be absolute", ErrFarmClientRoots)
		}
	}
	return SuiteUserRoots{
		Config:      filepath.Join(configBase, "AntSuite", "config"),
		BrowserData: filepath.Join(dataBase, "AntSuite", "browser-data"),
		AgentState:  filepath.Join(stateBase, "AntSuite", "agent-state"),
		Logs:        filepath.Join(logBase, "AntSuite", "logs"),
	}, nil
}

func suiteXDGBase(override, fallback string) string {
	if strings.TrimSpace(override) == "" {
		return fallback
	}
	return strings.TrimSpace(override)
}
