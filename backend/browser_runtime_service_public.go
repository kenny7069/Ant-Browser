package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/proxy"
	"fmt"
	"path/filepath"
	"strings"
)

// BrowserRuntimeServiceFactoryConfig is the small, Wails-free construction
// boundary for external hosts such as a farm agent. The factory copies the
// config and profiles; callers do not receive the internal Manager or proxy
// managers and must not implement a second lifecycle.
type BrowserRuntimeServiceFactoryConfig struct {
	AppRoot               string
	Config                *Config
	Profiles              []BrowserProfile
	Host                  BrowserRuntimeHost
	InitializedManager    *browser.Manager
	FingerprintLaunchArgs func(string, string, []string) []string
}

// NewBrowserRuntimeServiceForHost constructs the shared runtime service from
// public backend types. Process ownership, readiness monitoring, state and
// cleanup remain inside BrowserRuntimeService.
func NewBrowserRuntimeServiceForHost(options BrowserRuntimeServiceFactoryConfig) (*BrowserRuntimeService, error) {
	appRoot := strings.TrimSpace(options.AppRoot)
	if appRoot == "" {
		return nil, fmt.Errorf("browser runtime app root is required")
	}
	if options.Host.StartProcess == nil {
		return nil, fmt.Errorf("browser runtime host start capability is required")
	}
	if options.Host.StopProcess == nil {
		return nil, fmt.Errorf("browser runtime host stop capability is required")
	}
	if options.InitializedManager != nil {
		if options.Config != nil || options.Profiles != nil {
			return nil, fmt.Errorf("browser runtime initialized manager conflicts with config/profiles")
		}
		manager := options.InitializedManager
		if strings.TrimSpace(manager.AppRoot) == "" {
			return nil, fmt.Errorf("browser runtime initialized manager app root is required")
		}
		if filepath.Clean(manager.AppRoot) != filepath.Clean(appRoot) {
			return nil, fmt.Errorf("browser runtime initialized manager app root mismatch")
		}
		manager.Mutex.Lock()
		for profileID, profile := range manager.Profiles {
			if strings.TrimSpace(profileID) == "" || profile == nil || strings.TrimSpace(profile.ProfileId) == "" || strings.TrimSpace(profileID) != strings.TrimSpace(profile.ProfileId) {
				manager.Mutex.Unlock()
				return nil, fmt.Errorf("browser runtime profile id is required")
			}
		}
		manager.Mutex.Unlock()
		if manager.Config == nil {
			return nil, fmt.Errorf("browser runtime initialized manager config is required")
		}
		return NewBrowserRuntimeService(BrowserRuntimeServiceConfig{
			Manager: manager, Config: manager.Config,
			XrayMgr:    proxy.NewXrayManager(manager.Config, appRoot),
			ClashMgr:   proxy.NewClashManager(manager.Config, appRoot),
			SingBoxMgr: proxy.NewSingBoxManager(manager.Config, appRoot),
			Host:       options.Host, FingerprintLaunchArgs: options.FingerprintLaunchArgs,
			OwnsConnectorManagers: true,
		}), nil
	}

	var cfg *Config
	if options.Config == nil {
		cfg = DefaultConfig()
	} else {
		cfgCopy := *options.Config
		cfg = &cfgCopy
	}
	manager := browser.NewManager(cfg, appRoot)
	for _, profile := range options.Profiles {
		profileID := strings.TrimSpace(profile.ProfileId)
		if profileID == "" {
			return nil, fmt.Errorf("browser runtime profile id is required")
		}
		if _, exists := manager.Profiles[profileID]; exists {
			return nil, fmt.Errorf("browser runtime profile %q is duplicated", profileID)
		}
		profile.ProfileId = profileID
		manager.Profiles[profileID] = copyBrowserProfileSnapshot(&profile)
	}

	return NewBrowserRuntimeService(BrowserRuntimeServiceConfig{
		Manager:               manager,
		Config:                cfg,
		XrayMgr:               proxy.NewXrayManager(cfg, appRoot),
		ClashMgr:              proxy.NewClashManager(cfg, appRoot),
		SingBoxMgr:            proxy.NewSingBoxManager(cfg, appRoot),
		Host:                  options.Host,
		FingerprintLaunchArgs: options.FingerprintLaunchArgs,
		OwnsConnectorManagers: true,
	}), nil
}
