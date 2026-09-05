package backend

import (
	"ant-chrome/backend/internal/browser"
	"fmt"
	"strings"
)

// BrowserRuntimeServiceFactoryConfig is the small, Wails-free construction
// boundary for external hosts such as a farm agent. The factory copies the
// config and profiles; callers do not receive the internal Manager or proxy
// managers and must not implement a second lifecycle.
type BrowserRuntimeServiceFactoryConfig struct {
	AppRoot  string
	Config   *Config
	Profiles []BrowserProfile
	Host     BrowserRuntimeHost
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
		Manager: manager,
		Config:  cfg,
		Host:    options.Host,
	}), nil
}
