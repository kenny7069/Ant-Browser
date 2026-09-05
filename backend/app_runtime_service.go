package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

// startupInitRuntimeService wires the Wails effects around the already-loaded
// application state. It must receive the existing Manager and connector
// managers; creating another Manager here would split profile/DAO state.
func (a *App) startupInitRuntimeService() {
	if a == nil || a.browserMgr == nil {
		return
	}
	a.runtimeServiceMu.Lock()
	defer a.runtimeServiceMu.Unlock()
	if a.runtimeService != nil {
		return
	}
	a.runtimeService = a.newBrowserRuntimeService()
}

func (a *App) browserRuntimeService() (*BrowserRuntimeService, error) {
	if a == nil {
		return nil, fmt.Errorf("browser runtime service is not initialized")
	}
	a.runtimeServiceMu.Lock()
	defer a.runtimeServiceMu.Unlock()
	if a.runtimeService == nil {
		if a.browserMgr == nil {
			return nil, fmt.Errorf("browser manager is not initialized")
		}
		a.runtimeService = a.newBrowserRuntimeService()
	}
	return a.runtimeService, nil
}

func (a *App) newBrowserRuntimeService() *BrowserRuntimeService {
	serviceConfig := BrowserRuntimeServiceConfig{
		Manager:               a.browserMgr,
		Config:                a.runtimeConfig(),
		XrayMgr:               a.xrayMgr,
		ClashMgr:              a.clashMgr,
		SingBoxMgr:            a.singboxMgr,
		Host:                  a.newBrowserRuntimeHost(),
		BookmarkList:          a.BookmarkList,
		FingerprintLaunchArgs: a.buildBrowserFingerprintLaunchArgs,
		RuntimeBookmarks:      a.runtimeBookmarksForProfileExpectedArgsAndProfile,
		ResolveStartURLs:      a.resolveFingerprintCheckStartURLsForExpectedArgsAndProfile,
	}
	return NewBrowserRuntimeService(serviceConfig)
}

func (a *App) runtimeConfig() *config.Config {
	if a != nil && a.config != nil {
		return a.config
	}
	if a != nil && a.browserMgr != nil && a.browserMgr.Config != nil {
		return a.browserMgr.Config
	}
	return config.DefaultConfig()
}

func (a *App) buildBrowserFingerprintLaunchArgs(profileID, coreID string, fingerprintArgs []string) []string {
	if a == nil {
		return nil
	}
	return a.buildBrowserFingerprintCapabilityReport(profileID, coreID, fingerprintArgs).LaunchArgs
}

// newBrowserRuntimeHost exposes only App-owned effects. The runtime service
// remains the sole owner of readiness, state transitions, process monitoring,
// generation, proxy bridge references and cleanup.
func (a *App) newBrowserRuntimeHost() BrowserRuntimeHost {
	return BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			if plan == nil {
				return nil, fmt.Errorf("browser runtime launch plan is nil")
			}
			return NewBrowserRuntimeLocalProcess(plan.Spec)
		},
		EnsureLaunchCode: func(profile *browser.Profile) {
			if a != nil {
				a.ensureProfileLaunchCode(profile)
			}
		},
		IsProfileLive: func(profile *browser.Profile, trackedCmd *exec.Cmd) bool {
			return isBrowserProfileLive(profile, trackedCmd)
		},
		ResolveUserDataDir: func(profile *browser.Profile) string {
			if a == nil || a.browserMgr == nil {
				return ""
			}
			return a.browserMgr.ResolveUserDataDir(profile)
		},
		DetectRuntime: func(userDataDir string) (BrowserRuntimeDetection, bool) {
			detection, ok := detectBrowserRuntimeByUserDataDir(userDataDir)
			return BrowserRuntimeDetection{
				PID:        detection.PID,
				DebugPort:  detection.DebugPort,
				DebugReady: detection.DebugReady,
			}, ok
		},
		FingerprintArgs: func(profile *browser.Profile) []string {
			if a == nil {
				return nil
			}
			return a.fingerprintCheckExpectedArgsFromProfile(profile)
		},
		ResolveTargetURL: func(profileID string, expectedArgs []string, profile *browser.Profile, targetURL string) string {
			if a == nil {
				return targetURL
			}
			return a.resolveFingerprintCheckStartURLForExpectedArgsAndProfile(profileID, expectedArgs, profile, targetURL)
		},
		NavigateTarget: func(debugPort int, targetURL string) error {
			return openBrowserStartTargets(debugPort, []string{targetURL})
		},
		CreateTarget: func(debugPort int, targetURL string) error {
			return createBrowserStartTarget(debugPort, targetURL)
		},
		OpenRunningWindow: func(profile *browser.Profile, extraArgs, startURLs []string) error {
			if a == nil {
				return fmt.Errorf("app host is nil")
			}
			return a.openBrowserWindowForRunningProfile(profile, extraArgs, startURLs)
		},
		TryCloseCDP: func(debugPort int, timeout time.Duration) bool {
			return tryCloseBrowserViaCDP(debugPort, timeout)
		},
		StopProcess: func(cmd *exec.Cmd) error {
			return stopBrowserProcessCommand(cmd)
		},
		CanConnect: func(debugPort int, timeout time.Duration) bool {
			return canConnectDebugPort(debugPort, timeout)
		},
		SetActiveProfile: func(profile *browser.Profile) {
			if a != nil && a.launchServer != nil {
				a.launchServer.SetActiveProfile(profile)
			}
		},
		ClearActiveProfile: func(profileID string, _ uint64) {
			if a != nil && a.launchServer != nil {
				a.launchServer.ClearActiveProfile(profileID)
			}
		},
		EmitStarted: func(profile *browser.Profile, reused bool) {
			if a != nil {
				a.emitBrowserInstanceStarted(profile, reused)
			}
		},
		EmitUpdated: func(profile *browser.Profile) {
			if a != nil {
				a.emitBrowserInstanceUpdated(profile)
			}
		},
		EmitStopped: func(profileID string) {
			if a == nil || a.ctx == nil {
				return
			}
			runtime.EventsEmit(a.ctx, "browser:instance:stopped", profileID)
		},
		EmitCrashed: func(profileID, profileName string, err error) {
			if a == nil || a.ctx == nil {
				return
			}
			errMsg := ""
			if err != nil {
				errMsg = err.Error()
			}
			runtime.EventsEmit(a.ctx, "browser:instance:crashed", map[string]interface{}{
				"profileId":   profileID,
				"profileName": profileName,
				"error":       errMsg,
			})
		},
		GetTabs: func(profileID string) []browser.Tab {
			if a == nil {
				return nil
			}
			return a.BrowserInstanceGetTabs(profileID)
		},
	}
}

func (a *App) emitBrowserInstanceStopped(profileID string) {
	if a == nil || a.ctx == nil {
		return
	}
	runtime.EventsEmit(a.ctx, "browser:instance:stopped", strings.TrimSpace(profileID))
}

// WaitDebugReady is the service-owned readiness façade used by LaunchServer.
// The service's asynchronous monitor remains authoritative; this method only
// observes/commits a matching ready endpoint for a bounded caller wait.
func (s *BrowserRuntimeService) WaitDebugReady(profileID string, debugPort int, timeout time.Duration) (*browser.Profile, bool, error) {
	profileID = strings.TrimSpace(profileID)
	if s == nil {
		return nil, false, fmt.Errorf("browser runtime service is nil")
	}
	if profileID == "" {
		return nil, false, fmt.Errorf("profile id is required")
	}
	if timeout <= 0 {
		profile, err := s.Status(profileID)
		if err != nil {
			return nil, false, err
		}
		return profile, profile != nil && profile.DebugReady && (debugPort <= 0 || profile.DebugPort == debugPort), nil
	}
	deadline := time.Now().Add(timeout)
	for {
		profile, err := s.Status(profileID)
		if err != nil {
			return nil, false, err
		}
		if profile != nil && profile.Running && profile.DebugReady && (debugPort <= 0 || profile.DebugPort == debugPort) {
			return profile, true, nil
		}
		port := debugPort
		if port <= 0 && profile != nil {
			port = profile.DebugPort
		}
		if port > 0 && probeBrowserDebugPort(port, browserDebugProbeTimeout) == nil {
			if snapshot, changed := s.markDebugReady(profileID, port); snapshot != nil {
				if changed {
					s.mu.RLock()
					host := s.host
					s.mu.RUnlock()
					if host.SetActiveProfile != nil {
						host.SetActiveProfile(snapshot)
					}
					if host.EmitUpdated != nil {
						host.EmitUpdated(snapshot)
					}
				}
				return snapshot, snapshot.DebugReady, nil
			}
		}
		if time.Now().After(deadline) {
			return profile, profile != nil && profile.DebugReady, nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func (s *BrowserRuntimeService) markDebugReady(profileID string, debugPort int) (*browser.Profile, bool) {
	manager := s.Manager()
	if manager == nil {
		return nil, false
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil || !profile.Running || profile.DebugPort != debugPort {
		manager.Mutex.Unlock()
		return nil, false
	}
	changed := !profile.DebugReady || profile.RuntimeWarning != ""
	profile.DebugReady = true
	profile.RuntimeWarning = ""
	profile.LastError = ""
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	return snapshot, changed
}
