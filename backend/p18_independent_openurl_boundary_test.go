package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"testing"
)

// OpenUrl's stale-runtime branch is a lifecycle transition. It must clear the
// same generation-owned state as BrowserRuntimeService.Stop rather than only
// mutating the shared Manager and the App's legacy adjunct maps.
func TestP18IndependentOpenURLStaleRuntimeClearsServiceGenerationOwnership(t *testing.T) {
	app := NewApp(t.TempDir())
	cfg := config.DefaultConfig()
	cfg.Browser.UserDataRoot = t.TempDir()
	manager := browser.NewManager(cfg, app.appRoot)
	profile := &browser.Profile{
		ProfileId:          "profile-open-url",
		ProfileName:        "Open URL",
		UserDataDir:        t.TempDir(),
		RestoreLastSession: "never",
	}
	manager.Profiles[profile.ProfileId] = profile
	app.config = cfg
	app.browserMgr = manager
	service := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: manager, Config: cfg})
	app.runtimeService = service

	_, cmd := newCompletedRuntimeProcess(t, nil)
	identity := service.markRunning(profile.ProfileId, profile, cmd, cmd.Process.Pid, 65530, true, "")
	service.storeDeferredTargets(profile.ProfileId, identity, []string{"https://deferred.example"}, true)
	service.proxyMu.Lock()
	service.proxyRefs[profile.ProfileId] = browserRuntimeProxyRef{
		generation: identity.generation,
		ref:        newProfileProxyBridgeRef(profileProxyBridgeEngineXray, "stale-proxy"),
	}
	service.proxyMu.Unlock()

	if opened, err := app.BrowserInstanceOpenUrl(profile.ProfileId, "https://target.example"); err == nil || opened {
		t.Fatalf("OpenUrl stale runtime = opened:%v err:%v, want fail-closed", opened, err)
	}
	manager.Mutex.Lock()
	current := copyBrowserProfileSnapshot(manager.Profiles[profile.ProfileId])
	manager.Mutex.Unlock()
	if current.Running {
		t.Fatalf("stale profile remained running: %+v", current)
	}
	if got := service.Generation(profile.ProfileId); got != 0 {
		t.Fatalf("OpenUrl stale transition left service generation %d active", got)
	}
	service.deferredMu.Lock()
	_, deferredExists := service.deferred[profile.ProfileId]
	service.deferredMu.Unlock()
	service.proxyMu.Lock()
	_, proxyExists := service.proxyRefs[profile.ProfileId]
	service.proxyMu.Unlock()
	if deferredExists || proxyExists {
		t.Fatalf("OpenUrl stale transition leaked service adjuncts: deferred=%v proxy=%v", deferredExists, proxyExists)
	}
}
