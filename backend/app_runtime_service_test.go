package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/database"
	"ant-chrome/backend/internal/launchcode"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type appFacadeRuntimeChild struct {
	process  *BrowserRuntimeProcess
	owner    BrowserRuntimeProcessOwner
	server   *http.Server
	listener net.Listener
}

func TestAppRuntimeFacadeUsesSharedServiceAndLaunchServer(t *testing.T) {
	app := NewApp(t.TempDir())
	cfg := config.DefaultConfig()
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.DefaultStartURLs = []string{}
	cfg.Browser.StartReadyTimeoutMs = 2000
	cfg.Browser.StartStableWindowMs = 20
	coreRoot := t.TempDir()
	chromePath := filepath.Join(coreRoot, "chrome")
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "test-core", CoreName: "test", CorePath: coreRoot, IsDefault: true}}
	app.config = cfg

	db, err := database.NewDB(filepath.Join(t.TempDir(), "app.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := db.Migrate(); err != nil {
		t.Fatal(err)
	}
	manager := browser.NewManager(cfg, app.appRoot)
	manager.ProfileDAO = browser.NewSQLiteProfileDAO(db.GetConn())
	profile := &browser.Profile{
		ProfileId:          "profile-1",
		ProfileName:        "Profile 1",
		UserDataDir:        t.TempDir(),
		CoreId:             "test-core",
		ProxyConfig:        "direct://",
		RestoreLastSession: "never",
		CreatedAt:          time.Now().Format(time.RFC3339),
		UpdatedAt:          time.Now().Format(time.RFC3339),
	}
	manager.Profiles[profile.ProfileId] = profile
	if err := manager.ProfileDAO.Upsert(profile); err != nil {
		t.Fatal(err)
	}
	app.browserMgr = manager
	profileID := profile.ProfileId
	profileUserDataDir := profile.UserDataDir

	codeService := launchcode.NewLaunchCodeService(launchcode.NewMemoryLaunchCodeDAO())
	if err := codeService.LoadAll(); err != nil {
		t.Fatal(err)
	}
	app.launchCodeSvc = codeService
	manager.CodeProvider = codeService
	server := launchcode.NewLaunchServer(codeService, app, manager, 0)
	app.launchServer = server

	var startCalls atomic.Int32
	var stoppedEvents atomic.Int32
	var startedEvents atomic.Int32
	var cleanupCalls atomic.Int32
	var targetMu sync.Mutex
	var targets []string
	var childrenMu sync.Mutex
	var children []*appFacadeRuntimeChild

	service := app.newBrowserRuntimeService()
	host := app.newBrowserRuntimeHost()
	host.DetectRuntime = func(string) (BrowserRuntimeDetection, bool) {
		return BrowserRuntimeDetection{}, false
	}
	host.StartProcess = func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
		startCalls.Add(1)
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", plan.Spec.AssignedDebugPort))
		if err != nil {
			return nil, err
		}
		mux := http.NewServeMux()
		mux.HandleFunc("/json/version", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"Browser":"app-facade-test","webSocketDebuggerUrl":"ws://127.0.0.1/devtools"}`))
		})
		fixtureServer := &http.Server{Handler: mux}
		go func() { _ = fixtureServer.Serve(listener) }()

		cmd := exec.Command("/bin/sleep", "30")
		if err := cmd.Start(); err != nil {
			_ = fixtureServer.Close()
			return nil, err
		}
		owner, err := NewBrowserRuntimeCmdOwner(cmd)
		if err != nil {
			_ = cmd.Process.Kill()
			_ = fixtureServer.Close()
			return nil, err
		}
		child := &appFacadeRuntimeChild{owner: owner, server: fixtureServer, listener: listener}
		child.process, err = NewBrowserRuntimeProcess(cmd, owner, &runtimeStartTestMonitor{}, func() {
			cleanupCalls.Add(1)
			_ = fixtureServer.Close()
		})
		if err != nil {
			_ = cmd.Process.Kill()
			<-owner.Done()
			_ = fixtureServer.Close()
			return nil, err
		}
		childrenMu.Lock()
		children = append(children, child)
		childrenMu.Unlock()
		return child.process, nil
	}
	host.CreateTarget = func(_ int, target string) error {
		targetMu.Lock()
		targets = append(targets, target)
		targetMu.Unlock()
		return nil
	}
	host.EmitStarted = func(*browser.Profile, bool) { startedEvents.Add(1) }
	host.EmitStopped = func(string) { stoppedEvents.Add(1) }
	service.SetHost(host)
	app.runtimeService = service

	if service.Manager() != manager || service.Manager().ProfileDAO != manager.ProfileDAO {
		t.Fatal("App runtime service did not retain the exact Manager/DAO instances")
	}

	type startResult struct {
		profile *BrowserProfile
		err     error
	}
	startResults := make(chan startResult, 2)
	go func() {
		result, startErr := app.BrowserInstanceStart(profileID)
		startResults <- startResult{profile: result, err: startErr}
	}()
	go func() {
		result, startErr := app.BrowserInstanceStart(profileID)
		startResults <- startResult{profile: result, err: startErr}
	}()
	first := <-startResults
	second := <-startResults
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent BrowserInstanceStart errors = %v / %v", first.err, second.err)
	}
	started := first.profile
	if started == nil || second.profile == nil || started.Pid != second.profile.Pid || started.DebugPort != second.profile.DebugPort {
		t.Fatalf("concurrent BrowserInstanceStart results = %+v / %+v", started, second.profile)
	}
	if started == nil || !started.Running || !started.DebugReady || started.Pid <= 0 || started.DebugPort <= 0 {
		t.Fatalf("start result = %+v", started)
	}
	if startCalls.Load() != 1 {
		t.Fatalf("StartProcess calls = %d, want 1", startCalls.Load())
	}
	activeID, _, activePort := server.ActiveProfile()
	if activeID != profileID || activePort != started.DebugPort {
		t.Fatalf("LaunchServer active profile = %q/%d, want %q/%d", activeID, activePort, profileID, started.DebugPort)
	}

	status, err := app.BrowserInstanceStatus(profileID)
	if err != nil || status == nil || status.Pid != started.Pid || !status.Running || !status.DebugReady {
		t.Fatalf("BrowserInstanceStatus = %+v, err=%v", status, err)
	}
	if _, err := app.BrowserInstanceStartDirect(profileID); err != nil {
		t.Fatalf("BrowserInstanceStartDirect: %v", err)
	}
	if _, err := app.BrowserInstanceStartWithParams(profileID, []string{"--new-window"}, []string{"https://params.example"}, true); err != nil {
		t.Fatalf("BrowserInstanceStartWithParams: %v", err)
	}
	if _, err := app.StartInstanceWithParams(profileID, launchcode.LaunchRequestParams{StartURLs: []string{"https://launch.example"}, SkipDefaultStartURLs: true}); err != nil {
		t.Fatalf("StartInstanceWithParams: %v", err)
	}
	if startCalls.Load() != 1 {
		t.Fatalf("same-profile facade calls launched %d processes, want 1", startCalls.Load())
	}
	targetMu.Lock()
	gotTargets := append([]string(nil), targets...)
	targetMu.Unlock()
	if !containsString(gotTargets, "https://params.example") || !containsString(gotTargets, "https://launch.example") {
		t.Fatalf("one-shot targets = %v", gotTargets)
	}

	waited, ready, err := app.WaitInstanceDebugReady(profileID, started.DebugPort, 0)
	if err != nil || !ready || waited == nil || !waited.DebugReady {
		t.Fatalf("WaitInstanceDebugReady = %+v/%v, err=%v", waited, ready, err)
	}

	code, err := app.BrowserProfileGetCode(profileID)
	if err != nil || strings.TrimSpace(code) == "" {
		t.Fatalf("BrowserProfileGetCode = %q, err=%v", code, err)
	}
	launchResponse := httptest.NewRecorder()
	launchRequest := httptest.NewRequest(http.MethodGet, "/api/launch/"+code, nil)
	launchcode.NewTestHandler(server).ServeHTTP(launchResponse, launchRequest)
	if launchResponse.Code != http.StatusOK {
		t.Fatalf("LaunchServer launch status = %d, body=%s", launchResponse.Code, launchResponse.Body.String())
	}
	if startCalls.Load() != 1 {
		t.Fatalf("LaunchServer caller launched %d processes, want shared running process", startCalls.Load())
	}

	stopped, err := app.BrowserInstanceStop(profileID)
	if err != nil || stopped == nil || stopped.Running || stopped.DebugReady || stopped.Pid != 0 || stopped.DebugPort != 0 {
		t.Fatalf("BrowserInstanceStop = %+v, err=%v", stopped, err)
	}
	if stoppedEvents.Load() != 1 || cleanupCalls.Load() != 1 {
		t.Fatalf("first stop lifecycle = stopped:%d cleanup:%d", stoppedEvents.Load(), cleanupCalls.Load())
	}

	restarted, err := app.BrowserInstanceRestart(profileID)
	if err != nil || restarted == nil || !restarted.Running || !restarted.DebugReady {
		t.Fatalf("BrowserInstanceRestart = %+v, err=%v", restarted, err)
	}
	if startCalls.Load() != 2 || service.Generation(profileID) < 2 {
		t.Fatalf("restart lifecycle = starts:%d generation:%d", startCalls.Load(), service.Generation(profileID))
	}
	if _, err := app.BrowserInstanceStop(profileID); err != nil {
		t.Fatalf("final BrowserInstanceStop: %v", err)
	}
	if stoppedEvents.Load() != 2 || cleanupCalls.Load() != 2 {
		t.Fatalf("final stop lifecycle = stopped:%d cleanup:%d", stoppedEvents.Load(), cleanupCalls.Load())
	}

	if _, err := app.BrowserProfileUpdate(profileID, BrowserProfileInput{
		ProfileName: "Updated via shared DAO",
		UserDataDir: profileUserDataDir,
		CoreId:      "test-core",
		ProxyConfig: "direct://",
	}); err != nil {
		t.Fatalf("BrowserProfileUpdate: %v", err)
	}
	updated, err := app.BrowserInstanceStatus(profileID)
	if err != nil || updated == nil || updated.ProfileName != "Updated via shared DAO" {
		t.Fatalf("Status after shared DAO CRUD = %+v, err=%v", updated, err)
	}
	stored, err := manager.ProfileDAO.GetById(profileID)
	if err != nil || stored == nil || stored.ProfileName != "Updated via shared DAO" {
		t.Fatalf("shared DAO stored profile = %+v, err=%v", stored, err)
	}

	childrenMu.Lock()
	allChildren := append([]*appFacadeRuntimeChild(nil), children...)
	childrenMu.Unlock()
	for _, child := range allChildren {
		if child == nil || child.owner == nil {
			continue
		}
		select {
		case <-child.owner.Done():
		case <-time.After(time.Second):
			t.Fatal("facade child owner did not reap")
		}
	}
}

func TestAppRuntimeFacadeOneShotProxyOverridesRemainEphemeral(t *testing.T) {
	app := NewApp(t.TempDir())
	cfg := config.DefaultConfig()
	cfg.Browser.UserDataRoot = t.TempDir()
	cfg.Browser.DefaultStartURLs = []string{}
	cfg.Browser.StartReadyTimeoutMs = 2000
	cfg.Browser.StartStableWindowMs = 20
	coreRoot := t.TempDir()
	chromePath := filepath.Join(coreRoot, "chrome")
	if err := os.WriteFile(chromePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg.Browser.Cores = []browser.Core{{CoreId: "test-core", CoreName: "test", CorePath: coreRoot, IsDefault: true}}
	app.config = cfg
	manager := browser.NewManager(cfg, app.appRoot)
	profileID := "profile-proxy-override"
	persistentProxy := "socks5://127.0.0.1:1"
	manager.Profiles[profileID] = &browser.Profile{
		ProfileId:          profileID,
		ProfileName:        "Proxy override",
		UserDataDir:        t.TempDir(),
		CoreId:             "test-core",
		ProxyConfig:        persistentProxy,
		RestoreLastSession: "never",
		CreatedAt:          time.Now().Format(time.RFC3339),
		UpdatedAt:          time.Now().Format(time.RFC3339),
	}
	app.browserMgr = manager

	service := app.newBrowserRuntimeService()
	host := app.newBrowserRuntimeHost()
	host.DetectRuntime = func(string) (BrowserRuntimeDetection, bool) {
		return BrowserRuntimeDetection{}, false
	}
	var startCalls int
	var stoppedEvents int
	var effectiveProxies []string
	var children []*freshConcurrencyChild
	host.StartProcess = func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
		startCalls++
		effectiveProxies = append(effectiveProxies, plan.Spec.EffectiveProxy)
		child, err := newFreshConcurrencyChild(t, plan)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		return child.process, nil
	}
	host.EmitStopped = func(string) { stoppedEvents++ }
	service.SetHost(host)
	app.runtimeService = service
	defer func() { killFreshConcurrencyChildren(children) }()

	if _, err := app.BrowserInstanceStartDirect(profileID); err != nil {
		t.Fatalf("BrowserInstanceStartDirect: %v", err)
	}
	if got := effectiveProxies[len(effectiveProxies)-1]; got != "direct://" {
		t.Fatalf("direct effective proxy = %q, want direct://", got)
	}
	if _, err := app.BrowserInstanceStop(profileID); err != nil {
		t.Fatalf("stop after direct start: %v", err)
	}
	if got := manager.Profiles[profileID].ProxyConfig; got != persistentProxy {
		t.Fatalf("persistent proxy after direct start = %q, want %q", got, persistentProxy)
	}

	if _, err := app.StartInstanceWithParams(profileID, launchcode.LaunchRequestParams{
		ProxyConfig:          "direct://",
		SkipDefaultStartURLs: true,
	}); err != nil {
		t.Fatalf("StartInstanceWithParams temporary direct proxy: %v", err)
	}
	if got := effectiveProxies[len(effectiveProxies)-1]; got != "direct://" {
		t.Fatalf("temporary effective proxy = %q, want direct://", got)
	}
	if got := manager.Profiles[profileID].ProxyConfig; got != persistentProxy {
		t.Fatalf("persistent proxy after temporary override = %q, want %q", got, persistentProxy)
	}
	if _, err := app.BrowserInstanceStop(profileID); err != nil {
		t.Fatalf("stop after temporary proxy start: %v", err)
	}
	for _, child := range children {
		select {
		case <-child.cleanupDone:
		case <-time.After(time.Second):
			t.Fatal("one-shot proxy child cleanup did not complete")
		}
	}
	if startCalls != 2 || stoppedEvents != 2 || len(children) != 2 {
		t.Fatalf("one-shot proxy lifecycle = starts:%d stopped:%d children:%d", startCalls, stoppedEvents, len(children))
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
