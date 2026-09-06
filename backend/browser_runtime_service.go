package backend

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/config"
	"ant-chrome/backend/internal/logger"
	"ant-chrome/backend/internal/proxy"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// BrowserRuntimeStartOptions contains one-shot launch overrides. It has no
// Wails dependency so the lifecycle core can be reused by a farm agent.
type BrowserRuntimeStartOptions struct {
	ExtraLaunchArgs      []string
	StartURLs            []string
	SkipDefaultStartURLs bool
	PreferVisibleWindow  bool
	ForceDirectProxy     bool
	ProxyID              string
	ProxyConfig          string
}

// BrowserRuntimeStartRequest is the normalized request passed to host-side
// launch preparation and process creation.
type BrowserRuntimeStartRequest struct {
	ProfileID string
	Options   BrowserRuntimeStartOptions
}

// BrowserRuntimeDetection is the host-neutral result needed to adopt an
// already-running browser found in a profile's user-data directory.
type BrowserRuntimeDetection struct {
	PID        int
	DebugPort  int
	DebugReady bool
}

// BrowserRuntimeLaunchSpec is the immutable, host-facing portion of a launch
// plan. It contains no live Manager or App pointer.
type BrowserRuntimeLaunchSpec struct {
	ProfileID            string
	ChromeBinaryPath     string
	UserDataDir          string
	Args                 []string
	DeferredStartTargets []string
	DeferredStartNewTabs bool
	EffectiveProxy       string
	AssignedDebugPort    int
	StartReadyTimeout    time.Duration
	StartStableWindow    time.Duration
	MaxStartAttempts     int
	TotalReadyTimeout    time.Duration
	MemoryLimitMB        int
}

// BrowserRuntimeProcessOwner is the single owner of the underlying Cmd.Wait.
// Done closes only after the process has been reaped. Result must return
// immediately after Done closes and must never call Cmd.Wait itself.
type BrowserRuntimeProcessOwner interface {
	Done() <-chan struct{}
	Result() error
}

// BrowserRuntimeProcessMonitor is the readiness-only monitor contract. It is
// deliberately separate from process ownership; the service never calls a
// monitor's Wait method during teardown.
type BrowserRuntimeProcessMonitor interface {
	HasExited() bool
}

type browserProcessMonitorAPI interface {
	HasExited() bool
	Result() browserProcessExitResult
	DebugPort() (int, bool)
	SetDebugPort(int)
}

// BrowserRuntimeHost contains only process/CDP/storage side effects. It does
// not expose complete lifecycle operations; those algorithms are implemented
// by BrowserRuntimeService. It also has no Wails context requirement.
type BrowserRuntimeHost struct {
	StartProcess       func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error)
	EnsureLaunchCode   func(*browser.Profile)
	IsProfileLive      func(*browser.Profile, *exec.Cmd) bool
	ResolveUserDataDir func(*browser.Profile) string
	DetectRuntime      func(string) (BrowserRuntimeDetection, bool)
	FingerprintArgs    func(*browser.Profile) []string
	ResolveTargetURL   func(string, []string, *browser.Profile, string) string
	NavigateTarget     func(int, string) error
	CreateTarget       func(int, string) error
	OpenRunningWindow  func(*browser.Profile, []string, []string) error
	TryCloseCDP        func(int, time.Duration) bool
	StopProcess        func(*exec.Cmd) error
	CanConnect         func(int, time.Duration) bool
	SetActiveProfile   func(*browser.Profile)
	ClearActiveProfile func(string, uint64)
	EmitStarted        func(*browser.Profile, bool)
	EmitUpdated        func(*browser.Profile)
	EmitStopped        func(string)
	EmitCrashed        func(string, string, error)
	GetTabs            func(string) []browser.Tab
}

// BrowserRuntimeLaunchPlan contains host-prepared launch inputs. The service
// owns all orchestration after preparation; a host must not start, monitor, or
// mark a runtime from its preparation callback.
type BrowserRuntimeLaunchPlan struct {
	Spec                 BrowserRuntimeLaunchSpec
	profile              *BrowserProfile
	chromeBinaryPath     string
	userDataDir          string
	args                 []string
	extensionDirs        []string
	deferredStartTargets []string
	deferredStartNewTabs bool
	effectiveProxy       string
	acquiredProxyBridge  profileProxyBridgeRef
	releaseProxyBridge   bool
	assignedDebugPort    int
	startReadyTimeout    time.Duration
	startStableWindow    time.Duration
	maxStartAttempts     int
	totalReadyTimeout    time.Duration
}

// Keep existing package helpers and focused tests source-compatible while the
// concrete plan becomes part of the host-neutral lifecycle contract.
type browserStartPlan = BrowserRuntimeLaunchPlan

// BrowserRuntimeProcess is the opaque process handle returned by a host.
// StartProcess must not make readiness/state/event decisions. Hosts must use
// NewBrowserRuntimeProcess so the service can enforce a single reaping owner.
type BrowserRuntimeProcess struct {
	cmd         *exec.Cmd
	monitor     browserProcessMonitorAPI
	owner       BrowserRuntimeProcessOwner
	cleanupFn   func()
	cleanupOnce sync.Once
}

var (
	ErrInvalidBrowserRuntimeProcess     = errors.New("invalid browser runtime process")
	ErrBrowserRuntimeOwnerNotReady      = errors.New("browser runtime process owner is not ready")
	ErrBrowserRuntimeReapPending        = errors.New("browser runtime process reaping is pending")
	ErrBrowserRuntimeGenerationMismatch = errors.New("browser runtime generation mismatch")
)

// NewBrowserRuntimeProcess constructs a valid host-facing process result. The
// owner must already own the command's sole Wait operation. A nil/zero Cmd is
// rejected so an untracked process cannot enter the service lifecycle.
func NewBrowserRuntimeProcess(cmd *exec.Cmd, owner BrowserRuntimeProcessOwner, monitor BrowserRuntimeProcessMonitor, cleanup func()) (*BrowserRuntimeProcess, error) {
	if cmd == nil || cmd.Process == nil {
		return nil, fmt.Errorf("%w: command is not started", ErrInvalidBrowserRuntimeProcess)
	}
	if isNilBrowserRuntimeOwner(owner) {
		return nil, fmt.Errorf("%w: process owner is required", ErrInvalidBrowserRuntimeProcess)
	}
	if owner.Done() == nil {
		return nil, fmt.Errorf("%w: process owner Done channel is nil", ErrInvalidBrowserRuntimeProcess)
	}
	process := &BrowserRuntimeProcess{cmd: cmd, owner: owner, cleanupFn: cleanup}
	if monitor != nil {
		process.monitor = browserRuntimeMonitorAdapter{monitor: monitor, owner: owner}
	}
	return process, nil
}

func (p *BrowserRuntimeProcess) cleanup() {
	if p == nil || p.cleanupFn == nil {
		return
	}
	p.cleanupOnce.Do(p.cleanupFn)
}

// adoptCleanup transfers a cleanup action to the process owner. It is called
// before the service starts any monitor, so the wrapper is immutable while
// cleanup may later run asynchronously.
func (p *BrowserRuntimeProcess) adoptCleanup(cleanup func()) {
	if p == nil || cleanup == nil {
		return
	}
	existing := p.cleanupFn
	p.cleanupFn = func() {
		if existing != nil {
			existing()
		}
		cleanup()
	}
}

func isNilBrowserRuntimeOwner(owner BrowserRuntimeProcessOwner) bool {
	if owner == nil {
		return true
	}
	value := reflect.ValueOf(owner)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

type browserRuntimeCmdOwner struct {
	done chan struct{}
	mu   sync.Mutex
	err  error
}

func (o *browserRuntimeCmdOwner) Done() <-chan struct{} { return o.done }

func (o *browserRuntimeCmdOwner) Result() error {
	if o == nil || o.done == nil {
		return ErrBrowserRuntimeOwnerNotReady
	}
	select {
	case <-o.done:
		o.mu.Lock()
		err := o.err
		o.mu.Unlock()
		return err
	default:
		return ErrBrowserRuntimeOwnerNotReady
	}
}

// NewBrowserRuntimeCmdOwner starts the one and only Cmd.Wait owner for a
// host-created child. Hosts must pass the returned owner to
// NewBrowserRuntimeProcess and must not call Cmd.Wait themselves.
func NewBrowserRuntimeCmdOwner(cmd *exec.Cmd) (BrowserRuntimeProcessOwner, error) {
	if cmd == nil || cmd.Process == nil {
		return nil, fmt.Errorf("%w: command is not started", ErrInvalidBrowserRuntimeProcess)
	}
	owner := &browserRuntimeCmdOwner{done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		owner.mu.Lock()
		owner.err = err
		owner.mu.Unlock()
		close(owner.done)
	}()
	return owner, nil
}

type browserRuntimeMonitorAdapter struct {
	monitor BrowserRuntimeProcessMonitor
	owner   BrowserRuntimeProcessOwner
}

func (m browserRuntimeMonitorAdapter) HasExited() bool {
	return m.monitor.HasExited() && browserRuntimeDone(m.owner.Done())
}
func (m browserRuntimeMonitorAdapter) DebugPort() (int, bool) {
	if monitor, ok := m.monitor.(interface{ DebugPort() (int, bool) }); ok {
		return monitor.DebugPort()
	}
	return 0, false
}
func (m browserRuntimeMonitorAdapter) SetDebugPort(port int) {
	if monitor, ok := m.monitor.(interface{ SetDebugPort(int) }); ok {
		monitor.SetDebugPort(port)
	}
}
func (m browserRuntimeMonitorAdapter) Result() browserProcessExitResult {
	if monitor, ok := m.monitor.(interface {
		Result() browserProcessExitResult
	}); ok {
		return monitor.Result()
	}
	if m.owner == nil {
		return browserProcessExitResult{Err: ErrInvalidBrowserRuntimeProcess}
	}
	return browserProcessExitResult{Err: m.owner.Result()}
}

type browserRuntimeIdentity struct {
	generation uint64
	pid        int
	debugPort  int
	cmd        *exec.Cmd
}

type BrowserRuntimeServiceConfig struct {
	Manager               *browser.Manager
	Config                *config.Config
	XrayMgr               *proxy.XrayManager
	ClashMgr              *proxy.ClashManager
	SingBoxMgr            *proxy.SingBoxManager
	Host                  BrowserRuntimeHost
	BookmarkList          func() []BrowserBookmark
	FingerprintLaunchArgs func(string, string, []string) []string
	RuntimeBookmarks      func(string, []string, *BrowserProfile, []BrowserBookmark) ([]BrowserBookmark, string, error)
	ResolveStartURLs      func(string, []string, *BrowserProfile, []string) []string
}

type browserRuntimeProfileGate struct {
	mu   sync.Mutex
	refs int
}

type browserRuntimeDeferredTargets struct {
	generation uint64
	plan       deferredStartTargetsPlan
}

type browserRuntimeProxyRef struct {
	generation uint64
	ref        profileProxyBridgeRef
}

type browserRuntimePendingReap struct {
	process *BrowserRuntimeProcess
	plan    *BrowserRuntimeLaunchPlan
	profile string
}

// BrowserRuntimeService is the single lifecycle owner. Manager remains the
// sole source of profile/process state; the service adds operation gates.
type BrowserRuntimeService struct {
	mu                    sync.RWMutex
	manager               *browser.Manager
	config                *config.Config
	xrayMgr               *proxy.XrayManager
	clashMgr              *proxy.ClashManager
	singboxMgr            *proxy.SingBoxManager
	host                  BrowserRuntimeHost
	bookmarkList          func() []BrowserBookmark
	fingerprintLaunchArgs func(string, string, []string) []string
	runtimeBookmarks      func(string, []string, *BrowserProfile, []BrowserBookmark) ([]BrowserBookmark, string, error)
	resolveStartURLs      func(string, []string, *BrowserProfile, []string) []string

	gatesMu sync.Mutex
	gates   map[string]*browserRuntimeProfileGate

	identityMu sync.Mutex
	nextGen    map[string]uint64
	active     map[string]browserRuntimeIdentity

	deferredMu sync.Mutex
	deferred   map[string]browserRuntimeDeferredTargets
	proxyMu    sync.Mutex
	proxyRefs  map[string]browserRuntimeProxyRef

	pendingMu sync.Mutex
	pending   map[*BrowserRuntimeProcess]browserRuntimePendingReap
	processMu sync.Mutex
	processes map[string]*BrowserRuntimeProcess

	// These seams are intentionally unexported. Production keeps the original
	// 15-second attach grace and 500ms detached probe interval; package tests
	// can drive the real monitor lifecycle without fixed long sleeps.
	waitRuntimeDebugAttach     func(func(int, time.Duration) bool, int, time.Duration) bool
	waitRuntimeDebugDisconnect func(func(int, time.Duration) bool, int) bool
}

// BrowserRuntimeServiceSnapshot is a read-only observation of the shared
// lifecycle service. Unlike Status, RuntimeSnapshot never performs recovered
// runtime detection or adoption; callers that need strict ownership (for
// example FarmRuntimeService) can therefore observe a stopped/crashed
// generation without accidentally adopting an unrelated local Chrome.
type BrowserRuntimeServiceSnapshot struct {
	Profile    *browser.Profile
	Generation uint64
}

// NewBrowserRuntimeService supports zero-value construction for focused tests
// and config-based startup wiring.
func NewBrowserRuntimeService(config ...BrowserRuntimeServiceConfig) *BrowserRuntimeService {
	var cfg BrowserRuntimeServiceConfig
	if len(config) > 0 {
		cfg = config[0]
	}
	return &BrowserRuntimeService{
		manager:               cfg.Manager,
		config:                cfg.Config,
		xrayMgr:               cfg.XrayMgr,
		clashMgr:              cfg.ClashMgr,
		singboxMgr:            cfg.SingBoxMgr,
		host:                  cfg.Host,
		bookmarkList:          cfg.BookmarkList,
		fingerprintLaunchArgs: cfg.FingerprintLaunchArgs,
		runtimeBookmarks:      cfg.RuntimeBookmarks,
		resolveStartURLs:      cfg.ResolveStartURLs,
		gates:                 make(map[string]*browserRuntimeProfileGate),
		nextGen:               make(map[string]uint64),
		active:                make(map[string]browserRuntimeIdentity),
		deferred:              make(map[string]browserRuntimeDeferredTargets),
		proxyRefs:             make(map[string]browserRuntimeProxyRef),
		pending:               make(map[*BrowserRuntimeProcess]browserRuntimePendingReap),
		processes:             make(map[string]*BrowserRuntimeProcess),
	}
}

func (s *BrowserRuntimeService) SetManager(manager *browser.Manager) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.manager = manager
	s.mu.Unlock()
}

func (s *BrowserRuntimeService) Manager() *browser.Manager {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.manager
}

func (s *BrowserRuntimeService) SetHost(host BrowserRuntimeHost) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.host = host
	s.mu.Unlock()
}

func (s *BrowserRuntimeService) trackProcess(profileID string, process *BrowserRuntimeProcess) {
	if s == nil || process == nil || strings.TrimSpace(profileID) == "" {
		return
	}
	profileID = strings.TrimSpace(profileID)
	s.processMu.Lock()
	if s.processes == nil {
		s.processes = make(map[string]*BrowserRuntimeProcess)
	}
	s.processes[profileID] = process
	s.processMu.Unlock()
	process.adoptCleanup(func() { s.untrackProcess(profileID, process) })
}

func (s *BrowserRuntimeService) untrackProcess(profileID string, process *BrowserRuntimeProcess) {
	if s == nil || process == nil {
		return
	}
	s.processMu.Lock()
	if current := s.processes[profileID]; current == process {
		delete(s.processes, profileID)
	}
	s.processMu.Unlock()
}

func (s *BrowserRuntimeService) processFor(profileID string) *BrowserRuntimeProcess {
	if s == nil {
		return nil
	}
	s.processMu.Lock()
	process := s.processes[profileID]
	s.processMu.Unlock()
	return process
}

func (s *BrowserRuntimeService) bookmarkSnapshot() []BrowserBookmark {
	if s.bookmarkList == nil {
		return nil
	}
	return append([]BrowserBookmark(nil), s.bookmarkList()...)
}

func (s *BrowserRuntimeService) detectRuntime(userDataDir string) (BrowserRuntimeDetection, bool) {
	s.mu.RLock()
	detector := s.host.DetectRuntime
	s.mu.RUnlock()
	if detector != nil {
		return detector(userDataDir)
	}
	detection, ok := detectBrowserRuntimeByActivePort(userDataDir)
	return BrowserRuntimeDetection{PID: detection.PID, DebugPort: detection.DebugPort, DebugReady: detection.DebugReady}, ok
}

func (s *BrowserRuntimeService) prepareStart(request BrowserRuntimeStartRequest, profile *BrowserProfile) (*BrowserRuntimeLaunchPlan, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile not found")
	}
	input := browserStartInput{
		ProfileID:            strings.TrimSpace(request.ProfileID),
		ExtraLaunchArgs:      normalizeNonEmptyStrings(request.Options.ExtraLaunchArgs),
		StartURLs:            normalizeNonEmptyStrings(request.Options.StartURLs),
		SkipDefaultStartURLs: request.Options.SkipDefaultStartURLs,
		PreferVisibleWindow:  request.Options.PreferVisibleWindow,
		ForceDirectProxy:     request.Options.ForceDirectProxy,
		TemporaryProxyID:     strings.TrimSpace(request.Options.ProxyID),
		TemporaryProxyConfig: strings.TrimSpace(request.Options.ProxyConfig),
	}
	bookmarks := s.bookmarkSnapshot()
	sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs, fingerprintLaunchArgs, chromeBinaryPath, userDataDir, err := s.prepareLaunchContext(input, profile, bookmarks)
	if err != nil {
		return nil, err
	}

	effectiveProxy, acquiredProxyBridge, releaseProxyBridge, err := s.resolveStartProxy(input, profile)
	if err != nil {
		return nil, err
	}

	startReadyTimeout, startStableWindow := s.startTimingSettings()
	maxStartAttempts := browserStartAttemptCount()
	totalReadyTimeout := time.Duration(maxStartAttempts) * startReadyTimeout
	restoreLastSession := profileRestoreLastSession(profile, s.config)
	manager := s.Manager()
	manager.Mutex.Lock()
	extensionDirs := manager.EnabledExtensionDirsForProfile(input.ProfileID)
	manager.Mutex.Unlock()
	fingerprintExpectedArgs := combineFingerprintExpectedArgs(fingerprintLaunchArgs, sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs)
	defaultStartURLs := mergeStartURLs(browserDefaultStartURLs(s.config), bookmarkStartURLs(bookmarks))
	startURLs := input.StartURLs
	if s.resolveStartURLs != nil {
		defaultStartURLs = s.resolveStartURLs(profile.ProfileId, fingerprintExpectedArgs, profile, defaultStartURLs)
		startURLs = s.resolveStartURLs(profile.ProfileId, fingerprintExpectedArgs, profile, startURLs)
	}
	launchTargets, deferredStartTargets, deferredStartNewTabs := buildBrowserLaunchTargets(
		startURLs,
		defaultStartURLs,
		input.SkipDefaultStartURLs,
		restoreLastSession,
		browserLightStartEnabled(s.config),
	)

	assignedDebugPort, err := nextAvailablePort()
	if err != nil {
		startErr := fmt.Errorf("实例启动失败：本地调试端口分配失败。原因：%v。请关闭占用端口的程序后重试。", err)
		profile.LastError = startErr.Error()
		return nil, startErr
	}
	plan := &BrowserRuntimeLaunchPlan{
		Spec: BrowserRuntimeLaunchSpec{
			ProfileID:            profile.ProfileId,
			ChromeBinaryPath:     chromeBinaryPath,
			UserDataDir:          userDataDir,
			Args:                 append([]string(nil), buildBrowserLaunchArgs(userDataDir, assignedDebugPort, effectiveProxy, extensionDirs, fingerprintLaunchArgs, sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs, launchTargets, restoreLastSession)...),
			DeferredStartTargets: append([]string(nil), deferredStartTargets...),
			DeferredStartNewTabs: deferredStartNewTabs,
			EffectiveProxy:       effectiveProxy,
			AssignedDebugPort:    assignedDebugPort,
			StartReadyTimeout:    startReadyTimeout,
			StartStableWindow:    startStableWindow,
			MaxStartAttempts:     maxStartAttempts,
			TotalReadyTimeout:    totalReadyTimeout,
			MemoryLimitMB:        profile.MemoryLimitMB,
		},
		profile:              profile,
		chromeBinaryPath:     chromeBinaryPath,
		userDataDir:          userDataDir,
		extensionDirs:        extensionDirs,
		args:                 buildBrowserLaunchArgs(userDataDir, assignedDebugPort, effectiveProxy, extensionDirs, fingerprintLaunchArgs, sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs, launchTargets, restoreLastSession),
		deferredStartTargets: deferredStartTargets,
		deferredStartNewTabs: deferredStartNewTabs,
		effectiveProxy:       effectiveProxy,
		acquiredProxyBridge:  acquiredProxyBridge,
		releaseProxyBridge:   releaseProxyBridge,
		assignedDebugPort:    assignedDebugPort,
		startReadyTimeout:    startReadyTimeout,
		startStableWindow:    startStableWindow,
		maxStartAttempts:     maxStartAttempts,
		totalReadyTimeout:    totalReadyTimeout,
	}
	return plan, nil
}

func (s *BrowserRuntimeService) startTimingSettings() (time.Duration, time.Duration) {
	return time.Duration(browserStartReadyTimeoutMillis(s.config)) * time.Millisecond,
		time.Duration(browserStartStableWindowMillis(s.config)) * time.Millisecond
}

func (s *BrowserRuntimeService) prepareLaunchContext(input browserStartInput, profile *BrowserProfile, bookmarks []BrowserBookmark) ([]string, []string, []string, string, string, error) {
	log := logger.New("Browser")
	sanitizedProfileLaunchArgs, managedProfileArgs := sanitizeManagedLaunchArgs(profile.LaunchArgs)
	sanitizedExtraLaunchArgs, managedExtraArgs := sanitizeManagedLaunchArgs(input.ExtraLaunchArgs)
	logManagedLaunchArgOverrides(log, input.ProfileID, "profile.launchArgs", managedProfileArgs)
	logManagedLaunchArgOverrides(log, input.ProfileID, "start.extraLaunchArgs", managedExtraArgs)

	manager := s.Manager()
	manager.Mutex.Lock()
	manager.ApplyDefaults(profile)
	chromeBinaryPath, err := manager.ResolveChromeBinary(profile)
	userDataDir := manager.ResolveUserDataDir(profile)
	manager.Mutex.Unlock()
	if err != nil {
		startErr := fmt.Errorf("实例启动失败：%w", err)
		profile.LastError = startErr.Error()
		return nil, nil, nil, "", "", startErr
	}
	if err := os.MkdirAll(userDataDir, 0o755); err != nil {
		startErr := fmt.Errorf("实例启动失败：无法创建用户数据目录 %s。原因：%w。请检查目录权限或路径配置。", userDataDir, err)
		profile.LastError = startErr.Error()
		return nil, nil, nil, "", "", startErr
	}
	fingerprintLaunchArgs := []string(nil)
	if s.fingerprintLaunchArgs != nil {
		fingerprintLaunchArgs = s.fingerprintLaunchArgs(input.ProfileID, profile.CoreId, profile.FingerprintArgs)
	}
	fingerprintExpectedArgs := combineFingerprintExpectedArgs(fingerprintLaunchArgs, sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs)
	runtimeBookmarks := bookmarks
	fingerprintBookmarkURL := ""
	if s.runtimeBookmarks != nil {
		runtimeBookmarks, fingerprintBookmarkURL, err = s.runtimeBookmarks(profile.ProfileId, fingerprintExpectedArgs, profile, bookmarks)
		if err != nil {
			log.Warn("指纹检测书签生成失败", logger.F("profile_id", input.ProfileID), logger.F("error", err.Error()))
			runtimeBookmarks = bookmarks
		}
	}
	if fingerprintBookmarkURL != "" {
		if _, err := browser.ReplaceBookmarkURL(userDataDir, fingerprintCheckBookmarkURL, fingerprintBookmarkURL); err != nil {
			log.Warn("旧指纹检测书签更新失败", logger.F("profile_id", input.ProfileID), logger.F("error", err.Error()))
		}
	}
	if err := browser.EnsureDefaultBookmarks(userDataDir, runtimeBookmarks); err != nil {
		log.Warn("默认书签写入失败", logger.F("error", err.Error()))
	}
	if err := writeBrowserLanguagePreferences(userDataDir, fingerprintLaunchArgs); err != nil {
		log.Warn("浏览器语言偏好写入失败", logger.F("profile_id", input.ProfileID), logger.F("error", err.Error()))
	}
	if detection, ok := s.detectRuntime(userDataDir); ok && detection.DebugReady {
		profile.LastLaunchArgs = nil
		profile.Running = true
		profile.DebugReady = true
		profile.Pid = detection.PID
		profile.DebugPort = detection.DebugPort
		profile.RuntimeWarning = ""
		profile.LastError = ""
		return nil, nil, nil, "", "", errBrowserStartHandledByRecoveredRuntime
	}
	if !profileRestoreLastSession(profile, s.config) {
		if err := clearBrowserSessionRestoreData(userDataDir); err != nil {
			if terminated, terminateErr := terminateBrowserProcessesByUserDataDir(userDataDir, 5*time.Second); terminateErr == nil && terminated {
				if retryErr := clearBrowserSessionRestoreData(userDataDir); retryErr == nil {
					return sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs, fingerprintLaunchArgs, chromeBinaryPath, userDataDir, nil
				} else {
					err = retryErr
				}
			}
			sessionDir := filepath.Join(userDataDir, "Default", "Sessions")
			startErr := fmt.Errorf("实例启动失败：无法清理上次会话缓存 %s。原因：%w。请关闭占用该目录的浏览器进程后重试。", sessionDir, err)
			profile.LastError = startErr.Error()
			return nil, nil, nil, "", "", startErr
		}
	}
	return sanitizedProfileLaunchArgs, sanitizedExtraLaunchArgs, fingerprintLaunchArgs, chromeBinaryPath, userDataDir, nil
}

func (s *BrowserRuntimeService) expectedArgs(profile *BrowserProfile) []string {
	if profile == nil {
		return nil
	}
	if args := normalizeNonEmptyStrings(profile.LastLaunchArgs); len(args) > 0 {
		return args
	}
	if s.fingerprintLaunchArgs == nil {
		return normalizeNonEmptyStrings(profile.LaunchArgs)
	}
	return combineFingerprintExpectedArgs(s.fingerprintLaunchArgs(profile.ProfileId, profile.CoreId, profile.FingerprintArgs), profile.LaunchArgs)
}

func (s *BrowserRuntimeService) openRunningProfileForPrepare(profile *BrowserProfile, targets, extraArgs []string) error {
	if profile.DebugReady && profile.DebugPort > 0 {
		for _, target := range normalizeNonEmptyStrings(targets) {
			if err := createBrowserStartTarget(profile.DebugPort, target); err != nil {
				return err
			}
		}
		return nil
	}
	return nil
}

func (s *BrowserRuntimeService) latestProxies() []BrowserProxy {
	manager := s.Manager()
	if manager == nil {
		return nil
	}
	var configured []BrowserProxy
	if s.config != nil {
		configured = s.config.Browser.Proxies
	}
	return browser.LatestProxiesWithFallback(manager.ProxyDAO, configured)
}

func (s *BrowserRuntimeService) resolveStartProxy(input browserStartInput, profile *BrowserProfile) (string, profileProxyBridgeRef, bool, error) {
	proxies := s.latestProxies()
	if input.ForceDirectProxy {
		return "direct://", profileProxyBridgeRef{}, false, nil
	}
	resolvedProxyID := strings.TrimSpace(profile.ProxyId)
	resolvedProxyConfig := strings.TrimSpace(profile.ProxyConfig)
	if input.hasTemporaryProxy() {
		var err error
		resolvedProxyID, resolvedProxyConfig, err = resolveTemporaryBrowserStartProxy(input.TemporaryProxyID, input.TemporaryProxyConfig, proxies)
		if err != nil {
			profile.LastError = fmt.Errorf("实例启动失败：%s", err.Error()).Error()
			return "", profileProxyBridgeRef{}, false, fmt.Errorf("实例启动失败：%s", err.Error())
		}
	} else if resolvedProxyID != "" {
		for _, item := range proxies {
			if strings.EqualFold(item.ProxyId, resolvedProxyID) {
				resolvedProxyID = strings.TrimSpace(item.ProxyId)
				resolvedProxyConfig = strings.TrimSpace(item.ProxyConfig)
				break
			}
		}
	}
	if supported, errorMsg := proxy.ValidateProxyConfig(resolvedProxyConfig, proxies, resolvedProxyID); !supported {
		startErr := fmt.Errorf("实例启动失败：%s", errorMsg)
		profile.LastError = startErr.Error()
		return "", profileProxyBridgeRef{}, false, startErr
	}
	connectorType := config.BrowserConnectorXray
	if s.config != nil {
		connectorType = config.NormalizeBrowserConnectorType(s.config.Browser.DefaultConnectorType)
	}
	resolution, err := proxy.ResolveProxyKernelForConnector(resolvedProxyConfig, proxies, resolvedProxyID, connectorType)
	if err != nil {
		startErr := fmt.Errorf("实例启动失败：%s", err.Error())
		profile.LastError = startErr.Error()
		return "", profileProxyBridgeRef{}, false, startErr
	}
	switch resolution.Kernel {
	case proxy.ProxyKernelMihomo:
		if s.clashMgr == nil {
			startErr := fmt.Errorf("实例启动失败：mihomo 管理器未初始化，无法启动该协议代理。请先下载 Mihomo 内核。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		proxyURL, bridgeKey, bridgeErr := s.clashMgr.AcquireNodeBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			startErr := fmt.Errorf("实例启动失败：mihomo 代理桥接失败：%v", bridgeErr)
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return proxyURL, newProfileProxyBridgeRef(profileProxyBridgeEngineMihomo, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelSingBox:
		if s.singboxMgr == nil {
			startErr := fmt.Errorf("实例启动失败：sing-box 管理器未初始化，无法启动该协议代理。请检查 sing-box 内核配置。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		socksURL, bridgeKey, bridgeErr := s.singboxMgr.AcquireBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			startErr := fmt.Errorf("实例启动失败：sing-box 代理桥接失败：%v", bridgeErr)
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return socksURL, newProfileProxyBridgeRef(profileProxyBridgeEngineSingBox, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelXray:
		if s.xrayMgr == nil {
			startErr := fmt.Errorf("实例启动失败：xray 管理器未初始化，无法启动该协议代理。")
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		socksURL, bridgeKey, bridgeErr := s.xrayMgr.AcquireBridge(resolvedProxyConfig, proxies, resolvedProxyID)
		if bridgeErr != nil {
			startErr := fmt.Errorf("实例启动失败：Xray 代理桥接失败：%v", bridgeErr)
			profile.LastError = startErr.Error()
			return "", profileProxyBridgeRef{}, false, startErr
		}
		return socksURL, newProfileProxyBridgeRef(profileProxyBridgeEngineXray, bridgeKey), bridgeKey != "", nil
	case proxy.ProxyKernelNative:
		return resolvedProxyConfig, profileProxyBridgeRef{}, false, nil
	default:
		startErr := fmt.Errorf("实例启动失败：无法为协议 %s 选择代理内核", resolution.Protocol)
		profile.LastError = startErr.Error()
		return "", profileProxyBridgeRef{}, false, startErr
	}
}

func (s *BrowserRuntimeService) releaseProxyBridge(ref profileProxyBridgeRef) {
	if !ref.valid() {
		return
	}
	switch ref.Engine {
	case profileProxyBridgeEngineXray:
		if s.xrayMgr != nil {
			s.xrayMgr.ReleaseBridge(ref.Key)
		}
	case profileProxyBridgeEngineSingBox:
		if s.singboxMgr != nil {
			s.singboxMgr.ReleaseBridge(ref.Key)
		}
	case profileProxyBridgeEngineMihomo:
		if s.clashMgr != nil {
			s.clashMgr.ReleaseNodeBridge(ref.Key)
		}
	}
}

func (s *BrowserRuntimeService) releaseStartPlan(plan *BrowserRuntimeLaunchPlan) {
	if plan == nil || !plan.releaseProxyBridge {
		return
	}
	s.releaseProxyBridge(plan.acquiredProxyBridge)
}

func (s *BrowserRuntimeService) bindProxy(profileID string, identity browserRuntimeIdentity, ref profileProxyBridgeRef) {
	if strings.TrimSpace(profileID) == "" || identity.generation == 0 || !ref.valid() {
		return
	}
	s.proxyMu.Lock()
	if previous := s.proxyRefs[profileID]; previous.ref.valid() {
		s.releaseProxyBridge(previous.ref)
	}
	s.proxyRefs[profileID] = browserRuntimeProxyRef{generation: identity.generation, ref: ref}
	s.proxyMu.Unlock()
}

func (s *BrowserRuntimeService) releaseProfileProxy(profileID string, generation uint64) {
	s.proxyMu.Lock()
	entry := s.proxyRefs[profileID]
	if generation == 0 || entry.generation != generation {
		s.proxyMu.Unlock()
		return
	}
	delete(s.proxyRefs, profileID)
	s.proxyMu.Unlock()
	s.releaseProxyBridge(entry.ref)
}

func (s *BrowserRuntimeService) hostSnapshot() (BrowserRuntimeHost, error) {
	if s == nil {
		return BrowserRuntimeHost{}, fmt.Errorf("browser runtime service is nil")
	}
	s.mu.RLock()
	host := s.host
	s.mu.RUnlock()
	if host.StartProcess == nil {
		return BrowserRuntimeHost{}, fmt.Errorf("browser runtime host is not configured")
	}
	if host.StopProcess == nil {
		return BrowserRuntimeHost{}, fmt.Errorf("browser runtime host has no stop capability")
	}
	return host, nil
}

func (s *BrowserRuntimeService) hasPendingReap(profileID string) bool {
	if s == nil {
		return false
	}
	s.pendingMu.Lock()
	defer s.pendingMu.Unlock()
	for _, pending := range s.pending {
		if pending.profile == profileID {
			return true
		}
	}
	return false
}

func (s *BrowserRuntimeService) registerPendingReap(process *BrowserRuntimeProcess, plan *BrowserRuntimeLaunchPlan) {
	if s == nil || process == nil || process.owner == nil || process.owner.Done() == nil {
		return
	}
	profileID := ""
	if plan != nil {
		profileID = plan.Spec.ProfileID
	}
	s.pendingMu.Lock()
	if s.pending == nil {
		s.pending = make(map[*BrowserRuntimeProcess]browserRuntimePendingReap)
	}
	if _, exists := s.pending[process]; exists {
		s.pendingMu.Unlock()
		return
	}
	s.pending[process] = browserRuntimePendingReap{process: process, plan: plan, profile: profileID}
	s.pendingMu.Unlock()

	go func() {
		<-process.owner.Done()
		// Result is a non-blocking read after Done by contract. This is the
		// only completion observer; it never calls Cmd.Wait.
		_ = process.owner.Result()
		process.cleanup()
		s.pendingMu.Lock()
		delete(s.pending, process)
		s.pendingMu.Unlock()
	}()
}

// Shutdown requests termination of every process whose owner has not yet
// reached Done. A process that still cannot be observed is retained in the
// pending registry; its owner completion callback will eventually release its
// process and launch-plan/proxy resources exactly once.
func (s *BrowserRuntimeService) Shutdown() error {
	if s == nil {
		return nil
	}
	host, err := s.hostSnapshot()
	if err != nil {
		return err
	}
	s.pendingMu.Lock()
	entries := make([]browserRuntimePendingReap, 0, len(s.pending))
	for _, pending := range s.pending {
		entries = append(entries, pending)
	}
	s.pendingMu.Unlock()
	var errs []error
	for _, pending := range entries {
		if err := s.stopAndCleanupBrowserRuntimeProcess(host, pending.process, pending.plan); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *BrowserRuntimeService) acquire(profileID string) (func(), error) {
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	if s == nil {
		return nil, fmt.Errorf("browser runtime service is nil")
	}
	s.gatesMu.Lock()
	if s.gates == nil {
		s.gates = make(map[string]*browserRuntimeProfileGate)
	}
	gate := s.gates[profileID]
	if gate == nil {
		gate = &browserRuntimeProfileGate{}
		s.gates[profileID] = gate
	}
	gate.refs++
	s.gatesMu.Unlock()

	gate.mu.Lock()
	var once sync.Once
	return func() {
		once.Do(func() {
			gate.mu.Unlock()
			s.gatesMu.Lock()
			gate.refs--
			if gate.refs == 0 && s.gates[profileID] == gate {
				delete(s.gates, profileID)
			}
			s.gatesMu.Unlock()
		})
	}, nil
}

func (s *BrowserRuntimeService) withProfileResult(profileID string, fn func(BrowserRuntimeHost) (*browser.Profile, error)) (*browser.Profile, error) {
	host, err := s.hostSnapshot()
	if err != nil {
		return nil, err
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return nil, err
	}
	defer release()
	return fn(host)
}

func (s *BrowserRuntimeService) withProfile(profileID string, fn func(BrowserRuntimeHost) error) error {
	host, err := s.hostSnapshot()
	if err != nil {
		return err
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return err
	}
	defer release()
	return fn(host)
}

// Start is the canonical lifecycle entrypoint for a browser profile.
func (s *BrowserRuntimeService) Start(profileID string) (*browser.Profile, error) {
	return s.StartWithOptions(profileID, BrowserRuntimeStartOptions{})
}

func (s *BrowserRuntimeService) StartWithOptions(profileID string, options BrowserRuntimeStartOptions) (*browser.Profile, error) {
	profileID = strings.TrimSpace(profileID)
	return s.withProfileResult(profileID, func(host BrowserRuntimeHost) (*browser.Profile, error) {
		return s.startLocked(host, BrowserRuntimeStartRequest{ProfileID: profileID, Options: cloneBrowserRuntimeStartOptions(options)})
	})
}

// Status returns an immutable profile snapshot owned by the service. When a
// profile is not marked running, it performs the same explicit-profile
// recovery that the application facade historically performed: detect a
// ready browser for this profile's user-data directory and adopt it. The
// potentially slow detection runs outside Manager.Mutex; the final adoption
// is protected by both the profile pointer incarnation and the value snapshot
// captured before detection. Status never starts a process, stops another
// profile, or emits a duplicate started event.
func (s *BrowserRuntimeService) Status(profileID string) (*browser.Profile, error) {
	profileID = strings.TrimSpace(profileID)
	if s == nil {
		return nil, fmt.Errorf("browser runtime service is nil")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return nil, err
	}
	defer release()

	s.mu.RLock()
	host := s.host
	s.mu.RUnlock()
	return s.statusLocked(host, profileID)
}

// statusLocked is called while the profile gate is held. It deliberately
// does not hold Manager.Mutex across host callbacks or runtime detection.
func (s *BrowserRuntimeService) statusLocked(host BrowserRuntimeHost, profileID string) (*browser.Profile, error) {
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}

	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("profile not found")
	}
	incarnation := profile
	revision := copyBrowserProfileSnapshot(profile)
	snapshot := copyBrowserProfileSnapshot(profile)
	trackedCmd := manager.BrowserProcesses[profileID]
	manager.Mutex.Unlock()

	// EnsureLaunchCode only receives a detached snapshot, so a host cannot
	// retain or mutate Manager state while the lock is released.
	if host.EnsureLaunchCode != nil {
		host.EnsureLaunchCode(snapshot)
	}

	if snapshot.Running {
		if !reflect.DeepEqual(*snapshot, *revision) && !s.commitProfileSnapshot(profileID, revision, snapshot, incarnation) {
			return s.profileSnapshot(profileID)
		}
		// A profile loaded as already-running may not have an in-memory
		// identity yet. Establish it once without emitting a start event.
		if current := s.identity(profileID); current.generation == 0 {
			s.ensureIdentity(profileID, snapshot.Pid, snapshot.DebugPort, trackedCmd)
		}
		return s.profileSnapshot(profileID)
	}

	userDataDir := ""
	if host.ResolveUserDataDir != nil {
		userDataDir = host.ResolveUserDataDir(snapshot)
	} else {
		userDataDir = manager.ResolveUserDataDir(snapshot)
	}
	detection, ok := s.detectRuntime(userDataDir)
	if !ok || !detection.DebugReady {
		// Persist only host changes made to the detached snapshot (normally the
		// launch code). A concurrent Manager.Update/delete-recreate invalidates
		// this write and its result is simply the current profile state.
		if !reflect.DeepEqual(*snapshot, *revision) && !s.commitProfileSnapshot(profileID, revision, snapshot, incarnation) {
			return s.profileSnapshot(profileID)
		}
		return s.profileSnapshot(profileID)
	}

	snapshot.Running = true
	snapshot.DebugReady = true
	snapshot.Pid = detection.PID
	snapshot.DebugPort = detection.DebugPort
	snapshot.RuntimeWarning = ""
	snapshot.LastError = ""
	identity, adopted := s.adoptDetectedRuntime(profileID, revision, snapshot, incarnation)
	if !adopted {
		return s.profileSnapshot(profileID)
	}

	// Match BrowserInstanceStatus: adoption makes this runtime active but is
	// a read/status operation, so it does not emit browser:instance:started.
	if host.SetActiveProfile != nil && identity.generation != 0 {
		if current, err := s.profileSnapshot(profileID); err == nil {
			host.SetActiveProfile(current)
		}
	}
	return s.profileSnapshot(profileID)
}

// Generation returns the current opaque runtime generation for a profile.
// Zero means that this service has not adopted or launched a runtime yet.
func (s *BrowserRuntimeService) Generation(profileID string) uint64 {
	return s.identity(strings.TrimSpace(profileID)).generation
}

// RuntimeSnapshot returns the current profile state and service generation
// without launching, detecting, adopting, or stopping a runtime. The profile
// is copied before it is returned. A zero generation means this service has no
// active runtime identity for the profile.
func (s *BrowserRuntimeService) RuntimeSnapshot(profileID string) (*BrowserRuntimeServiceSnapshot, error) {
	profileID = strings.TrimSpace(profileID)
	if s == nil {
		return nil, fmt.Errorf("browser runtime service is nil")
	}
	if profileID == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}
	release, err := s.acquire(profileID)
	if err != nil {
		return nil, err
	}
	defer release()
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("profile not found")
	}
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	return &BrowserRuntimeServiceSnapshot{
		Profile:    snapshot,
		Generation: s.Generation(profileID),
	}, nil
}

// Stop terminates a service-owned process and transitions its profile only
// after the explicit process owner reaches Done. Recovered runtimes require a
// host TryCloseCDP callback because the service has no process handle to kill.
func (s *BrowserRuntimeService) Stop(profileID string) (*browser.Profile, error) {
	profileID = strings.TrimSpace(profileID)
	return s.withProfileResult(profileID, func(host BrowserRuntimeHost) (*browser.Profile, error) {
		return s.stopLocked(host, profileID)
	})
}

// StopIfGeneration is the strict stop boundary for ownership layers. The
// generation check runs after this service's per-profile gate is acquired, so
// a Farm stop cannot validate an old generation and then terminate a newer
// runtime that won the same-profile race in between.
func (s *BrowserRuntimeService) StopIfGeneration(profileID string, generation uint64) (*browser.Profile, error) {
	profileID = strings.TrimSpace(profileID)
	if generation == 0 {
		return nil, fmt.Errorf("%w: generation is required", ErrBrowserRuntimeGenerationMismatch)
	}
	return s.withProfileResult(profileID, func(host BrowserRuntimeHost) (*browser.Profile, error) {
		if current := s.Generation(profileID); current != generation {
			profile, err := s.currentProfileSnapshotResult(profileID, nil)
			return profile, errors.Join(err, fmt.Errorf("%w: expected %d, current %d", ErrBrowserRuntimeGenerationMismatch, generation, current))
		}
		return s.stopLocked(host, profileID)
	})
}

func (s *BrowserRuntimeService) stopLocked(host BrowserRuntimeHost, profileID string) (*browser.Profile, error) {
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("profile not found")
	}
	running := profile.Running
	debugPort := profile.DebugPort
	manager.Mutex.Unlock()
	process := s.processFor(profileID)
	if process == nil && !running {
		// Status acquires the same per-profile gate and may perform recovery;
		// stopLocked already holds that gate, so use the non-reentrant snapshot
		// helper here to avoid turning a no-op stop into a deadlock.
		return s.currentProfileSnapshotResult(profileID, profile)
	}

	var stopErr error
	if process != nil {
		stopErr = s.stopAndCleanupBrowserRuntimeProcess(host, process, nil)
		if errors.Is(stopErr, ErrBrowserRuntimeReapPending) {
			return s.currentProfileSnapshot(profileID, profile), stopErr
		}
	} else if debugPort > 0 {
		if host.TryCloseCDP == nil {
			return s.currentProfileSnapshot(profileID, profile), fmt.Errorf("browser runtime stop unavailable: recovered runtime has no process owner")
		}
		if !host.TryCloseCDP(debugPort, 5*time.Second) {
			return s.currentProfileSnapshot(profileID, profile), fmt.Errorf("browser runtime stop failed: recovered debug endpoint %d remains active", debugPort)
		}
	}

	identity := s.identity(profileID)
	var expected *browserRuntimeIdentity
	if identity.generation != 0 {
		expected = &identity
	}
	snapshot, stopped := s.stopState(host, profileID, expected)
	if stopped && host.EmitStopped != nil {
		host.EmitStopped(profileID)
	}
	if snapshot == nil {
		snapshot = s.currentProfileSnapshot(profileID, profile)
	}
	return snapshot, stopErr
}

func (s *BrowserRuntimeService) startLocked(host BrowserRuntimeHost, request BrowserRuntimeStartRequest) (*browser.Profile, error) {
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}
	profileID := strings.TrimSpace(request.ProfileID)
	if profileID == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	if s.hasPendingReap(profileID) {
		return nil, fmt.Errorf("实例启动失败：上一次浏览器进程仍在回收中，请稍后重试")
	}
	manager.Mutex.Lock()
	liveProfile := manager.Profiles[profileID]
	if liveProfile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("实例启动失败：未找到实例配置（ID=%s）。请刷新列表后重试。", profileID)
	}
	profileIncarnation := liveProfile
	profile := copyBrowserProfileSnapshot(liveProfile)
	// Keep a value snapshot for the compare-and-swap below. Manager.Update
	// mutates the map entry in place, so comparing the entry pointer would not
	// detect an update that races with launch preparation.
	profileRevision := copyBrowserProfileSnapshot(profile)
	if host.EnsureLaunchCode != nil {
		host.EnsureLaunchCode(profile)
	}
	trackedCmd := manager.BrowserProcesses[profileID]
	running := profile.Running
	manager.Mutex.Unlock()
	if !s.commitProfileSnapshot(profileID, profileRevision, profile, profileIncarnation) {
		return s.currentProfileSnapshot(profileID, profile), fmt.Errorf("实例启动失败：实例配置在启动准备期间发生变化，请重试。")
	}

	if running {
		live := host.IsProfileLive == nil || host.IsProfileLive(profile, trackedCmd)
		if live {
			s.ensureIdentity(profileID, profile.Pid, profile.DebugPort, trackedCmd)
			if len(normalizeNonEmptyStrings(request.Options.StartURLs)) == 0 && len(normalizeNonEmptyStrings(request.Options.ExtraLaunchArgs)) == 0 {
				if host.SetActiveProfile != nil && profile.DebugReady {
					host.SetActiveProfile(profile)
				}
				if host.EmitStarted != nil {
					host.EmitStarted(profile, true)
				}
				return profile, nil
			}
			if err := s.openRunningProfile(host, profileID, profile, request.Options.ExtraLaunchArgs, request.Options.StartURLs); err != nil {
				startErr := fmt.Errorf("实例已在运行，但新标签打开失败：%w", err)
				manager.Mutex.Lock()
				if current := manager.Profiles[profileID]; current != nil {
					current.LastError = startErr.Error()
					profile = current
				}
				manager.Mutex.Unlock()
				return profile, startErr
			}
			if host.SetActiveProfile != nil && profile.DebugReady {
				host.SetActiveProfile(profile)
			}
			if host.EmitStarted != nil {
				host.EmitStarted(profile, true)
			}
			return profile, nil
		}
		s.stopState(host, profileID, nil)
	}

	manager.Mutex.Lock()
	liveProfile = manager.Profiles[profileID]
	if liveProfile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("实例启动失败：实例配置已被删除")
	}
	prepareIncarnation := liveProfile
	profile = copyBrowserProfileSnapshot(liveProfile)
	prepareRevision := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	plan, err := s.prepareStart(request, profile)
	committed := s.commitProfileSnapshot(profileID, prepareRevision, profile, prepareIncarnation)
	if !committed {
		if plan != nil {
			s.releaseStartPlan(plan)
		}
		return s.currentProfileSnapshot(profileID, profile), fmt.Errorf("实例启动失败：实例配置在启动准备期间发生变化，请重试。")
	}
	if err == errBrowserStartHandledByRecoveredRuntime {
		identity := s.markRunning(profileID, profile, nil, profile.Pid, profile.DebugPort, true, "")
		manager.Mutex.Lock()
		if current := manager.Profiles[profileID]; current != nil && s.identityMatches(profileID, identity) {
			profile = copyBrowserProfileSnapshot(current)
		}
		manager.Mutex.Unlock()
		if len(request.Options.StartURLs) > 0 || len(request.Options.ExtraLaunchArgs) > 0 {
			if err := s.openRunningProfile(host, profileID, profile, request.Options.ExtraLaunchArgs, request.Options.StartURLs); err != nil {
				startErr := fmt.Errorf("实例已在运行，但新标签打开失败：%w", err)
				manager.Mutex.Lock()
				if current := manager.Profiles[profileID]; current != nil && s.identityMatches(profileID, identity) {
					current.LastError = startErr.Error()
					profile = copyBrowserProfileSnapshot(current)
				}
				manager.Mutex.Unlock()
				return profile, startErr
			}
		}
		if host.SetActiveProfile != nil {
			host.SetActiveProfile(profile)
		}
		if host.EmitStarted != nil {
			manager.Mutex.Lock()
			profile = copyBrowserProfileSnapshot(manager.Profiles[profileID])
			manager.Mutex.Unlock()
			host.EmitStarted(profile, true)
		}
		return profile, nil
	}
	if err != nil {
		return profile, err
	}
	if plan == nil {
		return profile, fmt.Errorf("实例启动失败：启动计划为空")
	}
	var processOwnsPlan atomic.Bool
	defer func() {
		if !processOwnsPlan.Load() {
			s.releaseStartPlan(plan)
		}
	}()

	process, err := host.StartProcess(plan)
	if err != nil {
		if process != nil && process.cmd != nil && process.owner != nil && process.owner.Done() != nil {
			// A host may return a started process together with an error after a
			// bounded local-factory cleanup attempt. Transfer plan ownership before
			// retaining or reaping the opaque handle; otherwise the proxy lease can
			// be released while its child is still pending.
			processOwnsPlan.Store(true)
			process.adoptCleanup(func() { s.releaseStartPlan(plan) })
			if errors.Is(err, ErrBrowserRuntimeReapPending) {
				s.registerPendingReap(process, plan)
			} else if teardownErr := s.stopAndCleanupBrowserRuntimeProcess(host, process, plan); teardownErr != nil {
				err = errors.Join(err, teardownErr)
			}
		}
		manager.Mutex.Lock()
		if current := manager.Profiles[profileID]; current != nil {
			current.LastError = err.Error()
			profile = current
		}
		manager.Mutex.Unlock()
		return profile, err
	}
	if process != nil && process.cmd != nil && process.owner != nil && process.owner.Done() != nil {
		processOwnsPlan.Store(true)
		process.adoptCleanup(func() { s.releaseStartPlan(plan) })
	}
	if process == nil || process.cmd == nil || process.owner == nil || process.monitor == nil {
		invalidHandleErr := fmt.Errorf("实例启动失败：浏览器进程句柄无效")
		if process != nil {
			if teardownErr := s.stopAndCleanupBrowserRuntimeProcess(host, process, plan); teardownErr != nil {
				invalidHandleErr = errors.Join(invalidHandleErr, teardownErr)
			}
		}
		return profile, invalidHandleErr
	}
	s.trackProcess(profileID, process)
	processOwned := true
	defer func() {
		if processOwned {
			process.cleanup()
		}
	}()

	attempts := plan.maxStartAttempts
	if attempts <= 0 {
		attempts = 1
	}
	var lastStartErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		stablePort, readyErr := waitBrowserDebugPortStable(plan.assignedDebugPort, plan.userDataDir, plan.startReadyTimeout, plan.startStableWindow, process.monitor)
		if readyErr == nil {
			identity := s.markRunning(profileID, profile, process.cmd, process.cmd.Process.Pid, stablePort, true, "")
			if plan.acquiredProxyBridge.valid() {
				s.bindProxy(profileID, identity, plan.acquiredProxyBridge)
				plan.releaseProxyBridge = false
			}
			if err := s.openDeferredTargets(host, stablePort, plan.deferredStartTargets, plan.deferredStartNewTabs); err != nil {
				s.setRuntimeWarning(profileID, identity, deferredStartTargetsWarning(plan.deferredStartTargets, err))
			}
			profile = s.currentProfileSnapshot(profileID, profile)
			if host.SetActiveProfile != nil && profile.DebugReady {
				host.SetActiveProfile(profile)
			}
			if host.EmitStarted != nil {
				host.EmitStarted(profile, false)
			}
			s.monitorProcess(host, profileID, process, identity)
			processOwned = false
			return profile, nil
		}
		lastStartErr = fmt.Errorf("%s", describeBrowserReadyFailure(plan.chromeBinaryPath, plan.assignedDebugPort, plan.totalReadyTimeout, readyErr))
		if attempt < attempts && shouldRetryBrowserReadyFailure(readyErr) {
			continue
		}
		break
	}

	if shouldKeepBrowserRunningPendingDebugReady(plan.assignedDebugPort, process.monitor) {
		warning := browserDebugPendingWarning(plan.totalReadyTimeout)
		pendingNotice := browserDebugPendingStartNotice(plan.totalReadyTimeout)
		identity := s.markRunning(profileID, profile, process.cmd, process.cmd.Process.Pid, plan.assignedDebugPort, false, warning)
		if len(plan.deferredStartTargets) > 0 {
			s.storeDeferredTargets(profileID, identity, plan.deferredStartTargets, plan.deferredStartNewTabs)
		}
		if plan.acquiredProxyBridge.valid() {
			s.bindProxy(profileID, identity, plan.acquiredProxyBridge)
			plan.releaseProxyBridge = false
		}
		profile = s.currentProfileSnapshot(profileID, profile)
		if host.EmitStarted != nil {
			host.EmitStarted(profile, false)
		}
		s.monitorProcess(host, profileID, process, identity)
		processOwned = false
		go s.waitDebugReadyAsync(host, profileID, plan.assignedDebugPort, identity, browserAsyncDebugAttachTimeout)
		manager.Mutex.Lock()
		if current := manager.Profiles[profileID]; current != nil {
			current.LastError = pendingNotice
			profile = current
		}
		manager.Mutex.Unlock()
		return profile, fmt.Errorf("%s", pendingNotice)
	}

	if lastStartErr == nil {
		lastStartErr = fmt.Errorf("实例启动失败：浏览器在等待窗口内仍未就绪")
	}
	teardownErr := s.stopAndCleanupBrowserRuntimeProcess(host, process, plan)
	processOwned = false
	if teardownErr != nil {
		lastStartErr = errors.Join(lastStartErr, teardownErr)
	}
	s.clearDeferredTargets(profileID, s.identity(profileID).generation)
	manager.Mutex.Lock()
	if current := manager.Profiles[profileID]; current != nil {
		current.LastError = lastStartErr.Error()
		profile = current
	}
	manager.Mutex.Unlock()
	return profile, lastStartErr
}

const browserRuntimeProcessReapTimeout = 5 * time.Second

func (s *BrowserRuntimeService) stopAndCleanupBrowserRuntimeProcess(host BrowserRuntimeHost, process *BrowserRuntimeProcess, plan *BrowserRuntimeLaunchPlan) error {
	return stopAndCleanupBrowserRuntimeProcessWithPending(host, process, func() {
		if s != nil {
			s.registerPendingReap(process, plan)
		}
	})
}

// stopAndCleanupBrowserRuntimeProcess is retained for focused package tests.
// Production Start always uses the service method so a timed-out owner is
// retained by the pending registry.
func stopAndCleanupBrowserRuntimeProcess(host BrowserRuntimeHost, process *BrowserRuntimeProcess) error {
	return stopAndCleanupBrowserRuntimeProcessWithPending(host, process, nil)
}

func stopAndCleanupBrowserRuntimeProcessWithPending(host BrowserRuntimeHost, process *BrowserRuntimeProcess, pending func()) error {
	if process == nil {
		return nil
	}
	if process.cmd == nil || process.cmd.Process == nil || process.owner == nil || process.owner.Done() == nil {
		return ErrInvalidBrowserRuntimeProcess
	}

	var errs []error
	ownerDone := process.owner.Done()
	shouldStop := !browserRuntimeDone(ownerDone)
	if shouldStop && host.StopProcess != nil {
		if err := host.StopProcess(process.cmd); err != nil {
			errs = append(errs, fmt.Errorf("browser process stop failed: %w", err))
			if killErr := process.cmd.Process.Kill(); killErr != nil && !isProcessAlreadyFinished(killErr) {
				errs = append(errs, fmt.Errorf("browser process fallback kill failed: %w", killErr))
			}
		}
	}

	deadline := time.Now().Add(browserRuntimeProcessReapTimeout)
	remaining := time.Until(deadline)
	if remaining < 0 {
		remaining = 0
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ownerDone:
		// The owner result is observed only after Done. A non-zero exit is
		// expected after an explicit stop/kill and is reported by the original
		// StopProcess error when one exists; it is not a second teardown fault.
		_ = process.owner.Result()
		process.cleanup()
		return errors.Join(errs...)
	case <-timer.C:
		if killErr := process.cmd.Process.Kill(); killErr != nil && !isProcessAlreadyFinished(killErr) {
			errs = append(errs, fmt.Errorf("browser process fallback kill failed: %w", killErr))
		}
		if browserRuntimeWaitOwnerUntil(ownerDone, time.Until(deadline)) {
			_ = process.owner.Result()
			process.cleanup()
			return errors.Join(errs...)
		}
		errs = append(errs, fmt.Errorf("%w: owner did not terminate within %s", ErrBrowserRuntimeReapPending, browserRuntimeProcessReapTimeout))
		if pending != nil {
			pending()
		}
		return errors.Join(errs...)
	}
}

func browserRuntimeDone(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

func browserRuntimeWaitOwnerUntil(done <-chan struct{}, timeout time.Duration) bool {
	if done == nil {
		return false
	}
	if timeout <= 0 {
		return browserRuntimeDone(done)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

func cloneBrowserRuntimeStartOptions(options BrowserRuntimeStartOptions) BrowserRuntimeStartOptions {
	options.ExtraLaunchArgs = append([]string(nil), options.ExtraLaunchArgs...)
	options.StartURLs = append([]string(nil), options.StartURLs...)
	return options
}

func (s *BrowserRuntimeService) profile(profileID string) (*browser.Profile, error) {
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}
	profileID = strings.TrimSpace(profileID)
	if profileID == "" {
		return nil, fmt.Errorf("profile id is required")
	}
	manager.Mutex.Lock()
	defer manager.Mutex.Unlock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		return nil, fmt.Errorf("profile not found")
	}
	return profile, nil
}

func (s *BrowserRuntimeService) profileSnapshot(profileID string) (*browser.Profile, error) {
	manager := s.Manager()
	if manager == nil {
		return nil, fmt.Errorf("browser manager is not initialized")
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return nil, fmt.Errorf("profile not found")
	}
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	return snapshot, nil
}

func (s *BrowserRuntimeService) currentProfileSnapshotResult(profileID string, fallback *browser.Profile) (*browser.Profile, error) {
	if snapshot, err := s.profileSnapshot(profileID); err == nil {
		return snapshot, nil
	}
	if fallback == nil {
		return nil, fmt.Errorf("profile not found")
	}
	return copyBrowserProfileSnapshot(fallback), nil
}

func (s *BrowserRuntimeService) currentProfileSnapshot(profileID string, fallback *browser.Profile) *browser.Profile {
	manager := s.Manager()
	if manager == nil {
		return fallback
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return fallback
	}
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	return snapshot
}

// commitProfileSnapshot applies host-free preparation changes with both an
// incarnation (map pointer) and value compare-and-swap. Manager.Update
// mutates a profile entry in place, while delete/recreate can produce an ABA
// profile with identical values but a new pointer; both cases must reject a
// stale launch snapshot. The optional pointer keeps focused helper callers
// source-compatible; Start always supplies it.
func (s *BrowserRuntimeService) commitProfileSnapshot(profileID string, expectedRevision, snapshot *BrowserProfile, expectedIncarnation ...*BrowserProfile) bool {
	manager := s.Manager()
	if manager == nil || expectedRevision == nil || snapshot == nil {
		return false
	}
	manager.Mutex.Lock()
	defer manager.Mutex.Unlock()
	current := manager.Profiles[profileID]
	if current == nil || (len(expectedIncarnation) > 0 && current != expectedIncarnation[0]) || !reflect.DeepEqual(*current, *expectedRevision) {
		return false
	}
	updated := copyBrowserProfileSnapshot(snapshot)
	changed := !reflect.DeepEqual(*current, *updated)
	*current = *updated
	if changed {
		_ = manager.SaveProfiles()
	}
	return true
}

func (s *BrowserRuntimeService) identity(profileID string) browserRuntimeIdentity {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	return s.active[profileID]
}

func (s *BrowserRuntimeService) nextIdentity(profileID string, pid, debugPort int, cmd *exec.Cmd) browserRuntimeIdentity {
	s.identityMu.Lock()
	defer s.identityMu.Unlock()
	if s.nextGen == nil {
		s.nextGen = make(map[string]uint64)
	}
	if s.active == nil {
		s.active = make(map[string]browserRuntimeIdentity)
	}
	s.nextGen[profileID]++
	identity := browserRuntimeIdentity{generation: s.nextGen[profileID], pid: pid, debugPort: debugPort, cmd: cmd}
	s.active[profileID] = identity
	return identity
}

func (s *BrowserRuntimeService) ensureIdentity(profileID string, pid, debugPort int, cmd *exec.Cmd) browserRuntimeIdentity {
	current := s.identity(profileID)
	if current.generation != 0 && current.pid == pid && current.debugPort == debugPort && current.cmd == cmd {
		return current
	}
	return s.nextIdentity(profileID, pid, debugPort, cmd)
}

func sameBrowserRuntimeIdentity(left, right browserRuntimeIdentity) bool {
	return left.generation != 0 && left.generation == right.generation && left.pid == right.pid && left.debugPort == right.debugPort && left.cmd == right.cmd
}

func (s *BrowserRuntimeService) identityMatches(profileID string, expected browserRuntimeIdentity) bool {
	return sameBrowserRuntimeIdentity(s.identity(profileID), expected)
}

func (s *BrowserRuntimeService) markRunning(profileID string, profile *browser.Profile, cmd *exec.Cmd, pid, debugPort int, debugReady bool, warning string) browserRuntimeIdentity {
	manager := s.Manager()
	if manager == nil || profile == nil {
		return browserRuntimeIdentity{}
	}
	manager.Mutex.Lock()
	current := manager.Profiles[profileID]
	if current == nil {
		current = profile
	}
	current.Running = true
	current.DebugPort = debugPort
	current.DebugReady = debugReady
	current.Pid = pid
	current.LastStartAt = time.Now().Format(time.RFC3339)
	current.RuntimeWarning = warning
	current.LastError = ""
	if manager.BrowserProcesses == nil {
		manager.BrowserProcesses = make(map[string]*exec.Cmd)
	}
	if cmd != nil {
		manager.BrowserProcesses[profileID] = cmd
	}
	manager.Mutex.Unlock()
	return s.nextIdentity(profileID, pid, debugPort, cmd)
}

// adoptDetectedRuntime commits a recovered runtime while the profile still
// has the incarnation and values observed before host detection. Keeping the
// commit and runtime-state mutation under one Manager lock prevents a
// delete/recreate or update interleave from marking a replacement profile
// running.
func (s *BrowserRuntimeService) adoptDetectedRuntime(profileID string, expectedRevision, snapshot, expectedIncarnation *browser.Profile) (browserRuntimeIdentity, bool) {
	manager := s.Manager()
	if manager == nil || expectedRevision == nil || snapshot == nil || expectedIncarnation == nil {
		return browserRuntimeIdentity{}, false
	}
	manager.Mutex.Lock()
	current := manager.Profiles[profileID]
	if current == nil || current != expectedIncarnation || !reflect.DeepEqual(*current, *expectedRevision) {
		manager.Mutex.Unlock()
		return browserRuntimeIdentity{}, false
	}
	updated := copyBrowserProfileSnapshot(snapshot)
	*current = *updated
	current.Running = true
	current.DebugReady = true
	current.RuntimeWarning = ""
	current.LastError = ""
	current.LastStartAt = time.Now().Format(time.RFC3339)
	if manager.BrowserProcesses == nil {
		manager.BrowserProcesses = make(map[string]*exec.Cmd)
	}
	identity := s.nextIdentity(profileID, current.Pid, current.DebugPort, nil)
	manager.Mutex.Unlock()
	return identity, true
}

func (s *BrowserRuntimeService) stopState(host BrowserRuntimeHost, profileID string, expected *browserRuntimeIdentity) (*browser.Profile, bool) {
	manager := s.Manager()
	if manager == nil {
		return nil, false
	}
	currentIdentity := s.identity(profileID)
	if expected != nil && !sameBrowserRuntimeIdentity(currentIdentity, *expected) {
		return nil, false
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil {
		manager.Mutex.Unlock()
		return nil, false
	}
	if expected != nil && !s.identityMatches(profileID, *expected) {
		manager.Mutex.Unlock()
		return profile, false
	}
	if !profile.Running {
		manager.Mutex.Unlock()
		return profile, false
	}
	generation := currentIdentity.generation
	profile.Running = false
	profile.DebugReady = false
	profile.Pid = 0
	profile.DebugPort = 0
	profile.RuntimeWarning = ""
	profile.LastStopAt = time.Now().Format(time.RFC3339)
	delete(manager.BrowserProcesses, profileID)
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()

	s.identityMu.Lock()
	if current := s.active[profileID]; expected == nil || (expected != nil && sameBrowserRuntimeIdentity(current, *expected)) {
		delete(s.active, profileID)
	}
	s.identityMu.Unlock()
	s.clearDeferredTargets(profileID, generation)
	s.releaseProfileProxy(profileID, generation)
	if host.ClearActiveProfile != nil {
		host.ClearActiveProfile(profileID, generation)
	}
	return snapshot, true
}

func (s *BrowserRuntimeService) openRunningProfile(host BrowserRuntimeHost, profileID string, profile *browser.Profile, extraArgs, startURLs []string) error {
	explicitTargets := normalizeNonEmptyStrings(startURLs)
	targets := explicitTargets
	normalizedExtraArgs := normalizeNonEmptyStrings(extraArgs)
	expected := []string(nil)
	if host.FingerprintArgs != nil {
		expected = host.FingerprintArgs(profile)
	}
	if host.ResolveTargetURL != nil {
		resolved := make([]string, 0, len(targets))
		for _, target := range targets {
			resolved = append(resolved, host.ResolveTargetURL(profileID, expected, profile, target))
		}
		targets = normalizeNonEmptyStrings(resolved)
	}
	if len(targets) == 0 {
		targets = []string{"about:blank"}
	}
	if profile != nil && profile.DebugReady && profile.DebugPort > 0 && host.CreateTarget != nil {
		for _, target := range targets {
			if err := host.CreateTarget(profile.DebugPort, target); err != nil {
				if len(explicitTargets) == 0 && len(normalizedExtraArgs) == 0 {
					return nil
				}
				return err
			}
		}
		return nil
	}
	if host.OpenRunningWindow == nil {
		return fmt.Errorf("running browser window host is not configured")
	}
	if err := host.OpenRunningWindow(profile, extraArgs, targets); err != nil {
		if len(explicitTargets) == 0 && len(normalizedExtraArgs) == 0 {
			return nil
		}
		return err
	}
	return nil
}

func (s *BrowserRuntimeService) openDeferredTargets(host BrowserRuntimeHost, debugPort int, targets []string, newTabs bool) error {
	targets = normalizeNonEmptyStrings(targets)
	if len(targets) == 0 {
		return nil
	}
	if host.CreateTarget == nil {
		return fmt.Errorf("browser target host is not configured")
	}
	if newTabs {
		for _, target := range targets {
			if err := host.CreateTarget(debugPort, target); err != nil {
				return err
			}
		}
		return nil
	}
	if host.NavigateTarget != nil {
		if err := host.NavigateTarget(debugPort, targets[0]); err == nil {
			for _, target := range targets[1:] {
				if err := host.CreateTarget(debugPort, target); err != nil {
					return err
				}
			}
			return nil
		}
	}
	for _, target := range targets {
		if err := host.CreateTarget(debugPort, target); err != nil {
			return err
		}
	}
	return nil
}

func (s *BrowserRuntimeService) storeDeferredTargets(profileID string, identity browserRuntimeIdentity, targets []string, newTabs bool) {
	targets = normalizeNonEmptyStrings(targets)
	s.deferredMu.Lock()
	defer s.deferredMu.Unlock()
	if identity.generation == 0 || len(targets) == 0 {
		delete(s.deferred, profileID)
		return
	}
	s.deferred[profileID] = browserRuntimeDeferredTargets{
		generation: identity.generation,
		plan:       deferredStartTargetsPlan{targets: append([]string(nil), targets...), newTabs: newTabs},
	}
}

func (s *BrowserRuntimeService) consumeDeferredTargets(profileID string, generation uint64) deferredStartTargetsPlan {
	s.deferredMu.Lock()
	defer s.deferredMu.Unlock()
	entry := s.deferred[profileID]
	if generation == 0 || entry.generation != generation {
		return deferredStartTargetsPlan{}
	}
	delete(s.deferred, profileID)
	plan := entry.plan
	plan.targets = append([]string(nil), plan.targets...)
	return plan
}

func (s *BrowserRuntimeService) clearDeferredTargets(profileID string, generation uint64) {
	s.deferredMu.Lock()
	if entry := s.deferred[profileID]; generation != 0 && entry.generation == generation {
		delete(s.deferred, profileID)
	}
	s.deferredMu.Unlock()
}

func (s *BrowserRuntimeService) setRuntimeWarning(profileID string, expected browserRuntimeIdentity, warning string) {
	if !s.identityMatches(profileID, expected) {
		return
	}
	manager := s.Manager()
	if manager == nil {
		return
	}
	manager.Mutex.Lock()
	profile := manager.Profiles[profileID]
	if profile == nil || !profile.Running || profile.DebugPort != expected.debugPort || !s.identityMatches(profileID, expected) {
		manager.Mutex.Unlock()
		return
	}
	profile.RuntimeWarning = warning
	profile.LastError = ""
	snapshot := copyBrowserProfileSnapshot(profile)
	manager.Mutex.Unlock()
	s.mu.RLock()
	host := s.host
	s.mu.RUnlock()
	if host.EmitUpdated != nil {
		host.EmitUpdated(snapshot)
	}
}

func (s *BrowserRuntimeService) monitorProcess(host BrowserRuntimeHost, profileID string, process *BrowserRuntimeProcess, expected browserRuntimeIdentity) {
	if process == nil || process.monitor == nil || process.owner == nil {
		return
	}
	go func() {
		defer process.cleanup()
		<-process.owner.Done()
		err := process.owner.Result()
		if !s.identityMatches(profileID, expected) {
			return
		}
		manager := s.Manager()
		if manager == nil {
			return
		}
		manager.Mutex.Lock()
		profile := manager.Profiles[profileID]
		debugPort := 0
		profileName := profileID
		wasRunning := profile != nil && profile.Running && s.identityMatches(profileID, expected)
		if profile != nil {
			debugPort = profile.DebugPort
			profileName = profile.ProfileName
		}
		manager.Mutex.Unlock()
		if !wasRunning {
			return
		}
		// Chrome commonly detaches its launcher process while the browser keeps
		// the debugging endpoint alive. Give delayed CDP startup the same grace
		// window as the local lifecycle, then require three consecutive misses.
		if debugPort > 0 && host.CanConnect != nil && s.waitRuntimeDebugAttachFor(host.CanConnect, debugPort, browserLauncherDetachGraceWindow) {
			manager.Mutex.Lock()
			if current := manager.Profiles[profileID]; current != nil && current.Running && current.DebugPort == debugPort && s.identityMatches(profileID, expected) {
				delete(manager.BrowserProcesses, profileID)
				current.Pid = 0
			}
			manager.Mutex.Unlock()
			if s.waitRuntimeDebugDisconnectFor(host.CanConnect, debugPort) {
				if _, stopped := s.stopState(host, profileID, &expected); stopped && host.EmitStopped != nil {
					host.EmitStopped(profileID)
				}
			}
			return
		}
		if _, stopped := s.stopState(host, profileID, &expected); !stopped {
			return
		}
		if err != nil && host.EmitCrashed != nil {
			host.EmitCrashed(profileID, profileName, err)
		} else if host.EmitStopped != nil {
			host.EmitStopped(profileID)
		}
	}()
}

func (s *BrowserRuntimeService) waitRuntimeDebugAttachFor(canConnect func(int, time.Duration) bool, debugPort int, grace time.Duration) bool {
	if s != nil && s.waitRuntimeDebugAttach != nil {
		return s.waitRuntimeDebugAttach(canConnect, debugPort, grace)
	}
	return waitForRuntimeDebugAttach(canConnect, debugPort, grace)
}

func (s *BrowserRuntimeService) waitRuntimeDebugDisconnectFor(canConnect func(int, time.Duration) bool, debugPort int) bool {
	if s != nil && s.waitRuntimeDebugDisconnect != nil {
		return s.waitRuntimeDebugDisconnect(canConnect, debugPort)
	}
	return waitForRuntimeDebugDisconnect(canConnect, debugPort)
}

func waitForRuntimeDebugAttach(canConnect func(int, time.Duration) bool, debugPort int, grace time.Duration) bool {
	return waitForRuntimeDebugAttachWithInterval(canConnect, debugPort, grace, 250*time.Millisecond)
}

func waitForRuntimeDebugAttachWithInterval(canConnect func(int, time.Duration) bool, debugPort int, grace, interval time.Duration) bool {
	if canConnect == nil || debugPort <= 0 {
		return false
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if canConnect(debugPort, 250*time.Millisecond) {
			return true
		}
		time.Sleep(interval)
	}
	return canConnect(debugPort, 250*time.Millisecond)
}

func waitForRuntimeDebugDisconnect(canConnect func(int, time.Duration) bool, debugPort int) bool {
	return waitForRuntimeDebugDisconnectWithInterval(canConnect, debugPort, 500*time.Millisecond)
}

func waitForRuntimeDebugDisconnectWithInterval(canConnect func(int, time.Duration) bool, debugPort int, interval time.Duration) bool {
	if canConnect == nil || debugPort <= 0 {
		return false
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	misses := 0
	for {
		if canConnect(debugPort, 250*time.Millisecond) {
			misses = 0
			time.Sleep(interval)
			continue
		}
		misses++
		if misses >= 3 {
			return true
		}
		time.Sleep(interval)
	}
}

func (s *BrowserRuntimeService) waitDebugReadyAsync(host BrowserRuntimeHost, profileID string, debugPort int, expected browserRuntimeIdentity, timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !s.identityMatches(profileID, expected) {
			return
		}
		if probeBrowserDebugPort(debugPort, browserDebugProbeTimeout) == nil {
			manager := s.Manager()
			if manager == nil {
				return
			}
			manager.Mutex.Lock()
			profile := manager.Profiles[profileID]
			if profile == nil || !profile.Running || profile.DebugPort != debugPort || !s.identityMatches(profileID, expected) {
				manager.Mutex.Unlock()
				return
			}
			profile.DebugReady = true
			profile.RuntimeWarning = ""
			profile.LastError = ""
			snapshot := copyBrowserProfileSnapshot(profile)
			manager.Mutex.Unlock()
			if host.SetActiveProfile != nil {
				host.SetActiveProfile(snapshot)
			}
			if host.EmitUpdated != nil {
				host.EmitUpdated(snapshot)
			}
			plan := s.consumeDeferredTargets(profileID, expected.generation)
			if len(plan.targets) > 0 {
				if err := s.openDeferredTargets(host, debugPort, plan.targets, plan.newTabs); err != nil {
					s.setRuntimeWarning(profileID, expected, deferredStartTargetsWarning(plan.targets, err))
				}
			}
			return
		}
		time.Sleep(250 * time.Millisecond)
	}
}
