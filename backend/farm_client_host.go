package backend

// The standalone Farm client composition root. This file intentionally owns
// only process bootstrap and resource lifetime; Farm lifecycle and transport
// semantics remain in the existing Browser/Farm/WSS services.

import (
	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/database"
	"ant-chrome/backend/internal/logger"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
	_ "modernc.org/sqlite"
)

// FarmClientHost owns one composed standalone client and all resources opened
// by its bootstrap. It exposes no private key or local profile details.
type FarmClientHost struct {
	config          FarmClientConfig
	identity        FarmClientIdentity
	lock            *FarmClientInstanceLock
	db              *sql.DB
	manager         *browser.Manager
	runtime         *BrowserRuntimeService
	farm            *FarmRuntimeService
	adapter         *FarmRuntimeControlAdapter
	transport       *FarmControlWSSClient
	log             *logger.Logger
	logging         bool
	updateMu        sync.Mutex
	updatePrepareMu sync.Mutex
	// preserveRuntimes is set only after the update drain fence has closed the
	// authenticated transport. Normal shutdown retains its existing behavior.
	preserveRuntimes bool

	shutdownOnce sync.Once
	shutdownErr  error
}

// NewFarmClientHost strictly loads config and local profile state before any
// runtime or network service is constructed. The returned host is ready for
// Run or an explicit Connect/Shutdown lifecycle.
func NewFarmClientHost(configPath string) (*FarmClientHost, error) {
	return NewFarmClientHostWithIdentityStore(configPath, nil)
}

// NewFarmClientHostWithIdentityStore is the injectable C2 composition seam.
// Production passes nil and receives the current OS store; tests and embedding
// hosts can supply a store without weakening the normal bootstrap path.
func NewFarmClientHostWithIdentityStore(configPath string, suppliedIdentityStore FarmClientIdentityStore) (*FarmClientHost, error) {
	cfg, err := LoadFarmClientConfig(configPath)
	if err != nil {
		return nil, err
	}
	if err := cfg.ValidateFarmClientConfig(); err != nil {
		return nil, err
	}
	appRoot, err := ValidateFarmClientApplicationRoot(cfg.ApplicationRoot)
	if err != nil {
		return nil, err
	}
	stateRoot, err := ValidateFarmClientStateRoot(cfg.StateRoot)
	if err != nil {
		return nil, err
	}
	cfg.ApplicationRoot, cfg.AppRoot, cfg.StateRoot = appRoot, appRoot, stateRoot

	var identity FarmClientIdentity
	if strings.TrimSpace(cfg.identityConfig().PrivateKeyRef) != "" {
		identityStore := suppliedIdentityStore
		if identityStore == nil {
			var storeErr error
			identityStore, storeErr = NewFarmClientIdentityStore(stateRoot)
			if storeErr != nil {
				return nil, farmClientIdentityStoreError(storeErr)
			}
		}
		identity, err = cfg.ResolveFarmClientIdentityFromStore(identityStore)
	} else {
		identity, err = cfg.ResolveFarmClientIdentity(nil)
	}
	if err != nil {
		return nil, err
	}
	// Do not retain the encoded identity after it has been decoded. The
	// expanded private key is kept only in this host and WSS client memory.
	cfg.PrivateKey, cfg.Identity.PrivateKey, cfg.PrivateKeyEnv, cfg.Identity.PrivateKeyEnv = "", "", "", ""

	lock, err := AcquireFarmClientInstanceLock(stateRoot)
	if err != nil {
		return nil, err
	}
	cleanupLock := true
	defer func() {
		if cleanupLock {
			_ = lock.Release()
		}
	}()

	antCfg, err := LoadFarmClientAntConfig(cfg.AntConfigPath)
	if err != nil {
		return nil, err
	}
	db, manager, err := loadFarmClientProfiles(antCfg, appRoot)
	if err != nil {
		return nil, err
	}
	capture := newFarmClientLaunchCapture()
	host := newFarmClientBrowserHost(manager, capture)
	fingerprintApp := &App{browserMgr: manager}
	runtimeService, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: appRoot, InitializedManager: manager, Host: host,
		FingerprintLaunchArgs: func(profileID, coreID string, args []string) []string {
			report := fingerprintApp.buildBrowserFingerprintCapabilityReport(profileID, coreID, args)
			return append([]string(nil), report.LaunchArgs...)
		},
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	ownershipKey, err := deriveFarmClientOwnershipKey(identity)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	ownershipStore, err := NewFileFarmRuntimeOwnershipStore(filepath.Join(stateRoot, "farm-ownership.json"), ownershipKey)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	farmService, err := NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		BrowserRuntimeService:    runtimeService,
		NodeUID:                  identity.NodeUID,
		ProviderInstanceID:       cfg.ProviderInstanceID,
		FencingEpoch:             cfg.FencingEpoch,
		OwnershipStore:           ownershipStore,
		AttestationStateProvider: newFarmClientAttestationProvider(runtimeService, capture),
		ProfilePairingVerifier: func(profileID, incarnation string) error {
			return farmClientValidateProfilePairing(manager, profileID, incarnation)
		},
	})
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	adapter, err := NewFarmRuntimeControlAdapter(farmService)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	transport, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: cfg.ControlURL, NodeUID: identity.NodeUID, PrivateKey: identity.PrivateKey,
		HandshakeTimeout: cfg.handshakeTimeout(), CommandTimeout: cfg.commandTimeout(),
		HeartbeatInterval: cfg.heartbeatInterval(), AutoReconnect: true,
		ReconnectMinBackoff: cfg.reconnectMinBackoff(), ReconnectMaxBackoff: cfg.reconnectMaxBackoff(),
	}, adapter)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	logger.InitWithConfig(context.Background(), logger.LoggerConfig{
		Level: "info", FileEnabled: true, FilePath: cfg.LogFile,
		Format: "json", BufferSize: 4, AsyncQueueSize: 256, FlushIntervalMs: 250,
	})
	log := logger.New("FarmClient")
	log.Info("standalone farm client started", logger.F("version", FarmClientVersion), logger.F("goos", FarmClientVersionInfoValue().GOOS), logger.F("goarch", FarmClientVersionInfoValue().GOARCH))
	cleanupLock = false
	return &FarmClientHost{
		config: cfg, identity: identity, lock: lock, db: db, manager: manager,
		runtime: runtimeService, farm: farmService, adapter: adapter,
		transport: transport, log: log, logging: true,
	}, nil
}

// VersionInfo intentionally excludes roots, profile IDs, URLs and identity.
func (h *FarmClientHost) VersionInfo() FarmClientVersionInfo { return FarmClientVersionInfoValue() }

func (h *FarmClientHost) RuntimeService() *BrowserRuntimeService {
	if h == nil {
		return nil
	}
	return h.runtime
}

func (h *FarmClientHost) FarmService() *FarmRuntimeService {
	if h == nil {
		return nil
	}
	return h.farm
}

func (h *FarmClientHost) Transport() *FarmControlWSSClient {
	if h == nil {
		return nil
	}
	return h.transport
}

// Run authenticates the WSS client and blocks until context cancellation or
// transport termination. AutoReconnect remains enabled after a later loss.
func (h *FarmClientHost) Run(ctx context.Context) error {
	return h.run(ctx, "", "")
}

// RunWithUpdateHealth writes a private nonce only after the successor has an
// authenticated heartbeat and the Server has completed inventory/reconcile.
func (h *FarmClientHost) RunWithUpdateHealth(ctx context.Context, markerPath, nonce string) error {
	return h.run(ctx, markerPath, nonce)
}

func (h *FarmClientHost) run(ctx context.Context, markerPath, nonce string) error {
	if h == nil || h.transport == nil {
		return ErrFarmControlWSSClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := h.transport.Connect(ctx); err != nil {
		// Connect starts the existing reconnect supervisor before attempting the
		// first dial. Keep this host alive so a controller that starts shortly
		// after the Agent can still establish the authenticated session.
		if !h.transport.config.AutoReconnect {
			return h.ShutdownWithError(err)
		}
	}
	if markerPath != "" {
		deadline := time.NewTimer(h.config.updateHealthTimeout())
		ticker := time.NewTicker(50 * time.Millisecond)
		ready := false
		for !ready {
			select {
			case <-ctx.Done():
				ticker.Stop()
				deadline.Stop()
				_ = h.PrepareForUpdate()
				return h.ShutdownWithError(ctx.Err())
			case <-deadline.C:
				ticker.Stop()
				_ = h.PrepareForUpdate()
				return h.ShutdownWithError(ErrFarmClientUpdateApply)
			case <-ticker.C:
				ready = h.transport.ControlRTTMilliseconds() > 0 && h.adapter != nil && h.adapter.FarmClientUpdateHealthReady()
			}
		}
		ticker.Stop()
		deadline.Stop()
		if err := WriteFarmClientUpdateHealthMarker(h.config, markerPath, nonce); err != nil {
			if h.log != nil {
				h.log.Error("farm client update health marker failed", logger.F("error", err))
			}
			_ = h.PrepareForUpdate()
			return h.ShutdownWithError(err)
		}
		healthTicker := time.NewTicker(time.Second)
		defer healthTicker.Stop()
		for {
			select {
			case <-ctx.Done():
				return h.Shutdown()
			case <-h.transport.Done():
				_ = h.PrepareForUpdate()
				return h.Shutdown()
			case <-healthTicker.C:
				if h.transport.ControlRTTMilliseconds() <= 0 || h.adapter == nil || !h.adapter.FarmClientUpdateHealthReady() {
					_ = os.Remove(markerPath)
					continue
				}
				if err := WriteFarmClientUpdateHealthMarker(h.config, markerPath, nonce); err != nil {
					if h.log != nil {
						h.log.Error("farm client update health refresh failed", logger.F("error", err))
					}
					_ = h.PrepareForUpdate()
					return h.ShutdownWithError(err)
				}
			}
		}
	}
	select {
	case <-ctx.Done():
		return h.Shutdown()
	case <-h.transport.Done():
		return h.Shutdown()
	}
}

// Shutdown is idempotent and bounded by the configured timeout. WSS/CDP are
// closed before the ownership-aware Browser runtime shutdown.
// Known limitation: the frozen BrowserRuntimeService.Shutdown API has no
// context/deadline parameter. This host bounds transport teardown and relies
// on the service's existing internal process/admission bounds; a host-wide
// hard deadline cannot be enforced without changing that frozen API.
func (h *FarmClientHost) Shutdown() error {
	if h == nil {
		return nil
	}
	h.shutdownOnce.Do(func() {
		h.updatePrepareMu.Lock()
		defer h.updatePrepareMu.Unlock()
		deadline := time.Now().Add(h.config.shutdownTimeout())
		if h.transport != nil {
			_ = h.transport.Close()
			select {
			case <-h.transport.Done():
			case <-time.After(time.Until(deadline)):
				h.shutdownErr = errors.Join(h.shutdownErr, context.DeadlineExceeded)
			}
		}
		h.updateMu.Lock()
		preserveRuntimes := h.preserveRuntimes
		h.updateMu.Unlock()
		if h.runtime != nil && !preserveRuntimes {
			if err := h.runtime.Shutdown(); err != nil {
				h.shutdownErr = errors.Join(h.shutdownErr, err)
			}
		}
		if h.db != nil {
			if err := h.db.Close(); err != nil {
				h.shutdownErr = errors.Join(h.shutdownErr, err)
			}
		}
		if h.log != nil {
			h.log.Info("standalone farm client stopping", logger.F("version", FarmClientVersion), logger.F("goos", FarmClientVersionInfoValue().GOOS), logger.F("goarch", FarmClientVersionInfoValue().GOARCH))
			_ = h.log.Flush()
		}
		if h.logging {
			if err := logger.Close(); err != nil {
				h.shutdownErr = errors.Join(h.shutdownErr, err)
			}
		}
		if h.lock != nil {
			if err := h.lock.Release(); err != nil {
				h.shutdownErr = errors.Join(h.shutdownErr, err)
			}
		}
	})
	return h.shutdownErr
}

// PrepareForUpdate closes the Control session behind the Farm connection
// mutation fence, then marks the subsequent host shutdown as handoff-style.
// Existing Chrome and connector ownership is intentionally preserved for the
// successor process to recover from the authenticated ownership store.
func (h *FarmClientHost) PrepareForUpdate() error {
	return h.prepareForUpdate(nil)
}

// PrepareForUpdateAndAuthorize publishes the launcher's probation phase only
// after the command fence and WSS drain have completed. Shutdown waits on the
// same mutex, so the process cannot exit between drain and durable authorize.
func (h *FarmClientHost) PrepareForUpdateAndAuthorize(authorize func() error) error {
	if authorize == nil {
		return ErrFarmClientUpdateApply
	}
	return h.prepareForUpdate(authorize)
}

func (h *FarmClientHost) prepareForUpdate(authorize func() error) error {
	if h == nil || h.farm == nil || h.transport == nil {
		return ErrFarmClientUpdateApply
	}
	h.updatePrepareMu.Lock()
	defer h.updatePrepareMu.Unlock()
	h.updateMu.Lock()
	h.preserveRuntimes = true
	h.updateMu.Unlock()
	// Close synchronously invalidates the connection through
	// EndControlConnection, whose write lock waits for every admitted mutation.
	// Holding that same lock here would deadlock the transport shutdown.
	if err := h.transport.Close(); err != nil {
		return errors.Join(ErrFarmClientUpdateApply, err)
	}
	deadline := time.NewTimer(h.config.shutdownTimeout())
	defer deadline.Stop()
	select {
	case <-h.transport.Done():
		if authorize != nil {
			if err := authorize(); err != nil {
				return errors.Join(ErrFarmClientUpdateApply, err)
			}
		}
		return nil
	case <-deadline.C:
		return errors.Join(ErrFarmClientUpdateApply, context.DeadlineExceeded)
	}
}

// loadFarmClientProfiles uses the canonical SQLite ProfileDAO and Manager
// InitData path. C3 opens the existing database read/write so profile creation
// uses the same DAO as Ant; it never creates a second profile store and still
// fails closed instead of creating a missing/corrupt database.
func (h *FarmClientHost) ShutdownWithError(runErr error) error {
	if err := h.Shutdown(); err != nil {
		return errors.Join(runErr, err)
	}
	return runErr
}

const farmClientOwnershipKeyInfo = "ant-farm-runtime-ownership-v1"

func deriveFarmClientOwnershipKey(identity FarmClientIdentity) ([]byte, error) {
	if len(identity.PrivateKey) != 32 && len(identity.PrivateKey) != 64 {
		return nil, fmt.Errorf("%w: private key length is invalid", ErrFarmClientIdentity)
	}
	seed := identity.PrivateKey
	if len(seed) == ed25519.PrivateKeySize {
		seed = seed[:ed25519.SeedSize]
	}
	reader := hkdf.New(sha256.New, seed, nil, []byte(farmClientOwnershipKeyInfo))
	key := make([]byte, 32)
	if _, err := io.ReadFull(reader, key); err != nil {
		return nil, fmt.Errorf("%w: derive ownership key: %v", ErrFarmClientIdentity, err)
	}
	return key, nil
}

func loadFarmClientProfiles(cfg *Config, appRoot string) (*sql.DB, *browser.Manager, error) {
	if cfg == nil || strings.ToLower(strings.TrimSpace(cfg.Database.Type)) != "sqlite" {
		return nil, nil, fmt.Errorf("%w: sqlite database is required", ErrFarmClientProfileStore)
	}
	dbPath := strings.TrimSpace(cfg.Database.SQLite.Path)
	if dbPath == "" {
		return nil, nil, fmt.Errorf("%w: sqlite path is empty", ErrFarmClientProfileStore)
	}
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(appRoot, dbPath)
	}
	dbPath = filepath.Clean(dbPath)
	info, err := os.Stat(dbPath)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%w: sqlite database file is missing", ErrFarmClientProfileStore)
	}
	canonicalDB, err := database.NewDB(dbPath)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: open sqlite store: %v", ErrFarmClientProfileStore, err)
	}
	db := canonicalDB.GetConn()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := canonicalDB.Migrate(); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("%w: migrate sqlite store: %v", ErrFarmClientProfileStore, err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("%w: configure sqlite busy timeout: %v", ErrFarmClientProfileStore, err)
	}
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = db.Close()
		}
	}()
	manager := browser.NewManager(cfg, appRoot)
	dao := browser.NewSQLiteProfileDAO(db)
	manager.ProfileDAO = dao
	manager.ProxyDAO = browser.NewSQLiteProxyDAO(db)
	manager.CoreDAO = browser.NewSQLiteCoreDAO(db)
	manager.BookmarkDAO = browser.NewSQLiteBookmarkDAO(db)
	manager.GroupDAO = browser.NewSQLiteGroupDAO(db)
	manager.ExtensionDAO = browser.NewSQLiteExtensionDAO(db)
	stored, err := dao.List()
	if err != nil {
		return nil, nil, fmt.Errorf("%w: read sqlite profiles: %v", ErrFarmClientProfileStore, err)
	}
	seen := make(map[string]struct{}, len(stored))
	for _, profile := range stored {
		if profile == nil || strings.TrimSpace(profile.ProfileId) == "" {
			return nil, nil, fmt.Errorf("%w: empty profile id", ErrFarmClientProfileStore)
		}
		profile.ProfileId = strings.TrimSpace(profile.ProfileId)
		if _, exists := seen[profile.ProfileId]; exists {
			return nil, nil, fmt.Errorf("%w: duplicate profile id %q", ErrFarmClientProfileStore, profile.ProfileId)
		}
		seen[profile.ProfileId] = struct{}{}
	}
	// The preflight List above proves the read-only DAO is usable, so InitData
	// cannot silently fall back to YAML when it populates the canonical Manager.
	manager.InitData()
	manager.Mutex.Lock()
	profiles := make([]BrowserProfile, 0, len(manager.Profiles))
	for _, profile := range manager.Profiles {
		if profile == nil || strings.TrimSpace(profile.ProfileId) == "" {
			manager.Mutex.Unlock()
			return nil, nil, fmt.Errorf("%w: empty profile id", ErrFarmClientProfileStore)
		}
		// SQLite decodes JSON [] as non-nil empty slices, while the shared
		// lifecycle snapshot helper canonicalizes an empty clone to nil. Keep
		// equivalent empty values canonical at this read-only composition
		// boundary so the lifecycle CAS does not report a false profile change.
		if len(profile.FingerprintArgs) == 0 {
			profile.FingerprintArgs = nil
		}
		if len(profile.LaunchArgs) == 0 {
			profile.LaunchArgs = nil
		}
		if len(profile.Tags) == 0 {
			profile.Tags = nil
		}
		if len(profile.Keywords) == 0 {
			profile.Keywords = nil
		}
		profiles = append(profiles, *profile)
	}
	manager.Mutex.Unlock()
	if len(profiles) != len(stored) {
		return nil, nil, fmt.Errorf("%w: profile store changed during load", ErrFarmClientProfileStore)
	}
	closeOnError = false
	return db, manager, nil
}

func farmClientSQLiteDSN(path string) string {
	normalized := strings.ReplaceAll(filepath.ToSlash(filepath.Clean(path)), `\`, "/")
	uri := url.URL{Scheme: "file", Path: normalized}
	uri.RawQuery = "mode=rw"
	return uri.String()
}

func newFarmClientBrowserHost(manager *browser.Manager, capture *farmClientLaunchCapture) BrowserRuntimeHost {
	return BrowserRuntimeHost{
		StartProcess: func(plan *BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) {
			if plan == nil {
				return nil, fmt.Errorf("browser runtime launch plan is nil")
			}
			process, err := NewBrowserRuntimeLocalProcess(plan.Spec)
			if err == nil && process != nil && process.cmd != nil && process.cmd.Process != nil && capture != nil {
				capture.CaptureStart(plan.Spec.ProfileID, plan.Spec, process.cmd.Process.Pid)
			}
			return process, err
		},
		IsProfileLive:      func(profile *browser.Profile, tracked *exec.Cmd) bool { return isBrowserProfileLive(profile, tracked) },
		ResolveUserDataDir: func(profile *browser.Profile) string { return manager.ResolveUserDataDir(profile) },
		DetectRuntime: func(userDataDir string) (BrowserRuntimeDetection, bool) {
			detection, ok := detectBrowserRuntimeByUserDataDir(userDataDir)
			return BrowserRuntimeDetection{PID: detection.PID, DebugPort: detection.DebugPort, DebugReady: detection.DebugReady}, ok
		},
		ResolveTargetURL: func(_ string, _ []string, _ *browser.Profile, target string) string { return target },
		NavigateTarget:   func(port int, target string) error { return openBrowserStartTargets(port, []string{target}) },
		CreateTarget:     func(port int, target string) error { return createBrowserStartTarget(port, target) },
		TryCloseCDP:      func(port int, timeout time.Duration) bool { return tryCloseBrowserViaCDP(port, timeout) },
		StopProcess:      func(cmd *exec.Cmd) error { return stopBrowserProcessCommand(cmd) },
		CanConnect:       func(port int, timeout time.Duration) bool { return canConnectDebugPort(port, timeout) },
		SetActiveProfileGeneration: func(profile *browser.Profile, generation uint64) {
			if capture != nil && profile != nil {
				capture.MarkGeneration(profile.ProfileId, generation)
			}
		},
		ClearActiveProfile: func(profileID string, generation uint64) {
			if capture != nil {
				capture.ClearGeneration(profileID, generation)
			}
		},
		EmitStopped: func(string) {},
		EmitUpdated: func(*browser.Profile) {},
		EmitStarted: func(*browser.Profile, bool) {},
		EmitCrashed: func(string, string, error) {},
		GetTabs:     func(string) []browser.Tab { return nil },
	}
}
