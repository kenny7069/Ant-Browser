package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/database"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
	"gopkg.in/yaml.v3"
)

func TestFarmClientConfigRejectsUnknownFieldsAndRelativeRoots(t *testing.T) {
	path := filepath.Join(t.TempDir(), "client.yaml")
	if err := os.WriteFile(path, []byte("application_root: /tmp\nstate_root: /tmp/state\nunknown: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFarmClientConfig(path); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("unknown field error = %v, want ErrFarmClientConfig", err)
	}
	config := FarmClientConfig{ApplicationRoot: "relative", StateRoot: "/tmp/state", ControlURL: "ws://127.0.0.1:1", NodeUID: "node-a"}
	if err := config.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("relative root error = %v, want ErrFarmClientRoots", err)
	}
	config = FarmClientConfig{ApplicationRoot: "/tmp", StateRoot: "/tmp/state", ControlURL: "ws://127.0.0.1:1", NodeUID: "node-a", LogFile: "../outside.log"}
	if err := config.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("escaping relative log path error = %v, want ErrFarmClientRoots", err)
	}
}

func TestFarmClientNegativeConfigMatrix(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := LoadFarmClientConfig(missing); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("missing config error = %v, want ErrFarmClientConfig", err)
	}
	malformed := filepath.Join(t.TempDir(), "malformed.yaml")
	if err := os.WriteFile(malformed, []byte("application_root: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadFarmClientConfig(malformed); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("malformed config error = %v, want ErrFarmClientConfig", err)
	}
	missingAppRoot := filepath.Join(t.TempDir(), "does-not-exist")
	if _, err := ValidateFarmClientApplicationRoot(missingAppRoot); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("missing app root error = %v, want ErrFarmClientRoots", err)
	}
	for name, config := range map[string]FarmClientConfig{
		"invalid node uid":    {ApplicationRoot: t.TempDir(), StateRoot: filepath.Join(t.TempDir(), "state"), ControlURL: "ws://127.0.0.1:1", NodeUID: "node with spaces", PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))},
		"invalid control url": {ApplicationRoot: t.TempDir(), StateRoot: filepath.Join(t.TempDir(), "state"), ControlURL: "http://controller.example", NodeUID: "node-a", PrivateKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize))},
	} {
		t.Run(name, func(t *testing.T) {
			if err := config.ValidateFarmClientConfig(); err == nil {
				t.Fatal("expected config validation error")
			}
		})
	}
	host := BrowserRuntimeHost{
		StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
		StopProcess:  func(*exec.Cmd) error { return nil },
	}
	_, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: t.TempDir(), Config: DefaultConfig(), Profiles: []BrowserProfile{{ProfileId: "duplicate"}, {ProfileId: "duplicate"}}, Host: host,
	})
	if err == nil || !strings.Contains(err.Error(), "duplicated") {
		t.Fatalf("duplicate profile error = %v", err)
	}
}

func TestFarmClientIdentityValidationDoesNotExposeKey(t *testing.T) {
	seed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	encoded := base64.StdEncoding.EncodeToString(seed)
	config := FarmClientConfig{Identity: FarmClientIdentityConfig{NodeUID: "node-a", PrivateKey: encoded}}
	identity, err := config.ResolveFarmClientIdentity(nil)
	if err != nil {
		t.Fatal(err)
	}
	if identity.String() == "" || containsSecret(identity.String(), encoded) {
		t.Fatalf("identity string exposed secret: %q", identity.String())
	}
	for _, invalid := range []string{"", "with space", "../node"} {
		config.Identity.NodeUID = invalid
		if _, err := config.ResolveFarmClientIdentity(nil); !errors.Is(err, ErrFarmClientIdentity) {
			t.Fatalf("node %q error = %v, want ErrFarmClientIdentity", invalid, err)
		}
	}
}

func TestFarmClientInstanceLockRejectsSecondOwner(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireFarmClientInstanceLock(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := AcquireFarmClientInstanceLock(root)
	if second != nil || !errors.Is(err, ErrFarmClientAlreadyRun) {
		t.Fatalf("second lock = %v, err = %v", second, err)
	}
}

func TestFarmClientOwnershipKeyUsesDomainSeparatedHKDF(t *testing.T) {
	seed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	identity := FarmClientIdentity{NodeUID: "node-a", PrivateKey: seed}
	key, err := deriveFarmClientOwnershipKey(identity)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(seed)
	if bytes.Equal(key, digest[:]) {
		t.Fatal("ownership key must not be a plain private-key hash")
	}
	reader := hkdf.New(sha256.New, seed[:ed25519.SeedSize], nil, []byte(farmClientOwnershipKeyInfo))
	expected := make([]byte, 32)
	if _, err := io.ReadFull(reader, expected); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, expected) {
		t.Fatal("ownership key does not use the documented HKDF label")
	}
	otherReader := hkdf.New(sha256.New, seed[:ed25519.SeedSize], nil, []byte("other-domain"))
	other := make([]byte, 32)
	if _, err := io.ReadFull(otherReader, other); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(key, other) {
		t.Fatal("ownership key label is not domain separated")
	}
	seedKey, err := deriveFarmClientOwnershipKey(FarmClientIdentity{NodeUID: "node-a", PrivateKey: seed[:ed25519.SeedSize]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, seedKey) {
		t.Fatal("32-byte seed and 64-byte expanded key must derive the same ownership key")
	}
}

func TestFarmClientProfileLoaderIsReadOnlyAndFailsClosed(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.Database.SQLite.Path = "missing.db"
	if _, _, err := loadFarmClientProfiles(cfg, root); !errors.Is(err, ErrFarmClientProfileStore) {
		t.Fatalf("missing DB error = %v, want ErrFarmClientProfileStore", err)
	}
	if _, err := os.Stat(filepath.Join(root, "missing.db")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing DB was created: %v", err)
	}
	corruptPath := filepath.Join(root, "corrupt.db")
	corrupt := []byte("not sqlite")
	if err := os.WriteFile(corruptPath, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Database.SQLite.Path = "corrupt.db"
	if _, _, err := loadFarmClientProfiles(cfg, root); !errors.Is(err, ErrFarmClientProfileStore) {
		t.Fatalf("corrupt DB error = %v, want ErrFarmClientProfileStore", err)
	}
	unchanged, err := os.ReadFile(corruptPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unchanged, corrupt) {
		t.Fatal("corrupt DB was modified")
	}
	specialPath := filepath.Join(root, "db with spaces.sqlite")
	seedDB, err := database.NewDB(specialPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := seedDB.Migrate(); err != nil {
		_ = seedDB.Close()
		t.Fatal(err)
	}
	if err := seedDB.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Database.SQLite.Path = specialPath
	loadedDB, _, err := loadFarmClientProfiles(cfg, root)
	if err != nil {
		t.Fatalf("special-character DB path failed: %v", err)
	}
	if err := loadedDB.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFarmClientSQLiteReadOnlyDSNEscapesPathCharacters(t *testing.T) {
	dsn := farmClientSQLiteReadOnlyDSN("/tmp/farm client #1?.sqlite")
	for _, escaped := range []string{"%20", "%23", "%3F"} {
		if !strings.Contains(strings.ToUpper(dsn), escaped) {
			t.Fatalf("DSN %q does not escape %s", dsn, escaped)
		}
	}
	if !strings.HasSuffix(dsn, "?mode=ro") {
		t.Fatalf("DSN %q missing read-only query", dsn)
	}
	windowsDSN := farmClientSQLiteReadOnlyDSN(`C:\Farm Client\profiles #1?.db`)
	if strings.Contains(windowsDSN, `\`) || !strings.Contains(strings.ToUpper(windowsDSN), "%23") {
		t.Fatalf("Windows path was not normalized/escaped: %q", windowsDSN)
	}
}

func TestFarmClientCanonicalManagerResolvesSQLiteOnlyProxy(t *testing.T) {
	root := t.TempDir()
	dbPath := filepath.Join(root, "profiles.db")
	seed, err := database.NewDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Migrate(); err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	const proxySecret = "sqlite-only-secret"
	proxyConfig := "http://user:" + proxySecret + "@127.0.0.1:18080"
	if err := browser.NewSQLiteProxyDAO(seed.GetConn()).Upsert(BrowserProxy{
		ProxyId: "proxy-db", ProxyName: "SQLite only", ProxyConfig: proxyConfig,
	}); err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := browser.NewSQLiteProfileDAO(seed.GetConn()).Upsert(&BrowserProfile{
		ProfileId: "profile-db", ProfileName: "SQLite proxy", ProxyId: "proxy-db",
	}); err != nil {
		_ = seed.Close()
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	cfg.Database.SQLite.Path = dbPath
	db, manager, err := loadFarmClientProfiles(cfg, root)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	service, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: root, InitializedManager: manager,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	binding, err := service.LocalProfileProxyBinding("profile-db")
	if err != nil {
		t.Fatal(err)
	}
	if !binding.Enabled || binding.ConnectorType != "xray" || binding.CredentialRevision == "" || binding.ConfigRevision == "" {
		t.Fatalf("unexpected SQLite proxy binding: %+v", binding)
	}
	if strings.Contains(fmt.Sprint(binding), proxySecret) {
		t.Fatal("secret appeared in proxy binding")
	}
}

func TestNewFarmClientHostLoadsSQLiteProfilesAndComposesServices(t *testing.T) {
	root := t.TempDir()
	appConfigPath := filepath.Join(root, "config.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	if err := antConfig.Save(appConfigPath); err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDB(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	clientConfig := FarmClientConfig{
		ApplicationRoot: root,
		StateRoot:       filepath.Join(root, "state"),
		AntConfigPath:   appConfigPath,
		ControlURL:      "ws://127.0.0.1:1",
		Identity: FarmClientIdentityConfig{
			NodeUID:    "node-a",
			PrivateKey: base64.StdEncoding.EncodeToString(key),
		},
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(clientPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := NewFarmClientHost(clientPath)
	if err != nil {
		t.Fatal(err)
	}
	if host.RuntimeService() == nil || host.FarmService() == nil || host.Transport() == nil {
		t.Fatal("host did not compose runtime, farm and transport services")
	}
	canonical := host.RuntimeService().Manager()
	if canonical == nil || canonical.ProfileDAO == nil || canonical.ProxyDAO == nil || canonical.CoreDAO == nil || canonical.BookmarkDAO == nil || canonical.GroupDAO == nil || canonical.ExtensionDAO == nil {
		t.Fatal("host did not retain canonical SQLite DAOs")
	}
	if err := host.Shutdown(); err != nil {
		t.Fatal(err)
	}
	logBytes, err := os.ReadFile(host.config.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(logBytes), "standalone farm client started") || strings.Contains(string(logBytes), base64.StdEncoding.EncodeToString(key)) {
		t.Fatalf("log safety/start evidence failed: %s", logBytes)
	}
	if _, err := os.Stat(filepath.Join(root, "state", ".ant-farm-client.lock")); err != nil {
		t.Fatalf("lock file should remain for advisory lock reuse: %v", err)
	}
}

func TestNewFarmClientHostLoadsSecureIdentityReference(t *testing.T) {
	root := t.TempDir()
	appConfigPath := filepath.Join(root, "config.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	if err := antConfig.Save(appConfigPath); err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDB(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	ref, _ := NewFarmClientIdentityKeyRef("secure-node-key")
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = 0x5a
	}
	key := ed25519.NewKeyFromSeed(seed)
	store := &fakeFarmClientIdentityStore{keys: make(map[FarmClientIdentityKeyRef][]byte)}
	if err := store.Save(ref, key); err != nil {
		t.Fatal(err)
	}
	clientConfig := FarmClientConfig{
		ApplicationRoot: root,
		StateRoot:       filepath.Join(root, "state"),
		AntConfigPath:   appConfigPath,
		ControlURL:      "ws://127.0.0.1:1",
		Identity: FarmClientIdentityConfig{
			NodeUID:       "node-secure",
			PrivateKeyRef: string(ref),
		},
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	clientPath := filepath.Join(root, "client-secure.yaml")
	if err := os.WriteFile(clientPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := NewFarmClientHostWithIdentityStore(clientPath, store)
	if err != nil {
		t.Fatal(err)
	}
	if !equalBytes(host.identity.PrivateKey, key) || host.identity.NodeUID != "node-secure" {
		t.Fatal("host did not compose the securely stored device identity")
	}
	if host.config.Identity.PrivateKey != "" || host.config.Identity.PrivateKeyEnv != "" {
		t.Fatal("host retained a development identity source")
	}
	if err := host.Shutdown(); err != nil {
		t.Fatal(err)
	}
	logBytes, err := os.ReadFile(host.config.LogFile)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(logBytes), base64.StdEncoding.EncodeToString(key)) || strings.Contains(string(logBytes), string(ref)) {
		t.Fatal("host log exposed secure identity material or reference")
	}
}

func TestFarmClientRunKeepsReconnectSupervisorAliveAfterInitialDialFailure(t *testing.T) {
	appRoot := t.TempDir()
	cfg := DefaultConfig()
	runtimeService, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: appRoot, Config: cfg,
		Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	farmService, err := NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		BrowserRuntimeService: runtimeService, NodeUID: "node-a", ProviderInstanceID: "provider-a", FencingEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewFarmRuntimeControlAdapter(farmService)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	transport, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: "ws://127.0.0.1:1", NodeUID: "node-a", PrivateKey: key,
		HandshakeTimeout: 20 * time.Millisecond, AutoReconnect: true,
		ReconnectMinBackoff: 10 * time.Millisecond, ReconnectMaxBackoff: 20 * time.Millisecond,
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	host := &FarmClientHost{config: FarmClientConfig{ShutdownTimeoutMs: 500}, runtime: runtimeService, farm: farmService, transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := host.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 50*time.Millisecond {
		t.Fatalf("Run returned after initial dial failure in %s; reconnect supervisor was not kept alive", elapsed)
	}
}

func TestFarmClientRealWSSReconnectHeartbeatAndInventory(t *testing.T) {
	var first atomic.Bool
	firstStarted := make(chan struct{}, 1)
	heartbeatSeen := make(chan struct{}, 1)
	commandSeen := make(chan struct{}, 1)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := upgrader.Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		defer connection.Close()
		if first.CompareAndSwap(false, true) {
			firstStarted <- struct{}{}
			time.Sleep(120 * time.Millisecond)
		}
		var begin farmControlAuthBegin
		if err := connection.ReadJSON(&begin); err != nil {
			return
		}
		publicKeyRaw, err := base64.StdEncoding.DecodeString(begin.DevicePubKey)
		if err != nil || len(publicKeyRaw) != ed25519.PublicKeySize {
			return
		}
		challengeRaw := bytes.Repeat([]byte{7}, 32)
		challenge := base64.StdEncoding.EncodeToString(challengeRaw)
		if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: begin.NodeUID, Challenge: challenge}); err != nil {
			return
		}
		var prove farmControlAuthProve
		if err := connection.ReadJSON(&prove); err != nil {
			return
		}
		message, err := farmControlAuthMessage(begin.NodeUID, challenge)
		if err != nil {
			return
		}
		signature, err := base64.StdEncoding.DecodeString(prove.Signature)
		if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKeyRaw), message, signature) {
			return
		}
		if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: begin.NodeUID, ControllerID: "controller-fixture", ControllerGeneration: 1}); err != nil {
			return
		}
		for {
			_, raw, err := connection.ReadMessage()
			if err != nil {
				return
			}
			var envelope struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(raw, &envelope) != nil {
				return
			}
			switch envelope.Type {
			case "heartbeat":
				var heartbeat farmControlHeartbeat
				if json.Unmarshal(raw, &heartbeat) != nil {
					return
				}
				if err := connection.WriteJSON(farmControlHeartbeatAck{Type: "heartbeat_ack", HeartbeatID: heartbeat.HeartbeatID}); err != nil {
					return
				}
				select {
				case heartbeatSeen <- struct{}{}:
				default:
				}
				_ = connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: begin.NodeUID, CorrelationID: "inventory-fixture", Command: "inventory", Payload: map[string]any{}})
			case "command_response":
				var response FarmRuntimeCommandResponse
				if json.Unmarshal(raw, &response) != nil || response.CorrelationID != "inventory-fixture" || !response.OK {
					return
				}
				commandSeen <- struct{}{}
				return
			}
		}
	}))
	defer server.Close()

	runtimeService, farmService, adapter := newFarmClientTestStack(t)
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	transport, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: "ws" + strings.TrimPrefix(server.URL, "http"), NodeUID: "node-a", PrivateKey: key,
		HandshakeTimeout: 40 * time.Millisecond, CommandTimeout: 500 * time.Millisecond,
		HeartbeatInterval: 20 * time.Millisecond, AutoReconnect: true,
		ReconnectMinBackoff: 10 * time.Millisecond, ReconnectMaxBackoff: 40 * time.Millisecond,
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	host := &FarmClientHost{config: FarmClientConfig{ShutdownTimeoutMs: 500}, runtime: runtimeService, farm: farmService, transport: transport}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- host.Run(ctx) }()
	select {
	case <-firstStarted:
	case <-time.After(time.Second):
		t.Fatal("fixture did not receive initial connection")
	}
	select {
	case <-heartbeatSeen:
	case <-time.After(time.Second):
		t.Fatal("authenticated client did not send heartbeat")
	}
	select {
	case <-commandSeen:
	case <-time.After(time.Second):
		t.Fatal("inventory command response was not observed")
	}
	cancel()
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("host did not shut down after context cancellation")
	}
}

func TestFarmClientCLIProcessLockAndSIGTERM(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SIGTERM process assertion is Unix-specific; Windows binary is compile-tested")
	}
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Dir(filepath.Dir(testFile))
	root := t.TempDir()
	configPath := writeFarmClientProcessFixture(t, root)
	binaryPath := filepath.Join(t.TempDir(), "ant-farm-client")
	build := exec.Command("go", "build", "-o", binaryPath, "./backend/cmd/ant-farm-client")
	build.Dir = repoRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	var firstOutput bytes.Buffer
	first := exec.Command(binaryPath, "-config", configPath)
	first.Stdout, first.Stderr = &firstOutput, &firstOutput
	var firstReaped atomic.Bool
	if err := first.Start(); err != nil {
		t.Fatal(err)
	}
	// Every failure path must reap the child. The normal assertion below calls
	// Wait itself; this cleanup only handles early test failures or timeouts.
	t.Cleanup(func() {
		if first.Process == nil || firstReaped.Load() {
			return
		}
		_ = first.Process.Signal(syscall.SIGTERM)
		waitDone := make(chan struct{})
		go func() {
			_, _ = first.Process.Wait()
			firstReaped.Store(true)
			close(waitDone)
		}()
		select {
		case <-waitDone:
		case <-time.After(2 * time.Second):
			_ = first.Process.Kill()
			select {
			case <-waitDone:
			case <-time.After(2 * time.Second):
			}
		}
	})
	lockDeadline := time.Now().Add(3 * time.Second)
	for {
		lock, err := AcquireFarmClientInstanceLock(filepath.Join(root, "state"))
		if errors.Is(err, ErrFarmClientAlreadyRun) {
			break
		}
		if err == nil {
			_ = lock.Release()
		}
		if time.Now().After(lockDeadline) {
			t.Fatalf("first CLI did not acquire state-root lock: %v\n%s", err, firstOutput.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	startupDeadline := time.Now().Add(3 * time.Second)
	for {
		logPath := filepath.Join(root, "state", "logs", "ant-farm-client.log")
		if logBytes, readErr := os.ReadFile(logPath); readErr == nil && strings.Contains(string(logBytes), "standalone farm client started") {
			break
		}
		if time.Now().After(startupDeadline) {
			t.Fatalf("first CLI did not finish startup: %s", firstOutput.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	second := exec.Command(binaryPath, "-config", configPath)
	secondOutput, secondErr := second.CombinedOutput()
	if secondErr == nil || !strings.Contains(string(secondOutput), ErrFarmClientAlreadyRun.Error()) {
		t.Fatalf("second CLI result = %v, output=%s", secondErr, secondOutput)
	}
	if err := first.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	wait := make(chan error, 1)
	go func() { wait <- first.Wait() }()
	select {
	case err := <-wait:
		firstReaped.Store(true)
		if err != nil {
			t.Fatalf("first CLI did not exit cleanly after SIGTERM: %v\n%s", err, firstOutput.String())
		}
	case <-time.After(3 * time.Second):
		_ = first.Process.Kill()
		select {
		case <-wait:
		case <-time.After(2 * time.Second):
		}
		t.Fatal("first CLI did not exit within bounded shutdown timeout")
	}
	lock, err := AcquireFarmClientInstanceLock(filepath.Join(root, "state"))
	if err != nil {
		t.Fatalf("state-root lock was not released after SIGTERM: %v", err)
	}
	_ = lock.Release()
}

func writeFarmClientProcessFixture(t *testing.T, root string) string {
	t.Helper()
	antConfigPath := filepath.Join(root, "config.yaml")
	antConfig := DefaultConfig()
	antConfig.Database.SQLite.Path = "profiles.db"
	if err := antConfig.Save(antConfigPath); err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDB(filepath.Join(root, "profiles.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	clientConfig := FarmClientConfig{
		ApplicationRoot: root, StateRoot: filepath.Join(root, "state"),
		AntConfigPath: antConfigPath, ControlURL: "ws://127.0.0.1:1",
		Identity: FarmClientIdentityConfig{NodeUID: "node-process", PrivateKey: base64.StdEncoding.EncodeToString(key)},
	}
	raw, err := yaml.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func newFarmClientTestStack(t *testing.T) (*BrowserRuntimeService, *FarmRuntimeService, *FarmRuntimeControlAdapter) {
	t.Helper()
	runtimeService, err := NewBrowserRuntimeServiceForHost(BrowserRuntimeServiceFactoryConfig{
		AppRoot: t.TempDir(), Config: DefaultConfig(), Host: BrowserRuntimeHost{
			StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:  func(*exec.Cmd) error { return nil },
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	farmService, err := NewFarmRuntimeServiceForHost(FarmRuntimeServiceFactoryConfig{
		BrowserRuntimeService: runtimeService, NodeUID: "node-a", ProviderInstanceID: "provider-a", FencingEpoch: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := NewFarmRuntimeControlAdapter(farmService)
	if err != nil {
		t.Fatal(err)
	}
	return runtimeService, farmService, adapter
}

func containsSecret(value, secret string) bool {
	return len(secret) > 0 && strings.Contains(value, secret)
}
