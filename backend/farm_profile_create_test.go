package backend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
	"ant-chrome/backend/internal/database"

	"github.com/google/uuid"
)

func newFarmProfileCreateFixture(t *testing.T) (*farmProfileManagement, *database.DB, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "app.db")
	db, err := database.NewDB(dbPath)
	if err != nil || db.Migrate() != nil {
		t.Fatalf("database setup: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.GetConn().Exec(`INSERT INTO browser_cores (core_id, core_name, core_path, is_default, created_at) VALUES ('core-stable', 'Stable', 'unused', 1, CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("", "af-create-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := browser.NewManager(DefaultConfig(), root)
	manager.ProfileDAO = browser.NewSQLiteProfileDAO(db.GetConn())
	manager.CoreDAO = browser.NewSQLiteCoreDAO(db.GetConn())
	manager.InitData()
	runtimeService := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{Manager: manager, Config: DefaultConfig(), Host: BrowserRuntimeHost{StartProcess: func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil }, StopProcess: func(*exec.Cmd) error { return nil }, DetectRuntime: func(string) (BrowserRuntimeDetection, bool) { return BrowserRuntimeDetection{}, false }}})
	host := &FarmClientHost{config: FarmClientConfig{StateRoot: stateRoot}, db: db.GetConn(), manager: manager, runtime: runtimeService, identity: FarmClientIdentity{NodeUID: "node-create-test"}}
	management, err := newFarmProfileManagement(host)
	if err != nil {
		t.Fatal(err)
	}
	return management, db, dbPath
}

func farmProfileCreateRequest(t *testing.T, operationUID, requestUID, name string) FarmProfileCreateRequest {
	t.Helper()
	request, err := NewFarmProfileCreateRequest(operationUID, requestUID, name, "core-stable")
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestFarmProfileCreateConcurrentReplayIsAtomicAndDeterministic(t *testing.T) {
	management, db, _ := newFarmProfileCreateFixture(t)
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "受控 Profile")
	const contenders = 100
	results := make([]FarmProfileCreateResult, contenders)
	errs := make([]error, contenders)
	var wait sync.WaitGroup
	for i := range results {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			results[index], errs[index] = management.Create(request)
		}(i)
	}
	wait.Wait()
	for i := range results {
		if errs[i] != nil || !reflect.DeepEqual(results[i], results[0]) {
			t.Fatalf("contender %d result=%+v err=%v", i, results[i], errs[i])
		}
	}
	var operations, profiles int
	if err := db.GetConn().QueryRow(`SELECT COUNT(*) FROM farm_profile_create_operations`).Scan(&operations); err != nil {
		t.Fatal(err)
	}
	if err := db.GetConn().QueryRow(`SELECT COUNT(*) FROM browser_profiles WHERE profile_id = ?`, results[0].AntProfileID).Scan(&profiles); err != nil {
		t.Fatal(err)
	}
	if operations != 1 || profiles != 1 || results[0].Status != "COMPLETED" {
		t.Fatalf("operations=%d profiles=%d result=%+v", operations, profiles, results[0])
	}
}

func TestFarmProfileCreateRejectsIdempotencyDriftAndABA(t *testing.T) {
	management, db, _ := newFarmProfileCreateFixture(t)
	operationUID, requestUID := uuid.NewString(), uuid.NewString()
	request := farmProfileCreateRequest(t, operationUID, requestUID, "Original")
	created, err := management.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	drift := farmProfileCreateRequest(t, operationUID, requestUID, "Changed")
	if _, err := management.Create(drift); !errors.Is(err, ErrFarmProfileCreateConflict) {
		t.Fatalf("payload drift error=%v", err)
	}
	otherRequest := farmProfileCreateRequest(t, operationUID, uuid.NewString(), "Original")
	if _, err := management.Create(otherRequest); !errors.Is(err, ErrFarmProfileCreateConflict) {
		t.Fatalf("operation reuse error=%v", err)
	}
	if _, err := db.GetConn().Exec(`UPDATE browser_profiles SET deleted_at = '2026-09-13T00:00:00Z' WHERE profile_id = ?`, created.AntProfileID); err != nil {
		t.Fatal(err)
	}
	if _, err := management.Create(request); !errors.Is(err, ErrFarmProfileCreateConflict) {
		t.Fatalf("soft-delete ABA error=%v", err)
	}
}

func TestFarmProfileCreateProfileFailureRollsBackJournal(t *testing.T) {
	management, db, _ := newFarmProfileCreateFixture(t)
	if _, err := db.GetConn().Exec(`CREATE TRIGGER reject_profile_create BEFORE INSERT ON browser_profiles BEGIN SELECT RAISE(ABORT, 'test rollback'); END`); err != nil {
		t.Fatal(err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Rollback")
	if _, err := management.Create(request); err == nil {
		t.Fatal("expected profile insert failure")
	}
	var count int
	if err := db.GetConn().QueryRow(`SELECT COUNT(*) FROM farm_profile_create_operations`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("journal survived rollback count=%d err=%v", count, err)
	}
}

func TestFarmProfileCreateRejectsUnknownCoreAndDeterministicCollision(t *testing.T) {
	management, db, _ := newFarmProfileCreateFixture(t)
	operationUID, requestUID := uuid.NewString(), uuid.NewString()
	digest, err := FarmProfileCreatePayloadDigest("Unknown", "core-missing")
	if err != nil {
		t.Fatal(err)
	}
	unknown := FarmProfileCreateRequest{OperationUID: operationUID, RequestUID: requestUID, PayloadDigest: digest, DisplayName: "Unknown", CoreRef: "core-missing"}
	if _, err := management.Create(unknown); !errors.Is(err, ErrFarmClientIPCInvalid) {
		t.Fatalf("unknown core error=%v", err)
	}
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Collision")
	profileID := deterministicFarmProfileUUID("ant-farm-profile-v1", management.host.identity.NodeUID, request.RequestUID)
	if _, err := db.GetConn().Exec(`INSERT INTO browser_profiles (profile_id, profile_name, user_data_dir, core_id, created_at, updated_at, incarnation_id) VALUES (?, 'foreign', ?, 'core-stable', 'now', 'now', ?)`, profileID, profileID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := management.Create(request); !errors.Is(err, ErrFarmProfileCreateConflict) {
		t.Fatalf("deterministic collision error=%v", err)
	}
	var journalCount int
	if err := db.GetConn().QueryRow(`SELECT COUNT(*) FROM farm_profile_create_operations WHERE request_uid = ?`, request.RequestUID).Scan(&journalCount); err != nil || journalCount != 0 {
		t.Fatalf("collision journal count=%d err=%v", journalCount, err)
	}
}

func TestFarmProfileCreateRejectsReservedAndAmbiguousCoreRefs(t *testing.T) {
	management, db, _ := newFarmProfileCreateFixture(t)
	if _, err := db.GetConn().Exec(`INSERT INTO browser_cores (core_id, core_name, core_path, created_at) VALUES ('default', 'Reserved', 'unused', CURRENT_TIMESTAMP), ('CORE-STABLE', 'Ambiguous', 'unused', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	for _, coreRef := range []string{"default", "DEFAULT", "core-stable", "CORE-STABLE"} {
		digest, err := FarmProfileCreatePayloadDigest("Core test", coreRef)
		if err != nil {
			t.Fatal(err)
		}
		request := FarmProfileCreateRequest{OperationUID: uuid.NewString(), RequestUID: uuid.NewString(), PayloadDigest: digest, DisplayName: "Core test", CoreRef: coreRef}
		if _, err := management.Create(request); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("core_ref %q error=%v", coreRef, err)
		}
	}
	var operations int
	if err := db.GetConn().QueryRow(`SELECT COUNT(*) FROM farm_profile_create_operations`).Scan(&operations); err != nil || operations != 0 {
		t.Fatalf("ambiguous core mutated journal count=%d err=%v", operations, err)
	}
}

func TestFarmProfileCreateRequestValidationIsClosed(t *testing.T) {
	operationUID, requestUID := uuid.NewString(), uuid.NewString()
	for _, item := range []struct{ name, core string }{
		{"", "core-stable"},
		{" leading", "core-stable"},
		{"trailing ", "core-stable"},
		{strings.Repeat("界", 101), "core-stable"},
		{"name", "../core"},
	} {
		if _, err := NewFarmProfileCreateRequest(operationUID, requestUID, item.name, item.core); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("invalid name/core accepted name=%q core=%q err=%v", item.name, item.core, err)
		}
	}
	request := farmProfileCreateRequest(t, operationUID, requestUID, "Valid")
	request.PayloadDigest = strings.Repeat("0", 64)
	management, _, _ := newFarmProfileCreateFixture(t)
	if _, err := management.Create(request); !errors.Is(err, ErrFarmClientIPCInvalid) {
		t.Fatalf("bad digest error=%v", err)
	}
}

func TestFarmProfileCreateReplayRecoversManagerAfterLostACK(t *testing.T) {
	management, db, dbPath := newFarmProfileCreateFixture(t)
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Replay")
	first, err := management.Create(request)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := database.NewDB(dbPath)
	if err != nil || reopened.Migrate() != nil {
		t.Fatalf("restart database: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	manager := browser.NewManager(DefaultConfig(), t.TempDir())
	manager.ProfileDAO = browser.NewSQLiteProfileDAO(reopened.GetConn())
	manager.CoreDAO = browser.NewSQLiteCoreDAO(reopened.GetConn())
	manager.InitData()
	restarted := &farmProfileManagement{host: &FarmClientHost{db: reopened.GetConn(), manager: manager, identity: FarmClientIdentity{NodeUID: "node-create-test"}}}
	second, err := restarted.Create(request)
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatalf("replay=%+v err=%v", second, err)
	}
	restarted.host.manager.Mutex.Lock()
	restored := restarted.host.manager.Profiles[first.AntProfileID]
	restarted.host.manager.Mutex.Unlock()
	expectedSafe := ""
	if restored != nil {
		expectedSafe, _ = farmClientProfileIncarnation(restored.ProfileId, restored.IncarnationID)
	}
	if restored == nil || expectedSafe != first.ProfileIncarnation {
		t.Fatalf("manager not reconciled: %+v", restored)
	}
}

func TestFarmProfileCreateIPCClosedPayloadAndSafeResult(t *testing.T) {
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "Safe")
	payload, _ := json.Marshal(request)
	envelope := farmClientIPCRequest{ProtocolVersion: FarmClientIPCProtocolVersion, RequestUID: uuid.NewString(), Operation: farmClientIPCProfileCreate, Payload: payload}
	if err := validateFarmClientIPCRequest(envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = append(payload[:len(payload)-1], []byte(`,"path":"secret"}`)...)
	if err := validateFarmClientIPCRequest(envelope); !errors.Is(err, ErrFarmClientIPCInvalid) {
		t.Fatalf("unknown field error=%v", err)
	}
	result := FarmProfileCreateResult{OperationUID: request.OperationUID, RequestUID: request.RequestUID, Status: "COMPLETED", AntProfileID: uuid.NewString(), DisplayName: request.DisplayName, ProfileIncarnation: strings.Repeat("a", 64), CoreRef: request.CoreRef}
	raw, _ := json.Marshal(result)
	var decoded FarmProfileCreateResult
	if err := decodeFarmClientIPCResult(farmClientIPCProfileCreate, raw, &decoded); err != nil || !reflect.DeepEqual(result, decoded) {
		t.Fatalf("decode=%+v err=%v", decoded, err)
	}
	for _, invalid := range []string{
		`null`,
		`{"operation_uid":"` + request.OperationUID + `","operation_uid":"` + request.OperationUID + `","request_uid":"` + request.RequestUID + `","payload_digest":"` + request.PayloadDigest + `","display_name":"Safe","core_ref":"core-stable"}`,
		`{"operation_uid":"` + request.OperationUID + `","request_uid":"` + request.RequestUID + `","payload_digest":"` + request.PayloadDigest + `","display_name":"Safe","core_ref":"core-stable","proxy":"secret"}`,
	} {
		envelope.Payload = json.RawMessage(invalid)
		if err := validateFarmClientIPCRequest(envelope); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("invalid payload accepted: %s err=%v", invalid, err)
		}
	}
	for _, invalidResult := range []string{
		`{"operation_uid":"` + request.OperationUID + `","request_uid":"` + request.RequestUID + `","status":"PENDING","ant_profile_id":"` + result.AntProfileID + `","display_name":"Safe","profile_incarnation":"` + result.ProfileIncarnation + `","core_ref":"core-stable"}`,
		`{"operation_uid":"` + request.OperationUID + `","request_uid":"` + request.RequestUID + `","status":"COMPLETED","ant_profile_id":"bad","display_name":"Safe","profile_incarnation":"` + result.ProfileIncarnation + `","core_ref":"core-stable"}`,
	} {
		if err := decodeFarmClientIPCResult(farmClientIPCProfileCreate, json.RawMessage(invalidResult), &decoded); !errors.Is(err, ErrFarmClientIPCInvalid) {
			t.Fatalf("invalid result accepted: %s err=%v", invalidResult, err)
		}
	}
}

func TestFarmProfileCreateThroughResidentIPC(t *testing.T) {
	management, _, _ := newFarmProfileCreateFixture(t)
	server, err := StartFarmClientIPCServer(management.host)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	request := farmProfileCreateRequest(t, uuid.NewString(), uuid.NewString(), "IPC Profile")
	client := &FarmClientIPCClient{stateRoot: management.host.config.StateRoot, timeout: 2 * time.Second}
	result, err := client.ProfileCreate(context.Background(), request)
	if err != nil || result.RequestUID != request.RequestUID || result.DisplayName != request.DisplayName {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}

func TestFarmProfileCreateCapabilityProjectionIsImmutable(t *testing.T) {
	first := FarmClientProfileCreateCapabilities()
	first[0] = "changed"
	second := FarmClientProfileCreateCapabilities()
	if len(second) != 1 || second[0] != FarmClientCapabilityProfileCreate {
		t.Fatalf("capabilities=%v", second)
	}
}
