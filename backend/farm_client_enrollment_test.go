package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type farmClientEnrollmentTestStore struct {
	mu      sync.Mutex
	keys    map[FarmClientIdentityKeyRef]ed25519.PrivateKey
	saves   int
	loadErr error
	saveErr error
}

func (s *farmClientEnrollmentTestStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return nil, s.loadErr
	}
	key := s.keys[ref]
	if key == nil {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	return append(ed25519.PrivateKey(nil), key...), nil
}

func (s *farmClientEnrollmentTestStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.saveErr != nil {
		return s.saveErr
	}
	key, _, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	if existing := s.keys[ref]; existing != nil && !equalBytes(existing, key) {
		clearBytes(key)
		return ErrFarmClientIdentityKeyConflict
	}
	if s.keys == nil {
		s.keys = make(map[FarmClientIdentityKeyRef]ed25519.PrivateKey)
	}
	s.keys[ref] = append(ed25519.PrivateKey(nil), key...)
	clearBytes(key)
	s.saves++
	return nil
}

func (s *farmClientEnrollmentTestStore) Delete(ref FarmClientIdentityKeyRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, ref)
	return nil
}

func farmClientEnrollmentTestConfig(t *testing.T, endpoint string) FarmClientConfig {
	t.Helper()
	return FarmClientConfig{
		ApplicationRoot: t.TempDir(), StateRoot: t.TempDir(),
		ControlURL: "ws://127.0.0.1:1", EnrollmentURL: endpoint,
		AllowLoopbackHTTPEnrollment: true,
		NodeName:                    "Enrollment test node",
		Identity:                    FarmClientIdentityConfig{NodeUID: "node-enroll", PrivateKeyRef: "device-node-enroll"},
	}
}

func TestEnrollFarmClientSendsOnlyPublicIdentityAndReusesStoredKey(t *testing.T) {
	code := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x41}, farmClientEnrollmentCodeBytes))
	var requests []farmClientEnrollmentWireRequest
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		var payload farmClientEnrollmentWireRequest
		if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/json" || json.NewDecoder(request.Body).Decode(&payload) != nil {
			http.Error(writer, "bad request", http.StatusBadRequest)
			return
		}
		requests = append(requests, payload)
		_ = json.NewEncoder(writer).Encode(farmClientEnrollmentWireResponse{
			Success: true, EnrollmentID: int64(len(requests)), NodeID: 9,
			NodeUID: payload.NodeUID, Status: "pending",
		})
	}))
	defer server.Close()
	store := &farmClientEnrollmentTestStore{}
	cfg := farmClientEnrollmentTestConfig(t, server.URL)
	for attempt := 0; attempt < 2; attempt++ {
		result, err := EnrollFarmClient(context.Background(), cfg, code, store, server.Client())
		if err != nil || result.NodeUID != "node-enroll" {
			t.Fatalf("attempt %d result=%+v err=%v", attempt, result, err)
		}
	}
	if store.saves != 1 || len(requests) != 2 || requests[0].DevicePublicKey != requests[1].DevicePublicKey {
		t.Fatalf("pending identity was not reused: saves=%d requests=%+v", store.saves, requests)
	}
	stored, err := store.Load("device-node-enroll")
	if err != nil {
		t.Fatal(err)
	}
	defer clearBytes(stored)
	publicRaw, err := base64.StdEncoding.DecodeString(requests[0].DevicePublicKey)
	if err != nil {
		t.Fatal(err)
	}
	challengeMessage := []byte("authenticated-wss-binding-proof")
	signature := ed25519.Sign(stored, challengeMessage)
	if !ed25519.Verify(ed25519.PublicKey(publicRaw), challengeMessage, signature) {
		t.Fatal("stored enrollment key does not authenticate as the enrolled public key")
	}
	privateEncoded := base64.StdEncoding.EncodeToString(stored)
	seedEncoded := base64.StdEncoding.EncodeToString(stored[:ed25519.SeedSize])
	for _, request := range requests {
		serialized, _ := json.Marshal(request)
		if strings.Contains(string(serialized), privateEncoded) || strings.Contains(string(serialized), seedEncoded) || request.EnrollmentCode != code || request.Platform == "" || request.Architecture == "" {
			t.Fatalf("unsafe or incomplete enrollment request: %s", serialized)
		}
	}
}

func TestEnrollFarmClientFailsClosedWithoutLeakingSecrets(t *testing.T) {
	code := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, farmClientEnrollmentCodeBytes))
	canary := "server-native-error-secret-canary"
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, canary+code, http.StatusServiceUnavailable)
	}))
	defer server.Close()
	store := &farmClientEnrollmentTestStore{}
	_, err := EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, server.URL), code, store, server.Client())
	if !errors.Is(err, ErrFarmClientEnrollmentTransport) || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), code) {
		t.Fatalf("unsafe enrollment error: %v", err)
	}
	store = &farmClientEnrollmentTestStore{loadErr: errors.New(canary)}
	_, err = EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, server.URL), code, store, server.Client())
	if !errors.Is(err, ErrFarmClientIdentityStore) || strings.Contains(err.Error(), canary) {
		t.Fatalf("unsafe identity-store error: %v", err)
	}
}

func TestEnrollFarmClientRejectsInvalidCodeResponseAndRedirect(t *testing.T) {
	validCode := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x43}, farmClientEnrollmentCodeBytes))
	if _, err := EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, "http://127.0.0.1:1"), "not-a-code", &farmClientEnrollmentTestStore{}, nil); !errors.Is(err, ErrFarmClientEnrollmentRejected) {
		t.Fatalf("invalid code error=%v", err)
	}
	redirectReached := false
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirectReached = true }))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL, http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	_, err := EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, redirect.URL), validCode, &farmClientEnrollmentTestStore{}, redirect.Client())
	if !errors.Is(err, ErrFarmClientEnrollmentRejected) || redirectReached {
		t.Fatalf("redirect handling error=%v reached=%v", err, redirectReached)
	}

	unknown := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(`{"success":true,"enrollment_id":1,"node_id":2,"node_uid":"node-enroll","status":"pending","secret":"bad"}`))
	}))
	defer unknown.Close()
	_, err = EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, unknown.URL), validCode, &farmClientEnrollmentTestStore{}, unknown.Client())
	if !errors.Is(err, ErrFarmClientEnrollment) {
		t.Fatalf("unknown response field error=%v", err)
	}
}

func TestEnrollFarmClientClassifiesServerUnavailableAsTransport(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "PRIVATE_KEY_CANARY", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	validCode := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{4}, farmClientEnrollmentCodeBytes))
	_, err := EnrollFarmClient(context.Background(), farmClientEnrollmentTestConfig(t, server.URL), validCode, &farmClientEnrollmentTestStore{}, server.Client())
	if !errors.Is(err, ErrFarmClientEnrollmentTransport) || strings.Contains(err.Error(), "CANARY") {
		t.Fatalf("server unavailable error = %v", err)
	}
}

func TestEnrollFarmClientLostResponseRetryReusesExactIdentity(t *testing.T) {
	code := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{5}, farmClientEnrollmentCodeBytes))
	var attempts atomic.Int32
	var publicKeys []string
	var publicKeysMu sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var payload farmClientEnrollmentWireRequest
		if json.NewDecoder(request.Body).Decode(&payload) != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		publicKeysMu.Lock()
		publicKeys = append(publicKeys, payload.DevicePublicKey)
		publicKeysMu.Unlock()
		if attempts.Add(1) == 1 {
			connection, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = connection.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(farmClientEnrollmentWireResponse{
			Success: true, EnrollmentID: 7, NodeID: 9,
			NodeUID: payload.NodeUID, Status: "pending",
		})
	}))
	defer server.Close()
	store := &farmClientEnrollmentTestStore{}
	cfg := farmClientEnrollmentTestConfig(t, server.URL)
	if _, err := EnrollFarmClient(context.Background(), cfg, code, store, server.Client()); !errors.Is(err, ErrFarmClientEnrollmentTransport) {
		t.Fatalf("lost response error=%v", err)
	}
	if _, err := EnrollFarmClient(context.Background(), cfg, code, store, server.Client()); err != nil {
		t.Fatalf("idempotent confirmation retry failed: %v", err)
	}
	publicKeysMu.Lock()
	defer publicKeysMu.Unlock()
	if len(publicKeys) != 2 || publicKeys[0] != publicKeys[1] || store.saves != 1 {
		t.Fatalf("retry identity changed: keys=%v saves=%d", publicKeys, store.saves)
	}
}

func TestFarmClientConfigIdentitySourcesAndEnrollmentURL(t *testing.T) {
	cfg := farmClientEnrollmentTestConfig(t, "https://controller.example/api/farm/enroll")
	cfg.Identity.PrivateKey = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize))
	if err := cfg.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientIdentity) {
		t.Fatalf("conflicting identity sources error=%v", err)
	}
	cfg = farmClientEnrollmentTestConfig(t, "http://controller.example/api/farm/enroll")
	if err := cfg.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("remote plaintext enrollment URL error=%v", err)
	}
	cfg = farmClientEnrollmentTestConfig(t, "http://127.0.0.1:8080/api/farm/enroll")
	cfg.AllowLoopbackHTTPEnrollment = false
	if err := cfg.ValidateFarmClientConfig(); !errors.Is(err, ErrFarmClientConfig) {
		t.Fatalf("implicit loopback plaintext enrollment URL error=%v", err)
	}
}
