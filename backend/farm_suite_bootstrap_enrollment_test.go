package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"
)

type suiteEnrollmentMemoryStore struct {
	mu      sync.Mutex
	seeds   map[FarmClientIdentityKeyRef][]byte
	saveErr error
	loadErr error
}

func newSuiteEnrollmentMemoryStore() *suiteEnrollmentMemoryStore {
	return &suiteEnrollmentMemoryStore{seeds: map[FarmClientIdentityKeyRef][]byte{}}
}

func (store *suiteEnrollmentMemoryStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	seed, ok := store.seeds[ref]
	if !ok {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	return ed25519.NewKeyFromSeed(append([]byte(nil), seed...)), nil
}

func (store *suiteEnrollmentMemoryStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.saveErr != nil {
		return store.saveErr
	}
	_, seed, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	defer clearBytes(seed)
	if existing, ok := store.seeds[ref]; ok && !equalBytes(existing, seed) {
		return ErrFarmClientIdentityKeyConflict
	}
	store.seeds[ref] = append([]byte(nil), seed...)
	return nil
}

func (store *suiteEnrollmentMemoryStore) Delete(ref FarmClientIdentityKeyRef) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	delete(store.seeds, ref)
	return nil
}

type suiteEnrollmentRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip suiteEnrollmentRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func suiteEnrollmentDiscoveryFixture() SuiteBootstrapDiscovery {
	return SuiteBootstrapDiscovery{
		SchemaVersion: 3, DeploymentUID: "123e4567-e89b-12d3-a456-426614174000",
		MinimumSuiteVersion: "0.1.0-dev", MinimumProtocolVersion: "3.0.0",
		EnrollmentEndpoint:    "https://farm.example.test/api/farm/v3/bootstrap/enroll",
		ControlEndpoint:       "wss://farm.example.test/control/ws",
		SupportedCapabilities: []string{"browser.manage", "profile.list"},
		EndpointAllowlist:     []string{"https://farm.example.test"},
	}
}

func suiteEnrollmentCode(byteValue byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{byteValue}, 32))
}

func suiteEnrollmentSuccessResponse(state string) *http.Response {
	raw := `{"node_uid":"node-accepted-by-server","enrollment_state":"` + state + `","control_endpoint":"wss://farm.example.test/control/ws"}`
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(raw))}
}

func suiteEnrollmentTestDependencies(store FarmClientIdentityStore, roundTrip suiteEnrollmentRoundTripper) suiteBootstrapEnrollmentDependencies {
	return suiteBootstrapEnrollmentDependencies{
		IdentityStore: store,
		Client:        &http.Client{Transport: roundTrip},
		Random:        bytes.NewReader(bytes.Repeat([]byte{0x42}, ed25519.SeedSize)),
	}
}

func TestEnrollSuiteBootstrapLegacyEntryPointFailsClosedWithoutSideEffects(t *testing.T) {
	base := filepath.Join(t.TempDir(), "must-not-exist")
	roots := SuiteUserRoots{Config: filepath.Join(base, "config"), BrowserData: filepath.Join(base, "browser"), AgentState: filepath.Join(base, "state"), Logs: filepath.Join(base, "logs")}
	bootstrap := BootstrapConfig{ServerURL: "https://farm.example.test", StatePath: filepath.Join(roots.AgentState, "setup.json"), NodeName: "Node One"}
	for _, code := range []string{"", suiteEnrollmentCode(0x31), "invalid"} {
		if _, err := EnrollSuiteBootstrap(context.Background(), bootstrap, roots, code); !errors.Is(err, ErrSuiteBootstrapEnrollmentConfig) {
			t.Fatalf("code length=%d err=%v", len(code), err)
		}
	}
	if _, err := os.Lstat(base); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy entry point touched roots: %v", err)
	}
}

func TestEnrollSuiteBootstrapRequireExistingIdentityNeverCreates(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
		t.Fatal("POST with missing identity")
		return nil, nil
	})
	deps.Random = nil
	deps.RequireExistingIdentity = true
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", suiteEnrollmentCode(0x31), suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentIdentity) {
		t.Fatalf("err=%v", err)
	}
	if len(store.seeds) != 0 {
		t.Fatal("require-existing identity was created")
	}
}

func TestLoadSuiteBootstrapEnrollmentPreparationRequiresDraftedExactBootstrap(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	bootstrap := BootstrapConfig{ServerURL: "https://farm.example.test", StatePath: filepath.Join(roots.AgentState, "setup.json"), NodeName: "Node One"}
	digest, err := bootstrapConfigDigest(bootstrap)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := SetupPreparationCheckpoint{SchemaVersion: 1, Stage: SetupInputValidated, RequestUID: "123e4567-e89b-12d3-a456-426614174001", BootstrapSHA256: digest}
	for _, stage := range []SetupStage{SetupInputValidated, SetupUserRootsReady, SetupBootstrapDrafted} {
		checkpoint.Stage = stage
		if err := saveSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName), checkpoint); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := loadSuiteBootstrapEnrollmentPreparation(bootstrap, roots)
	if err != nil || loaded.RequestUID != checkpoint.RequestUID {
		t.Fatalf("preparation=%+v err=%v", loaded, err)
	}
	changed := bootstrap
	changed.NodeName = "Other Node"
	if _, err := loadSuiteBootstrapEnrollmentPreparation(changed, roots); !errors.Is(err, ErrSuiteBootstrapEnrollmentConfig) {
		t.Fatalf("bootstrap drift error=%v", err)
	}
	missingRoots := suiteBootstrapEnrollmentTestRoots(t)
	missing := bootstrap
	missing.StatePath = filepath.Join(missingRoots.AgentState, "setup.json")
	if _, err := loadSuiteBootstrapEnrollmentPreparation(missing, missingRoots); !errors.Is(err, ErrSuiteBootstrapEnrollmentConfig) {
		t.Fatalf("missing preparation error=%v", err)
	}
}

func TestSuiteBootstrapEnrollmentNodeUIDWireContract(t *testing.T) {
	for _, value := range []string{"node-1", "node.example:8443", strings.Repeat("a", 128)} {
		if !validSuiteBootstrapEnrollmentNodeUID(value) {
			t.Fatalf("valid node UID rejected: %q", value)
		}
	}
	for _, value := range []string{strings.Repeat("a", 129), " leading", "trailing ", "node uid", "node\x00uid", "nøde", string([]byte{0xff})} {
		if validSuiteBootstrapEnrollmentNodeUID(value) {
			t.Fatalf("invalid node UID accepted: %q", value)
		}
	}
}

func TestSuiteBootstrapEnrollmentNodeNameWireContract(t *testing.T) {
	for _, value := range []string{strings.Repeat("é", 100), "Node One"} {
		if !validSuiteBootstrapEnrollmentNodeName(value) {
			t.Fatalf("valid node name rejected: rune_count=%d", utf8.RuneCountInString(value))
		}
	}
	for _, value := range []string{strings.Repeat("é", 101), " Node", "Node ", "node\x00name", string([]byte{0xff})} {
		if validSuiteBootstrapEnrollmentNodeName(value) {
			t.Fatalf("invalid node name accepted: %q", value)
		}
	}
}

func TestEnrollSuiteBootstrapACKNodeUIDSecretWordsAreSafeValues(t *testing.T) {
	for _, nodeUID := range []string{"token", "password"} {
		t.Run(nodeUID, func(t *testing.T) {
			roots := suiteBootstrapEnrollmentTestRoots(t)
			store := newSuiteEnrollmentMemoryStore()
			calls := 0
			deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
				calls++
				raw, _ := json.Marshal(suiteBootstrapEnrollmentResponse{NodeUID: nodeUID, EnrollmentState: "ENROLLED", ControlEndpoint: suiteEnrollmentDiscoveryFixture().ControlEndpoint})
				return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(raw))}, nil
			})
			result, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", suiteEnrollmentCode(0x61), suiteEnrollmentDiscoveryFixture(), deps)
			if err != nil || result.NodeUID != nodeUID {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			loaded, err := loadSuiteBootstrapEnrollmentAttempt(roots)
			if err != nil || loaded.NodeUID != nodeUID {
				t.Fatalf("loaded=%+v err=%v", loaded, err)
			}
			result, err = enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", "", suiteEnrollmentDiscoveryFixture(), deps)
			if err != nil || result.NodeUID != nodeUID || calls != 1 {
				t.Fatalf("empty-code resume=%+v calls=%d err=%v", result, calls, err)
			}
		})
	}
}

func TestEnrollSuiteBootstrapFreshPersistsBeforePOSTAndKeepsJournalSecretFree(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	code := suiteEnrollmentCode(0x11)
	publicRaw := ""
	deps := suiteEnrollmentTestDependencies(store, func(request *http.Request) (*http.Response, error) {
		attempt, err := loadSuiteBootstrapEnrollmentAttempt(roots)
		if err != nil || attempt == nil || attempt.Stage != SuiteBootstrapRequestReady {
			t.Fatalf("attempt before POST=%+v err=%v", attempt, err)
		}
		if request.Method != http.MethodPost || request.URL.String() != suiteEnrollmentDiscoveryFixture().EnrollmentEndpoint || request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" || request.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("request method=%s URL=%s headers=%v", request.Method, request.URL, request.Header)
		}
		var body map[string]json.RawMessage
		raw, _ := io.ReadAll(request.Body)
		if len(raw) > maxSuiteBootstrapEnrollmentBytes || json.Unmarshal(raw, &body) != nil || !exactFarmClientIPCKeys(body, []string{"request_uid", "enrollment_code", "device_public_key_ed25519_b64", "metadata"}) {
			t.Fatalf("request body invalid: %s", raw)
		}
		if string(body["enrollment_code"]) != `"`+code+`"` {
			t.Fatal("enrollment code changed")
		}
		_ = json.Unmarshal(body["device_public_key_ed25519_b64"], &publicRaw)
		var metadata map[string]json.RawMessage
		if json.Unmarshal(body["metadata"], &metadata) != nil || !exactFarmClientIPCKeys(metadata, []string{"node_name", "suite_version"}) {
			t.Fatalf("metadata=%s", body["metadata"])
		}
		if request.Header.Get("Idempotency-Key") != "ant-suite-enrollment-v3-123e4567-e89b-12d3-a456-426614174001" {
			t.Fatalf("idempotency=%q", request.Header.Get("Idempotency-Key"))
		}
		return suiteEnrollmentSuccessResponse("ENROLLED"), nil
	})
	result, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps)
	if err != nil || result.EnrollmentState != "ENROLLED" || result.NodeUID != "node-accepted-by-server" {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	raw, err := os.ReadFile(filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName))
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{code, publicRaw, "private_key", "device_public_key_ed25519_b64", "enrollment_code\""} {
		if forbidden != "" && strings.Contains(string(raw), forbidden) {
			t.Fatalf("journal contains forbidden value %q", forbidden)
		}
	}
	calls := 0
	deps.Client = &http.Client{Transport: suiteEnrollmentRoundTripper(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("must not POST acknowledged attempt")
	})}
	recovered, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", "", suiteEnrollmentDiscoveryFixture(), deps)
	if err != nil || calls != 0 || recovered.NodeUID != result.NodeUID {
		t.Fatalf("durable ACK recovery=%+v calls=%d err=%v", recovered, calls, err)
	}
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", suiteEnrollmentCode(0x12), suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("changed code after ACK error=%v", err)
	}
}

func TestEnrollSuiteBootstrapIdentityCrashAndACKLossRetryReuseIdentityAndRequest(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	code := suiteEnrollmentCode(0x21)
	crash := true
	deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentSuccessResponse("ENROLLED"), nil
	})
	deps.AfterIdentityPersisted = func() error {
		if crash {
			crash = false
			return errors.New("injected identity crash")
		}
		return nil
	}
	_, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps)
	if !errors.Is(err, ErrSuiteBootstrapEnrollmentIdentity) {
		t.Fatalf("identity crash error=%v", err)
	}
	if attempt, loadErr := loadSuiteBootstrapEnrollmentAttempt(roots); loadErr != nil || attempt != nil {
		t.Fatalf("journal written before identity confirmation: %+v %v", attempt, loadErr)
	}
	var requests [][]byte
	var idempotency []string
	calls := 0
	deps.Client = &http.Client{Transport: suiteEnrollmentRoundTripper(func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		requests = append(requests, raw)
		idempotency = append(idempotency, request.Header.Get("Idempotency-Key"))
		calls++
		if calls == 1 {
			return nil, errors.New("ACK lost")
		}
		return suiteEnrollmentSuccessResponse("ALREADY_ENROLLED"), nil
	})}
	result, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps)
	if err != nil || result.EnrollmentState != "ALREADY_ENROLLED" || len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) || idempotency[0] != idempotency[1] {
		t.Fatalf("retry result=%+v requests=%d ids=%v err=%v", result, len(requests), idempotency, err)
	}
}

func TestEnrollSuiteBootstrapRejectsBindingAndIdentityDrift(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	code := suiteEnrollmentCode(0x31)
	deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
		return nil, errors.New("offline")
	})
	_, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps)
	if !errors.Is(err, ErrSuiteBootstrapEnrollmentTransport) {
		t.Fatalf("initial error=%v", err)
	}
	changed := suiteEnrollmentDiscoveryFixture()
	changed.ControlEndpoint = "wss://farm.example.test:8443/control/ws"
	changed.EndpointAllowlist = []string{"https://farm.example.test", "https://farm.example.test:8443"}
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, changed, deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("discovery drift error=%v", err)
	}
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node Two", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("metadata drift error=%v", err)
	}
	attempt, _ := loadSuiteBootstrapEnrollmentAttempt(roots)
	ref, _ := NewFarmClientIdentityKeyRef(attempt.IdentityRef)
	store.mu.Lock()
	store.seeds[ref] = bytes.Repeat([]byte{0x99}, ed25519.SeedSize)
	store.mu.Unlock()
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("identity drift error=%v", err)
	}
}

func TestPostSuiteBootstrapEnrollmentClosedResponseAndStatusMatrix(t *testing.T) {
	endpoint := suiteEnrollmentDiscoveryFixture().EnrollmentEndpoint
	cases := []struct {
		name        string
		status      int
		body        string
		contentType string
		want        error
	}{
		{"server", 503, "secret server body", "text/plain", ErrSuiteBootstrapEnrollmentRetryable},
		{"rate limit", 429, "secret rate body", "text/plain", ErrSuiteBootstrapEnrollmentRetryable},
		{"rejected", 400, "secret rejection", "application/json", ErrSuiteBootstrapEnrollmentRejected},
		{"conflict", 409, "secret conflict", "application/json", ErrSuiteBootstrapEnrollmentConflict},
		{"unknown", 200, `{"node_uid":"node","enrollment_state":"ENROLLED","control_endpoint":"wss://farm.example.test/control/ws","secret":"x"}`, "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"duplicate", 200, `{"node_uid":"node","node_uid":"node","enrollment_state":"ENROLLED","control_endpoint":"wss://farm.example.test/control/ws"}`, "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"state", 200, `{"node_uid":"node","enrollment_state":"READY","control_endpoint":"wss://farm.example.test/control/ws"}`, "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"node control character", 200, "{\"node_uid\":\"node\\u0001\",\"enrollment_state\":\"ENROLLED\",\"control_endpoint\":\"wss://farm.example.test/control/ws\"}", "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"invalid control endpoint", 200, `{"node_uid":"node","enrollment_state":"ENROLLED","control_endpoint":"wss://farm.example.test/control/ws?x=1"}`, "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"control", 200, `{"node_uid":"node","enrollment_state":"ENROLLED","control_endpoint":"wss://evil.example.test/control/ws"}`, "application/json", nil},
		{"truncated", 200, `{"node_uid":`, "application/json", ErrSuiteBootstrapEnrollmentResponse},
		{"type", 200, `{}`, "text/plain", ErrSuiteBootstrapEnrollmentResponse},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client := &http.Client{Transport: suiteEnrollmentRoundTripper(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: test.status, Header: http.Header{"Content-Type": []string{test.contentType}}, Body: io.NopCloser(strings.NewReader(test.body))}, nil
			})}
			response, err := postSuiteBootstrapEnrollment(context.Background(), client, endpoint, "stable", []byte(`{}`))
			if test.name == "control" {
				if err != nil || response.ControlEndpoint == "" {
					t.Fatalf("control parse response=%+v err=%v", response, err)
				}
				return
			}
			if !errors.Is(err, test.want) || strings.Contains(strings.ToLower(err.Error()), "secret") || strings.Contains(err.Error(), endpoint) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	oversized := strings.Repeat(" ", maxSuiteBootstrapEnrollmentBytes+1)
	client := &http.Client{Transport: suiteEnrollmentRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(oversized))}, nil
	})}
	if _, err := postSuiteBootstrapEnrollment(context.Background(), client, endpoint, "stable", []byte(`{}`)); !errors.Is(err, ErrSuiteBootstrapEnrollmentResponse) {
		t.Fatalf("oversized response error=%v", err)
	}
}

func TestPostSuiteBootstrapEnrollmentRetriesExactRequestWithinBound(t *testing.T) {
	endpoint := suiteEnrollmentDiscoveryFixture().EnrollmentEndpoint
	body := []byte(`{"request":"same"}`)
	var requests [][]byte
	var keys []string
	calls := 0
	client := &http.Client{Transport: suiteEnrollmentRoundTripper(func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		requests = append(requests, raw)
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		calls++
		if calls < 3 {
			return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("secret"))}, nil
		}
		return suiteEnrollmentSuccessResponse("ALREADY_ENROLLED"), nil
	})}
	response, err := postSuiteBootstrapEnrollment(context.Background(), client, endpoint, "stable-key", body)
	if err != nil || response.EnrollmentState != "ALREADY_ENROLLED" || calls != 3 {
		t.Fatalf("response=%+v calls=%d err=%v", response, calls, err)
	}
	for index := range requests {
		if !bytes.Equal(requests[index], body) || keys[index] != "stable-key" {
			t.Fatalf("retry %d changed body/header", index)
		}
	}
}

func TestPostSuiteBootstrapEnrollmentDoesNotRetryTLSRedirectOrOversizedHeaders(t *testing.T) {
	endpoint := suiteEnrollmentDiscoveryFixture().EnrollmentEndpoint
	tests := []struct {
		name      string
		roundTrip suiteEnrollmentRoundTripper
		want      error
	}{
		{"TLS", func(*http.Request) (*http.Response, error) {
			return nil, &tls.CertificateVerificationError{}
		}, ErrSuiteBootstrapEnrollmentTLS},
		{"redirect", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://other.example.test/"}}, Body: io.NopCloser(strings.NewReader("")), Request: request}, nil
		}, ErrSuiteBootstrapEnrollmentRedirect},
		{"header", func(request *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}, "X-Fill": []string{strings.Repeat("x", maxSuiteBootstrapHeaderBytes)}}, Body: io.NopCloser(strings.NewReader(`{}`)), Request: request}, nil
		}, ErrSuiteBootstrapEnrollmentResponse},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			client := &http.Client{Transport: suiteEnrollmentRoundTripper(func(request *http.Request) (*http.Response, error) {
				calls++
				return test.roundTrip(request)
			})}
			_, err := postSuiteBootstrapEnrollment(context.Background(), client, endpoint, "stable", []byte(`{}`))
			if !errors.Is(err, test.want) || calls != 1 || strings.Contains(err.Error(), endpoint) {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
		})
	}
}

func TestEnrollSuiteBootstrapRejectsInvalidCodeStoreFailureAndControlDriftSafely(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	calls := 0
	deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"node_uid":"node","enrollment_state":"ENROLLED","control_endpoint":"wss://evil.example.test/control/ws"}`))}, nil
	})
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", "not-base64", suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentConfig) {
		t.Fatalf("invalid code error=%v", err)
	}
	if len(store.seeds) != 0 || calls != 0 {
		t.Fatal("invalid code created identity or called transport")
	}
	store.saveErr = errors.New("secret store detail")
	code := suiteEnrollmentCode(0x51)
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentIdentity) || strings.Contains(err.Error(), code) || strings.Contains(strings.ToLower(err.Error()), "secret") {
		t.Fatalf("store error=%v", err)
	}
	store.saveErr = nil
	deps.Random = bytes.NewReader(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	if _, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", code, suiteEnrollmentDiscoveryFixture(), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentResponse) {
		t.Fatalf("control drift error=%v", err)
	}
	attempt, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil || attempt.Stage != SuiteBootstrapRequestReady {
		t.Fatalf("attempt after response drift=%+v err=%v", attempt, err)
	}
	for _, value := range []string{code, "secret", suiteEnrollmentDiscoveryFixture().EnrollmentEndpoint} {
		if strings.Contains(attempt.String(), value) || strings.Contains(ErrSuiteBootstrapEnrollmentResponse.Error(), value) {
			t.Fatalf("safe string leaked %q", value)
		}
	}
	if strings.Contains((SuiteBootstrapEnrollmentAttempt{Stage: "secret-stage"}).String(), "secret") || strings.Contains((SuiteBootstrapEnrollmentResult{EnrollmentState: "secret-state"}).String(), "secret") {
		t.Fatal("unvalidated String value leaked")
	}
}

func TestEnrollSuiteBootstrapConcurrentLockRejectsSecondAttempt(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	store := newSuiteEnrollmentMemoryStore()
	entered := make(chan struct{})
	release := make(chan struct{})
	deps := suiteEnrollmentTestDependencies(store, func(*http.Request) (*http.Response, error) {
		close(entered)
		<-release
		return suiteEnrollmentSuccessResponse("ENROLLED"), nil
	})
	firstDone := make(chan error, 1)
	go func() {
		_, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", suiteEnrollmentCode(0x41), suiteEnrollmentDiscoveryFixture(), deps)
		firstDone <- err
	}()
	<-entered
	_, err := enrollSuiteBootstrapWithDependencies(context.Background(), roots, "123e4567-e89b-12d3-a456-426614174001", "Node One", "0.1.0-dev", suiteEnrollmentCode(0x41), suiteEnrollmentDiscoveryFixture(), deps)
	if !errors.Is(err, ErrSuiteSetupLocked) {
		t.Fatalf("second attempt error=%v", err)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first attempt error=%v", err)
	}
}
