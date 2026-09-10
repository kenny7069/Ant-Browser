package backend

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newFarmRuntimeBrowserCDPFixture(t *testing.T) (*farmRuntimeTestFixture, func()) {
	t.Helper()
	var acceptedMu sync.Mutex
	accepted := make([]*websocket.Conn, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/json/version" {
			_, _ = fmt.Fprintf(writer, `{"webSocketDebuggerUrl":"ws://%s/devtools/browser/p114-test"}`, request.Host)
			return
		}
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		acceptedMu.Lock()
		accepted = append(accepted, connection)
		acceptedMu.Unlock()
	}))
	endpoint, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	port, err := strconv.Atoi(endpoint.Port())
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	fixture.runtime.host.DetectRuntime = func(string) (BrowserRuntimeDetection, bool) {
		return BrowserRuntimeDetection{PID: 7001, DebugPort: port, DebugReady: true}, true
	}
	return fixture, func() {
		acceptedMu.Lock()
		for _, connection := range accepted {
			_ = connection.Close()
		}
		acceptedMu.Unlock()
		server.Close()
	}
}

func TestFarmCDPTunnelRejectsUnknownRuntimeAndIdentityContradictions(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:   "session-1",
		TunnelToken: "token-1",
		RuntimeIdentity: FarmRuntimeIdentity{
			NodeUID:            runtime.NodeUID,
			ProfileID:          runtime.ProfileID,
			RuntimeUID:         runtime.RuntimeUID,
			ProviderInstanceID: runtime.ProviderInstanceID,
			FencingEpoch:       runtime.FencingEpoch,
			ConfigHash:         runtime.ConfigHash,
			Generation:         runtime.Generation,
		},
	}
	request.RuntimeIdentity.RuntimeUID = "replacement-runtime"
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPIdentity) {
		t.Fatalf("contradictory runtime identity error = %v", err)
	}
	request.RuntimeIdentity = FarmRuntimeIdentity{}
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPIdentity) {
		t.Fatalf("missing runtime identity error = %v", err)
	}
	request.RuntimeIdentity = runtime.FarmRuntimeIdentity
	request.SessionID = "bad session"
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPRequestInvalid) {
		t.Fatalf("invalid token/session error = %v", err)
	}
}

func TestFarmCDPTunnelOneTimeSessionReplayBeforeLocalDial(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-replay",
		TunnelToken:     "token-replay",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	fixture.farm.cdpSessions[request.SessionID] = &farmCDPSession{}
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPReplay) {
		t.Fatalf("replay error = %v", err)
	}
	delete(fixture.farm.cdpSessions, request.SessionID)
}

func TestFarmCDPTunnelCleanupRetainsTombstoneForFutureAttempt(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-cleanup",
		TunnelToken:     "token-cleanup",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	if err := fixture.farm.claimCDPSession(request); err != nil {
		t.Fatal(err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	fixture.farm.cdpSessions[request.SessionID] = &farmCDPSession{}
	fixture.farm.cdpSessionsMu.Unlock()
	fixture.farm.CloseCDPTunnel(request.SessionID, nil)
	fixture.farm.cdpSessionsMu.Lock()
	_, stillPresent := fixture.farm.cdpSessions[request.SessionID]
	fixture.farm.cdpSessionsMu.Unlock()
	if stillPresent {
		t.Fatal("closed CDP session remained active")
	}
	if _, err := fixture.farm.OpenCDPTunnel(request); !errors.Is(err, ErrFarmCDPReplay) {
		t.Fatalf("future attempt did not hit consumed session tombstone: %v", err)
	}
}

func TestFarmCDPTunnelConcurrentClaimHasExactlyOneWinner(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-concurrent",
		TunnelToken:     "token-concurrent",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	// The local browser dial is expected to fail in this unit fixture, but the
	// first atomic claim must still consume the token before that failure.
	const contenders = 12
	results := make(chan error, contenders)
	var start sync.WaitGroup
	start.Add(1)
	var workers sync.WaitGroup
	for i := 0; i < contenders; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			start.Wait()
			_, openErr := fixture.farm.OpenCDPTunnel(request)
			results <- openErr
		}()
	}
	start.Done()
	workers.Wait()
	close(results)
	winners := 0
	replays := 0
	failedDial := 0
	for openErr := range results {
		if openErr == nil {
			winners++
		} else if errors.Is(openErr, ErrFarmCDPReplay) {
			replays++
		} else if errors.Is(openErr, ErrFarmCDPNotReady) {
			failedDial++
		} else {
			t.Fatalf("unexpected concurrent claim error: %v", openErr)
		}
	}
	if winners != 0 || failedDial != 1 || replays != contenders-1 {
		t.Fatalf("concurrent claim results winners=%d failedDial=%d replays=%d want 0/1/%d", winners, failedDial, replays, contenders-1)
	}
}

func TestFarmCDPTombstonesRemainBounded(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	requests := make([]FarmCDPTunnelRequest, 0, farmCDPMaxTombstones)
	for index := 0; index < farmCDPMaxTombstones; index++ {
		request := FarmCDPTunnelRequest{
			SessionID:       fmt.Sprintf("bounded-session-%d", index),
			TunnelToken:     fmt.Sprintf("bounded-token-%d", index),
			RuntimeIdentity: runtime.FarmRuntimeIdentity,
		}
		if err := fixture.farm.claimCDPSession(request); err != nil {
			t.Fatal(err)
		}
		requests = append(requests, request)
	}
	extra := FarmCDPTunnelRequest{
		SessionID:       "bounded-session-extra",
		TunnelToken:     "bounded-token-extra",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	if err := fixture.farm.claimCDPSession(extra); !errors.Is(err, ErrFarmCDPCapacity) {
		t.Fatalf("full live tombstone set accepted new claim: %v", err)
	}
	if _, err := fixture.farm.OpenCDPTunnel(requests[0]); !errors.Is(err, ErrFarmCDPReplay) {
		t.Fatalf("full live tombstone set evicted first ticket: %v", err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	sessions := len(fixture.farm.cdpTombstones)
	tokens := len(fixture.farm.cdpTokenTombstones)
	fixture.farm.cdpSessionsMu.Unlock()
	if sessions != farmCDPMaxTombstones || tokens != farmCDPMaxTombstones {
		t.Fatalf("full live tombstone set changed: sessions=%d tokens=%d", sessions, tokens)
	}
}

func TestFarmCDPTunnelStrictStopClosesRuntimeSessions(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	fixture.farm.cdpSessions["session-stop"] = &farmCDPSession{identity: runtime.FarmRuntimeIdentity}
	fixture.farm.cdpSessionsMu.Unlock()
	if _, err := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
		NodeUID:            runtime.NodeUID,
		ProfileID:          runtime.ProfileID,
		RuntimeUID:         runtime.RuntimeUID,
		ProviderInstanceID: runtime.ProviderInstanceID,
		FencingEpoch:       runtime.FencingEpoch,
		ConfigHash:         runtime.ConfigHash,
		Generation:         runtime.Generation,
	}); err != nil {
		t.Fatal(err)
	}
	fixture.farm.cdpSessionsMu.Lock()
	_, stillPresent := fixture.farm.cdpSessions["session-stop"]
	fixture.farm.cdpSessionsMu.Unlock()
	if stillPresent {
		t.Fatal("strict runtime stop left a CDP session behind")
	}
}

func TestFarmCDPOpenAndStrictStopAreProfileLinearized(t *testing.T) {
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{ProfileID: "profile-1", ConfigHash: "config-hash"})
	if err != nil {
		t.Fatal(err)
	}
	validated := make(chan struct{})
	releaseValidation := make(chan struct{})
	fixture.farm.cdpOpenHook = func(stage string) {
		if stage != "validated" {
			return
		}
		select {
		case <-validated:
		default:
			close(validated)
		}
		<-releaseValidation
	}
	request := FarmCDPTunnelRequest{
		SessionID:       "session-stop-race",
		TunnelToken:     "token-stop-race",
		RuntimeIdentity: runtime.FarmRuntimeIdentity,
	}
	openDone := make(chan error, 1)
	go func() {
		_, openErr := fixture.farm.OpenCDPTunnel(request)
		openDone <- openErr
	}()
	select {
	case <-validated:
	case <-time.After(2 * time.Second):
		t.Fatal("OpenCDPTunnel did not reach deterministic validation barrier")
	}
	stopDone := make(chan error, 1)
	go func() {
		_, stopErr := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
			NodeUID:            runtime.NodeUID,
			ProfileID:          runtime.ProfileID,
			RuntimeUID:         runtime.RuntimeUID,
			ProviderInstanceID: runtime.ProviderInstanceID,
			FencingEpoch:       runtime.FencingEpoch,
			ConfigHash:         runtime.ConfigHash,
			Generation:         runtime.Generation,
		})
		stopDone <- stopErr
	}()
	select {
	case stopErr := <-stopDone:
		t.Fatalf("strict stop bypassed OpenCDPTunnel profile gate: %v", stopErr)
	case <-time.After(100 * time.Millisecond):
	}
	close(releaseValidation)
	if openErr := <-openDone; openErr == nil {
		t.Fatal("OpenCDPTunnel unexpectedly published a session after the stop race")
	}
	if stopErr := <-stopDone; stopErr != nil {
		t.Fatalf("strict stop after open race: %v", stopErr)
	}
	fixture.farm.cdpSessionsMu.Lock()
	active := len(fixture.farm.cdpSessions)
	tombstones := len(fixture.farm.cdpTombstones)
	fixture.farm.cdpSessionsMu.Unlock()
	if active != 0 || tombstones != 1 {
		t.Fatalf("stop race left active=%d tombstones=%d, want 0/1", active, tombstones)
	}
}

func TestFarmCDPOpenAndStrictStopAreLinearizedAfterDialAndRegister(t *testing.T) {
	for _, stage := range []string{"dialed", "registered"} {
		t.Run(stage, func(t *testing.T) {
			fixture, closeBrowser := newFarmRuntimeBrowserCDPFixture(t)
			defer closeBrowser()
			runtime, err := fixture.farm.EnsureRuntime(FarmRuntimeEnsureRequest{
				ProfileID:  "profile-1",
				ConfigHash: "config-hash",
			})
			if err != nil {
				t.Fatal(err)
			}
			reached := make(chan struct{})
			releaseStage := make(chan struct{})
			var stageOnce sync.Once
			fixture.farm.cdpOpenHook = func(observed string) {
				if observed != stage {
					return
				}
				stageOnce.Do(func() { close(reached) })
				<-releaseStage
			}
			request := FarmCDPTunnelRequest{
				SessionID:       "session-stop-post-" + stage,
				TunnelToken:     "token-stop-post-" + stage,
				RuntimeIdentity: runtime.FarmRuntimeIdentity,
			}
			type openResult struct {
				conn *websocket.Conn
				err  error
			}
			openDone := make(chan openResult, 1)
			go func() {
				conn, openErr := fixture.farm.OpenCDPTunnel(request)
				openDone <- openResult{conn: conn, err: openErr}
			}()
			select {
			case <-reached:
			case <-time.After(2 * time.Second):
				t.Fatal("OpenCDPTunnel did not reach post-dial/register barrier")
			}
			if stage == "registered" {
				fixture.farm.cdpSessionsMu.Lock()
				_, published := fixture.farm.cdpSessions[request.SessionID]
				fixture.farm.cdpSessionsMu.Unlock()
				if !published {
					t.Fatal("registered barrier was reached before session publication")
				}
			}
			stopDone := make(chan error, 1)
			go func() {
				_, stopErr := fixture.farm.StopRuntime(FarmRuntimeStopRequest{
					NodeUID:            runtime.NodeUID,
					ProfileID:          runtime.ProfileID,
					RuntimeUID:         runtime.RuntimeUID,
					ProviderInstanceID: runtime.ProviderInstanceID,
					FencingEpoch:       runtime.FencingEpoch,
					ConfigHash:         runtime.ConfigHash,
					Generation:         runtime.Generation,
				})
				stopDone <- stopErr
			}()
			select {
			case stopErr := <-stopDone:
				t.Fatalf("strict stop bypassed %s profile gate: %v", stage, stopErr)
			case <-time.After(100 * time.Millisecond):
			}
			close(releaseStage)
			result := <-openDone
			if result.err != nil {
				t.Fatalf("OpenCDPTunnel after %s barrier: %v", stage, result.err)
			}
			if stopErr := <-stopDone; stopErr != nil {
				t.Fatalf("strict stop after %s barrier: %v", stage, stopErr)
			}
			if result.conn != nil {
				_ = result.conn.Close()
			}
			fixture.farm.cdpSessionsMu.Lock()
			active := len(fixture.farm.cdpSessions)
			fixture.farm.cdpSessionsMu.Unlock()
			if active != 0 {
				t.Fatalf("strict stop after %s barrier left %d active session(s)", stage, active)
			}
		})
	}
}

func TestFarmCDPCommandPayloadIsStrictAndReadyWireIsAllowlisted(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"session_id":       "session-1",
		"tunnel_token":     "token-1",
		"runtime_identity": FarmRuntimeIdentity{},
		"unexpected":       true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := farmCDPDecodeRequest(raw); !errors.Is(err, ErrFarmCDPRequestInvalid) {
		t.Fatalf("unknown command field error = %v", err)
	}
	encoded, err := json.Marshal(FarmRuntimeCommandResponse{
		Type:    "command_response",
		NodeUID: "node-test",
		OK:      true,
		Payload: FarmCDPTunnelReady{SessionID: "session-1", Ready: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" {
		t.Fatal("empty ready response")
	}
}
