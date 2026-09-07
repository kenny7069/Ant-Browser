package backend

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newCDPRelaySocketPair(t *testing.T) (*websocket.Conn, *websocket.Conn, func()) {
	t.Helper()
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		accepted <- connection
	}))
	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	client, _, err := websocket.DefaultDialer.Dial(endpoint, nil)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	var peer *websocket.Conn
	select {
	case peer = <-accepted:
	case <-time.After(time.Second):
		client.Close()
		server.Close()
		t.Fatal("CDP relay test peer did not accept")
	}
	return client, peer, func() {
		_ = client.Close()
		_ = peer.Close()
		server.Close()
	}
}

func assertCDPRelayClosed(t *testing.T, client *FarmControlWSSClient, sessionID string, session *farmControlCDPSession, expectOversize bool, peers ...*websocket.Conn) {
	t.Helper()
	select {
	case <-session.closed:
	default:
		t.Fatal("terminal relay event did not close session")
	}
	client.cdpMu.Lock()
	_, active := client.cdpSessions[sessionID]
	client.cdpMu.Unlock()
	if active {
		t.Fatal("terminal relay event left active session map entry")
	}
	for _, peer := range peers {
		if peer == nil {
			continue
		}
		_ = peer.SetReadDeadline(time.Now().Add(time.Second))
		closed := false
		errorFrame := false
		for attempt := 0; attempt < 4; attempt++ {
			_, payload, err := peer.ReadMessage()
			if err != nil {
				if expectOversize {
					if !errorFrame || !websocket.IsCloseError(err, websocket.CloseMessageTooBig) {
						t.Fatalf("oversize relay peer close = %v, error frame=%v", err, errorFrame)
					}
				}
				closed = true
				break
			}
			if !expectOversize {
				t.Fatal("relay peer received a frame after terminal cleanup")
			}
			if string(payload) != `{"error":"CDP_MESSAGE_TOO_LARGE"}` {
				t.Fatalf("oversize relay error frame = %s", payload)
			}
			errorFrame = true
		}
		if !closed {
			t.Fatal("relay peer remained readable after terminal cleanup")
		}
	}
}

func TestFarmControlCDPRelayCloseInterruptsBothDirectionsAndCleansSession(t *testing.T) {
	browserConn, browserPeer, closeBrowser := newCDPRelaySocketPair(t)
	defer closeBrowser()
	tunnelConn, tunnelPeer, closeTunnel := newCDPRelaySocketPair(t)
	defer closeTunnel()
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		t.Fatal(err)
	}
	client := &FarmControlWSSClient{
		adapter:     adapter,
		cdpSessions: make(map[string]*farmControlCDPSession),
	}
	session := newFarmControlCDPSession(browserConn, tunnelConn)
	client.addCDPSession("relay-close", session)
	relayDone := make(chan struct{})
	go func() {
		client.relayCDP("relay-close", session)
		close(relayDone)
	}()
	if err := browserPeer.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-relayDone:
	case <-time.After(3 * time.Second):
		t.Fatal("CDP relay did not terminate after one-side close")
	}
	select {
	case <-session.closed:
	default:
		t.Fatal("terminal relay event did not close session")
	}
	client.cdpMu.Lock()
	_, active := client.cdpSessions["relay-close"]
	client.cdpMu.Unlock()
	if active {
		t.Fatal("terminal relay event left active session map entry")
	}
	_ = tunnelPeer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := tunnelPeer.ReadMessage(); err == nil {
		t.Fatal("opposite tunnel peer remained open after relay close")
	}
}

func TestFarmControlCDPRelayTerminalEventsAreBoundedAndBidirectional(t *testing.T) {
	for _, mode := range []string{"browser-close", "tunnel-close", "write-error", "blocked-write", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			browserConn, browserPeer, closeBrowser := newCDPRelaySocketPair(t)
			defer closeBrowser()
			tunnelConn, tunnelPeer, closeTunnel := newCDPRelaySocketPair(t)
			defer closeTunnel()
			fixture := newFarmRuntimeTestFixture(t, "profile-1")
			adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
			if err != nil {
				t.Fatal(err)
			}
			client := &FarmControlWSSClient{
				adapter:     adapter,
				cdpSessions: make(map[string]*farmControlCDPSession),
			}
			sessionID := "relay-terminal-" + mode
			session := newFarmControlCDPSession(browserConn, tunnelConn)
			var writeStarted chan struct{}
			var writeOnce sync.Once
			switch mode {
			case "write-error":
				session.writeHook = func(conn *websocket.Conn, _ int, _ []byte) error {
					if conn == tunnelConn {
						return errors.New("injected CDP destination write failure")
					}
					return nil
				}
			case "blocked-write":
				writeStarted = make(chan struct{})
				session.writeHook = func(conn *websocket.Conn, _ int, _ []byte) error {
					if conn != tunnelConn {
						return nil
					}
					writeOnce.Do(func() { close(writeStarted) })
					<-session.closed
					return ErrFarmControlWSSClosed
				}
			}
			client.addCDPSession(sessionID, session)
			relayDone := make(chan struct{})
			go func() {
				client.relayCDP(sessionID, session)
				close(relayDone)
			}()
			switch mode {
			case "browser-close":
				_ = browserPeer.Close()
			case "tunnel-close":
				_ = tunnelPeer.Close()
			case "write-error":
				_ = browserPeer.WriteMessage(websocket.TextMessage, []byte("write-error"))
			case "blocked-write":
				if err := browserPeer.WriteMessage(websocket.TextMessage, []byte("blocked-write")); err != nil {
					t.Fatal(err)
				}
				select {
				case <-writeStarted:
				case <-time.After(time.Second):
					t.Fatal("relay did not enter controllable blocked write")
				}
				// The opposite read error must interrupt the blocked destination
				// write; waiting for its deadline would make cleanup unbounded.
				_ = tunnelPeer.Close()
			case "oversize":
				payload := make([]byte, farmCDPMessageBytes+1)
				_ = browserPeer.SetWriteDeadline(time.Now().Add(3 * time.Second))
				_ = browserPeer.WriteMessage(websocket.BinaryMessage, payload)
			}
			select {
			case <-relayDone:
			case <-time.After(4 * time.Second):
				t.Fatal("relay terminal cleanup exceeded bounded deadline")
			}
			assertCDPRelayClosed(t, client, sessionID, session, mode == "oversize", browserPeer, tunnelPeer)
		})
	}
}
