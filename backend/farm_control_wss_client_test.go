package backend

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func newFarmControlTestClient(t *testing.T, handler func(*websocket.Conn, ed25519.PublicKey)) (*FarmControlWSSClient, *httptest.Server) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		connection, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(writer, request, nil)
		if err != nil {
			return
		}
		handler(connection, private.Public().(ed25519.PublicKey))
	}))
	url := "ws" + strings.TrimPrefix(server.URL, "http")
	fixture := newFarmRuntimeTestFixture(t, "profile-1")
	adapter, err := NewFarmRuntimeControlAdapter(fixture.farm)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	client, err := NewFarmControlWSSClient(FarmControlWSSClientConfig{
		URL: url, NodeUID: "node-test", PrivateKey: private,
		HandshakeTimeout: time.Second, CommandTimeout: time.Second,
		HeartbeatInterval: 20 * time.Millisecond,
	}, adapter)
	if err != nil {
		server.Close()
		t.Fatal(err)
	}
	return client, server
}

func TestFarmControlWSSClientAuthenticatesAndDispatchesSharedAdapter(t *testing.T) {
	serverDone := make(chan error, 1)
	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, publicKey ed25519.PublicKey) {
		defer connection.Close()
		defer close(serverDone)
		var begin farmControlAuthBegin
		if err := connection.ReadJSON(&begin); err != nil || begin.Type != "auth_begin" || begin.NodeUID != "node-test" {
			serverDone <- fmt.Errorf("auth_begin: %v %+v", err, begin)
			return
		}
		challengeRaw := make([]byte, 32)
		for index := range challengeRaw {
			challengeRaw[index] = byte(index + 1)
		}
		challenge := base64.StdEncoding.EncodeToString(challengeRaw)
		if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: "node-test", Challenge: challenge}); err != nil {
			serverDone <- err
			return
		}
		var prove farmControlAuthProve
		if err := connection.ReadJSON(&prove); err != nil {
			serverDone <- err
			return
		}
		message, err := farmControlAuthMessage("node-test", challenge)
		if err != nil || prove.Type != "auth_prove" || prove.Protocol != farmControlProtocolVersion || prove.NodeUID != "node-test" {
			serverDone <- fmt.Errorf("auth_prove: %v %+v", err, prove)
			return
		}
		signature, err := base64.StdEncoding.DecodeString(prove.Signature)
		if err != nil || !ed25519.Verify(publicKey, message, signature) {
			serverDone <- fmt.Errorf("invalid challenge signature")
			return
		}
		if err := connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: "node-test"}); err != nil {
			serverDone <- err
			return
		}
		command := FarmRuntimeCommand{Type: "command", NodeUID: "node-test", CorrelationID: "inventory-1", Command: "inventory", Payload: map[string]any{}}
		if err := connection.WriteJSON(command); err != nil {
			serverDone <- err
			return
		}
		var response FarmRuntimeCommandResponse
		if err := connection.ReadJSON(&response); err != nil {
			serverDone <- err
			return
		}
		if response.Type != "command_response" || response.NodeUID != "node-test" || response.CorrelationID != "inventory-1" || !response.OK {
			serverDone <- fmt.Errorf("bad command response: %+v", response)
			return
		}
		serverDone <- nil
	})
	defer server.Close()
	if err := client.Connect(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe authenticated dispatch")
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFarmControlWSSClientRejectsContradictoryNodeAndOversize(t *testing.T) {
	for _, test := range []struct {
		name    string
		message func() []byte
	}{
		{name: "wrong-node", message: func() []byte {
			return []byte(`{"type":"command","node_uid":"other","correlation_id":"bad","command":"inventory","payload":{}}`)
		}},
		{name: "oversize", message: func() []byte {
			return []byte(`{"type":"unknown","payload":"` + strings.Repeat("x", maxFarmControlMessageBytes) + `"}`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverDone := make(chan struct{})
			client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
				defer close(serverDone)
				defer connection.Close()
				var begin farmControlAuthBegin
				if connection.ReadJSON(&begin) != nil {
					return
				}
				challengeRaw := make([]byte, 32)
				challenge := base64.StdEncoding.EncodeToString(challengeRaw)
				_ = connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: "node-test", Challenge: challenge})
				var prove farmControlAuthProve
				if connection.ReadJSON(&prove) != nil {
					return
				}
				_ = connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: "node-test"})
				if err := connection.WriteMessage(websocket.TextMessage, test.message()); err != nil {
					t.Logf("server write: %v", err)
				}
				assertFarmControlPeerCloses(t, connection)
			})
			defer server.Close()
			if err := client.Connect(nil); err != nil {
				t.Fatal(err)
			}
			select {
			case <-client.Done():
			case <-time.After(2 * time.Second):
				t.Fatal("contradictory/oversize message did not close client")
			}
			<-serverDone
			if client.Err() == nil {
				t.Fatal("malformed command did not record failure")
			}
		})
	}
}

func TestFarmControlWSSClientMutationSensitiveEnvelopeRejectsDuplicateKeys(t *testing.T) {
	serverDone := make(chan struct{})
	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
		defer close(serverDone)
		defer connection.Close()
		var begin farmControlAuthBegin
		if connection.ReadJSON(&begin) != nil {
			return
		}
		challenge := base64.StdEncoding.EncodeToString(make([]byte, 32))
		_ = connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: "node-test", Challenge: challenge})
		var prove farmControlAuthProve
		if connection.ReadJSON(&prove) != nil {
			return
		}
		_ = connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: "node-test"})
		_ = connection.WriteMessage(websocket.TextMessage, []byte(`{"type":"command","node_uid":"node-test","correlation_id":"x","correlation_id":"y","command":"inventory","payload":{}}`))
		assertFarmControlPeerCloses(t, connection)
	})
	defer server.Close()
	if err := client.Connect(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("duplicate envelope was accepted")
	}
	<-serverDone
	// The client has no pending browser command and therefore cannot leak a
	// response for a malformed/ambiguous envelope.
}

// Keep the server open until the Agent closes; a remote Close cannot make
// these rejection tests pass when the client validator has been removed.
func assertFarmControlPeerCloses(t *testing.T, connection *websocket.Conn) {
	t.Helper()
	_ = connection.SetReadDeadline(time.Now().Add(time.Second))
	for {
		var message struct {
			Type string `json:"type"`
		}
		if err := connection.ReadJSON(&message); err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.ClosePolicyViolation, websocket.CloseMessageTooBig) {
				t.Errorf("expected explicit fail-closed close, got %v", err)
			}
			return
		}
		if message.Type != "heartbeat" {
			t.Errorf("malformed command was dispatched: %s", message.Type)
			return
		}
		_ = connection.WriteJSON(map[string]string{"type": "heartbeat_ack"})
	}
}

func farmControlTestHandshake(connection *websocket.Conn) error {
	var begin farmControlAuthBegin
	if err := connection.ReadJSON(&begin); err != nil {
		return err
	}
	challenge := base64.StdEncoding.EncodeToString(make([]byte, 32))
	if err := connection.WriteJSON(farmControlChallenge{Type: "auth_challenge", Protocol: farmControlProtocolVersion, NodeUID: "node-test", Challenge: challenge}); err != nil {
		return err
	}
	var prove farmControlAuthProve
	if err := connection.ReadJSON(&prove); err != nil {
		return err
	}
	return connection.WriteJSON(farmControlAuthenticated{Type: "authenticated", NodeUID: "node-test"})
}

func TestFarmControlWSSClientCancelAndCloseRace(t *testing.T) {
	for _, duringHandshake := range []bool{false, true} {
		t.Run(fmt.Sprint(duringHandshake), func(t *testing.T) {
			entered := make(chan struct{})
			serverDone := make(chan struct{})
			client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
				defer close(serverDone)
				defer connection.Close()
				if !duringHandshake {
					_ = farmControlTestHandshake(connection)
				} else {
					var begin farmControlAuthBegin
					_ = connection.ReadJSON(&begin)
				}
				close(entered)
				assertFarmControlPeerCloses(t, connection)
			})
			defer server.Close()
			ctx, cancel := context.WithCancel(context.Background())
			connectDone := make(chan error, 1)
			go func() { connectDone <- client.Connect(ctx) }()
			<-entered
			if !duringHandshake {
				if err := <-connectDone; err != nil {
					t.Fatal(err)
				}
			}
			cancel()
			var wg sync.WaitGroup
			for i := 0; i < 20; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); _ = client.Close() }()
			}
			wg.Wait()
			if duringHandshake {
				if err := <-connectDone; err == nil {
					t.Fatal("cancelled handshake succeeded")
				}
			}
			select {
			case <-client.Done():
			case <-time.After(time.Second):
				t.Fatal("cancel did not close")
			}
			if err := client.Connect(context.Background()); err == nil {
				t.Fatal("closed client reconnected")
			}
			<-serverDone
		})
	}
}

func TestFarmControlWSSClientHeartbeatTimeout(t *testing.T) {
	peerDone := make(chan struct{})
	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
		defer close(peerDone)
		defer connection.Close()
		_ = farmControlTestHandshake(connection)
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		for {
			if _, _, err := connection.ReadMessage(); err != nil {
				return
			}
		}
	})
	defer server.Close()
	if err := client.Connect(nil); err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	case <-time.After(500 * time.Millisecond):
		t.Fatal("missing heartbeat ack did not close")
	}
	if !errors.Is(client.Err(), ErrFarmControlWSSClosed) {
		t.Fatalf("unexpected timeout error: %v", client.Err())
	}
	<-peerDone
}

func TestFarmControlWSSClientCommandTimeoutDiscardsLateResponse(t *testing.T) {
	peerDone := make(chan struct{})
	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
		defer close(peerDone)
		defer connection.Close()
		_ = farmControlTestHandshake(connection)
		_ = connection.WriteJSON(FarmRuntimeCommand{Type: "command", NodeUID: "node-test", CorrelationID: "blocked", Command: "inventory", Payload: map[string]any{}})
		assertFarmControlPeerCloses(t, connection)
	})
	defer server.Close()
	client.config.CommandTimeout = 40 * time.Millisecond
	client.adapter.service.recordsMu.Lock()
	if err := client.Connect(nil); err != nil {
		client.adapter.service.recordsMu.Unlock()
		t.Fatal(err)
	}
	select {
	case <-client.Done():
	case <-time.After(time.Second):
		client.adapter.service.recordsMu.Unlock()
		t.Fatal("blocked command did not time out")
	}
	client.adapter.service.recordsMu.Unlock()
	if !errors.Is(client.Err(), context.DeadlineExceeded) {
		t.Fatalf("command timeout = %v", client.Err())
	}
	<-peerDone
}

func TestFarmControlWSSClientHandshakeRejectsIdentityProtocolAndEarlyCommand(t *testing.T) {
	for _, raw := range []string{
		`{"type":"auth_challenge","protocol_version":"bf-p1.6","node_uid":"foreign","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"type":"auth_challenge","protocol_version":"old","node_uid":"node-test","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}`,
		`{"type":"command","node_uid":"node-test","correlation_id":"early","command":"inventory","payload":{}}`,
		`{"type":"auth_challenge","type":"authenticated","node_uid":"node-test"}`,
	} {
		peerDone := make(chan struct{})
		client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
			defer close(peerDone)
			defer connection.Close()
			var begin farmControlAuthBegin
			_ = connection.ReadJSON(&begin)
			_ = connection.WriteMessage(websocket.TextMessage, []byte(raw))
			_ = connection.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := connection.ReadMessage(); err == nil {
				t.Error("rejected handshake sent auth proof or command response")
			}
		})
		if err := client.Connect(nil); err == nil {
			t.Error("malformed handshake succeeded")
		}
		<-peerDone
		server.Close()
	}
}

func TestFarmControlWSSClientConcurrentConnectHasOneOwner(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
		defer connection.Close()
		close(entered)
		<-release
	})
	defer server.Close()
	result := make(chan error, 1)
	go func() { result <- client.Connect(nil) }()
	<-entered
	if err := client.Connect(nil); !errors.Is(err, ErrFarmControlWSSClosed) {
		t.Errorf("second Connect was not rejected: %v", err)
	}
	_ = client.Close()
	close(release)
	if err := <-result; err == nil {
		t.Fatal("first Connect succeeded after close")
	}
}
