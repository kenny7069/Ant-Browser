package backend

import (
	"crypto/ed25519"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

// A first ensure can spend seconds starting Chrome.  Heartbeats must continue
// while that command is admitted: otherwise the control peer can expire the
// authenticated node before ensure returns.
func TestFarmControlWSSClientFirstEnsureDoesNotBlockHeartbeats(t *testing.T) {
	const requiredHeartbeats = 20 // 400ms at the 20ms test cadence; ack deadline is 300ms.
	ensureEntered := make(chan struct{})
	releaseEnsure := make(chan struct{})
	heartbeatsObserved := make(chan struct{})
	serverDone := make(chan error, 1)
	var enterOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseEnsure) }) }
	defer release()

	client, server := newFarmControlTestClient(t, func(connection *websocket.Conn, _ ed25519.PublicKey) {
		defer connection.Close()
		if err := farmControlTestHandshake(connection); err != nil {
			serverDone <- fmt.Errorf("handshake: %w", err)
			return
		}
		if err := connection.WriteJSON(FarmRuntimeCommand{
			Type:          "command",
			NodeUID:       "node-test",
			CorrelationID: "blocked-first-ensure",
			Command:       "ensure_runtime",
			Payload: map[string]any{
				"profile_id":  "profile-1",
				"launch_mode": FarmRuntimeLaunchModeDirectNoProxy,
			},
		}); err != nil {
			serverDone <- fmt.Errorf("send ensure: %w", err)
			return
		}

		heartbeats := 0
		for {
			if err := connection.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
				serverDone <- err
				return
			}
			var envelope struct {
				Type          string `json:"type"`
				HeartbeatID   string `json:"heartbeat_id"`
				CorrelationID string `json:"correlation_id"`
				OK            bool   `json:"ok"`
			}
			if err := connection.ReadJSON(&envelope); err != nil {
				serverDone <- fmt.Errorf("read agent message: %w", err)
				return
			}
			switch envelope.Type {
			case "heartbeat":
				heartbeats++
				if err := connection.WriteJSON(farmControlHeartbeatAck{
					Type:        "heartbeat_ack",
					HeartbeatID: envelope.HeartbeatID,
				}); err != nil {
					serverDone <- fmt.Errorf("ack heartbeat: %w", err)
					return
				}
				if heartbeats == requiredHeartbeats {
					close(heartbeatsObserved)
				}
			case "command_response":
				if envelope.CorrelationID != "blocked-first-ensure" || !envelope.OK {
					serverDone <- fmt.Errorf("unexpected ensure response: %+v", envelope)
					return
				}
				if heartbeats < requiredHeartbeats {
					serverDone <- fmt.Errorf("ensure returned before heartbeat barrier released")
					return
				}
				serverDone <- nil
				return
			default:
				serverDone <- fmt.Errorf("unexpected agent message type %q", envelope.Type)
				return
			}
		}
	})
	defer server.Close()
	client.adapter.service.runtimeService.startReservationHook = func() {
		enterOnce.Do(func() { close(ensureEntered) })
		<-releaseEnsure
	}
	client.adapter.service.resourceTelemetryHooks = &FarmResourceTelemetryHooks{
		ProcessIdentity: func(int) (string, error) {
			return "deterministic-process-start", nil
		},
	}

	if err := client.Connect(nil); err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case <-ensureEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("first ensure did not reach the deterministic start barrier")
	}
	select {
	case <-heartbeatsObserved:
	case err := <-serverDone:
		t.Fatalf("peer ended before observing heartbeats: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("heartbeats stopped while first ensure was blocked")
	}
	select {
	case <-client.Done():
		t.Fatalf("client disconnected during acknowledged ensure: %v", client.Err())
	default:
	}
	release()
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ensure did not finish after releasing the barrier")
	}
}
