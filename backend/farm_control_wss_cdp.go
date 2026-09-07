package backend

// Control WSS CDP command/tunnel handling.  The authenticated command opens
// a browser-level CDP socket from local Farm-owned state, then the Agent dials
// the Server's CDP tunnel path outbound.  Each WebSocket message is relayed
// as-is; there is no byte-stream framing or node-local URL supplied by Server.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const (
	farmCDPControlTunnelPath = "/control/cdp-tunnel"
	farmCDPMessageBytes      = 32 * 1024 * 1024
	farmCDPWriteTimeout      = 2 * time.Second
	farmCDPCleanupTimeout    = 3 * time.Second
)

type farmControlCDPSession struct {
	browserConn    *websocket.Conn
	tunnelConn     *websocket.Conn
	browserWriteMu sync.Mutex
	tunnelWriteMu  sync.Mutex
	closeOnce      sync.Once
	cleanupOnce    sync.Once
	closed         chan struct{}
	// writeHook is nil in production. Package tests use it only to model a
	// destination that blocks or returns a write error, so cancellation and
	// cleanup are verified without relying on kernel socket-buffer timing.
	writeHook func(*websocket.Conn, int, []byte) error
}

func newFarmControlCDPSession(browserConn, tunnelConn *websocket.Conn) *farmControlCDPSession {
	return &farmControlCDPSession{
		browserConn: browserConn,
		tunnelConn:  tunnelConn,
		closed:      make(chan struct{}),
	}
}

func (session *farmControlCDPSession) write(conn *websocket.Conn, messageType int, payload []byte) error {
	if session == nil || conn == nil {
		return ErrFarmControlWSSClosed
	}
	var writeMu *sync.Mutex
	switch conn {
	case session.browserConn:
		writeMu = &session.browserWriteMu
	case session.tunnelConn:
		writeMu = &session.tunnelWriteMu
	default:
		return ErrFarmControlWSSClosed
	}
	select {
	case <-session.closed:
		return ErrFarmControlWSSClosed
	default:
	}
	writeMu.Lock()
	defer writeMu.Unlock()
	select {
	case <-session.closed:
		return ErrFarmControlWSSClosed
	default:
	}
	if session.writeHook != nil {
		return session.writeHook(conn, messageType, payload)
	}
	if err := conn.SetWriteDeadline(time.Now().Add(farmCDPWriteTimeout)); err != nil {
		return err
	}
	err := conn.WriteMessage(messageType, payload)
	if err == nil {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	return err
}

func (session *farmControlCDPSession) terminate(closeCode int, reason string) {
	if session == nil {
		return
	}
	session.closeOnce.Do(func() {
		if session.closed == nil {
			session.closed = make(chan struct{})
		}
		close(session.closed)
		deadline := time.Now().Add(100 * time.Millisecond)
		message := websocket.FormatCloseMessage(closeCode, reason)
		if session.browserConn != nil {
			_ = session.browserConn.WriteControl(websocket.CloseMessage, message, deadline)
			_ = session.browserConn.Close()
		}
		if session.tunnelConn != nil {
			_ = session.tunnelConn.WriteControl(websocket.CloseMessage, message, deadline)
			_ = session.tunnelConn.Close()
		}
	})
}

func (c *FarmControlWSSClient) addCDPSession(sessionID string, session *farmControlCDPSession) {
	if session == nil || sessionID == "" {
		return
	}
	c.cdpMu.Lock()
	c.cdpSessions[sessionID] = session
	c.cdpMu.Unlock()
}

func (c *FarmControlWSSClient) removeCDPSession(sessionID string, expected *farmControlCDPSession) {
	c.cdpMu.Lock()
	current := c.cdpSessions[sessionID]
	if expected == nil || current == expected {
		delete(c.cdpSessions, sessionID)
	}
	c.cdpMu.Unlock()
}

func (c *FarmControlWSSClient) closeCDPSessions() {
	c.cdpMu.Lock()
	type closedSession struct {
		id      string
		session *farmControlCDPSession
	}
	sessions := make([]closedSession, 0, len(c.cdpSessions))
	for sessionID, session := range c.cdpSessions {
		delete(c.cdpSessions, sessionID)
		sessions = append(sessions, closedSession{id: sessionID, session: session})
	}
	c.cdpMu.Unlock()
	for _, closed := range sessions {
		session := closed.session
		if session == nil {
			continue
		}
		session.terminate(websocket.CloseNormalClosure, "Control WSS closed")
		c.adapter.CloseCDPTunnel(closed.id, session.browserConn)
		c.removeCDPSession(closed.id, session)
	}
}

func farmCDPDecodeRequest(payload any) (FarmCDPTunnelRequest, error) {
	var raw []byte
	switch value := payload.(type) {
	case json.RawMessage:
		raw = append([]byte(nil), value...)
	case []byte:
		raw = append([]byte(nil), value...)
	default:
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			return FarmCDPTunnelRequest{}, ErrFarmCDPRequestInvalid
		}
	}
	if len(raw) == 0 || len(raw) > maxFarmRuntimeEnvelopeBytes {
		return FarmCDPTunnelRequest{}, ErrFarmCDPRequestInvalid
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return FarmCDPTunnelRequest{}, ErrFarmCDPRequestInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var request FarmCDPTunnelRequest
	if err := decoder.Decode(&request); err != nil {
		return FarmCDPTunnelRequest{}, ErrFarmCDPRequestInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FarmCDPTunnelRequest{}, ErrFarmCDPRequestInvalid
	}
	if err := request.validate(); err != nil {
		return FarmCDPTunnelRequest{}, err
	}
	return request, nil
}

func (c *FarmControlWSSClient) controlCDPTunnelURL() (string, error) {
	endpoint, err := url.Parse(c.config.URL)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return "", ErrFarmControlWSSProtocol
	}
	path := strings.TrimSuffix(endpoint.Path, "/")
	if strings.HasSuffix(path, "/control/ws") {
		path = strings.TrimSuffix(path, "/control/ws") + farmCDPControlTunnelPath
	} else {
		path = farmCDPControlTunnelPath
	}
	endpoint.Path = path
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	return endpoint.String(), nil
}

func (c *FarmControlWSSClient) dialCDPTunnel(ctx context.Context, request FarmCDPTunnelRequest) (*websocket.Conn, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	endpoint, err := c.controlCDPTunnelURL()
	if err != nil {
		return nil, err
	}
	dialer := *websocket.DefaultDialer
	if c.config.Dialer != nil {
		dialer = *c.config.Dialer
	}
	dialer.HandshakeTimeout = c.config.HandshakeTimeout
	header := make(http.Header)
	header.Set("X-BF-CDP-Node", c.config.NodeUID)
	header.Set("X-BF-CDP-Session", request.SessionID)
	header.Set("X-BF-CDP-Token", request.TunnelToken)
	conn, _, err := dialer.DialContext(ctx, endpoint, header)
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(farmCDPMessageBytes)
	if err := conn.SetReadDeadline(time.Now().Add(c.config.HandshakeTimeout)); err != nil {
		_ = conn.Close()
		return nil, err
	}
	messageType, raw, err := conn.ReadMessage()
	if err != nil || messageType != websocket.TextMessage {
		_ = conn.Close()
		if err == nil {
			err = ErrFarmControlWSSProtocol
		}
		return nil, err
	}
	var ready struct {
		Type      string `json:"type"`
		SessionID string `json:"session_id"`
	}
	if err := strictFarmControlDecode(raw, &ready, maxFarmControlMessageBytes); err != nil || ready.Type != "cdp_tunnel_ready" || ready.SessionID != request.SessionID {
		_ = conn.Close()
		return nil, ErrFarmControlWSSProtocol
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return conn, nil
}

func (c *FarmControlWSSClient) writeCDPResponse(conn *websocket.Conn, command FarmRuntimeCommand, ok bool, payload any, err error) {
	response := FarmRuntimeCommandResponse{
		Type:          "command_response",
		NodeUID:       c.config.NodeUID,
		CorrelationID: command.CorrelationID,
		OK:            ok,
		Payload:       payload,
	}
	if err != nil {
		response.Error = farmRuntimeWireError(err)
	}
	if writeErr := c.writeJSON(conn, response); writeErr != nil {
		c.shutdown(writeErr)
	}
}

func (c *FarmControlWSSClient) handleOpenCDPCommand(conn *websocket.Conn, command FarmRuntimeCommand) {
	request, err := farmCDPDecodeRequest(command.Payload)
	if err != nil {
		c.writeCDPResponse(conn, command, false, nil, err)
		return
	}
	browserConn, err := c.adapter.OpenCDPTunnel(request)
	if err != nil {
		c.writeCDPResponse(conn, command, false, nil, err)
		return
	}
	ctx, cancel := context.WithTimeout(c.ctx, c.config.CommandTimeout)
	tunnelConn, err := c.dialCDPTunnel(ctx, request)
	cancel()
	if err != nil {
		c.adapter.CloseCDPTunnel(request.SessionID, browserConn)
		c.writeCDPResponse(conn, command, false, nil, ErrFarmControlWSSProtocol)
		return
	}
	session := newFarmControlCDPSession(browserConn, tunnelConn)
	c.addCDPSession(request.SessionID, session)
	ready := FarmCDPTunnelReady{SessionID: request.SessionID, Ready: true}
	if writeErr := c.writeJSON(conn, FarmRuntimeCommandResponse{
		Type:          "command_response",
		NodeUID:       c.config.NodeUID,
		CorrelationID: command.CorrelationID,
		OK:            true,
		Payload:       ready,
	}); writeErr != nil {
		session.terminate(websocket.CloseInternalServerErr, "CDP command response failed")
		c.adapter.CloseCDPTunnel(request.SessionID, browserConn)
		c.removeCDPSession(request.SessionID, session)
		c.shutdown(writeErr)
		return
	}
	go c.relayCDP(request.SessionID, session)
}

func (c *FarmControlWSSClient) relayCDP(sessionID string, session *farmControlCDPSession) {
	if session == nil {
		return
	}
	browserConn, tunnelConn := session.browserConn, session.tunnelConn
	if browserConn == nil || tunnelConn == nil {
		session.terminate(websocket.CloseInternalServerErr, "CDP tunnel incomplete")
		c.adapter.CloseCDPTunnel(sessionID, browserConn)
		c.removeCDPSession(sessionID, session)
		return
	}
	done := make(chan error, 2)
	var pumps sync.WaitGroup
	pumps.Add(2)
	pump := func(source, destination *websocket.Conn) {
		defer pumps.Done()
		for {
			messageType, payload, err := farmReadCDPMessage(source)
			if err != nil {
				done <- farmCDPRelayError(err)
				return
			}
			if err := session.write(destination, messageType, payload); err != nil {
				done <- err
				return
			}
		}
	}
	go pump(browserConn, tunnelConn)
	go pump(tunnelConn, browserConn)
	firstErr := <-done
	closeCode := websocket.CloseNormalClosure
	closeReason := "CDP tunnel closed"
	if errors.Is(firstErr, ErrFarmControlWSSMessageLimit) {
		closeCode = websocket.CloseMessageTooBig
		closeReason = "CDP_MESSAGE_TOO_LARGE"
		message := []byte("{\"error\":\"CDP_MESSAGE_TOO_LARGE\"}")
		_ = session.write(browserConn, websocket.TextMessage, message)
		_ = session.write(tunnelConn, websocket.TextMessage, message)
	}
	// The first terminal event closes both sockets immediately. This interrupts
	// a blocked ReadMessage or a write waiting on the peer; write deadlines are
	// an additional bound for a peer that stops consuming frames.
	session.terminate(closeCode, closeReason)
	waited := make(chan struct{})
	go func() {
		pumps.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(farmCDPCleanupTimeout):
	}
	session.cleanupOnce.Do(func() {
		c.adapter.CloseCDPTunnel(sessionID, browserConn)
		c.removeCDPSession(sessionID, session)
	})
}

// farmReadCDPMessage keeps the relay's allocation bounded while retaining
// enough of an oversized frame to emit the explicit protocol error before the
// 1009 close. Using ReadMessage with an exact read limit lets Gorilla send its
// own close immediately and leaves no opportunity for the error frame.
func farmReadCDPMessage(conn *websocket.Conn) (int, []byte, error) {
	if conn == nil {
		return 0, nil, ErrFarmControlWSSClosed
	}
	conn.SetReadLimit(farmCDPMessageBytes + 1)
	messageType, reader, err := conn.NextReader()
	if err != nil {
		return 0, nil, err
	}
	payload, err := io.ReadAll(io.LimitReader(reader, int64(farmCDPMessageBytes)+1))
	if err != nil {
		return 0, nil, err
	}
	if len(payload) > farmCDPMessageBytes {
		return 0, nil, ErrFarmControlWSSMessageLimit
	}
	return messageType, payload, nil
}

func farmCDPRelayError(err error) error {
	if errors.Is(err, websocket.ErrReadLimit) || websocket.IsCloseError(err, websocket.CloseMessageTooBig) {
		return ErrFarmControlWSSMessageLimit
	}
	return err
}
