package backend

// This file is the Wails-free outbound side of BF-P1.12.  It speaks only the
// authenticated Control WSS command envelope and hands lifecycle commands to
// the existing FarmRuntimeControlAdapter.  It deliberately contains no CDP
// relay, proxy, listener, or browser locator logic.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	farmControlProtocolVersion  = "bf-p1.6"
	farmControlAuthDomain       = "auto-scraper/browser-farm/node-enrollment-auth/v1"
	defaultFarmControlTimeout   = 5 * time.Second
	defaultFarmControlHeartbeat = 30 * time.Second
	maxFarmControlMessageBytes  = 64 * 1024
)

var (
	ErrFarmControlWSSClosed       = errors.New("farm control WSS client is closed")
	ErrFarmControlWSSProtocol     = errors.New("invalid farm control WSS protocol message")
	ErrFarmControlWSSAuth         = errors.New("farm control WSS authentication failed")
	ErrFarmControlWSSMessageLimit = errors.New("farm control WSS message exceeds limit")
)

// FarmControlWSSClientConfig contains only in-memory identity and bounded
// transport settings. PrivateKey may be an Ed25519 seed or expanded key.
type FarmControlWSSClientConfig struct {
	URL               string
	NodeUID           string
	PrivateKey        ed25519.PrivateKey
	Dialer            *websocket.Dialer
	HandshakeTimeout  time.Duration
	CommandTimeout    time.Duration
	HeartbeatInterval time.Duration
	MaxMessageBytes   int
	// AutoReconnect keeps the authenticated Agent process alive across a
	// controller/WSS restart. It is opt-in for the one-shot P1.12 contract.
	AutoReconnect       bool
	ReconnectMinBackoff time.Duration
	ReconnectMaxBackoff time.Duration
}

type FarmControlWSSClient struct {
	config  FarmControlWSSClientConfig
	adapter *FarmRuntimeControlAdapter
	private ed25519.PrivateKey

	mu                 sync.Mutex
	conn               *websocket.Conn
	closed             bool
	connecting         bool
	closeErr           error
	closeOnce          sync.Once
	done               chan struct{}
	ctx                context.Context
	cancel             context.CancelFunc
	writeMu            sync.Mutex
	commandSlots       chan struct{}
	reconnectNotify    chan struct{}
	supervisorOnce     sync.Once
	cdpMu              sync.Mutex
	cdpSessions        map[string]*farmControlCDPSession
	lastHeartbeatAck   time.Time
	heartbeatSent      map[string]time.Time
	heartbeatTelemetry map[string]FarmResourceTelemetry
	lastControlRTT     time.Duration
	heartbeatSeq       uint64
	connectionCancel   context.CancelFunc
	connectionFence    uint64
}

// NewFarmControlWSSClient constructs the production agent transport without
// a Wails dependency. A nil adapter is rejected so authenticated commands can
// never disappear into a fabricated/mock dispatch path.
func NewFarmControlWSSClient(config FarmControlWSSClientConfig, adapter *FarmRuntimeControlAdapter) (*FarmControlWSSClient, error) {
	if adapter == nil {
		return nil, fmt.Errorf("%w: adapter required", ErrFarmControlWSSProtocol)
	}
	if config.URL == "" || config.NodeUID == "" {
		return nil, fmt.Errorf("%w: URL and node uid required", ErrFarmControlWSSProtocol)
	}
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Fragment != "" {
		return nil, ErrFarmControlWSSProtocol
	}
	loopback := endpoint.Hostname() == "localhost" || net.ParseIP(endpoint.Hostname()).IsLoopback()
	if endpoint.Scheme != "wss" && !(endpoint.Scheme == "ws" && loopback) {
		return nil, fmt.Errorf("%w: TLS required outside loopback", ErrFarmControlWSSProtocol)
	}
	if config.Dialer != nil && config.Dialer.TLSClientConfig != nil && config.Dialer.TLSClientConfig.InsecureSkipVerify {
		return nil, fmt.Errorf("%w: TLS verification required", ErrFarmControlWSSProtocol)
	}
	if adapter.service == nil || adapter.service.NodeUID() != config.NodeUID {
		return nil, fmt.Errorf("%w: adapter node mismatch", ErrFarmControlWSSProtocol)
	}
	if len(config.PrivateKey) != ed25519.SeedSize && len(config.PrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: Ed25519 key must be seed or expanded key", ErrFarmControlWSSAuth)
	}
	privateKey := append(ed25519.PrivateKey(nil), config.PrivateKey...)
	if len(privateKey) == ed25519.SeedSize {
		privateKey = ed25519.NewKeyFromSeed(privateKey)
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = defaultFarmControlTimeout
	}
	if config.CommandTimeout <= 0 {
		config.CommandTimeout = defaultFarmControlTimeout
	}
	if config.HeartbeatInterval <= 0 {
		config.HeartbeatInterval = defaultFarmControlHeartbeat
	}
	if config.MaxMessageBytes <= 0 || config.MaxMessageBytes > maxFarmControlMessageBytes {
		config.MaxMessageBytes = maxFarmControlMessageBytes
	}
	if config.ReconnectMinBackoff <= 0 {
		config.ReconnectMinBackoff = 250 * time.Millisecond
	}
	if config.ReconnectMaxBackoff <= 0 {
		config.ReconnectMaxBackoff = 10 * time.Second
	}
	if config.ReconnectMinBackoff > config.ReconnectMaxBackoff || config.ReconnectMaxBackoff > 120*time.Second {
		return nil, fmt.Errorf("%w: reconnect backoff invalid", ErrFarmControlWSSProtocol)
	}
	if config.HandshakeTimeout > 120*time.Second || config.CommandTimeout > 120*time.Second || config.HeartbeatInterval > 60*time.Second {
		return nil, fmt.Errorf("%w: timeout exceeds limit", ErrFarmControlWSSProtocol)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &FarmControlWSSClient{
		config: config, adapter: adapter, private: privateKey,
		done: make(chan struct{}), ctx: ctx, cancel: cancel, commandSlots: make(chan struct{}, 16),
		reconnectNotify: make(chan struct{}, 1),
		cdpSessions:     make(map[string]*farmControlCDPSession),
		heartbeatSent:   make(map[string]time.Time),
	}, nil
}

type farmControlAuthBegin struct {
	Type         string `json:"type"`
	NodeUID      string `json:"node_uid"`
	DevicePubKey string `json:"device_public_key"`
}

type farmControlChallenge struct {
	Type      string `json:"type"`
	Protocol  string `json:"protocol_version"`
	NodeUID   string `json:"node_uid"`
	Challenge string `json:"challenge"`
}

type farmControlAuthProve struct {
	Type         string `json:"type"`
	Protocol     string `json:"protocol_version"`
	NodeUID      string `json:"node_uid"`
	DevicePubKey string `json:"device_public_key"`
	Challenge    string `json:"challenge"`
	Signature    string `json:"signature"`
}

type farmControlAuthenticated struct {
	Type                 string `json:"type"`
	NodeUID              string `json:"node_uid"`
	ControllerID         string `json:"controller_id"`
	ControllerGeneration uint64 `json:"controller_generation"`
}

type farmControlHeartbeat struct {
	Type        string                 `json:"type"`
	HeartbeatID string                 `json:"heartbeat_id"`
	Telemetry   *FarmResourceTelemetry `json:"telemetry,omitempty"`
}

type farmControlHeartbeatAck struct {
	Type        string `json:"type"`
	HeartbeatID string `json:"heartbeat_id,omitempty"`
}

func strictFarmControlDecode(raw []byte, target any, max int) error {
	if len(raw) > max {
		return ErrFarmControlWSSMessageLimit
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return ErrFarmControlWSSProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return ErrFarmControlWSSProtocol
		}
		return err
	}
	return nil
}

func farmControlFrame(value []byte) []byte {
	result := make([]byte, 4+len(value))
	binary.BigEndian.PutUint32(result[:4], uint32(len(value)))
	copy(result[4:], value)
	return result
}

func farmControlAuthMessage(nodeUID, challenge string) ([]byte, error) {
	challengeRaw, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil || len(challengeRaw) != 32 || base64.StdEncoding.EncodeToString(challengeRaw) != challenge {
		return nil, ErrFarmControlWSSAuth
	}
	result := []byte(farmControlAuthDomain)
	result = append(result, 0)
	result = append(result, farmControlFrame([]byte(farmControlProtocolVersion))...)
	result = append(result, farmControlFrame([]byte(nodeUID))...)
	result = append(result, farmControlFrame(challengeRaw)...)
	return result, nil
}

func (c *FarmControlWSSClient) writeJSON(conn *websocket.Conn, value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(raw) > c.config.MaxMessageBytes {
		return ErrFarmControlWSSMessageLimit
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.ctx.Err() != nil {
		return ErrFarmControlWSSClosed
	}
	if err := conn.SetWriteDeadline(time.Now().Add(c.config.CommandTimeout)); err != nil {
		return err
	}
	return conn.WriteMessage(websocket.TextMessage, raw)
}

func (c *FarmControlWSSClient) readHandshake(conn *websocket.Conn, target any) error {
	if err := conn.SetReadDeadline(time.Now().Add(c.config.HandshakeTimeout)); err != nil {
		return err
	}
	messageType, raw, err := conn.ReadMessage()
	if err != nil {
		return err
	}
	if messageType != websocket.TextMessage {
		return ErrFarmControlWSSProtocol
	}
	return strictFarmControlDecode(raw, target, c.config.MaxMessageBytes)
}

// Connect performs the actual P1.6 challenge/prove exchange, then starts one
// reader and one heartbeat loop. When AutoReconnect is enabled, transport
// loss starts a bounded reconnect supervisor while Chrome/CDP process state
// remains owned by the Agent.
func (c *FarmControlWSSClient) Connect(ctx context.Context) error {
	if c.config.AutoReconnect {
		c.startReconnectSupervisor()
	}
	return c.connectOnce(ctx)
}

func (c *FarmControlWSSClient) connectOnce(ctx context.Context) error {
	c.mu.Lock()
	if c.closed || c.connecting {
		c.mu.Unlock()
		return ErrFarmControlWSSClosed
	}
	c.connecting = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.connecting = false
		c.mu.Unlock()
	}()
	dialer := *websocket.DefaultDialer
	if c.config.Dialer != nil {
		dialer = *c.config.Dialer
	}
	dialer.HandshakeTimeout = c.config.HandshakeTimeout
	if ctx == nil {
		ctx = context.Background()
	}
	stopParent := context.AfterFunc(ctx, func() { c.shutdown(ErrFarmControlWSSClosed) })
	go func() { <-c.done; stopParent() }()
	dialCtx, cancelDial := context.WithTimeout(c.ctx, c.config.HandshakeTimeout)
	defer cancelDial()
	conn, _, err := dialer.DialContext(dialCtx, c.config.URL, http.Header{})
	if err != nil {
		c.fail(err)
		return err
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		_ = conn.Close()
		return ErrFarmControlWSSClosed
	}
	c.conn = conn
	c.mu.Unlock()
	conn.SetReadLimit(int64(c.config.MaxMessageBytes))
	publicKey := c.private.Public().(ed25519.PublicKey)
	if err := c.writeJSON(conn, farmControlAuthBegin{
		Type: "auth_begin", NodeUID: c.config.NodeUID,
		DevicePubKey: base64.StdEncoding.EncodeToString(publicKey),
	}); err != nil {
		_ = conn.Close()
		c.fail(err)
		return err
	}
	var challenge farmControlChallenge
	if err := c.readHandshake(conn, &challenge); err != nil || challenge.Type != "auth_challenge" || challenge.Protocol != farmControlProtocolVersion || challenge.NodeUID != c.config.NodeUID {
		_ = conn.Close()
		if err == nil {
			err = ErrFarmControlWSSAuth
		}
		c.fail(err)
		return err
	}
	message, err := farmControlAuthMessage(c.config.NodeUID, challenge.Challenge)
	if err != nil {
		_ = conn.Close()
		c.fail(err)
		return err
	}
	if err := c.writeJSON(conn, farmControlAuthProve{
		Type: "auth_prove", Protocol: farmControlProtocolVersion,
		NodeUID:      c.config.NodeUID,
		DevicePubKey: base64.StdEncoding.EncodeToString(publicKey),
		Challenge:    challenge.Challenge,
		Signature:    base64.StdEncoding.EncodeToString(ed25519.Sign(c.private, message)),
	}); err != nil {
		_ = conn.Close()
		c.fail(err)
		return err
	}
	var authenticated farmControlAuthenticated
	if err := c.readHandshake(conn, &authenticated); err != nil || authenticated.Type != "authenticated" || authenticated.NodeUID != c.config.NodeUID || strings.TrimSpace(authenticated.ControllerID) == "" || authenticated.ControllerGeneration == 0 {
		_ = conn.Close()
		if err == nil {
			err = ErrFarmControlWSSAuth
		}
		c.fail(err)
		return err
	}
	if err := conn.SetReadDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		c.fail(err)
		return err
	}
	connectionFence, err := c.adapter.BeginAuthenticatedControlConnection(authenticated.ControllerID, authenticated.ControllerGeneration)
	if err != nil {
		_ = conn.Close()
		c.fail(err)
		return err
	}
	connectionCtx, cancelConnection := context.WithCancel(c.ctx)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		cancelConnection()
		c.adapter.EndControlConnection(connectionFence)
		_ = conn.Close()
		return ErrFarmControlWSSClosed
	}
	c.conn = conn
	c.lastHeartbeatAck = time.Now()
	c.lastControlRTT = 0
	c.heartbeatSent = make(map[string]time.Time)
	c.heartbeatTelemetry = make(map[string]FarmResourceTelemetry)
	c.connectionCancel = cancelConnection
	c.connectionFence = connectionFence
	c.mu.Unlock()
	go c.readLoop(conn, connectionCtx, connectionFence)
	go c.heartbeatLoop(conn)
	return nil
}

func (c *FarmControlWSSClient) startReconnectSupervisor() {
	c.supervisorOnce.Do(func() {
		go c.reconnectLoop()
	})
}

func (c *FarmControlWSSClient) reconnectLoop() {
	for {
		select {
		case <-c.reconnectNotify:
		case <-c.done:
			return
		case <-c.ctx.Done():
			return
		}
		backoff := c.config.ReconnectMinBackoff
		for {
			c.mu.Lock()
			closed, connected, connecting := c.closed, c.conn != nil, c.connecting
			c.mu.Unlock()
			if closed || connected || connecting {
				break
			}
			if err := c.connectOnce(c.ctx); err == nil {
				break
			}
			timer := time.NewTimer(backoff)
			select {
			case <-timer.C:
			case <-c.done:
				timer.Stop()
				return
			case <-c.ctx.Done():
				timer.Stop()
				return
			}
			backoff *= 2
			if backoff > c.config.ReconnectMaxBackoff {
				backoff = c.config.ReconnectMaxBackoff
			}
		}
	}
}

func (c *FarmControlWSSClient) notifyReconnect() {
	if !c.config.AutoReconnect {
		return
	}
	select {
	case c.reconnectNotify <- struct{}{}:
	default:
	}
}

func (c *FarmControlWSSClient) fail(err error) {
	if c.config.AutoReconnect {
		c.transportFailure(nil, err)
		return
	}
	c.shutdown(err)
}

func (c *FarmControlWSSClient) transportFailure(conn *websocket.Conn, err error) {
	if !c.config.AutoReconnect {
		c.shutdown(err)
		return
	}
	c.mu.Lock()
	if c.closed || (conn != nil && c.conn != conn) {
		c.mu.Unlock()
		return
	}
	active := c.conn
	cancelConnection := c.connectionCancel
	connectionFence := c.connectionFence
	c.conn = nil
	c.connectionCancel = nil
	c.connectionFence = 0
	c.connecting = false
	if err != nil {
		c.closeErr = err
	}
	c.mu.Unlock()
	if cancelConnection != nil {
		cancelConnection()
	}
	c.adapter.EndControlConnection(connectionFence)
	c.closeCDPSessions()
	if active != nil {
		_ = active.Close()
	}
	c.notifyReconnect()
}

func (c *FarmControlWSSClient) shutdown(err error) {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closed, c.closeErr = true, err
		conn := c.conn
		cancelConnection := c.connectionCancel
		connectionFence := c.connectionFence
		c.conn = nil
		c.connectionCancel = nil
		c.connectionFence = 0
		c.connecting = false
		c.mu.Unlock()
		if cancelConnection != nil {
			cancelConnection()
		}
		c.adapter.EndControlConnection(connectionFence)
		c.closeCDPSessions()
		c.cancel()
		if conn != nil {
			code := websocket.CloseNormalClosure
			if err != nil {
				code = websocket.ClosePolicyViolation
			}
			if errors.Is(err, ErrFarmControlWSSMessageLimit) {
				code = websocket.CloseMessageTooBig
			}
			_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(code, "control session closed"), time.Now().Add(100*time.Millisecond))
			_ = conn.Close()
		}
		close(c.done)
	})
}

func (c *FarmControlWSSClient) readLoop(conn *websocket.Conn, connectionCtx context.Context, connectionFence uint64) {
	defer c.transportFailure(conn, ErrFarmControlWSSClosed)
	for {
		messageType, raw, err := conn.ReadMessage()
		if err != nil {
			if errors.Is(err, websocket.ErrReadLimit) {
				c.shutdown(ErrFarmControlWSSMessageLimit)
			} else {
				c.transportFailure(conn, ErrFarmControlWSSClosed)
			}
			return
		}
		if messageType != websocket.TextMessage || len(raw) > c.config.MaxMessageBytes {
			c.shutdown(ErrFarmControlWSSMessageLimit)
			return
		}
		if err := validateFarmRuntimeJSON(raw); err != nil {
			c.shutdown(fmt.Errorf("%w: %v", ErrFarmControlWSSProtocol, err))
			return
		}
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			c.shutdown(fmt.Errorf("%w: message envelope", ErrFarmControlWSSProtocol))
			return
		}
		switch envelope.Type {
		case "heartbeat_ack":
			var ack farmControlHeartbeatAck
			if strictFarmControlDecode(raw, &ack, c.config.MaxMessageBytes) != nil {
				c.shutdown(ErrFarmControlWSSProtocol)
				return
			}
			now := time.Now()
			c.mu.Lock()
			c.lastHeartbeatAck = now
			if ack.HeartbeatID != "" {
				if sent, ok := c.heartbeatSent[ack.HeartbeatID]; ok {
					if rtt := now.Sub(sent); rtt >= 0 {
						c.lastControlRTT = rtt
					}
					delete(c.heartbeatSent, ack.HeartbeatID)
				}
				if telemetry, ok := c.heartbeatTelemetry[ack.HeartbeatID]; ok {
					c.adapter.AcknowledgeResourceTelemetry(telemetry.SampleSequence, telemetry.ObservedAt)
					delete(c.heartbeatTelemetry, ack.HeartbeatID)
				}
			}
			c.mu.Unlock()
			continue
		case "command":
			command, err := decodeFarmRuntimeEnvelope(raw)
			if err != nil || command.Type != "command" || command.NodeUID != c.config.NodeUID || command.CorrelationID == "" {
				c.shutdown(fmt.Errorf("%w: command envelope", ErrFarmControlWSSProtocol))
				return
			}
			select {
			case c.commandSlots <- struct{}{}:
			case <-connectionCtx.Done():
				return
			default:
				c.shutdown(ErrFarmControlWSSProtocol)
				return
			}
			go func(command FarmRuntimeCommand) {
				defer func() { <-c.commandSlots }()
				if command.Command == "open_cdp_tunnel" {
					// CDP is a separate WebSocket message relay.  It must be
					// opened only after the shared runtime service proves current
					// ownership; the helper sends the compact command response
					// after the outbound tunnel receives its ready handshake.
					service := c.adapter.service
					service.connectionOperationMu.RLock()
					if connectionCtx.Err() == nil && service.connectionIsCurrent(connectionFence) {
						c.handleOpenCDPCommand(conn, command)
					}
					service.connectionOperationMu.RUnlock()
					return
				}
				// Runtime calls retain their existing service ownership/bounds.
				// Cancel the transport wait and discard late results; disconnect
				// must preserve persistent Chrome for subsequent reconciliation.
				result := make(chan FarmRuntimeCommandResponse, 1)
				go func() {
					if connectionCtx.Err() != nil {
						return
					}
					result <- c.adapter.DispatchCommandForConnection(command, connectionFence)
				}()
				timer := time.NewTimer(c.config.CommandTimeout)
				defer timer.Stop()
				select {
				case response := <-result:
					if err := c.writeJSON(conn, response); err != nil {
						c.transportFailure(conn, err)
					}
				case <-timer.C:
					c.transportFailure(conn, context.DeadlineExceeded)
				case <-connectionCtx.Done():
				}
			}(command)
		default:
			c.shutdown(fmt.Errorf("%w: message type", ErrFarmControlWSSProtocol))
			return
		}
	}
}

func (c *FarmControlWSSClient) heartbeatLoop(conn *websocket.Conn) {
	ticker := time.NewTicker(c.config.HeartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.mu.Lock()
			lastAck := c.lastHeartbeatAck
			lastRTT := c.lastControlRTT
			c.mu.Unlock()
			// RTT policy explicitly supports sustained samples above 200ms.  Do
			// not self-disconnect before such a sample can be observed; retain a
			// bounded liveness deadline independent from the sampling cadence.
			ackDeadline := 4 * c.config.HeartbeatInterval
			if ackDeadline < 300*time.Millisecond {
				ackDeadline = 300 * time.Millisecond
			}
			if !lastAck.IsZero() && time.Since(lastAck) > ackDeadline {
				c.transportFailure(conn, ErrFarmControlWSSClosed)
				return
			}
			heartbeatID := strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.FormatUint(atomic.AddUint64(&c.heartbeatSeq, 1), 10)
			var telemetry *FarmResourceTelemetry
			if value, err := c.adapter.ResourceTelemetry(durationMilliseconds(lastRTT)); err == nil {
				telemetry = &value
			}
			sentAt := time.Now()
			c.mu.Lock()
			if len(c.heartbeatSent) >= 64 {
				for id := range c.heartbeatSent {
					delete(c.heartbeatSent, id)
					delete(c.heartbeatTelemetry, id)
					break
				}
			}
			c.heartbeatSent[heartbeatID] = sentAt
			if telemetry != nil {
				c.heartbeatTelemetry[heartbeatID] = *telemetry
			}
			c.mu.Unlock()
			if err := c.writeJSON(conn, farmControlHeartbeat{
				Type: "heartbeat", HeartbeatID: heartbeatID, Telemetry: telemetry,
			}); err != nil {
				c.transportFailure(conn, err)
				return
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func durationMilliseconds(value time.Duration) float64 {
	if value <= 0 {
		return -1
	}
	return float64(value) / float64(time.Millisecond)
}

// ControlRTTMilliseconds returns the latest measured authenticated heartbeat
// round trip. A negative value means no matching heartbeat acknowledgement has
// been observed yet.
func (c *FarmControlWSSClient) ControlRTTMilliseconds() float64 {
	if c == nil {
		return -1
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return durationMilliseconds(c.lastControlRTT)
}

// Done closes when the authenticated connection has terminated. Closing the
// client is bounded by the websocket close and never waits on browser Cmd.Wait.
func (c *FarmControlWSSClient) Done() <-chan struct{} { return c.done }

func (c *FarmControlWSSClient) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeErr
}

func (c *FarmControlWSSClient) Close() error {
	c.shutdown(nil)
	return nil
}
