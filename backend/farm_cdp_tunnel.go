package backend

// Farm Agent CDP tunnel ownership.  This layer is intentionally transport
// agnostic: FarmControlWSSClient supplies the outbound WebSocket, while this
// service proves that the requested runtime is owned/current and opens only
// the browser-level CDP socket resolved from local service state.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	farmCDPMaxSessionID  = 128
	farmCDPMaxToken      = 256
	farmCDPTombstoneTTL  = 10 * time.Minute
	farmCDPMaxTombstones = 4096
)

var (
	ErrFarmCDPRequestInvalid = errors.New("farm CDP tunnel request invalid")
	ErrFarmCDPReplay         = errors.New("farm CDP tunnel session replay")
	ErrFarmCDPCapacity       = errors.New("farm CDP tunnel replay tombstone capacity reached")
	ErrFarmCDPIdentity       = errors.New("farm CDP tunnel identity mismatch")
	ErrFarmCDPNotReady       = errors.New("farm CDP runtime is not ready")
)

type FarmCDPTunnelRequest struct {
	SessionID       string              `json:"session_id"`
	TunnelToken     string              `json:"tunnel_token"`
	RuntimeIdentity FarmRuntimeIdentity `json:"runtime_identity"`
}

type FarmCDPTunnelReady struct {
	SessionID string `json:"session_id"`
	Ready     bool   `json:"ready"`
}

type farmCDPSession struct {
	identity  FarmRuntimeIdentity
	tokenHash string
	conn      *websocket.Conn
}

type farmCDPTombstone struct {
	tokenHash string
	identity  FarmRuntimeIdentity
	expiresAt time.Time
}

func farmCDPTokenHash(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}

func validateFarmCDPToken(value string, maximum int) error {
	trimmed := strings.TrimSpace(value)
	if value != trimmed || trimmed == "" || len(value) > maximum || strings.ContainsAny(value, "\r\n\t ") {
		return ErrFarmCDPRequestInvalid
	}
	return nil
}

func (s *FarmRuntimeService) validateCDPRequest(request FarmCDPTunnelRequest) (farmRuntimeRecord, error) {
	if s == nil {
		return farmRuntimeRecord{}, ErrFarmRuntimeServiceUnavailable
	}
	if err := request.validate(); err != nil {
		return farmRuntimeRecord{}, err
	}
	identity := request.RuntimeIdentity
	if identity.NodeUID == "" || identity.ProfileID == "" || identity.RuntimeUID == "" || identity.ProviderInstanceID == "" || identity.ConfigHash == "" || identity.FencingEpoch == 0 || identity.Generation == 0 {
		return farmRuntimeRecord{}, ErrFarmCDPIdentity
	}
	controllerID, controllerGeneration := s.controllerBinding()
	if controllerID != "" {
		if identity.ControllerID != controllerID || identity.ControllerGeneration != controllerGeneration || identity.ControllerGeneration == 0 {
			return farmRuntimeRecord{}, ErrFarmCDPIdentity
		}
	} else if identity.ControllerID != "" || identity.ControllerGeneration != 0 {
		return farmRuntimeRecord{}, ErrFarmCDPIdentity
	}
	if err := s.validateControllerIdentity(identity.NodeUID, identity.ProviderInstanceID, identity.FencingEpoch); err != nil {
		return farmRuntimeRecord{}, ErrFarmCDPIdentity
	}
	record, owned := s.currentRecord(identity.ProfileID)
	if !owned {
		return farmRuntimeRecord{}, ErrFarmRuntimeUnknown
	}
	if record.runtime.FarmRuntimeIdentity != identity {
		return farmRuntimeRecord{}, ErrFarmCDPIdentity
	}
	if record.runtime.State != FarmRuntimeStateIdle || !record.runtime.DebugReady {
		return farmRuntimeRecord{}, ErrFarmCDPNotReady
	}
	return record, nil
}

// OpenCDPTunnel validates the full Farm identity before opening a local
// browser-level CDP WebSocket.  No port or URL from the Server command is
// consumed here.
func (s *FarmRuntimeService) OpenCDPTunnel(request FarmCDPTunnelRequest) (*websocket.Conn, error) {
	if s == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	s.controllerOperationMu.RLock()
	defer s.controllerOperationMu.RUnlock()
	if err := request.validate(); err != nil {
		return nil, err
	}
	if request.RuntimeIdentity.NodeUID == "" || request.RuntimeIdentity.ProfileID == "" ||
		request.RuntimeIdentity.RuntimeUID == "" || request.RuntimeIdentity.ProviderInstanceID == "" ||
		request.RuntimeIdentity.ConfigHash == "" || request.RuntimeIdentity.FencingEpoch == 0 ||
		request.RuntimeIdentity.Generation == 0 {
		return nil, ErrFarmCDPIdentity
	}
	profileID := strings.TrimSpace(request.RuntimeIdentity.ProfileID)
	release, err := s.acquire(profileID)
	if err != nil {
		return nil, err
	}
	defer release()
	if s.cdpOpenHook != nil {
		s.cdpOpenHook("validate")
	}
	record, err := s.validateCDPRequest(request)
	if err != nil {
		return nil, err
	}
	if s.cdpOpenHook != nil {
		s.cdpOpenHook("validated")
	}
	if err := s.claimCDPSession(request); err != nil {
		return nil, err
	}
	conn, err := s.runtimeService.OpenOwnedBrowserCDP(
		record.runtime.ProfileID,
		record.runtime.Generation,
	)
	if err != nil {
		return nil, ErrFarmCDPNotReady
	}
	if s.cdpOpenHook != nil {
		s.cdpOpenHook("dialed")
	}
	// StopRuntime uses the same Farm profile gate. This second identity read
	// closes the post-dial window even if the local Chrome state changed while
	// the browser-level WebSocket handshake was in flight.
	if _, err := s.validateCDPRequest(request); err != nil {
		_ = conn.Close()
		return nil, err
	}
	s.cdpSessionsMu.Lock()
	s.cdpSessions[request.SessionID] = &farmCDPSession{
		identity:  request.RuntimeIdentity,
		tokenHash: farmCDPTokenHash(request.TunnelToken),
		conn:      conn,
	}
	s.cdpSessionsMu.Unlock()
	if s.cdpOpenHook != nil {
		s.cdpOpenHook("registered")
	}
	return conn, nil
}

func (s *FarmRuntimeService) claimCDPSession(request FarmCDPTunnelRequest) error {
	now := time.Now()
	tokenHash := farmCDPTokenHash(request.TunnelToken)
	s.cdpSessionsMu.Lock()
	defer s.cdpSessionsMu.Unlock()
	if s.cdpSessions == nil {
		s.cdpSessions = make(map[string]*farmCDPSession)
	}
	if s.cdpTombstones == nil {
		s.cdpTombstones = make(map[string]farmCDPTombstone)
	}
	if s.cdpTokenTombstones == nil {
		s.cdpTokenTombstones = make(map[string]farmCDPTombstone)
	}
	s.pruneCDPTombstonesLocked(now)
	if _, exists := s.cdpSessions[request.SessionID]; exists {
		return ErrFarmCDPReplay
	}
	if _, exists := s.cdpTombstones[request.SessionID]; exists {
		return ErrFarmCDPReplay
	}
	if _, exists := s.cdpTokenTombstones[tokenHash]; exists {
		return ErrFarmCDPReplay
	}
	if len(s.cdpTombstones) >= farmCDPMaxTombstones {
		// Never evict a live one-time ticket to make room for a new claim.
		// Refusing the new claim preserves replay safety until TTL pruning.
		return ErrFarmCDPCapacity
	}
	tombstone := farmCDPTombstone{
		tokenHash: tokenHash,
		identity:  request.RuntimeIdentity,
		expiresAt: now.Add(farmCDPTombstoneTTL),
	}
	// Claim and tombstone insertion are one mutex transaction. A failed local
	// dial therefore consumes the one-time ticket just like a successful one.
	s.cdpTombstones[request.SessionID] = tombstone
	s.cdpTokenTombstones[tokenHash] = tombstone
	return nil
}

func (s *FarmRuntimeService) pruneCDPTombstonesLocked(now time.Time) {
	for sessionID, tombstone := range s.cdpTombstones {
		if !tombstone.expiresAt.After(now) {
			delete(s.cdpTombstones, sessionID)
			delete(s.cdpTokenTombstones, tombstone.tokenHash)
		}
	}
	for tokenHash, tombstone := range s.cdpTokenTombstones {
		if !tombstone.expiresAt.After(now) {
			delete(s.cdpTokenTombstones, tokenHash)
			for sessionID, session := range s.cdpTombstones {
				if session.tokenHash == tokenHash {
					delete(s.cdpTombstones, sessionID)
				}
			}
		}
	}
}

// CloseCDPTunnel removes exactly one session.  It is idempotent and never
// stops the persistent Chrome runtime itself.
func (s *FarmRuntimeService) CloseCDPTunnel(sessionID string, conn *websocket.Conn) {
	if s == nil || sessionID == "" {
		return
	}
	s.cdpSessionsMu.Lock()
	session := s.cdpSessions[sessionID]
	if session != nil && (conn == nil || session.conn == conn) {
		delete(s.cdpSessions, sessionID)
	} else {
		session = nil
	}
	s.cdpSessionsMu.Unlock()
	if session != nil && session.conn != nil {
		_ = session.conn.Close()
	}
}

func (s *FarmRuntimeService) closeCDPSessionsForRuntime(profileID string, generation uint64) {
	if s == nil || profileID == "" || generation == 0 {
		return
	}
	s.cdpSessionsMu.Lock()
	sessions := make([]*farmCDPSession, 0)
	for sessionID, session := range s.cdpSessions {
		if session == nil || session.identity.ProfileID != profileID || session.identity.Generation != generation {
			continue
		}
		delete(s.cdpSessions, sessionID)
		sessions = append(sessions, session)
	}
	s.cdpSessionsMu.Unlock()
	for _, session := range sessions {
		if session != nil && session.conn != nil {
			_ = session.conn.Close()
		}
	}
}

func (adapter *FarmRuntimeControlAdapter) OpenCDPTunnel(request FarmCDPTunnelRequest) (*websocket.Conn, error) {
	if adapter == nil || adapter.service == nil {
		return nil, ErrFarmRuntimeServiceUnavailable
	}
	return adapter.service.OpenCDPTunnel(request)
}

func (adapter *FarmRuntimeControlAdapter) CloseCDPTunnel(sessionID string, conn *websocket.Conn) {
	if adapter == nil || adapter.service == nil {
		return
	}
	adapter.service.CloseCDPTunnel(sessionID, conn)
}

func (request FarmCDPTunnelRequest) validate() error {
	if err := validateFarmCDPToken(request.SessionID, farmCDPMaxSessionID); err != nil {
		return fmt.Errorf("%w: session", err)
	}
	if err := validateFarmCDPToken(request.TunnelToken, farmCDPMaxToken); err != nil {
		return fmt.Errorf("%w: token", err)
	}
	return nil
}
