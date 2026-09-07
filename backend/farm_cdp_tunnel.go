package backend

// Farm Agent CDP tunnel ownership.  This layer is intentionally transport
// agnostic: FarmControlWSSClient supplies the outbound WebSocket, while this
// service proves that the requested runtime is owned/current and opens only
// the browser-level CDP socket resolved from local service state.

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gorilla/websocket"
)

const (
	farmCDPMaxSessionID = 128
	farmCDPMaxToken     = 256
)

var (
	ErrFarmCDPRequestInvalid = errors.New("farm CDP tunnel request invalid")
	ErrFarmCDPReplay         = errors.New("farm CDP tunnel session replay")
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
	identity FarmRuntimeIdentity
	conn     *websocket.Conn
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
	record, err := s.validateCDPRequest(request)
	if err != nil {
		return nil, err
	}
	s.cdpSessionsMu.Lock()
	if s.cdpSessions == nil {
		s.cdpSessions = make(map[string]*farmCDPSession)
	}
	if _, exists := s.cdpSessions[request.SessionID]; exists {
		s.cdpSessionsMu.Unlock()
		return nil, ErrFarmCDPReplay
	}
	s.cdpSessionsMu.Unlock()
	conn, err := s.runtimeService.OpenOwnedBrowserCDP(
		record.runtime.ProfileID,
		record.runtime.Generation,
	)
	if err != nil {
		return nil, ErrFarmCDPNotReady
	}
	s.cdpSessionsMu.Lock()
	if _, exists := s.cdpSessions[request.SessionID]; exists {
		s.cdpSessionsMu.Unlock()
		_ = conn.Close()
		return nil, ErrFarmCDPReplay
	}
	s.cdpSessions[request.SessionID] = &farmCDPSession{
		identity: request.RuntimeIdentity,
		conn:     conn,
	}
	s.cdpSessionsMu.Unlock()
	return conn, nil
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
