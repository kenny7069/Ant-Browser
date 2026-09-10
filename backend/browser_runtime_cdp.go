package backend

// Browser-level CDP resolution for an already-owned Farm runtime.  The
// caller supplies only the profile identity and generation; the service reads
// the current local debug port from its own fenced runtime snapshot and never
// accepts a Server-provided port or WebSocket URL as identity.

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	ownedBrowserCDPHTTPTimeout      = 3 * time.Second
	ownedBrowserCDPHandshakeTimeout = 3 * time.Second
	ownedBrowserCDPMaxMessageBytes  = 32 * 1024 * 1024
)

type ownedBrowserCDPVersion struct {
	WebSocketDebuggerURL string `json:"webSocketDebuggerUrl"`
}

func loopbackCDPHost(host string) bool {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func browserLevelCDPURL(debugPort int) (string, error) {
	if debugPort <= 0 || debugPort > 65535 {
		return "", fmt.Errorf("browser CDP debug port invalid")
	}
	transport := &http.Transport{Proxy: nil}
	client := &http.Client{Transport: transport, Timeout: ownedBrowserCDPHTTPTimeout}
	defer transport.CloseIdleConnections()
	resp, err := client.Get("http://127.0.0.1:" + strconv.Itoa(debugPort) + "/json/version")
	if err != nil {
		return "", fmt.Errorf("browser CDP version request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("browser CDP version status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return "", fmt.Errorf("browser CDP version read failed")
	}
	var version ownedBrowserCDPVersion
	if err := json.Unmarshal(body, &version); err != nil {
		return "", fmt.Errorf("browser CDP version invalid")
	}
	wsURL := strings.TrimSpace(version.WebSocketDebuggerURL)
	if wsURL == "" {
		return "", fmt.Errorf("browser CDP WebSocket URL missing")
	}
	parsed, err := url.Parse(wsURL)
	if err != nil || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.User != nil || parsed.Hostname() == "" || parsed.Path == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("browser CDP WebSocket URL invalid")
	}
	if !loopbackCDPHost(parsed.Hostname()) {
		return "", fmt.Errorf("browser CDP WebSocket is not loopback")
	}
	if port := parsed.Port(); port != strconv.Itoa(debugPort) {
		return "", fmt.Errorf("browser CDP WebSocket port mismatch")
	}
	if !strings.HasPrefix(parsed.Path, "/devtools/browser/") || strings.TrimPrefix(parsed.Path, "/devtools/browser/") == "" {
		return "", fmt.Errorf("browser CDP WebSocket is not browser-level")
	}
	return parsed.String(), nil
}

// OpenOwnedBrowserCDP opens the browser-level target for the exact runtime
// generation currently owned by this BrowserRuntimeService.
func (s *BrowserRuntimeService) OpenOwnedBrowserCDP(profileID string, generation uint64) (*websocket.Conn, error) {
	if s == nil {
		return nil, ErrBrowserRuntimeServiceShutdown
	}
	if generation == 0 {
		return nil, ErrBrowserRuntimeGenerationMismatch
	}
	snapshot, err := s.RuntimeSnapshot(profileID)
	if err != nil {
		return nil, err
	}
	if snapshot == nil || snapshot.Profile == nil || snapshot.Generation != generation || !snapshot.Profile.Running || !snapshot.Profile.DebugReady {
		return nil, ErrBrowserRuntimeGenerationMismatch
	}
	wsURL, err := browserLevelCDPURL(snapshot.Profile.DebugPort)
	if err != nil {
		return nil, err
	}
	dialer := *websocket.DefaultDialer
	dialer.Proxy = nil
	dialer.HandshakeTimeout = ownedBrowserCDPHandshakeTimeout
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("browser CDP WebSocket dial failed")
	}
	conn.SetReadLimit(ownedBrowserCDPMaxMessageBytes)
	return conn, nil
}
