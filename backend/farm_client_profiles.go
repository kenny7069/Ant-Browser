package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	farmClientPairingDomain       = "auto-scraper/browser-farm/profile-pairing/v1"
	farmClientPairingCodeBytes    = 32
	farmClientPairingRequestBytes = 16
)

var (
	ErrFarmClientProfileNotFound = errors.New("ant farm client profile not found")
	ErrFarmClientPairing         = errors.New("ant farm client profile pairing failed")
	ErrFarmClientPairingRejected = errors.New("ant farm client profile pairing rejected")
)

// FarmClientProfileProjection is the complete local-profile disclosure
// allowlist. It intentionally has no UserDataDir, fingerprint, proxy, cookie,
// launch argument, process ID, port, tag or keyword field.
type FarmClientProfileProjection struct {
	ProfileID          string `json:"profile_id"`
	DisplayName        string `json:"display_name"`
	LoginReadiness     string `json:"login_readiness"`
	Provider           string `json:"provider"`
	ProfileIncarnation string `json:"profile_incarnation"`
}

type FarmClientPairingResult struct {
	Success         bool   `json:"success"`
	NodeUID         string `json:"node_uid"`
	ProfileID       string `json:"profile_id"`
	ServerProfileID int64  `json:"server_profile_id"`
	Status          string `json:"status"`
}

type farmClientPairWireRequest struct {
	Action             string `json:"action"`
	PairingCode        string `json:"pairing_code"`
	NodeUID            string `json:"node_uid"`
	DevicePublicKey    string `json:"device_public_key"`
	RequestID          string `json:"request_id"`
	IssuedAt           string `json:"issued_at"`
	AntProfileID       string `json:"ant_profile_id"`
	ProfileIncarnation string `json:"profile_incarnation"`
	SafeDisplayName    string `json:"safe_display_name"`
	LoginReadiness     string `json:"login_readiness"`
	Signature          string `json:"signature"`
}

type farmClientUnpairWireRequest struct {
	Action             string `json:"action"`
	NodeUID            string `json:"node_uid"`
	DevicePublicKey    string `json:"device_public_key"`
	RequestID          string `json:"request_id"`
	IssuedAt           string `json:"issued_at"`
	AntProfileID       string `json:"ant_profile_id"`
	ProfileIncarnation string `json:"profile_incarnation"`
	Signature          string `json:"signature"`
}

func farmClientProfileIncarnation(profileID, incarnationID string) (string, error) {
	profileID, incarnationID = strings.TrimSpace(profileID), strings.TrimSpace(incarnationID)
	if profileID == "" || incarnationID == "" {
		return "", ErrFarmClientPairing
	}
	h := sha256.New()
	_, _ = h.Write([]byte(farmClientPairingDomain + "/profile-incarnation\x00"))
	for _, value := range []string{profileID, incarnationID} {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len([]byte(value))))
		_, _ = h.Write(length[:])
		_, _ = h.Write([]byte(value))
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func farmClientReadiness(_ bool, _ bool) string {
	// Ant currently has no durable provider-login oracle. Browser/CDP readiness
	// must not be mislabeled as an authenticated social session.
	return "unknown"
}

func farmClientProjection(profile *BrowserProfile) (FarmClientProfileProjection, error) {
	if profile == nil {
		return FarmClientProfileProjection{}, ErrFarmClientProfileNotFound
	}
	incarnation, err := farmClientProfileIncarnation(profile.ProfileId, profile.IncarnationID)
	if err != nil {
		return FarmClientProfileProjection{}, err
	}
	name := strings.TrimSpace(profile.ProfileName)
	if name == "" {
		name = "Ant profile"
	}
	if len([]rune(name)) > 100 {
		name = string([]rune(name)[:100])
	}
	for _, char := range name {
		if char < 0x20 || char == 0x7f {
			return FarmClientProfileProjection{}, ErrFarmClientPairing
		}
	}
	return FarmClientProfileProjection{
		ProfileID: strings.TrimSpace(profile.ProfileId), DisplayName: name,
		LoginReadiness: farmClientReadiness(profile.Running, profile.DebugReady),
		Provider:       "ant", ProfileIncarnation: incarnation,
	}, nil
}

func (h *FarmClientHost) ProfileList() ([]FarmClientProfileProjection, error) {
	if h == nil || h.manager == nil {
		return nil, ErrFarmClientProfileStore
	}
	profiles := h.manager.List()
	result := make([]FarmClientProfileProjection, 0, len(profiles))
	for index := range profiles {
		projection, err := farmClientProjection(&profiles[index])
		if err != nil {
			return nil, err
		}
		result = append(result, projection)
	}
	return result, nil
}

func (h *FarmClientHost) profileProjection(profileID string) (FarmClientProfileProjection, error) {
	if h == nil || h.manager == nil {
		return FarmClientProfileProjection{}, ErrFarmClientProfileStore
	}
	profileID = strings.TrimSpace(profileID)
	h.manager.Mutex.Lock()
	profile := h.manager.Profiles[profileID]
	if profile != nil {
		copy := *profile
		profile = &copy
	}
	h.manager.Mutex.Unlock()
	return farmClientProjection(profile)
}

func (h *FarmClientHost) ProfileCreate(displayName string) (FarmClientProfileProjection, error) {
	if h == nil || h.manager == nil {
		return FarmClientProfileProjection{}, ErrFarmClientProfileStore
	}
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || len([]rune(displayName)) > 100 {
		return FarmClientProfileProjection{}, ErrFarmClientPairing
	}
	profile, err := h.manager.Create(BrowserProfileInput{ProfileName: displayName})
	if err != nil {
		return FarmClientProfileProjection{}, err
	}
	return farmClientProjection(profile)
}

func (h *FarmClientHost) ProfileOpen(profileID string) (FarmClientProfileProjection, error) {
	if h == nil || h.runtime == nil {
		return FarmClientProfileProjection{}, ErrFarmClientProfileStore
	}
	profile, err := h.runtime.Start(strings.TrimSpace(profileID))
	if err != nil {
		return FarmClientProfileProjection{}, err
	}
	return farmClientProjection(profile)
}

// ValidateProfilePairingIncarnation is the Agent-side durable ABA gate. Farm
// commands must present the token captured during pairing, independently of
// the runtime-process incarnation used by lifecycle fencing.
func (h *FarmClientHost) ValidateProfilePairingIncarnation(profileID, expected string) error {
	if h == nil {
		return ErrFarmClientProfileStore
	}
	return farmClientValidateProfilePairing(h.manager, profileID, expected)
}

func farmClientValidateProfilePairing(manager interface {
	List() []BrowserProfile
}, profileID, expected string) error {
	if manager == nil {
		return ErrFarmClientProfileStore
	}
	var selected *BrowserProfile
	for _, profile := range manager.List() {
		if strings.TrimSpace(profile.ProfileId) == strings.TrimSpace(profileID) {
			copy := profile
			selected = &copy
			break
		}
	}
	projection, err := farmClientProjection(selected)
	if err != nil {
		return err
	}
	if expected == "" || !strings.EqualFold(projection.ProfileIncarnation, expected) {
		return ErrFarmClientPairingRejected
	}
	return nil
}

func farmClientPairingMessage(fields ...string) []byte {
	var out bytes.Buffer
	out.WriteString(farmClientPairingDomain)
	out.WriteByte(0)
	for _, field := range fields {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len([]byte(field))))
		out.Write(length[:])
		out.WriteString(field)
	}
	return out.Bytes()
}

func farmClientPairingRequestID() (string, error) {
	raw := make([]byte, farmClientPairingRequestBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

func (h *FarmClientHost) PairProfile(ctx context.Context, profileID, pairingCode string, client *http.Client) (FarmClientPairingResult, error) {
	projection, err := h.profileProjection(profileID)
	if err != nil {
		return FarmClientPairingResult{}, err
	}
	code := strings.TrimSpace(pairingCode)
	raw, err := base64.StdEncoding.DecodeString(code)
	if err != nil || len(raw) != farmClientPairingCodeBytes || base64.StdEncoding.EncodeToString(raw) != code {
		clearBytes(raw)
		return FarmClientPairingResult{}, ErrFarmClientPairingRejected
	}
	clearBytes(raw)
	requestID, err := farmClientPairingRequestID()
	if err != nil {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
	publicKey := h.identity.PrivateKey.Public().(ed25519.PublicKey)
	message := farmClientPairingMessage("pair", h.identity.NodeUID, requestID, issuedAt, code,
		projection.ProfileID, projection.ProfileIncarnation, projection.DisplayName, projection.LoginReadiness, projection.Provider)
	signature := ed25519.Sign(h.identity.PrivateKey, message)
	payload := farmClientPairWireRequest{
		Action: "pair", PairingCode: code, NodeUID: h.identity.NodeUID,
		DevicePublicKey: base64.StdEncoding.EncodeToString(publicKey), RequestID: requestID, IssuedAt: issuedAt,
		AntProfileID: projection.ProfileID, ProfileIncarnation: projection.ProfileIncarnation,
		SafeDisplayName: projection.DisplayName, LoginReadiness: projection.LoginReadiness,
		Signature: base64.StdEncoding.EncodeToString(signature),
	}
	result, err := h.doProfilePairing(ctx, h.config.PairingURL, payload, client)
	if err != nil {
		return FarmClientPairingResult{}, err
	}
	if result.ProfileID != projection.ProfileID || result.Status != "assigned" {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	return result, nil
}

func (h *FarmClientHost) UnpairProfile(ctx context.Context, profileID string, client *http.Client) (FarmClientPairingResult, error) {
	projection, err := h.profileProjection(profileID)
	if err != nil {
		return FarmClientPairingResult{}, err
	}
	requestID, err := farmClientPairingRequestID()
	if err != nil {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
	publicKey := h.identity.PrivateKey.Public().(ed25519.PublicKey)
	message := farmClientPairingMessage("unpair", h.identity.NodeUID, requestID, issuedAt, projection.ProfileID, projection.ProfileIncarnation)
	payload := farmClientUnpairWireRequest{
		Action: "unpair", NodeUID: h.identity.NodeUID, DevicePublicKey: base64.StdEncoding.EncodeToString(publicKey),
		RequestID: requestID, IssuedAt: issuedAt, AntProfileID: projection.ProfileID,
		ProfileIncarnation: projection.ProfileIncarnation,
		Signature:          base64.StdEncoding.EncodeToString(ed25519.Sign(h.identity.PrivateKey, message)),
	}
	endpoint, err := farmClientUnpairURL(h.config.PairingURL)
	if err != nil {
		return FarmClientPairingResult{}, err
	}
	result, err := h.doProfilePairing(ctx, endpoint, payload, client)
	if err != nil {
		return FarmClientPairingResult{}, err
	}
	if result.ProfileID != projection.ProfileID || result.Status != "disabled" {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	return result, nil
}

func farmClientUnpairURL(pairingURL string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(pairingURL))
	if err != nil || !strings.HasSuffix(parsed.Path, "/pair") {
		return "", ErrFarmClientPairing
	}
	parsed.Path = strings.TrimSuffix(parsed.Path, "/pair") + "/unpair"
	return parsed.String(), nil
}

func (h *FarmClientHost) doProfilePairing(ctx context.Context, endpoint string, payload any, source *http.Client) (FarmClientPairingResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(endpoint) == "" {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := farmClientEnrollmentHTTPClient(source).Do(request)
	if err != nil {
		return FarmClientPairingResult{}, ErrFarmClientEnrollmentTransport
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		if response.StatusCode >= 500 {
			return FarmClientPairingResult{}, ErrFarmClientEnrollmentTransport
		}
		return FarmClientPairingResult{}, ErrFarmClientPairingRejected
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var result FarmClientPairingResult
	if err := decoder.Decode(&result); err != nil {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	if !result.Success || result.NodeUID != h.identity.NodeUID || result.ProfileID == "" || result.ServerProfileID <= 0 || result.Status == "" {
		return FarmClientPairingResult{}, ErrFarmClientPairing
	}
	return result, nil
}

func (r FarmClientPairingResult) String() string {
	return fmt.Sprintf("FarmClientPairingResult{paired=%t,status=%q}", r.Success, r.Status)
}
