package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"time"
)

var (
	ErrFarmClientEnrollment          = errors.New("farm client enrollment failed")
	ErrFarmClientEnrollmentRejected  = errors.New("farm client enrollment rejected")
	ErrFarmClientEnrollmentTransport = errors.New("farm client enrollment transport unavailable")
)

const farmClientEnrollmentCodeBytes = 32

// FarmClientEnrollmentResult is safe to expose in first-run diagnostics. It
// deliberately excludes the code, device keys and endpoint.
type FarmClientEnrollmentResult struct {
	NodeUID      string `json:"node_uid"`
	EnrollmentID int64  `json:"enrollment_id"`
	NodeID       int64  `json:"node_id"`
	Status       string `json:"status"`
}

type farmClientEnrollmentWireRequest struct {
	EnrollmentCode  string `json:"enrollment_code"`
	NodeUID         string `json:"node_uid"`
	NodeName        string `json:"node_name"`
	DevicePublicKey string `json:"device_public_key"`
	ClientVersion   string `json:"client_version"`
	Platform        string `json:"platform"`
	Architecture    string `json:"architecture"`
}

type farmClientEnrollmentWireResponse struct {
	Success      bool   `json:"success"`
	EnrollmentID int64  `json:"enrollment_id"`
	NodeID       int64  `json:"node_id"`
	NodeUID      string `json:"node_uid"`
	Status       string `json:"status"`
}

// EnrollFarmClient generates or reuses one securely stored device identity,
// then sends only the public key to the existing Server enrollment facade.
// The stored pending key is intentionally retained after ambiguous network
// failure so a retry/reinstall cannot bind the node to a different key.
func EnrollFarmClient(ctx context.Context, cfg FarmClientConfig, enrollmentCode string, store FarmClientIdentityStore, client *http.Client) (FarmClientEnrollmentResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := cfg.ValidateFarmClientConfig(); err != nil {
		return FarmClientEnrollmentResult{}, err
	}
	if strings.TrimSpace(cfg.EnrollmentURL) == "" || store == nil {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	identityCfg := cfg.identityConfig()
	ref, err := NewFarmClientIdentityKeyRef(identityCfg.PrivateKeyRef)
	if err != nil {
		return FarmClientEnrollmentResult{}, err
	}
	code := strings.TrimSpace(enrollmentCode)
	codeRaw, err := base64.StdEncoding.DecodeString(code)
	if err != nil || len(codeRaw) != farmClientEnrollmentCodeBytes || base64.StdEncoding.EncodeToString(codeRaw) != code {
		clearBytes(codeRaw)
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollmentRejected
	}
	clearBytes(codeRaw)

	key, err := farmClientEnrollmentIdentity(store, ref)
	if err != nil {
		return FarmClientEnrollmentResult{}, err
	}
	defer clearBytes(key)
	publicKey := farmClientIdentityPublicKey(key)
	if len(publicKey) != ed25519.PublicKeySize {
		return FarmClientEnrollmentResult{}, ErrFarmClientIdentityKeyCorrupt
	}
	defer clearBytes(publicKey)

	payload := farmClientEnrollmentWireRequest{
		EnrollmentCode: code,
		NodeUID:        strings.TrimSpace(identityCfg.NodeUID), NodeName: cfg.NodeName,
		DevicePublicKey: base64.StdEncoding.EncodeToString(publicKey),
		ClientVersion:   FarmClientVersion, Platform: runtime.GOOS, Architecture: runtime.GOARCH,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	defer clearBytes(body)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.EnrollmentURL, bytes.NewReader(body))
	if err != nil {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")

	httpClient := farmClientEnrollmentHTTPClient(client)
	response, err := httpClient.Do(request)
	if err != nil {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollmentTransport
	}
	defer response.Body.Close()
	if response.StatusCode >= 500 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollmentTransport
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollmentRejected
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	var wire farmClientEnrollmentWireResponse
	if err := decoder.Decode(&wire); err != nil {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	if !wire.Success || wire.EnrollmentID <= 0 || wire.NodeID <= 0 || strings.TrimSpace(wire.NodeUID) != strings.TrimSpace(identityCfg.NodeUID) || strings.TrimSpace(wire.Status) == "" {
		return FarmClientEnrollmentResult{}, ErrFarmClientEnrollment
	}
	return FarmClientEnrollmentResult{
		NodeUID: wire.NodeUID, EnrollmentID: wire.EnrollmentID, NodeID: wire.NodeID,
		Status: wire.Status,
	}, nil
}

func farmClientEnrollmentIdentity(store FarmClientIdentityStore, ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	key, err := store.Load(ref)
	if err == nil {
		normalized, seed, normalizeErr := normalizeFarmClientIdentityKey(key)
		clearBytes(key)
		clearBytes(seed)
		if normalizeErr != nil {
			return nil, ErrFarmClientIdentityKeyCorrupt
		}
		return normalized, nil
	}
	if !errors.Is(err, ErrFarmClientIdentityKeyNotFound) {
		return nil, farmClientIdentityStoreError(err)
	}
	_, generated, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrFarmClientIdentityStore
	}
	if err := store.Save(ref, generated); err != nil {
		clearBytes(generated)
		if errors.Is(err, ErrFarmClientIdentityKeyConflict) {
			loaded, loadErr := store.Load(ref)
			if loadErr != nil {
				return nil, farmClientIdentityStoreError(loadErr)
			}
			return loaded, nil
		}
		return nil, farmClientIdentityStoreError(err)
	}
	return generated, nil
}

func farmClientEnrollmentHTTPClient(source *http.Client) *http.Client {
	var value http.Client
	if source != nil {
		value = *source
	}
	if value.Timeout <= 0 || value.Timeout > 60*time.Second {
		value.Timeout = 15 * time.Second
	}
	value.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &value
}

func (r FarmClientEnrollmentResult) String() string {
	return fmt.Sprintf("FarmClientEnrollmentResult{node=%t,enrolled=%t}", strings.TrimSpace(r.NodeUID) != "", r.EnrollmentID > 0)
}
