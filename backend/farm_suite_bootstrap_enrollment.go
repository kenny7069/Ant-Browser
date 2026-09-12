package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	maxSuiteBootstrapEnrollmentBytes = 8192
	suiteBootstrapEnrollmentTimeout  = 15 * time.Second
)

var (
	ErrSuiteBootstrapEnrollmentConfig    = errors.New("suite bootstrap enrollment configuration invalid")
	ErrSuiteBootstrapEnrollmentIdentity  = errors.New("suite bootstrap enrollment identity unavailable")
	ErrSuiteBootstrapEnrollmentTransport = errors.New("suite bootstrap enrollment transport unavailable")
	ErrSuiteBootstrapEnrollmentTLS       = errors.New("suite bootstrap enrollment TLS verification failed")
	ErrSuiteBootstrapEnrollmentRedirect  = errors.New("suite bootstrap enrollment redirect rejected")
	ErrSuiteBootstrapEnrollmentRetryable = errors.New("suite bootstrap enrollment temporarily unavailable")
	ErrSuiteBootstrapEnrollmentRejected  = errors.New("suite bootstrap enrollment rejected")
	ErrSuiteBootstrapEnrollmentConflict  = errors.New("suite bootstrap enrollment idempotency conflict")
	ErrSuiteBootstrapEnrollmentResponse  = errors.New("suite bootstrap enrollment response invalid")
)

type SuiteBootstrapEnrollmentResult struct {
	NodeUID         string `json:"node_uid"`
	EnrollmentState string `json:"enrollment_state"`
	ControlEndpoint string `json:"control_endpoint"`
	IdentityRef     string `json:"identity_ref"`
}

func (result SuiteBootstrapEnrollmentResult) String() string {
	state := "UNKNOWN"
	if result.EnrollmentState == "ENROLLED" || result.EnrollmentState == "ALREADY_ENROLLED" {
		state = result.EnrollmentState
	}
	return "SuiteBootstrapEnrollmentResult{state=" + state + "}"
}

type suiteBootstrapEnrollmentMetadata struct {
	NodeName     string `json:"node_name"`
	SuiteVersion string `json:"suite_version"`
}

type suiteBootstrapEnrollmentRequest struct {
	RequestUID                   string                           `json:"request_uid"`
	EnrollmentCode               string                           `json:"enrollment_code"`
	DevicePublicKeyEd25519Base64 string                           `json:"device_public_key_ed25519_b64"`
	Metadata                     suiteBootstrapEnrollmentMetadata `json:"metadata"`
}

type suiteBootstrapEnrollmentResponse struct {
	NodeUID         string `json:"node_uid"`
	EnrollmentState string `json:"enrollment_state"`
	ControlEndpoint string `json:"control_endpoint"`
}

type suiteBootstrapEnrollmentDependencies struct {
	IdentityStore          FarmClientIdentityStore
	Client                 *http.Client
	Random                 io.Reader
	AfterIdentityPersisted func() error
	AfterStageSaved        func(SuiteBootstrapEnrollmentStage) error
	AfterResponse          func() error
}

// EnrollSuiteBootstrap performs trusted discovery before touching the device
// identity or sending the one-time code. A non-empty code must be supplied on
// every retry until ACKNOWLEDGED has been durably recorded.
func EnrollSuiteBootstrap(ctx context.Context, bootstrap BootstrapConfig, roots SuiteUserRoots, enrollmentCode string) (SuiteBootstrapEnrollmentResult, error) {
	if ctx == nil || validateSuiteSetupInputs(&bootstrap, roots) != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	ctx, cancel := context.WithTimeout(ctx, suiteBootstrapEnrollmentTimeout)
	defer cancel()
	preparation, err := loadSuiteBootstrapEnrollmentPreparation(bootstrap, roots)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	discovery, err := FetchSuiteBootstrapDiscovery(ctx, bootstrap)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	store, err := NewFarmClientIdentityStore(roots.AgentState)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentIdentity
	}
	transport := &http.Transport{
		Proxy:                  http.ProxyFromEnvironment,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		MaxResponseHeaderBytes: maxSuiteBootstrapHeaderBytes,
		ResponseHeaderTimeout:  10 * time.Second,
		DisableCompression:     true,
	}
	defer transport.CloseIdleConnections()
	return enrollSuiteBootstrapWithDependencies(ctx, roots, preparation.RequestUID, bootstrap.NodeName, FarmClientVersion, enrollmentCode, discovery, suiteBootstrapEnrollmentDependencies{
		IdentityStore: store,
		Client:        &http.Client{Transport: transport},
		Random:        rand.Reader,
	})
}

func loadSuiteBootstrapEnrollmentPreparation(bootstrap BootstrapConfig, roots SuiteUserRoots) (*SetupPreparationCheckpoint, error) {
	if validateSuiteSetupInputs(&bootstrap, roots) != nil {
		return nil, ErrSuiteBootstrapEnrollmentConfig
	}
	preparation, err := loadSetupPreparationCheckpoint(filepathJoinAgentState(roots, suitePreparationStateName))
	if err != nil || preparation == nil || preparation.Stage != SetupBootstrapDrafted {
		return nil, ErrSuiteBootstrapEnrollmentConfig
	}
	digest, err := bootstrapConfigDigest(bootstrap)
	if err != nil || digest != preparation.BootstrapSHA256 {
		return nil, ErrSuiteBootstrapEnrollmentConfig
	}
	return preparation, nil
}

func filepathJoinAgentState(roots SuiteUserRoots, name string) string {
	return filepath.Join(roots.AgentState, name)
}

func enrollSuiteBootstrapWithDependencies(ctx context.Context, roots SuiteUserRoots, preparationRequestUID, nodeName, suiteVersion, enrollmentCode string, discovery SuiteBootstrapDiscovery, deps suiteBootstrapEnrollmentDependencies) (SuiteBootstrapEnrollmentResult, error) {
	if ctx == nil || deps.IdentityStore == nil || deps.Client == nil || deps.Random == nil || validateSuiteSetupRoots(roots) != nil || validateFarmClientNodeName(nodeName) != nil || !validSuiteReleaseSemver(suiteVersion) {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	if err := ensureOwnerDirectory(roots.AgentState); err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
	}
	lock, err := acquireSuiteSetupLock(filepathJoinAgentState(roots, suiteBootstrapEnrollmentLockName))
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	defer lock.release()

	discoveryRaw, err := json.Marshal(discovery)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	enrollmentOrigin, err := validateSuiteBootstrapEndpoint(discovery.EnrollmentEndpoint, "https", "/api/farm/v3/bootstrap/enroll")
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	validatedDiscovery, err := parseSuiteBootstrapDiscovery(discoveryRaw, enrollmentOrigin, suiteVersion, FarmSuiteBootstrapProtocolVersion)
	if err != nil || validatedDiscovery.DeploymentUID != discovery.DeploymentUID {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	metadata := suiteBootstrapEnrollmentMetadata{NodeName: strings.TrimSpace(nodeName), SuiteVersion: suiteVersion}
	metadataRaw, _ := json.Marshal(metadata)
	discoveryDigest := suiteBootstrapSHA256(discoveryRaw)
	metadataDigest := suiteBootstrapSHA256(metadataRaw)
	identityRef, err := suiteBootstrapEnrollmentIdentityRef(discovery.DeploymentUID, preparationRequestUID)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	attempt, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	if attempt != nil && (attempt.PreparationRequestUID != preparationRequestUID || attempt.DeploymentUID != discovery.DeploymentUID || attempt.DiscoverySHA256 != discoveryDigest || attempt.MetadataSHA256 != metadataDigest || attempt.IdentityRef != string(identityRef)) {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
	}
	codeDigest := ""
	if attempt == nil || attempt.Stage != SuiteBootstrapAcknowledged {
		codeRaw, err := decodeSuiteBootstrapEnrollmentCode(enrollmentCode)
		if err != nil {
			return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
		}
		codeDigest = suiteBootstrapSHA256(codeRaw)
		clearBytes(codeRaw)
		if attempt != nil && attempt.EnrollmentCodeSHA256 != codeDigest {
			return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
		}
	}
	key, err := loadOrCreateSuiteBootstrapIdentity(deps, identityRef, attempt == nil)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	defer clearBytes(key)
	publicKey := farmClientIdentityPublicKey(key)
	publicKeyDigest := suiteBootstrapSHA256(publicKey)
	defer clearBytes(publicKey)

	if attempt != nil && attempt.Stage == SuiteBootstrapAcknowledged {
		if !matchesSuiteBootstrapAcknowledgedBinding(*attempt, preparationRequestUID, discovery, discoveryDigest, metadataDigest, identityRef, publicKeyDigest, enrollmentCode) {
			return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
		}
		return suiteBootstrapEnrollmentResultFromAttempt(*attempt), nil
	}
	requestUID, err := canonicalSuiteBootstrapRequestUID(preparationRequestUID)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	idempotencyKey := "ant-suite-enrollment-v3-" + requestUID
	request := suiteBootstrapEnrollmentRequest{
		RequestUID: requestUID, EnrollmentCode: enrollmentCode,
		DevicePublicKeyEd25519Base64: base64.StdEncoding.EncodeToString(publicKey), Metadata: metadata,
	}
	requestRaw, err := json.Marshal(request)
	if err != nil || len(requestRaw) == 0 || len(requestRaw) > maxSuiteBootstrapEnrollmentBytes {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentConfig
	}
	baseAttempt := SuiteBootstrapEnrollmentAttempt{
		SchemaVersion: suiteBootstrapEnrollmentSchema, Stage: SuiteBootstrapIdentityReady,
		PreparationRequestUID: requestUID, DeploymentUID: discovery.DeploymentUID,
		DiscoverySHA256: discoveryDigest, MetadataSHA256: metadataDigest, IdentityRef: string(identityRef),
		PublicKeySHA256: publicKeyDigest, EnrollmentCodeSHA256: codeDigest,
		RequestSHA256: suiteBootstrapSHA256(requestRaw), IdempotencySHA256: suiteBootstrapSHA256([]byte(idempotencyKey)),
	}
	if attempt != nil && !sameSuiteBootstrapEnrollmentBinding(*attempt, baseAttempt) {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
	}
	if attempt == nil {
		if err := saveSuiteBootstrapEnrollmentAttempt(roots, baseAttempt); err != nil {
			return SuiteBootstrapEnrollmentResult{}, err
		}
		attempt = &baseAttempt
		if deps.AfterStageSaved != nil {
			if err := deps.AfterStageSaved(attempt.Stage); err != nil {
				return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
			}
		}
	}
	if attempt.Stage == SuiteBootstrapIdentityReady {
		next := baseAttempt
		next.Stage = SuiteBootstrapRequestReady
		if err := saveSuiteBootstrapEnrollmentAttempt(roots, next); err != nil {
			return SuiteBootstrapEnrollmentResult{}, err
		}
		attempt = &next
		if deps.AfterStageSaved != nil {
			if err := deps.AfterStageSaved(attempt.Stage); err != nil {
				return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentState
			}
		}
	}
	response, err := postSuiteBootstrapEnrollment(ctx, deps.Client, discovery.EnrollmentEndpoint, idempotencyKey, requestRaw)
	if err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	if response.ControlEndpoint != discovery.ControlEndpoint {
		return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentResponse
	}
	if deps.AfterResponse != nil {
		if err := deps.AfterResponse(); err != nil {
			return SuiteBootstrapEnrollmentResult{}, ErrSuiteBootstrapEnrollmentTransport
		}
	}
	ack := baseAttempt
	ack.Stage = SuiteBootstrapAcknowledged
	ack.NodeUID = response.NodeUID
	ack.EnrollmentState = response.EnrollmentState
	ack.ControlEndpoint = response.ControlEndpoint
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, ack); err != nil {
		return SuiteBootstrapEnrollmentResult{}, err
	}
	return suiteBootstrapEnrollmentResultFromAttempt(ack), nil
}

func suiteBootstrapEnrollmentIdentityRef(deploymentUID, requestUID string) (FarmClientIdentityKeyRef, error) {
	if parsed, err := uuid.Parse(deploymentUID); err != nil || parsed.String() != deploymentUID {
		return "", ErrSuiteBootstrapEnrollmentConfig
	}
	if parsed, err := uuid.Parse(requestUID); err != nil || parsed.String() != requestUID {
		return "", ErrSuiteBootstrapEnrollmentConfig
	}
	return NewFarmClientIdentityKeyRef("suite-v3-" + suiteBootstrapSHA256([]byte(deploymentUID+"\x00"+requestUID)))
}

func canonicalSuiteBootstrapRequestUID(value string) (string, error) {
	parsed, err := uuid.Parse(value)
	if err != nil || parsed.String() != value {
		return "", ErrSuiteBootstrapEnrollmentConfig
	}
	return value, nil
}

func decodeSuiteBootstrapEnrollmentCode(value string) ([]byte, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.StdEncoding.EncodeToString(raw) != value {
		if raw != nil {
			clearBytes(raw)
		}
		return nil, ErrSuiteBootstrapEnrollmentConfig
	}
	return raw, nil
}

func loadOrCreateSuiteBootstrapIdentity(deps suiteBootstrapEnrollmentDependencies, ref FarmClientIdentityKeyRef, allowCreate bool) (ed25519.PrivateKey, error) {
	key, err := deps.IdentityStore.Load(ref)
	if errors.Is(err, ErrFarmClientIdentityKeyNotFound) && allowCreate {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := io.ReadFull(deps.Random, seed); err != nil {
			clearBytes(seed)
			return nil, ErrSuiteBootstrapEnrollmentIdentity
		}
		if err := deps.IdentityStore.Save(ref, seed); err != nil {
			clearBytes(seed)
			return nil, ErrSuiteBootstrapEnrollmentIdentity
		}
		clearBytes(seed)
		if deps.AfterIdentityPersisted != nil {
			if err := deps.AfterIdentityPersisted(); err != nil {
				return nil, ErrSuiteBootstrapEnrollmentIdentity
			}
		}
		key, err = deps.IdentityStore.Load(ref)
	}
	if err != nil || len(key) != ed25519.PrivateKeySize {
		if key != nil {
			clearBytes(key)
		}
		return nil, ErrSuiteBootstrapEnrollmentIdentity
	}
	return key, nil
}

func matchesSuiteBootstrapAcknowledgedBinding(attempt SuiteBootstrapEnrollmentAttempt, requestUID string, discovery SuiteBootstrapDiscovery, discoveryDigest, metadataDigest string, ref FarmClientIdentityKeyRef, publicDigest, enrollmentCode string) bool {
	if attempt.PreparationRequestUID != requestUID || attempt.DeploymentUID != discovery.DeploymentUID || attempt.DiscoverySHA256 != discoveryDigest || attempt.MetadataSHA256 != metadataDigest || attempt.IdentityRef != string(ref) || attempt.PublicKeySHA256 != publicDigest || attempt.ControlEndpoint != discovery.ControlEndpoint {
		return false
	}
	if enrollmentCode == "" {
		return true
	}
	raw, err := decodeSuiteBootstrapEnrollmentCode(enrollmentCode)
	if err != nil {
		return false
	}
	digest := suiteBootstrapSHA256(raw)
	clearBytes(raw)
	return digest == attempt.EnrollmentCodeSHA256
}

func suiteBootstrapEnrollmentResultFromAttempt(attempt SuiteBootstrapEnrollmentAttempt) SuiteBootstrapEnrollmentResult {
	return SuiteBootstrapEnrollmentResult{NodeUID: attempt.NodeUID, EnrollmentState: attempt.EnrollmentState, ControlEndpoint: attempt.ControlEndpoint, IdentityRef: attempt.IdentityRef}
}

func postSuiteBootstrapEnrollment(ctx context.Context, supplied *http.Client, endpoint, idempotencyKey string, requestRaw []byte) (suiteBootstrapEnrollmentResponse, error) {
	ctx, cancel := context.WithTimeout(ctx, suiteBootstrapEnrollmentTimeout)
	defer cancel()
	client := *supplied
	client.Timeout = suiteBootstrapEnrollmentTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return ErrSuiteBootstrapEnrollmentRedirect }
	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if ctx.Err() != nil {
			break
		}
		parsed, retry, err := postSuiteBootstrapEnrollmentOnce(ctx, &client, endpoint, idempotencyKey, requestRaw)
		if err == nil || !retry {
			return parsed, err
		}
		lastErr = err
	}
	if lastErr != nil {
		return suiteBootstrapEnrollmentResponse{}, lastErr
	}
	return suiteBootstrapEnrollmentResponse{}, ErrSuiteBootstrapEnrollmentTransport
}

func postSuiteBootstrapEnrollmentOnce(ctx context.Context, client *http.Client, endpoint, idempotencyKey string, requestRaw []byte) (suiteBootstrapEnrollmentResponse, bool, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(requestRaw))
	if err != nil {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentConfig
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("Idempotency-Key", idempotencyKey)
	response, err := client.Do(request)
	if err != nil {
		if errors.Is(err, ErrSuiteBootstrapEnrollmentRedirect) {
			return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentRedirect
		}
		var certificateError *tls.CertificateVerificationError
		if errors.As(err, &certificateError) || strings.Contains(strings.ToLower(err.Error()), "x509:") || strings.Contains(strings.ToLower(err.Error()), "tls:") {
			return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentTLS
		}
		return suiteBootstrapEnrollmentResponse{}, true, ErrSuiteBootstrapEnrollmentTransport
	}
	defer response.Body.Close()
	if suiteBootstrapHeaderSize(response.Header) > maxSuiteBootstrapHeaderBytes {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxSuiteBootstrapEnrollmentBytes))
	}
	if response.StatusCode == http.StatusConflict {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentConflict
	}
	if response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
		return suiteBootstrapEnrollmentResponse{}, true, ErrSuiteBootstrapEnrollmentRetryable
	}
	if response.StatusCode >= 400 {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentRejected
	}
	if response.StatusCode != http.StatusOK {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	mediaType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxSuiteBootstrapEnrollmentBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxSuiteBootstrapEnrollmentBytes {
		return suiteBootstrapEnrollmentResponse{}, true, ErrSuiteBootstrapEnrollmentResponse
	}
	if !json.Valid(raw) {
		return suiteBootstrapEnrollmentResponse{}, true, ErrSuiteBootstrapEnrollmentResponse
	}
	if rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || !exactFarmClientIPCKeys(keys, []string{"node_uid", "enrollment_state", "control_endpoint"}) {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var parsed suiteBootstrapEnrollmentResponse
	if decoder.Decode(&parsed) != nil || requireJSONEOF(decoder) != nil || !validSuiteBootstrapEnrollmentNodeUID(parsed.NodeUID) || (parsed.EnrollmentState != "ENROLLED" && parsed.EnrollmentState != "ALREADY_ENROLLED") {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	if _, err := validateSuiteBootstrapEndpoint(parsed.ControlEndpoint, "wss", "/control/ws"); err != nil {
		return suiteBootstrapEnrollmentResponse{}, false, ErrSuiteBootstrapEnrollmentResponse
	}
	return parsed, false, nil
}
