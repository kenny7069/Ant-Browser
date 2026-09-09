package backend

// Signed update discovery and staging for the standalone Farm Client. This
// layer deliberately stops before process execution: only an authenticated,
// target-specific artifact may enter the private state-root staging area.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	FarmClientUpdateEnvelopeVersion  = 1
	FarmClientControlProtocolVersion = "bf-p1.6"
	farmClientUpdateManifestLimit    = 64 << 10
	farmClientUpdateArtifactLimit    = int64(512 << 20)
)

var (
	ErrFarmClientUpdateInvalid     = errors.New("farm client update metadata invalid")
	ErrFarmClientUpdateSignature   = errors.New("farm client update signature invalid")
	ErrFarmClientUpdateTarget      = errors.New("farm client update target incompatible")
	ErrFarmClientUpdatePolicy      = errors.New("farm client update policy rejected")
	ErrFarmClientUpdateUnavailable = errors.New("farm client update unavailable")
	ErrFarmClientUpdateIntegrity   = errors.New("farm client update integrity failed")
	ErrFarmClientUpdateNoChange    = errors.New("farm client update is current")
)

type FarmClientUpdateEnvelope struct {
	Version   int    `json:"version"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type FarmClientUpdateArtifact struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type FarmClientUpdateManifest struct {
	Version                string                              `json:"version"`
	ProtocolVersion        string                              `json:"protocol_version"`
	MinimumProtocolVersion string                              `json:"minimum_protocol_version"`
	Channel                string                              `json:"channel"`
	PublishedAt            string                              `json:"published_at"`
	ExpiresAt              string                              `json:"expires_at"`
	AllowDowngrade         bool                                `json:"allow_downgrade"`
	Artifacts              map[string]FarmClientUpdateArtifact `json:"artifacts"`
}

type FarmClientUpdateCandidate struct {
	Manifest FarmClientUpdateManifest `json:"manifest"`
	Artifact FarmClientUpdateArtifact `json:"artifact"`
	Target   string                   `json:"target"`
	// Envelope is the exact signed metadata verified during discovery.  It is
	// deliberately retained so the immutable launcher can re-establish the
	// complete trust chain immediately before every activation and startup.
	Envelope []byte `json:"-"`
}

type FarmClientStagedUpdate struct {
	Candidate    FarmClientUpdateCandidate `json:"candidate"`
	Path         string                    `json:"-"`
	EnvelopePath string                    `json:"-"`
}

func FetchAndStageFarmClientUpdate(
	ctx context.Context,
	client *http.Client,
	config FarmClientConfig,
	currentVersion string,
	now time.Time,
) (FarmClientStagedUpdate, error) {
	candidate, err := CheckFarmClientUpdate(ctx, client, config, currentVersion, now)
	if err != nil {
		return FarmClientStagedUpdate{}, err
	}
	return StageFarmClientUpdate(ctx, client, config.StateRoot, candidate)
}

func CheckFarmClientUpdate(
	ctx context.Context,
	client *http.Client,
	config FarmClientConfig,
	currentVersion string,
	now time.Time,
) (FarmClientUpdateCandidate, error) {
	if strings.TrimSpace(config.UpdateManifestURL) == "" || strings.TrimSpace(config.UpdatePublicKey) == "" {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdatePolicy
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, config.UpdateManifestURL, nil)
	if err != nil {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateInvalid
	}
	response, err := farmClientUpdateHTTPClient(client).Do(request)
	if err != nil {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, farmClientUpdateManifestLimit+1))
	if err != nil || len(raw) > farmClientUpdateManifestLimit {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateInvalid
	}
	candidate, err := VerifyFarmClientUpdateEnvelope(
		raw, config.UpdatePublicKey, currentVersion,
		FarmClientControlProtocolVersion, config.UpdateChannel,
		runtime.GOOS, runtime.GOARCH, config.AllowUpdateDowngrade, now,
	)
	if err != nil {
		return FarmClientUpdateCandidate{}, err
	}
	return candidate, nil
}

var farmClientUpdateChannelPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
var farmClientUpdateTargets = map[string]struct{}{
	"windows-amd64": {},
	"linux-amd64":   {},
	"linux-arm64":   {},
	"darwin-amd64":  {},
	"darwin-arm64":  {},
}

func decodeStrictFarmClientUpdateJSON(raw []byte, destination any) error {
	if len(raw) == 0 || len(raw) > farmClientUpdateManifestLimit {
		return ErrFarmClientUpdateInvalid
	}
	if err := validateFarmRuntimeJSON(raw); err != nil {
		return ErrFarmClientUpdateInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return ErrFarmClientUpdateInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrFarmClientUpdateInvalid
	}
	return nil
}

func decodeFarmClientUpdatePublicKey(encoded string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, ErrFarmClientUpdateSignature
	}
	return ed25519.PublicKey(append([]byte(nil), raw...)), nil
}

func BuildFarmClientUpdateEnvelope(manifestRaw []byte, encodedPrivateKey string, now time.Time) ([]byte, error) {
	var manifest FarmClientUpdateManifest
	if err := decodeStrictFarmClientUpdateJSON(manifestRaw, &manifest); err != nil {
		return nil, err
	}
	if err := validateFarmClientUpdateManifest(manifest, now); err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPrivateKey))
	if err != nil || (len(raw) != ed25519.SeedSize && len(raw) != ed25519.PrivateKeySize) {
		return nil, ErrFarmClientUpdateSignature
	}
	privateKey := ed25519.PrivateKey(raw)
	if len(raw) == ed25519.SeedSize {
		privateKey = ed25519.NewKeyFromSeed(raw)
	}
	envelope := FarmClientUpdateEnvelope{
		Version:   FarmClientUpdateEnvelopeVersion,
		Payload:   base64.StdEncoding.EncodeToString(manifestRaw),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestRaw)),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, ErrFarmClientUpdateInvalid
	}
	return encoded, nil
}

func VerifyFarmClientUpdateEnvelope(
	raw []byte,
	encodedPublicKey string,
	currentVersion string,
	currentProtocol string,
	channel string,
	goos string,
	goarch string,
	allowDowngrade bool,
	now time.Time,
) (FarmClientUpdateCandidate, error) {
	manifest, err := verifyFarmClientUpdateEnvelopeManifest(raw, encodedPublicKey, now)
	if err != nil {
		return FarmClientUpdateCandidate{}, err
	}
	return selectFarmClientUpdateCandidate(raw, manifest, currentVersion, currentProtocol, channel, goos, goarch, allowDowngrade)
}

func verifyFarmClientUpdateEnvelopeManifest(raw []byte, encodedPublicKey string, now time.Time) (FarmClientUpdateManifest, error) {
	var envelope FarmClientUpdateEnvelope
	if err := decodeStrictFarmClientUpdateJSON(raw, &envelope); err != nil {
		return FarmClientUpdateManifest{}, err
	}
	if envelope.Version != FarmClientUpdateEnvelopeVersion {
		return FarmClientUpdateManifest{}, ErrFarmClientUpdateInvalid
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > farmClientUpdateManifestLimit {
		return FarmClientUpdateManifest{}, ErrFarmClientUpdateInvalid
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return FarmClientUpdateManifest{}, ErrFarmClientUpdateSignature
	}
	publicKey, err := decodeFarmClientUpdatePublicKey(encodedPublicKey)
	if err != nil || !ed25519.Verify(publicKey, payload, signature) {
		return FarmClientUpdateManifest{}, ErrFarmClientUpdateSignature
	}
	var manifest FarmClientUpdateManifest
	if err := decodeStrictFarmClientUpdateJSON(payload, &manifest); err != nil {
		return FarmClientUpdateManifest{}, err
	}
	if err := validateFarmClientUpdateManifest(manifest, now); err != nil {
		return FarmClientUpdateManifest{}, err
	}
	return manifest, nil
}

func selectFarmClientUpdateCandidate(
	raw []byte,
	manifest FarmClientUpdateManifest,
	currentVersion string,
	currentProtocol string,
	channel string,
	goos string,
	goarch string,
	allowDowngrade bool,
) (FarmClientUpdateCandidate, error) {
	current, err := parseFarmClientSemver(currentVersion)
	if err != nil {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdatePolicy
	}
	next, err := parseFarmClientSemver(manifest.Version)
	if err != nil {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateInvalid
	}
	comparison := compareFarmClientSemver(next, current)
	if comparison == 0 {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateNoChange
	}
	if comparison < 0 && !(allowDowngrade && manifest.AllowDowngrade) {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdatePolicy
	}
	if strings.TrimSpace(channel) != manifest.Channel {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdatePolicy
	}
	currentProtocolVersion, err := parseFarmClientProtocol(currentProtocol)
	if err != nil {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdatePolicy
	}
	minimumProtocolVersion, err := parseFarmClientProtocol(manifest.MinimumProtocolVersion)
	if err != nil || currentProtocolVersion.major != minimumProtocolVersion.major ||
		compareFarmClientProtocol(currentProtocolVersion, minimumProtocolVersion) < 0 {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateTarget
	}
	target := strings.TrimSpace(goos) + "-" + strings.TrimSpace(goarch)
	if _, allowed := farmClientUpdateTargets[target]; !allowed {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateTarget
	}
	artifact, ok := manifest.Artifacts[target]
	if !ok {
		return FarmClientUpdateCandidate{}, ErrFarmClientUpdateTarget
	}
	return FarmClientUpdateCandidate{
		Manifest: manifest,
		Artifact: artifact,
		Target:   target,
		Envelope: append([]byte(nil), raw...),
	}, nil
}

func validateFarmClientUpdateManifest(manifest FarmClientUpdateManifest, now time.Time) error {
	if _, err := parseFarmClientSemver(manifest.Version); err != nil {
		return ErrFarmClientUpdateInvalid
	}
	targetProtocol, err := parseFarmClientProtocol(manifest.ProtocolVersion)
	if err != nil {
		return ErrFarmClientUpdateInvalid
	}
	minimumProtocol, err := parseFarmClientProtocol(manifest.MinimumProtocolVersion)
	if err != nil || targetProtocol.major != minimumProtocol.major || compareFarmClientProtocol(targetProtocol, minimumProtocol) < 0 {
		return ErrFarmClientUpdateInvalid
	}
	if !farmClientUpdateChannelPattern.MatchString(manifest.Channel) {
		return ErrFarmClientUpdateInvalid
	}
	published, err := time.Parse(time.RFC3339, manifest.PublishedAt)
	if err != nil {
		return ErrFarmClientUpdateInvalid
	}
	expires, err := time.Parse(time.RFC3339, manifest.ExpiresAt)
	if err != nil || !expires.After(published) {
		return ErrFarmClientUpdateInvalid
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()
	if published.After(now.Add(10*time.Minute)) || !expires.After(now) {
		return ErrFarmClientUpdatePolicy
	}
	if len(manifest.Artifacts) != len(farmClientUpdateTargets) {
		return ErrFarmClientUpdateInvalid
	}
	for target := range farmClientUpdateTargets {
		artifact, ok := manifest.Artifacts[target]
		if !ok || validateFarmClientUpdateArtifact(artifact) != nil {
			return ErrFarmClientUpdateInvalid
		}
	}
	return nil
}

func validateFarmClientUpdateArtifact(artifact FarmClientUpdateArtifact) error {
	parsed, err := url.Parse(strings.TrimSpace(artifact.URL))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return ErrFarmClientUpdateInvalid
	}
	if artifact.Size <= 0 || artifact.Size > farmClientUpdateArtifactLimit {
		return ErrFarmClientUpdateInvalid
	}
	if artifact.SHA256 != strings.ToLower(artifact.SHA256) || len(artifact.SHA256) != sha256.Size*2 {
		return ErrFarmClientUpdateInvalid
	}
	if _, err := hex.DecodeString(artifact.SHA256); err != nil {
		return ErrFarmClientUpdateInvalid
	}
	return nil
}

func StageFarmClientUpdate(
	ctx context.Context,
	client *http.Client,
	stateRoot string,
	candidate FarmClientUpdateCandidate,
) (FarmClientStagedUpdate, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if validateFarmClientUpdateArtifact(candidate.Artifact) != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateInvalid
	}
	root, err := ValidateFarmClientStateRoot(stateRoot)
	if err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	stagingRoot := filepath.Join(root, "updates")
	if err := secureFarmClientUpdateDirectory(stagingRoot); err != nil {
		return FarmClientStagedUpdate{}, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.Artifact.URL, nil)
	if err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateInvalid
	}
	httpClient := farmClientUpdateHTTPClient(client)
	response, err := httpClient.Do(request)
	if err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || (response.ContentLength >= 0 && response.ContentLength != candidate.Artifact.Size) {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	temporary, err := os.CreateTemp(stagingRoot, ".download-*")
	if err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	temporaryPath := temporary.Name()
	keep := false
	defer func() {
		_ = temporary.Close()
		if !keep {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	hasher := sha256.New()
	written, err := io.Copy(io.MultiWriter(temporary, hasher), io.LimitReader(response.Body, candidate.Artifact.Size+1))
	if err != nil || written != candidate.Artifact.Size {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateIntegrity
	}
	var extra [1]byte
	if count, _ := response.Body.Read(extra[:]); count != 0 {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateIntegrity
	}
	if !strings.EqualFold(hex.EncodeToString(hasher.Sum(nil)), candidate.Artifact.SHA256) {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateIntegrity
	}
	if err := temporary.Sync(); err != nil || temporary.Close() != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	finalPath := filepath.Join(stagingRoot, "candidate-"+candidate.Manifest.Version+"-"+candidate.Artifact.SHA256+".bin")
	if _, statErr := os.Lstat(finalPath); statErr == nil {
		if err := verifyFarmClientUpdateFile(finalPath, candidate.Artifact.SHA256, candidate.Artifact.Size); err != nil {
			return FarmClientStagedUpdate{}, ErrFarmClientUpdateIntegrity
		}
		_ = os.Remove(temporaryPath)
	} else if !os.IsNotExist(statErr) {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	} else if err := os.Rename(temporaryPath, finalPath); err != nil {
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	if err := syncFarmClientUpdateDirectory(stagingRoot); err != nil {
		_ = os.Remove(finalPath)
		return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
	}
	envelopePath := ""
	if len(candidate.Envelope) > 0 {
		envelopePath = finalPath + ".manifest"
		if err := writeFarmClientUpdateState(envelopePath, candidate.Envelope, 0o600); err != nil {
			_ = os.Remove(finalPath)
			return FarmClientStagedUpdate{}, ErrFarmClientUpdateUnavailable
		}
	}
	keep = true
	return FarmClientStagedUpdate{Candidate: candidate, Path: finalPath, EnvelopePath: envelopePath}, nil
}

func farmClientUpdateHTTPClient(source *http.Client) *http.Client {
	if source == nil {
		source = &http.Client{Timeout: 5 * time.Minute}
	}
	copyClient := *source
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &copyClient
}

func secureFarmClientUpdateDirectory(path string) error {
	_, beforeErr := os.Lstat(path)
	created := os.IsNotExist(beforeErr)
	if beforeErr != nil && !created {
		return ErrFarmClientUpdateUnavailable
	}
	if created {
		var err error
		created, err = createFarmClientUpdateDirectoryPlatform(path)
		if err != nil {
			return ErrFarmClientUpdateUnavailable
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrFarmClientUpdateUnavailable
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return ErrFarmClientUpdateUnavailable
	}
	return secureFarmClientUpdateDirectoryPlatform(path, created)
}

type farmClientSemver struct {
	major, minor, patch uint64
	prerelease          string
}

func parseFarmClientSemver(value string) (farmClientSemver, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "v") || value == "" || strings.Contains(value, "+") {
		return farmClientSemver{}, ErrFarmClientUpdateInvalid
	}
	parts := strings.SplitN(value, "-", 2)
	core := strings.Split(parts[0], ".")
	if len(core) != 3 {
		return farmClientSemver{}, ErrFarmClientUpdateInvalid
	}
	numbers := make([]uint64, 3)
	for index, item := range core {
		if item == "" || (len(item) > 1 && item[0] == '0') {
			return farmClientSemver{}, ErrFarmClientUpdateInvalid
		}
		parsed, err := strconv.ParseUint(item, 10, 64)
		if err != nil {
			return farmClientSemver{}, ErrFarmClientUpdateInvalid
		}
		numbers[index] = parsed
	}
	prerelease := ""
	if len(parts) == 2 {
		prerelease = parts[1]
		if prerelease == "" {
			return farmClientSemver{}, ErrFarmClientUpdateInvalid
		}
		for _, identifier := range strings.Split(prerelease, ".") {
			numeric := identifier != ""
			for _, character := range identifier {
				numeric = numeric && character >= '0' && character <= '9'
			}
			if identifier == "" || (numeric && len(identifier) > 1 && identifier[0] == '0') {
				return farmClientSemver{}, ErrFarmClientUpdateInvalid
			}
			for _, character := range identifier {
				if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '-') {
					return farmClientSemver{}, ErrFarmClientUpdateInvalid
				}
			}
		}
	}
	return farmClientSemver{numbers[0], numbers[1], numbers[2], prerelease}, nil
}

func compareFarmClientSemver(left, right farmClientSemver) int {
	for _, pair := range [][2]uint64{{left.major, right.major}, {left.minor, right.minor}, {left.patch, right.patch}} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	if left.prerelease == right.prerelease {
		return 0
	}
	if left.prerelease == "" {
		return 1
	}
	if right.prerelease == "" {
		return -1
	}
	leftParts, rightParts := strings.Split(left.prerelease, "."), strings.Split(right.prerelease, ".")
	for index := 0; index < len(leftParts) && index < len(rightParts); index++ {
		leftNumber, leftErr := strconv.ParseUint(leftParts[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightParts[index], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil && leftNumber != rightNumber:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr == nil && rightErr != nil:
			return -1
		case leftErr != nil && rightErr == nil:
			return 1
		case leftParts[index] < rightParts[index]:
			return -1
		case leftParts[index] > rightParts[index]:
			return 1
		}
	}
	if len(leftParts) < len(rightParts) {
		return -1
	}
	if len(leftParts) > len(rightParts) {
		return 1
	}
	return 0
}

type farmClientProtocol struct{ major, minor uint64 }

func parseFarmClientProtocol(value string) (farmClientProtocol, error) {
	if !strings.HasPrefix(value, "bf-p") {
		return farmClientProtocol{}, ErrFarmClientUpdateInvalid
	}
	parts := strings.Split(strings.TrimPrefix(value, "bf-p"), ".")
	if len(parts) != 2 {
		return farmClientProtocol{}, ErrFarmClientUpdateInvalid
	}
	major, errMajor := strconv.ParseUint(parts[0], 10, 64)
	minor, errMinor := strconv.ParseUint(parts[1], 10, 64)
	if errMajor != nil || errMinor != nil || major == 0 {
		return farmClientProtocol{}, ErrFarmClientUpdateInvalid
	}
	return farmClientProtocol{major, minor}, nil
}

func compareFarmClientProtocol(left, right farmClientProtocol) int {
	if left.major < right.major {
		return -1
	}
	if left.major > right.major {
		return 1
	}
	if left.minor < right.minor {
		return -1
	}
	if left.minor > right.minor {
		return 1
	}
	return 0
}

func (candidate FarmClientUpdateCandidate) String() string {
	return fmt.Sprintf("FarmClientUpdateCandidate{version=%s,target=%s}", candidate.Manifest.Version, candidate.Target)
}
