package backend

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

var ErrSuiteReleaseManifest = errors.New("invalid signed suite release manifest")

const (
	SuiteReleaseEntryBinary  = "binary"
	SuiteReleaseEntryLibrary = "library"
	SuiteReleaseEntryConfig  = "config"
	SuiteReleaseEntryAsset   = "asset"
	SuiteReleaseEntryLegal   = "legal"

	maxSuiteReleaseManifestBytes = 1 << 20
	maxSuiteReleaseEnvelopeBytes = 16 << 10
	maxSuiteReleaseEntries       = 4096
	maxSuiteReleaseCapabilities  = 256
	maxSuiteReleaseDependencies  = 512
	maxSuiteReleaseCoreVersions  = 128
	maxSuiteReleaseEntryBytes    = int64(1 << 40)
)

var suiteReleaseTokenPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
var suiteReleaseCommitPattern = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
var suiteReleaseSemverPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$`)

type SuiteReleaseTarget struct {
	OS   string `json:"os"`
	Arch string `json:"arch"`
}

type SuiteReleaseCommits struct {
	AntBrowser  string `json:"ant_browser"`
	FarmAgent   string `json:"farm_agent"`
	FarmControl string `json:"farm_control"`
}

type SuiteReleaseDependency struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type SuiteReleaseEntry struct {
	Path       string `json:"path"`
	Role       string `json:"role"`
	Size       int64  `json:"size"`
	SHA256     string `json:"sha256"`
	Executable bool   `json:"executable"`
}

type SuiteReleaseManifest struct {
	SchemaVersion int                      `json:"schema_version"`
	Version       string                   `json:"version"`
	Target        SuiteReleaseTarget       `json:"target"`
	Commits       SuiteReleaseCommits      `json:"commits"`
	ConfigSchema  int                      `json:"config_schema"`
	Capabilities  []string                 `json:"capabilities"`
	CoreVersions  map[string]string        `json:"core_versions"`
	Dependencies  []SuiteReleaseDependency `json:"dependencies"`
	Entries       []SuiteReleaseEntry      `json:"entries"`
}

// SuiteReleaseManifestEnvelope is detached: it authenticates the separately
// supplied manifest bytes and deliberately carries no trust key.
type SuiteReleaseManifestEnvelope struct {
	SchemaVersion  int    `json:"schema_version"`
	Algorithm      string `json:"algorithm"`
	KeyID          string `json:"key_id"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Signature      string `json:"signature"`
}

func (m SuiteReleaseManifest) Validate() error {
	if m.SchemaVersion != 1 || !suiteReleaseSemverPattern.MatchString(m.Version) || m.ConfigSchema < 1 {
		return ErrSuiteReleaseManifest
	}
	if !validSuiteReleaseTarget(m.Target) || !validSuiteReleaseCommits(m.Commits) || len(m.Entries) == 0 || len(m.Entries) > maxSuiteReleaseEntries {
		return ErrSuiteReleaseManifest
	}
	if m.Capabilities == nil || len(m.Capabilities) > maxSuiteReleaseCapabilities || m.Dependencies == nil ||
		len(m.Dependencies) > maxSuiteReleaseDependencies || len(m.CoreVersions) == 0 || len(m.CoreVersions) > maxSuiteReleaseCoreVersions {
		return fmt.Errorf("%w: core versions are required", ErrSuiteReleaseManifest)
	}
	if err := validateSuiteReleaseTokens(m.Capabilities); err != nil {
		return err
	}
	seenCoreVersions := map[string]struct{}{}
	for name, version := range m.CoreVersions {
		if !suiteReleaseTokenPattern.MatchString(name) || !suiteReleaseTokenPattern.MatchString(version) {
			return fmt.Errorf("%w: invalid core version", ErrSuiteReleaseManifest)
		}
		folded := strings.ToLower(name)
		if _, exists := seenCoreVersions[folded]; exists {
			return fmt.Errorf("%w: case-folded core version collision", ErrSuiteReleaseManifest)
		}
		seenCoreVersions[folded] = struct{}{}
	}
	seenDependencies := map[string]struct{}{}
	for _, dependency := range m.Dependencies {
		key := strings.ToLower(dependency.Name)
		if !suiteReleaseTokenPattern.MatchString(dependency.Name) || !suiteReleaseTokenPattern.MatchString(dependency.Version) ||
			!suiteReleaseTokenPattern.MatchString(dependency.License) {
			return fmt.Errorf("%w: invalid dependency", ErrSuiteReleaseManifest)
		}
		if _, exists := seenDependencies[key]; exists {
			return fmt.Errorf("%w: duplicate dependency", ErrSuiteReleaseManifest)
		}
		seenDependencies[key] = struct{}{}
	}
	seenPaths := map[string]struct{}{}
	hasBinary, hasLegal := false, false
	for _, entry := range m.Entries {
		normalized, err := normalizeSuiteReleasePath(entry.Path)
		if err != nil || normalized != entry.Path {
			return fmt.Errorf("%w: invalid entry path %q", ErrSuiteReleaseManifest, entry.Path)
		}
		folded := strings.ToLower(normalized)
		if _, exists := seenPaths[folded]; exists {
			return fmt.Errorf("%w: duplicate or case-folded entry path", ErrSuiteReleaseManifest)
		}
		seenPaths[folded] = struct{}{}
		if entry.Size < 0 || entry.Size > maxSuiteReleaseEntryBytes || !validLowerSHA256(entry.SHA256) || !validSuiteReleaseEntryRole(entry.Role) {
			return fmt.Errorf("%w: invalid entry metadata", ErrSuiteReleaseManifest)
		}
		if (entry.Role == SuiteReleaseEntryBinary) != entry.Executable {
			return fmt.Errorf("%w: executable flag does not match role", ErrSuiteReleaseManifest)
		}
		if entry.Role == SuiteReleaseEntryBinary {
			hasBinary = true
			if entry.Size == 0 {
				return fmt.Errorf("%w: binary entry cannot be empty", ErrSuiteReleaseManifest)
			}
		}
		hasLegal = hasLegal || entry.Role == SuiteReleaseEntryLegal
	}
	if !hasBinary || !hasLegal {
		return fmt.Errorf("%w: binary and legal entries are required", ErrSuiteReleaseManifest)
	}
	return nil
}

func MarshalSuiteReleaseManifest(manifest SuiteReleaseManifest) ([]byte, error) {
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > maxSuiteReleaseManifestBytes {
		return nil, fmt.Errorf("%w: manifest exceeds size limit", ErrSuiteReleaseManifest)
	}
	return raw, nil
}

func ParseSuiteReleaseManifest(raw []byte) (SuiteReleaseManifest, error) {
	if len(raw) == 0 || len(raw) > maxSuiteReleaseManifestBytes {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: manifest size", ErrSuiteReleaseManifest)
	}
	var manifest SuiteReleaseManifest
	if err := decodeSuiteReleaseStrictJSON(raw, &manifest); err != nil {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: decode", ErrSuiteReleaseManifest)
	}
	if err := manifest.Validate(); err != nil {
		return SuiteReleaseManifest{}, err
	}
	return manifest, nil
}

func SignSuiteReleaseManifest(manifestRaw []byte, keyID string, privateKey ed25519.PrivateKey) ([]byte, error) {
	if _, err := ParseSuiteReleaseManifest(manifestRaw); err != nil {
		return nil, err
	}
	if !suiteReleaseTokenPattern.MatchString(keyID) || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrSuiteReleaseManifest
	}
	digest := sha256.Sum256(manifestRaw)
	envelope := SuiteReleaseManifestEnvelope{
		SchemaVersion: 1, Algorithm: "Ed25519", KeyID: keyID,
		ManifestSHA256: hex.EncodeToString(digest[:]),
		Signature:      base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, manifestRaw)),
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func VerifySuiteReleaseManifest(manifestRaw, envelopeRaw []byte, expectedKeyID string, trustedPublicKey ed25519.PublicKey) (SuiteReleaseManifest, error) {
	if len(trustedPublicKey) != ed25519.PublicKeySize || !suiteReleaseTokenPattern.MatchString(expectedKeyID) ||
		len(envelopeRaw) == 0 || len(envelopeRaw) > maxSuiteReleaseEnvelopeBytes ||
		len(manifestRaw) == 0 || len(manifestRaw) > maxSuiteReleaseManifestBytes {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: caller trust key is invalid", ErrSuiteReleaseManifest)
	}
	var envelope SuiteReleaseManifestEnvelope
	if err := decodeSuiteReleaseStrictJSON(envelopeRaw, &envelope); err != nil || envelope.SchemaVersion != 1 ||
		envelope.Algorithm != "Ed25519" || envelope.KeyID != expectedKeyID || !validLowerSHA256(envelope.ManifestSHA256) {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: invalid detached envelope", ErrSuiteReleaseManifest)
	}
	digest := sha256.Sum256(manifestRaw)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), envelope.ManifestSHA256) {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: manifest digest mismatch", ErrSuiteReleaseManifest)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(trustedPublicKey, manifestRaw, signature) {
		return SuiteReleaseManifest{}, fmt.Errorf("%w: signature verification failed", ErrSuiteReleaseManifest)
	}
	return ParseSuiteReleaseManifest(manifestRaw)
}

func SuiteReleaseManifestSHA256(raw []byte) (string, error) {
	if _, err := ParseSuiteReleaseManifest(raw); err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeSuiteReleasePath(raw string) (string, error) {
	if raw == "" || strings.TrimSpace(raw) != raw || strings.Contains(raw, `\`) || strings.Contains(raw, ":") ||
		strings.IndexByte(raw, 0) >= 0 || strings.HasPrefix(raw, "/") || filepath.IsAbs(raw) {
		return "", ErrSuiteReleaseManifest
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || cleaned != raw || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", ErrSuiteReleaseManifest
	}
	for _, segment := range strings.Split(cleaned, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", ErrSuiteReleaseManifest
		}
	}
	return cleaned, nil
}

func validSuiteReleaseTarget(target SuiteReleaseTarget) bool {
	validOS := target.OS == "windows" || target.OS == "linux" || target.OS == "darwin"
	validArch := target.Arch == "amd64" || target.Arch == "arm64"
	return validOS && validArch
}

func validSuiteReleaseCommits(commits SuiteReleaseCommits) bool {
	return suiteReleaseCommitPattern.MatchString(commits.AntBrowser) &&
		suiteReleaseCommitPattern.MatchString(commits.FarmAgent) && suiteReleaseCommitPattern.MatchString(commits.FarmControl)
}

func validateSuiteReleaseTokens(values []string) error {
	seen := map[string]struct{}{}
	for _, value := range values {
		key := strings.ToLower(value)
		if !suiteReleaseTokenPattern.MatchString(value) {
			return fmt.Errorf("%w: invalid capability", ErrSuiteReleaseManifest)
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("%w: duplicate capability", ErrSuiteReleaseManifest)
		}
		seen[key] = struct{}{}
	}
	return nil
}

func validSuiteReleaseEntryRole(role string) bool {
	switch role {
	case SuiteReleaseEntryBinary, SuiteReleaseEntryLibrary, SuiteReleaseEntryConfig, SuiteReleaseEntryAsset, SuiteReleaseEntryLegal:
		return true
	default:
		return false
	}
}

func validLowerSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == value
}

func decodeSuiteReleaseStrictJSON(raw []byte, destination any) error {
	if err := rejectSuiteReleaseDuplicateJSONKeys(raw); err != nil {
		return err
	}
	return decodeStrictJSON(raw, destination)
}

func rejectSuiteReleaseDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := walkSuiteReleaseJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: trailing JSON", ErrSuiteReleaseManifest)
	}
	return nil
}

func walkSuiteReleaseJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrSuiteReleaseManifest
			}
			folded := strings.ToLower(key)
			if _, exists := seen[folded]; exists {
				return fmt.Errorf("%w: duplicate or case-folded JSON key", ErrSuiteReleaseManifest)
			}
			seen[folded] = struct{}{}
			if err := walkSuiteReleaseJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrSuiteReleaseManifest
		}
	case '[':
		for decoder.More() {
			if err := walkSuiteReleaseJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrSuiteReleaseManifest
		}
	default:
		return ErrSuiteReleaseManifest
	}
	return nil
}
