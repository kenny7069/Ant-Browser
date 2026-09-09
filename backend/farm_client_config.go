package backend

// Configuration and identity validation for the Wails-free Ant Farm client.
//
// This file intentionally does not use backend.LoadConfig.  That helper is
// desktop-oriented and repairs a broken config on disk.  A standalone client
// must fail closed before it constructs any runtime or network service.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	appconfig "ant-chrome/backend/internal/config"
	"gopkg.in/yaml.v3"
)

const FarmClientVersion = "0.1.0-dev"

var (
	ErrFarmClientConfig       = errors.New("invalid ant farm client config")
	ErrFarmClientIdentity     = errors.New("invalid ant farm client identity")
	ErrFarmClientRoots        = errors.New("invalid ant farm client roots")
	ErrFarmClientAlreadyRun   = errors.New("ant farm client is already running")
	ErrFarmClientProfileStore = errors.New("invalid ant farm client profile store")
)

var farmClientNodeUIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// FarmClientIdentityConfig accepts the C2 opaque secure-store reference. The
// encoded key fields remain only for C1 development fixtures and are never
// written by this package.
type FarmClientIdentityConfig struct {
	NodeUID       string `yaml:"node_uid" json:"node_uid"`
	PrivateKey    string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	PrivateKeyEnv string `yaml:"private_key_env,omitempty" json:"private_key_env,omitempty"`
	PrivateKeyRef string `yaml:"private_key_ref,omitempty" json:"private_key_ref,omitempty"`
}

// FarmClientConfig describes only client-owned configuration. ApplicationRoot
// is the immutable Ant installation/config root; StateRoot is the mutable
// client-owned root. Both must be explicit absolute paths.
type FarmClientConfig struct {
	ApplicationRoot string `yaml:"application_root,omitempty" json:"application_root,omitempty"`
	// AppRoot is a compatibility spelling for development/test configs. If both
	// spellings are supplied they must resolve to the same path.
	AppRoot   string `yaml:"app_root,omitempty" json:"app_root,omitempty"`
	StateRoot string `yaml:"state_root" json:"state_root"`

	AntConfigPath string `yaml:"ant_config_path,omitempty" json:"ant_config_path,omitempty"`
	ControlURL    string `yaml:"control_url,omitempty" json:"control_url,omitempty"`
	// WSSURL is a compatibility spelling for the control endpoint.
	WSSURL string `yaml:"wss_url,omitempty" json:"wss_url,omitempty"`
	// EnrollmentURL is used only by the explicit first-run enrollment command.
	// The one-time code is never stored in this config.
	EnrollmentURL string `yaml:"enrollment_url,omitempty" json:"enrollment_url,omitempty"`
	// PairingURL is the C3 signed profile-pair endpoint. Unpair uses the same
	// origin and the sibling /unpair path; neither endpoint is stored in output.
	PairingURL string `yaml:"pairing_url,omitempty" json:"pairing_url,omitempty"`
	NodeName   string `yaml:"node_name,omitempty" json:"node_name,omitempty"`
	// AllowLoopbackHTTPEnrollment is an explicit development/test escape hatch.
	// Production enrollment remains HTTPS-only, including loopback by default.
	AllowLoopbackHTTPEnrollment bool `yaml:"allow_loopback_http_enrollment,omitempty" json:"allow_loopback_http_enrollment,omitempty"`

	Identity FarmClientIdentityConfig `yaml:"identity,omitempty" json:"identity,omitempty"`
	// The flat identity fields make one-shot development launch easy while the
	// nested form remains the canonical on-disk shape.
	NodeUID       string `yaml:"node_uid,omitempty" json:"node_uid,omitempty"`
	PrivateKey    string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	PrivateKeyEnv string `yaml:"private_key_env,omitempty" json:"private_key_env,omitempty"`

	ProviderInstanceID    string `yaml:"provider_instance_id,omitempty" json:"provider_instance_id,omitempty"`
	FencingEpoch          uint64 `yaml:"fencing_epoch,omitempty" json:"fencing_epoch,omitempty"`
	ShutdownTimeoutMs     int    `yaml:"shutdown_timeout_ms,omitempty" json:"shutdown_timeout_ms,omitempty"`
	HandshakeTimeoutMs    int    `yaml:"handshake_timeout_ms,omitempty" json:"handshake_timeout_ms,omitempty"`
	CommandTimeoutMs      int    `yaml:"command_timeout_ms,omitempty" json:"command_timeout_ms,omitempty"`
	HeartbeatIntervalMs   int    `yaml:"heartbeat_interval_ms,omitempty" json:"heartbeat_interval_ms,omitempty"`
	ReconnectMinBackoffMs int    `yaml:"reconnect_min_backoff_ms,omitempty" json:"reconnect_min_backoff_ms,omitempty"`
	ReconnectMaxBackoffMs int    `yaml:"reconnect_max_backoff_ms,omitempty" json:"reconnect_max_backoff_ms,omitempty"`

	LogFile string `yaml:"log_file,omitempty" json:"log_file,omitempty"`
}

// FarmClientIdentity is the in-memory identity passed to the authenticated
// WSS constructor. Stringification deliberately never includes PrivateKey.
type FarmClientIdentity struct {
	NodeUID    string
	PrivateKey ed25519.PrivateKey
}

// FarmClientVersionInfo is safe to expose in diagnostics and contains no
// profile, root, URL, node identity, or secret material.
type FarmClientVersionInfo struct {
	Version string `json:"version"`
	GOOS    string `json:"goos"`
	GOARCH  string `json:"goarch"`
}

func (c FarmClientConfig) String() string {
	return "FarmClientConfig{version=" + FarmClientVersion + "}"
}

func (i FarmClientIdentity) String() string {
	return "FarmClientIdentity{configured=" + fmt.Sprint(strings.TrimSpace(i.NodeUID) != "") + "}"
}

func FarmClientVersionInfoValue() FarmClientVersionInfo {
	return FarmClientVersionInfo{Version: FarmClientVersion, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH}
}

// LoadFarmClientConfig reads the client config without repairing it. Unknown
// YAML fields are rejected so an operator cannot believe a misspelled safety
// setting was applied.
func LoadFarmClientConfig(path string) (FarmClientConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return FarmClientConfig{}, fmt.Errorf("%w: config path is required", ErrFarmClientConfig)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return FarmClientConfig{}, fmt.Errorf("%w: read config: %v", ErrFarmClientConfig, err)
	}
	var config FarmClientConfig
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return FarmClientConfig{}, fmt.Errorf("%w: decode config: %v", ErrFarmClientConfig, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return FarmClientConfig{}, fmt.Errorf("%w: multiple YAML documents", ErrFarmClientConfig)
		}
		return FarmClientConfig{}, fmt.Errorf("%w: decode trailing YAML: %v", ErrFarmClientConfig, err)
	}
	return config, nil
}

// ValidateFarmClientConfig normalizes the explicit roots and bounded timing
// values. It does not create directories or read identity secrets.
func (c *FarmClientConfig) ValidateFarmClientConfig() error {
	if c == nil {
		return fmt.Errorf("%w: config is nil", ErrFarmClientConfig)
	}
	appRoot, err := mergeFarmClientRoot(c.ApplicationRoot, c.AppRoot, "application root")
	if err != nil {
		return err
	}
	stateRoot, err := validateAbsoluteFarmClientRoot(c.StateRoot, "state root")
	if err != nil {
		return err
	}
	c.ApplicationRoot = appRoot
	c.AppRoot = appRoot
	c.StateRoot = stateRoot

	controlURL, err := mergeFarmClientURL(c.ControlURL, c.WSSURL, "control URL")
	if err != nil {
		return err
	}
	if err := validateFarmClientControlURL(controlURL); err != nil {
		return err
	}
	c.ControlURL = controlURL
	c.WSSURL = controlURL

	identity := c.identityConfig()
	if err := validateFarmClientNodeUID(identity.NodeUID); err != nil {
		return err
	}
	identitySources := 0
	for _, value := range []string{identity.PrivateKey, identity.PrivateKeyEnv, identity.PrivateKeyRef} {
		if strings.TrimSpace(value) != "" {
			identitySources++
		}
	}
	if identitySources > 1 {
		return fmt.Errorf("%w: private key, environment and key reference are mutually exclusive", ErrFarmClientIdentity)
	}
	if strings.TrimSpace(identity.PrivateKeyRef) != "" {
		if _, err := NewFarmClientIdentityKeyRef(identity.PrivateKeyRef); err != nil {
			return err
		}
	}
	if strings.TrimSpace(c.NodeName) != "" {
		if err := validateFarmClientNodeName(c.NodeName); err != nil {
			return err
		}
	} else {
		c.NodeName = strings.TrimSpace(identity.NodeUID)
	}
	if strings.TrimSpace(c.EnrollmentURL) != "" {
		enrollmentURL, err := normalizeFarmClientEnrollmentURL(c.EnrollmentURL, c.AllowLoopbackHTTPEnrollment)
		if err != nil {
			return err
		}
		c.EnrollmentURL = enrollmentURL
	}
	if strings.TrimSpace(c.PairingURL) != "" {
		pairingURL, err := normalizeFarmClientEnrollmentURL(c.PairingURL, c.AllowLoopbackHTTPEnrollment)
		if err != nil {
			return fmt.Errorf("%w: pairing URL is invalid", ErrFarmClientConfig)
		}
		parsed, _ := url.Parse(pairingURL)
		if parsed == nil || !strings.HasSuffix(strings.TrimRight(parsed.Path, "/"), "/pair") {
			return fmt.Errorf("%w: pairing URL must end in /pair", ErrFarmClientConfig)
		}
		c.PairingURL = pairingURL
	}
	if strings.TrimSpace(c.ProviderInstanceID) == "" {
		c.ProviderInstanceID = "ant-farm-client-" + identity.NodeUID
	}
	if !farmClientNodeUIDPattern.MatchString(strings.TrimSpace(c.ProviderInstanceID)) {
		return fmt.Errorf("%w: provider instance id is invalid", ErrFarmClientConfig)
	}
	if c.FencingEpoch == 0 {
		c.FencingEpoch = 1
	}
	if err := validateFarmClientMilliseconds(c.ShutdownTimeoutMs, 1, 120000, "shutdown timeout"); err != nil {
		return err
	}
	if err := validateFarmClientMilliseconds(c.HandshakeTimeoutMs, 1, 120000, "handshake timeout"); err != nil {
		return err
	}
	if err := validateFarmClientMilliseconds(c.CommandTimeoutMs, 1, 120000, "command timeout"); err != nil {
		return err
	}
	if err := validateFarmClientMilliseconds(c.HeartbeatIntervalMs, 1, 60000, "heartbeat interval"); err != nil {
		return err
	}
	if err := validateFarmClientMilliseconds(c.ReconnectMinBackoffMs, 1, 120000, "reconnect minimum backoff"); err != nil {
		return err
	}
	if err := validateFarmClientMilliseconds(c.ReconnectMaxBackoffMs, 1, 120000, "reconnect maximum backoff"); err != nil {
		return err
	}
	if c.ReconnectMinBackoffMs > 0 && c.ReconnectMaxBackoffMs > 0 && c.ReconnectMinBackoffMs > c.ReconnectMaxBackoffMs {
		return fmt.Errorf("%w: reconnect minimum exceeds maximum", ErrFarmClientConfig)
	}
	if strings.TrimSpace(c.AntConfigPath) != "" {
		if filepath.IsAbs(strings.TrimSpace(c.AntConfigPath)) {
			c.AntConfigPath = filepath.Clean(strings.TrimSpace(c.AntConfigPath))
		} else {
			c.AntConfigPath = filepath.Clean(filepath.Join(c.ApplicationRoot, strings.TrimSpace(c.AntConfigPath)))
		}
	} else {
		c.AntConfigPath = filepath.Join(c.ApplicationRoot, "config.yaml")
	}
	if strings.TrimSpace(c.LogFile) != "" {
		if filepath.IsAbs(strings.TrimSpace(c.LogFile)) {
			c.LogFile = filepath.Clean(strings.TrimSpace(c.LogFile))
		} else {
			relative := filepath.Clean(strings.TrimSpace(c.LogFile))
			candidate := filepath.Clean(filepath.Join(c.StateRoot, relative))
			rel, relErr := filepath.Rel(c.StateRoot, candidate)
			if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				return fmt.Errorf("%w: log file must remain inside state root", ErrFarmClientRoots)
			}
			c.LogFile = candidate
		}
	} else {
		c.LogFile = filepath.Join(c.StateRoot, "logs", "ant-farm-client.log")
	}
	return nil
}

func validateFarmClientMilliseconds(value, min, max int, name string) error {
	if value == 0 {
		return nil
	}
	if value < min || value > max {
		return fmt.Errorf("%w: %s must be between %d and %d ms", ErrFarmClientConfig, name, min, max)
	}
	return nil
}

func mergeFarmClientRoot(primary, alias, name string) (string, error) {
	primary = strings.TrimSpace(primary)
	alias = strings.TrimSpace(alias)
	if primary != "" && alias != "" {
		p, err := validateAbsoluteFarmClientRoot(primary, name)
		if err != nil {
			return "", err
		}
		a, err := validateAbsoluteFarmClientRoot(alias, name)
		if err != nil {
			return "", err
		}
		if p != a {
			return "", fmt.Errorf("%w: conflicting %s values", ErrFarmClientRoots, name)
		}
		return p, nil
	}
	if primary == "" {
		primary = alias
	}
	return validateAbsoluteFarmClientRoot(primary, name)
}

func validateAbsoluteFarmClientRoot(value, name string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return "", fmt.Errorf("%w: %s must be an absolute path", ErrFarmClientRoots, name)
	}
	clean := filepath.Clean(value)
	if clean == "." {
		return "", fmt.Errorf("%w: %s is invalid", ErrFarmClientRoots, name)
	}
	return clean, nil
}

func mergeFarmClientURL(primary, alias, name string) (string, error) {
	primary = strings.TrimSpace(primary)
	alias = strings.TrimSpace(alias)
	if primary != "" && alias != "" && primary != alias {
		return "", fmt.Errorf("%w: conflicting %s values", ErrFarmClientConfig, name)
	}
	if primary == "" {
		primary = alias
	}
	if primary == "" {
		return "", fmt.Errorf("%w: %s is required", ErrFarmClientConfig, name)
	}
	return primary, nil
}

func validateFarmClientControlURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return fmt.Errorf("%w: control URL is invalid", ErrFarmClientConfig)
	}
	loopback := parsed.Hostname() == "localhost" || net.ParseIP(parsed.Hostname()).IsLoopback()
	if parsed.Scheme != "wss" && !(parsed.Scheme == "ws" && loopback) {
		return fmt.Errorf("%w: control URL must use wss (ws only on loopback)", ErrFarmClientConfig)
	}
	return nil
}

func validateFarmClientNodeUID(nodeUID string) error {
	if !farmClientNodeUIDPattern.MatchString(strings.TrimSpace(nodeUID)) {
		return fmt.Errorf("%w: node uid is invalid", ErrFarmClientIdentity)
	}
	return nil
}

func validateFarmClientNodeName(nodeName string) error {
	nodeName = strings.TrimSpace(nodeName)
	if nodeName == "" || len(nodeName) > 100 {
		return fmt.Errorf("%w: node name is invalid", ErrFarmClientIdentity)
	}
	for _, char := range nodeName {
		if char < 0x20 || char == 0x7f {
			return fmt.Errorf("%w: node name is invalid", ErrFarmClientIdentity)
		}
	}
	return nil
}

func normalizeFarmClientEnrollmentURL(raw string, allowLoopbackHTTP bool) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" || parsed.RawQuery != "" {
		return "", fmt.Errorf("%w: enrollment URL is invalid", ErrFarmClientConfig)
	}
	loopback := parsed.Hostname() == "localhost" || net.ParseIP(parsed.Hostname()).IsLoopback()
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && loopback && allowLoopbackHTTP) {
		return "", fmt.Errorf("%w: enrollment URL must use https (http only on loopback)", ErrFarmClientConfig)
	}
	return parsed.String(), nil
}

func (c FarmClientConfig) identityConfig() FarmClientIdentityConfig {
	identity := c.Identity
	if strings.TrimSpace(c.NodeUID) != "" {
		if strings.TrimSpace(identity.NodeUID) != "" && strings.TrimSpace(identity.NodeUID) != strings.TrimSpace(c.NodeUID) {
			return FarmClientIdentityConfig{NodeUID: "\x00conflict"}
		}
		identity.NodeUID = c.NodeUID
	}
	if strings.TrimSpace(c.PrivateKey) != "" {
		identity.PrivateKey = c.PrivateKey
	}
	if strings.TrimSpace(c.PrivateKeyEnv) != "" {
		identity.PrivateKeyEnv = c.PrivateKeyEnv
	}
	return identity
}

// ResolveFarmClientIdentity resolves the explicit development/test identity.
// The returned key is copied so callers can clear their source buffer without
// changing the WSS client identity.
func (c FarmClientConfig) ResolveFarmClientIdentity(lookup func(string) string) (FarmClientIdentity, error) {
	identity := c.identityConfig()
	if err := validateFarmClientNodeUID(identity.NodeUID); err != nil {
		return FarmClientIdentity{}, err
	}
	encoded := strings.TrimSpace(identity.PrivateKey)
	if encoded == "" && strings.TrimSpace(identity.PrivateKeyEnv) != "" {
		if lookup == nil {
			lookup = os.Getenv
		}
		encoded = strings.TrimSpace(lookup(strings.TrimSpace(identity.PrivateKeyEnv)))
	}
	if encoded == "" {
		if strings.TrimSpace(identity.PrivateKeyRef) != "" {
			return FarmClientIdentity{}, fmt.Errorf("%w: secure key reference requires identity store", ErrFarmClientIdentity)
		}
		return FarmClientIdentity{}, fmt.Errorf("%w: development private key input is required", ErrFarmClientIdentity)
	}
	key, err := decodeFarmClientPrivateKey(encoded)
	if err != nil {
		return FarmClientIdentity{}, err
	}
	return FarmClientIdentity{NodeUID: strings.TrimSpace(identity.NodeUID), PrivateKey: key}, nil
}

// ResolveFarmClientIdentityFromStore loads a production identity through its
// validated opaque reference. Native errors are collapsed to stable classes
// before crossing the bootstrap boundary.
func (c FarmClientConfig) ResolveFarmClientIdentityFromStore(store FarmClientIdentityStore) (FarmClientIdentity, error) {
	identity := c.identityConfig()
	if err := validateFarmClientNodeUID(identity.NodeUID); err != nil {
		return FarmClientIdentity{}, err
	}
	ref, err := NewFarmClientIdentityKeyRef(identity.PrivateKeyRef)
	if err != nil || store == nil {
		return FarmClientIdentity{}, ErrFarmClientIdentityStore
	}
	key, err := store.Load(ref)
	if err != nil {
		return FarmClientIdentity{}, farmClientIdentityStoreError(err)
	}
	return FarmClientIdentity{NodeUID: strings.TrimSpace(identity.NodeUID), PrivateKey: append(ed25519.PrivateKey(nil), key...)}, nil
}

func decodeFarmClientPrivateKey(encoded string) (ed25519.PrivateKey, error) {
	encoded = strings.TrimSpace(encoded)
	for _, prefix := range []string{"base64:", "b64:"} {
		if strings.HasPrefix(strings.ToLower(encoded), prefix) {
			encoded = strings.TrimSpace(encoded[len(prefix):])
			break
		}
	}
	var raw []byte
	var err error
	if len(encoded) == ed25519.SeedSize*2 || len(encoded) == ed25519.PrivateKeySize*2 {
		raw, err = hex.DecodeString(encoded)
	} else {
		raw, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			raw, err = base64.RawStdEncoding.DecodeString(encoded)
		}
	}
	if err != nil || (len(raw) != ed25519.SeedSize && len(raw) != ed25519.PrivateKeySize) {
		return nil, fmt.Errorf("%w: private key must be base64/hex Ed25519 seed or expanded key", ErrFarmClientIdentity)
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func (c FarmClientConfig) handshakeTimeout() time.Duration {
	if c.HandshakeTimeoutMs > 0 {
		return time.Duration(c.HandshakeTimeoutMs) * time.Millisecond
	}
	return 10 * time.Second
}

func (c FarmClientConfig) commandTimeout() time.Duration {
	if c.CommandTimeoutMs > 0 {
		return time.Duration(c.CommandTimeoutMs) * time.Millisecond
	}
	return 10 * time.Second
}

func (c FarmClientConfig) heartbeatInterval() time.Duration {
	if c.HeartbeatIntervalMs > 0 {
		return time.Duration(c.HeartbeatIntervalMs) * time.Millisecond
	}
	return 5 * time.Second
}

func (c FarmClientConfig) reconnectMinBackoff() time.Duration {
	if c.ReconnectMinBackoffMs > 0 {
		return time.Duration(c.ReconnectMinBackoffMs) * time.Millisecond
	}
	return 250 * time.Millisecond
}

func (c FarmClientConfig) reconnectMaxBackoff() time.Duration {
	if c.ReconnectMaxBackoffMs > 0 {
		return time.Duration(c.ReconnectMaxBackoffMs) * time.Millisecond
	}
	return 10 * time.Second
}

func (c FarmClientConfig) shutdownTimeout() time.Duration {
	if c.ShutdownTimeoutMs > 0 {
		return time.Duration(c.ShutdownTimeoutMs) * time.Millisecond
	}
	return 15 * time.Second
}

// IsLoopbackControlURL is kept public for process/integration tests and
// diagnostics without exposing the URL from version output.
func IsLoopbackControlURL(raw string) bool {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	return err == nil && (parsed.Hostname() == "localhost" || net.ParseIP(parsed.Hostname()).IsLoopback())
}

// ValidateFarmClientApplicationRoot is the side-effecting root check used by
// the process bootstrap. StateRoot is created later while acquiring the lock.
func ValidateFarmClientApplicationRoot(path string) (string, error) {
	clean, err := validateAbsoluteFarmClientRoot(path, "application root")
	if err != nil {
		return "", err
	}
	info, err := os.Stat(clean)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: application root is not an existing directory", ErrFarmClientRoots)
	}
	return clean, nil
}

func ValidateFarmClientStateRoot(path string) (string, error) {
	clean, err := validateAbsoluteFarmClientRoot(path, "state root")
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return "", fmt.Errorf("%w: create state root: %v", ErrFarmClientRoots, err)
	}
	if info, err := os.Stat(clean); err != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: state root is not a directory", ErrFarmClientRoots)
	}
	return clean, nil
}

// FarmClientAntConfigLoader is a strict loader for the existing Ant config;
// unlike backend.LoadConfig it never creates or repairs a file.
func LoadFarmClientAntConfig(path string) (*Config, error) {
	path = strings.TrimSpace(path)
	if path == "" || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: Ant config path must be absolute", ErrFarmClientConfig)
	}
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return nil, fmt.Errorf("%w: Ant config file is missing or unreadable", ErrFarmClientConfig)
	}
	cfg, err := appconfig.Load(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("%w: load Ant config: %v", ErrFarmClientConfig, err)
	}
	if strings.ToLower(strings.TrimSpace(cfg.Database.Type)) != "sqlite" {
		return nil, fmt.Errorf("%w: only sqlite profile storage is supported", ErrFarmClientProfileStore)
	}
	if strings.TrimSpace(cfg.Database.SQLite.Path) == "" {
		return nil, fmt.Errorf("%w: Ant sqlite path is empty", ErrFarmClientProfileStore)
	}
	return cfg, nil
}
