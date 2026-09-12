package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"
)

const (
	SuiteClientConfigName       = "client.yaml"
	SuiteOwnershipHandoffName   = "ownership-handoff.json"
	maxSuiteClientConfigBytes   = 64 << 10
	maxSuiteOwnershipHandoffRaw = 16 << 10
	suiteHandoffIntentDurable   = "INTENT_DURABLE"
)

var (
	ErrSuiteOwnershipHandoff         = errors.New("invalid suite ownership handoff")
	ErrSuiteOwnershipHandoffConflict = errors.New("suite ownership handoff conflicts with durable intent")
)

// SuiteOwnershipHandoff is the durable boundary between setup and service or
// GUI startup. It contains paths and digests only; identity keys and enrollment
// material remain in the protected client configuration and secret store.
type SuiteOwnershipHandoff struct {
	SchemaVersion      int    `json:"schema_version"`
	HandoffState       string `json:"handoff_state"`
	SetupRequestUID    string `json:"setup_request_uid"`
	GUIBinaryPath      string `json:"gui_binary_path"`
	SuiteBinaryRoot    string `json:"suite_binary_root"`
	ClientConfigPath   string `json:"client_config_path"`
	AgentStateRoot     string `json:"agent_state_root"`
	ApplicationRoot    string `json:"application_root"`
	ClientConfigSHA256 string `json:"client_config_sha256"`
}

type SuiteGUIInvocation struct {
	Executable string
	Arguments  []string
}

// FinalizeSuiteOwnershipHandoff creates or confirms the immutable intent. A
// Suite launcher must complete this operation before starting the Agent.
func FinalizeSuiteOwnershipHandoff(roots SuiteUserRoots, setupRequestUID, suiteBinaryRoot, guiBinaryPath string) (SuiteOwnershipHandoff, error) {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	if err := validateExistingSuiteOwnerRoot(roots.Config); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	if err := validateExistingSuiteOwnerRoot(roots.AgentState); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	checkpoint, err := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupBootstrapDrafted || checkpoint.RequestUID != setupRequestUID {
		return SuiteOwnershipHandoff{}, fmt.Errorf("%w: setup preparation mismatch", ErrSuiteOwnershipHandoff)
	}
	configPath := filepath.Join(roots.Config, SuiteClientConfigName)
	config, digest, err := loadSuiteHandoffClientConfig(configPath)
	if err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	if !sameSuiteHandoffPath(config.StateRoot, roots.AgentState) {
		return SuiteOwnershipHandoff{}, fmt.Errorf("%w: agent state root mismatch", ErrSuiteOwnershipHandoff)
	}
	if err := validateSuiteMutableApplicationRoot(config.ApplicationRoot, roots.BrowserData); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	guiBinaryPath, suiteBinaryRoot, err = validateSuiteImmutableGUIPath(guiBinaryPath, suiteBinaryRoot)
	if err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	handoff := SuiteOwnershipHandoff{
		SchemaVersion: 1, HandoffState: suiteHandoffIntentDurable, SetupRequestUID: checkpoint.RequestUID,
		GUIBinaryPath: guiBinaryPath, SuiteBinaryRoot: suiteBinaryRoot, ClientConfigPath: configPath,
		AgentStateRoot: config.StateRoot, ApplicationRoot: config.ApplicationRoot,
		ClientConfigSHA256: digest,
	}
	if err := validateSuiteOwnershipHandoffValue(handoff, roots); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	if err := saveSuiteOwnershipHandoff(roots, handoff); err != nil {
		return SuiteOwnershipHandoff{}, err
	}
	return handoff, nil
}

func LoadSuiteOwnershipHandoff(roots SuiteUserRoots) (*SuiteOwnershipHandoff, error) {
	path, err := suiteOwnershipHandoffPath(roots)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && info.Size() > maxSuiteOwnershipHandoffRaw {
		return nil, fmt.Errorf("%w: handoff exceeds size limit", ErrSuiteOwnershipHandoff)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	raw, exists, err := readOwnerFile(path)
	if err != nil || !exists {
		return nil, err
	}
	var handoff SuiteOwnershipHandoff
	if err := decodeSuiteOwnershipHandoff(raw, &handoff); err != nil {
		return nil, err
	}
	if err := validateSuiteOwnershipHandoffValue(handoff, roots); err != nil {
		return nil, err
	}
	checkpoint, err := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupBootstrapDrafted || checkpoint.RequestUID != handoff.SetupRequestUID {
		return nil, fmt.Errorf("%w: setup preparation mismatch", ErrSuiteOwnershipHandoff)
	}
	config, digest, err := loadSuiteHandoffClientConfig(handoff.ClientConfigPath)
	if err != nil || digest != handoff.ClientConfigSHA256 || !sameSuiteHandoffPath(config.StateRoot, handoff.AgentStateRoot) ||
		!sameSuiteHandoffPath(config.ApplicationRoot, handoff.ApplicationRoot) {
		return nil, fmt.Errorf("%w: client configuration mismatch", ErrSuiteOwnershipHandoff)
	}
	if _, _, err := validateSuiteImmutableGUIPath(handoff.GUIBinaryPath, handoff.SuiteBinaryRoot); err != nil {
		return nil, err
	}
	if err := validateSuiteMutableApplicationRoot(handoff.ApplicationRoot, roots.BrowserData); err != nil {
		return nil, err
	}
	return &handoff, nil
}

func LoadSuiteGUIInvocation(roots SuiteUserRoots) (SuiteGUIInvocation, error) {
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		if err == nil {
			err = ErrSuiteOwnershipHandoff
		}
		return SuiteGUIInvocation{}, err
	}
	return SuiteGUIInvocation{
		Executable: handoff.GUIBinaryPath,
		Arguments:  []string{"--farm-client-config", handoff.ClientConfigPath},
	}, nil
}

func saveSuiteOwnershipHandoff(roots SuiteUserRoots, handoff SuiteOwnershipHandoff) error {
	path, err := suiteOwnershipHandoffPath(roots)
	if err != nil {
		return err
	}
	lock, err := acquireSuiteSetupLock(path + ".lock")
	if err != nil {
		return err
	}
	defer lock.release()
	existing, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing != nil {
		if *existing != handoff {
			return ErrSuiteOwnershipHandoffConflict
		}
		return nil
	}
	raw, err := json.Marshal(handoff)
	if err != nil {
		return err
	}
	return writeOwnerAtomic(path, append(raw, '\n'))
}

func suiteOwnershipHandoffPath(roots SuiteUserRoots) (string, error) {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return "", err
	}
	if err := validateExistingSuiteOwnerRoot(roots.AgentState); err != nil {
		return "", err
	}
	return filepath.Join(roots.AgentState, SuiteOwnershipHandoffName), nil
}

func validateExistingSuiteOwnerRoot(path string) error {
	if err := validateSuiteSetupPathSecurity(path, true); err != nil {
		return fmt.Errorf("%w: owner root: %v", ErrSuiteOwnershipHandoff, err)
	}
	return nil
}

func loadSuiteHandoffClientConfig(path string) (FarmClientConfig, string, error) {
	info, err := os.Lstat(path)
	if err != nil || info.Size() <= 0 || info.Size() > maxSuiteClientConfigBytes {
		return FarmClientConfig{}, "", fmt.Errorf("%w: client config missing or oversized", ErrSuiteOwnershipHandoff)
	}
	raw, exists, err := readOwnerFile(path)
	if err != nil || !exists {
		return FarmClientConfig{}, "", fmt.Errorf("%w: unsafe client config", ErrSuiteOwnershipHandoff)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	decoder.KnownFields(true)
	var config FarmClientConfig
	if err := decoder.Decode(&config); err != nil {
		return FarmClientConfig{}, "", fmt.Errorf("%w: decode client config", ErrSuiteOwnershipHandoff)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return FarmClientConfig{}, "", fmt.Errorf("%w: trailing client config", ErrSuiteOwnershipHandoff)
	}
	if err := config.ValidateFarmClientConfig(); err != nil {
		return FarmClientConfig{}, "", fmt.Errorf("%w: validate client config", ErrSuiteOwnershipHandoff)
	}
	identity := config.identityConfig()
	if identity.PrivateKey != "" || identity.PrivateKeyEnv != "" || strings.TrimSpace(identity.PrivateKeyRef) == "" {
		return FarmClientConfig{}, "", fmt.Errorf("%w: client config must use a secret-store reference", ErrSuiteOwnershipHandoff)
	}
	digest := sha256.Sum256(raw)
	return config, hex.EncodeToString(digest[:]), nil
}

func validateSuiteOwnershipHandoffValue(handoff SuiteOwnershipHandoff, roots SuiteUserRoots) error {
	if handoff.SchemaVersion != 1 || handoff.HandoffState != suiteHandoffIntentDurable || !validLowerSHA256(handoff.ClientConfigSHA256) {
		return ErrSuiteOwnershipHandoff
	}
	parsed, err := uuid.Parse(handoff.SetupRequestUID)
	if err != nil || parsed.String() != handoff.SetupRequestUID {
		return ErrSuiteOwnershipHandoff
	}
	for _, path := range []string{handoff.GUIBinaryPath, handoff.SuiteBinaryRoot, handoff.ClientConfigPath, handoff.AgentStateRoot, handoff.ApplicationRoot} {
		if strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrSuiteOwnershipHandoff
		}
	}
	if !sameSuiteHandoffPath(handoff.ClientConfigPath, filepath.Join(roots.Config, SuiteClientConfigName)) ||
		!sameSuiteHandoffPath(handoff.AgentStateRoot, roots.AgentState) {
		return ErrSuiteOwnershipHandoff
	}
	return nil
}

func validateSuiteImmutableGUIPath(guiPath, suiteBinaryRoot string) (string, string, error) {
	guiPath, suiteBinaryRoot = filepath.Clean(strings.TrimSpace(guiPath)), filepath.Clean(strings.TrimSpace(suiteBinaryRoot))
	if !filepath.IsAbs(guiPath) || !filepath.IsAbs(suiteBinaryRoot) {
		return "", "", ErrSuiteOwnershipHandoff
	}
	relative, err := filepath.Rel(suiteBinaryRoot, guiPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("%w: GUI is outside suite binary root", ErrSuiteOwnershipHandoff)
	}
	for _, path := range []string{suiteBinaryRoot, guiPath} {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil || !sameSuiteHandoffPath(resolved, path) {
			return "", "", fmt.Errorf("%w: redirected immutable path", ErrSuiteOwnershipHandoff)
		}
	}
	rootInfo, rootErr := os.Stat(suiteBinaryRoot)
	guiInfo, guiErr := os.Stat(guiPath)
	if rootErr != nil || !rootInfo.IsDir() || guiErr != nil || !guiInfo.Mode().IsRegular() {
		return "", "", fmt.Errorf("%w: immutable GUI path is missing", ErrSuiteOwnershipHandoff)
	}
	return guiPath, suiteBinaryRoot, nil
}

func validateSuiteMutableApplicationRoot(applicationRoot, browserDataRoot string) error {
	applicationRoot, browserDataRoot = filepath.Clean(strings.TrimSpace(applicationRoot)), filepath.Clean(strings.TrimSpace(browserDataRoot))
	if !filepath.IsAbs(applicationRoot) || !filepath.IsAbs(browserDataRoot) {
		return ErrSuiteOwnershipHandoff
	}
	relative, err := filepath.Rel(browserDataRoot, applicationRoot)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: Ant application root is outside browser data root", ErrSuiteOwnershipHandoff)
	}
	if err := validateSuiteSetupPathSecurity(applicationRoot, true); err != nil {
		return fmt.Errorf("%w: unsafe Ant application root", ErrSuiteOwnershipHandoff)
	}
	return nil
}

func decodeSuiteOwnershipHandoff(raw []byte, destination *SuiteOwnershipHandoff) error {
	if len(raw) == 0 || len(raw) > maxSuiteOwnershipHandoffRaw || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return ErrSuiteOwnershipHandoff
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || !exactFarmClientIPCKeys(object, []string{
		"schema_version", "handoff_state", "setup_request_uid", "gui_binary_path", "suite_binary_root", "client_config_path",
		"agent_state_root", "application_root", "client_config_sha256",
	}) {
		return ErrSuiteOwnershipHandoff
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil || requireJSONEOF(decoder) != nil {
		return ErrSuiteOwnershipHandoff
	}
	return nil
}

func sameSuiteHandoffPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
