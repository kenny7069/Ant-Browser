package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	SuiteClientConfigDraftName     = "client-config-draft.json"
	suiteConfigDraftMaxBytes       = 16 << 10
	suiteConfigDraftTempPrefix     = ".client-config-draft-"
	suiteConfigDraftLogName        = "ant-farm-client.log"
	suiteConfigDraftApplicationDir = "ant-application"
)

var (
	ErrSuiteCanonicalConfigDraft = errors.New("suite canonical config draft failed")
	ErrSuiteConfigDraft          = errors.New("invalid immutable suite client config draft")
	ErrSuiteConfigDraftConflict  = errors.New("suite client config draft conflict")
)

type SuiteClientConfigDraft struct {
	SchemaVersion    int                `json:"schema_version"`
	RequestUID       string             `json:"request_uid"`
	SetupStageID     string             `json:"setup_stage_id"`
	BootstrapSHA256  string             `json:"bootstrap_sha256"`
	ManifestSHA256   string             `json:"manifest_sha256"`
	Target           SuiteReleaseTarget `json:"target"`
	Version          string             `json:"version"`
	SuiteBinaryRoot  string             `json:"suite_binary_root"`
	ServerOrigin     string             `json:"server_origin"`
	NodeName         string             `json:"node_name"`
	ClientConfigPath string             `json:"client_config_path"`
	AgentStateRoot   string             `json:"agent_state_root"`
	ApplicationRoot  string             `json:"application_root"`
	AntConfigPath    string             `json:"ant_config_path"`
	LogPath          string             `json:"log_path"`
}

func (draft SuiteClientConfigDraft) validate(bootstrap BootstrapConfig, roots SuiteUserRoots) error {
	validatedBootstrap := bootstrap
	bootstrapDigest, digestErr := bootstrapConfigDigest(bootstrap)
	if validateSuiteSetupInputs(&validatedBootstrap, roots) != nil || validatedBootstrap != bootstrap || draft.SchemaVersion != 1 ||
		digestErr != nil || draft.BootstrapSHA256 != bootstrapDigest || !validLowerSHA256(draft.ManifestSHA256) || !validSuiteReleaseTarget(draft.Target) ||
		!validSuiteReleaseSemver(draft.Version) || draft.SetupStageID != deriveSuiteSetupStageID(draft.ManifestSHA256, draft.Target) ||
		draft.ServerOrigin != bootstrap.ServerURL || draft.NodeName != bootstrap.NodeName ||
		draft.ClientConfigPath != filepath.Join(roots.Config, SuiteClientConfigName) || draft.AgentStateRoot != roots.AgentState ||
		draft.ApplicationRoot != filepath.Join(roots.BrowserData, suiteConfigDraftApplicationDir) ||
		draft.AntConfigPath != filepath.Join(draft.ApplicationRoot, "config.yaml") || draft.LogPath != filepath.Join(roots.Logs, suiteConfigDraftLogName) ||
		draft.SuiteBinaryRoot == "" || strings.TrimSpace(draft.SuiteBinaryRoot) != draft.SuiteBinaryRoot || !filepath.IsAbs(draft.SuiteBinaryRoot) || filepath.Clean(draft.SuiteBinaryRoot) != draft.SuiteBinaryRoot {
		return ErrSuiteConfigDraft
	}
	return SetupCheckpoint{SchemaVersion: 1, Stage: SetupConfigDrafted, RequestUID: draft.RequestUID}.validate()
}

func LoadSuiteClientConfigDraft(roots SuiteUserRoots, bootstrap BootstrapConfig) (*SuiteClientConfigDraft, error) {
	if err := validateSuiteSetupInputs(&bootstrap, roots); err != nil {
		return nil, ErrSuiteConfigDraft
	}
	rootInfo, err := os.Lstat(roots.Config)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || validateSuiteSetupPathSecurity(roots.Config, true) != nil {
		return nil, ErrSuiteConfigDraft
	}
	_, resolvedRootInfo, err := suitePrecheckResolvedPath(roots.Config)
	if err != nil || resolvedRootInfo == nil || !os.SameFile(rootInfo, resolvedRootInfo) {
		return nil, ErrSuiteConfigDraft
	}
	path := filepath.Join(roots.Config, SuiteClientConfigDraftName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > suiteConfigDraftMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteConfigDraft
	}
	raw, err := readSuiteConfigDraftFile(path, info)
	if err != nil || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteConfigDraft
	}
	keys := []string{"schema_version", "request_uid", "setup_stage_id", "bootstrap_sha256", "manifest_sha256", "target", "version", "suite_binary_root", "server_origin", "node_name", "client_config_path", "agent_state_root", "application_root", "ant_config_path", "log_path"}
	top, err := exactSuiteReleaseJSONObject(raw, keys)
	if err != nil {
		return nil, ErrSuiteConfigDraft
	}
	if _, err := exactSuiteReleaseJSONObject(top["target"], []string{"os", "arch"}); err != nil {
		return nil, ErrSuiteConfigDraft
	}
	var draft SuiteClientConfigDraft
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&draft) != nil || requireJSONEOF(decoder) != nil || draft.validate(bootstrap, roots) != nil {
		return nil, ErrSuiteConfigDraft
	}
	return &draft, nil
}

func readSuiteConfigDraftFile(path string, initial os.FileInfo) (raw []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteConfigDraft
	}
	defer func() {
		if err := file.Close(); resultErr == nil && err != nil {
			resultErr = ErrSuiteConfigDraft
		}
	}()
	handleInfo, err := file.Stat()
	if err != nil || !handleInfo.Mode().IsRegular() || !os.SameFile(initial, handleInfo) || handleInfo.Size() <= 0 || handleInfo.Size() > suiteConfigDraftMaxBytes {
		return nil, ErrSuiteConfigDraft
	}
	raw, err = io.ReadAll(io.LimitReader(file, suiteConfigDraftMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > suiteConfigDraftMaxBytes || int64(len(raw)) != handleInfo.Size() {
		return nil, ErrSuiteConfigDraft
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteConfigDraft
	}
	return raw, nil
}

func marshalSuiteClientConfigDraft(draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots) ([]byte, error) {
	if err := draft.validate(bootstrap, roots); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(draft)
	if err != nil || len(raw)+1 > suiteConfigDraftMaxBytes {
		return nil, ErrSuiteConfigDraft
	}
	return append(raw, '\n'), nil
}

func suiteConfigDraftTempName(draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots) (string, error) {
	raw, err := marshalSuiteClientConfigDraft(draft, bootstrap, roots)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	stageDigest := sha256.Sum256([]byte(draft.SetupStageID))
	return suiteConfigDraftTempPrefix + draft.RequestUID + "-" + hex.EncodeToString(stageDigest[:6]) + "-" + hex.EncodeToString(digest[:16]) + ".tmp", nil
}

func saveSuiteClientConfigDraft(roots SuiteUserRoots, bootstrap BootstrapConfig, draft SuiteClientConfigDraft) error {
	raw, err := marshalSuiteClientConfigDraft(draft, bootstrap, roots)
	if err != nil {
		return err
	}
	existing, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil {
		return err
	}
	if existing != nil {
		if *existing != draft {
			return ErrSuiteConfigDraftConflict
		}
		return nil
	}
	name, err := suiteConfigDraftTempName(draft, bootstrap, roots)
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(roots.Config, name)
	temporary, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrSuiteConfigDraft
	}
	defer os.Remove(temporaryPath)
	if secureSuiteSetupPath(temporaryPath, false) != nil {
		_ = temporary.Close()
		return ErrSuiteConfigDraft
	}
	if _, err := temporary.Write(raw); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return ErrSuiteConfigDraft
	}
	path := filepath.Join(roots.Config, SuiteClientConfigDraftName)
	if err := replaceSuiteSetupFile(temporaryPath, path); err != nil || syncSuiteSetupDirectory(roots.Config) != nil {
		return ErrSuiteConfigDraft
	}
	written, err := LoadSuiteClientConfigDraft(roots, bootstrap)
	if err != nil || written == nil || *written != draft {
		return ErrSuiteConfigDraft
	}
	return nil
}

func cleanupSuiteConfigDraftTemp(roots SuiteUserRoots, name string) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, suiteConfigDraftTempPrefix) || !strings.HasSuffix(name, ".tmp") {
		return ErrSuiteConfigDraft
	}
	path := filepath.Join(roots.Config, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteConfigDraft
	}
	if err := os.Remove(path); err != nil || syncSuiteSetupDirectory(roots.Config) != nil {
		return ErrSuiteConfigDraft
	}
	return nil
}
