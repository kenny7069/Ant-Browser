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
	"reflect"
	"strings"
)

const (
	SuiteTransportReceiptName     = "setup-transport-receipt.json"
	suiteTransportReceiptMaxBytes = 64 << 10
	suiteTransportTempPrefix      = ".setup-transport-receipt-"
)

var (
	ErrSuiteCanonicalTransport       = errors.New("suite canonical transport verification failed")
	ErrSuiteTransportReceipt         = errors.New("invalid suite transport receipt")
	ErrSuiteTransportReceiptConflict = errors.New("suite transport receipt conflict")
)

type SuiteTransportReceipt struct {
	SchemaVersion          int                   `json:"schema_version"`
	RequestUID             string                `json:"request_uid"`
	SetupStageID           string                `json:"setup_stage_id"`
	BootstrapSHA256        string                `json:"bootstrap_sha256"`
	ManifestSHA256         string                `json:"manifest_sha256"`
	ConfigDraftSHA256      string                `json:"config_draft_sha256"`
	Target                 SuiteReleaseTarget    `json:"target"`
	Version                string                `json:"version"`
	DeploymentUID          string                `json:"deployment_uid"`
	MinimumSuiteVersion    string                `json:"minimum_suite_version"`
	MinimumProtocolVersion string                `json:"minimum_protocol_version"`
	EnrollmentEndpoint     string                `json:"enrollment_endpoint"`
	ControlEndpoint        string                `json:"control_endpoint"`
	SupportedCapabilities  []string              `json:"supported_capabilities"`
	EndpointAllowlist      []string              `json:"endpoint_allowlist"`
	Update                 *SuiteBootstrapUpdate `json:"update,omitempty"`
	DiscoverySHA256        string                `json:"discovery_sha256"`
}

func canonicalSuiteTransportDiscovery(discovery SuiteBootstrapDiscovery, bootstrap BootstrapConfig, suiteVersion string) ([]byte, string, error) {
	raw, err := json.Marshal(discovery)
	if err != nil || len(raw) == 0 || len(raw) > maxSuiteBootstrapBodyBytes {
		return nil, "", ErrSuiteTransportReceipt
	}
	origin, err := canonicalSuiteBootstrapOrigin(bootstrap.ServerURL, "https")
	if err != nil {
		return nil, "", ErrSuiteTransportReceipt
	}
	parsed, err := parseSuiteBootstrapDiscovery(raw, origin, suiteVersion, FarmSuiteBootstrapProtocolVersion)
	if err != nil || !reflect.DeepEqual(parsed, discovery) {
		return nil, "", ErrSuiteTransportReceipt
	}
	digest := sha256.Sum256(raw)
	return raw, hex.EncodeToString(digest[:]), nil
}

func suiteConfigDraftCanonicalDigest(draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots) (string, error) {
	raw, err := marshalSuiteClientConfigDraft(draft, bootstrap, roots)
	if err != nil {
		return "", ErrSuiteTransportReceipt
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func newSuiteTransportReceipt(preparation SetupPreparationCheckpoint, plan SuiteSetupPlan, draft SuiteClientConfigDraft, bootstrap BootstrapConfig, roots SuiteUserRoots, version string, discovery SuiteBootstrapDiscovery) (SuiteTransportReceipt, error) {
	draftDigest, err := suiteConfigDraftCanonicalDigest(draft, bootstrap, roots)
	if err != nil {
		return SuiteTransportReceipt{}, err
	}
	_, discoveryDigest, err := canonicalSuiteTransportDiscovery(discovery, bootstrap, version)
	if err != nil {
		return SuiteTransportReceipt{}, err
	}
	receipt := SuiteTransportReceipt{
		SchemaVersion: 1, RequestUID: preparation.RequestUID, SetupStageID: plan.StageID,
		BootstrapSHA256: preparation.BootstrapSHA256, ManifestSHA256: plan.ManifestSHA256,
		ConfigDraftSHA256: draftDigest, Target: plan.Target, Version: version,
		DeploymentUID: discovery.DeploymentUID, MinimumSuiteVersion: discovery.MinimumSuiteVersion,
		MinimumProtocolVersion: discovery.MinimumProtocolVersion, EnrollmentEndpoint: discovery.EnrollmentEndpoint,
		ControlEndpoint: discovery.ControlEndpoint, SupportedCapabilities: append([]string(nil), discovery.SupportedCapabilities...),
		EndpointAllowlist: append([]string(nil), discovery.EndpointAllowlist...), Update: cloneSuiteTransportUpdate(discovery.Update),
		DiscoverySHA256: discoveryDigest,
	}
	if err := receipt.validate(bootstrap); err != nil {
		return SuiteTransportReceipt{}, err
	}
	return receipt, nil
}

func cloneSuiteTransportUpdate(update *SuiteBootstrapUpdate) *SuiteBootstrapUpdate {
	if update == nil {
		return nil
	}
	copy := *update
	return &copy
}

func (receipt SuiteTransportReceipt) discovery() SuiteBootstrapDiscovery {
	return SuiteBootstrapDiscovery{
		SchemaVersion: 3, DeploymentUID: receipt.DeploymentUID,
		MinimumSuiteVersion: receipt.MinimumSuiteVersion, MinimumProtocolVersion: receipt.MinimumProtocolVersion,
		EnrollmentEndpoint: receipt.EnrollmentEndpoint, ControlEndpoint: receipt.ControlEndpoint,
		SupportedCapabilities: append([]string(nil), receipt.SupportedCapabilities...),
		EndpointAllowlist:     append([]string(nil), receipt.EndpointAllowlist...), Update: cloneSuiteTransportUpdate(receipt.Update),
	}
}

func (receipt SuiteTransportReceipt) validate(bootstrap BootstrapConfig) error {
	if receipt.SchemaVersion != 1 || !validLowerSHA256(receipt.BootstrapSHA256) || !validLowerSHA256(receipt.ManifestSHA256) ||
		!validLowerSHA256(receipt.ConfigDraftSHA256) || !validLowerSHA256(receipt.DiscoverySHA256) || !validSuiteReleaseTarget(receipt.Target) ||
		!validSuiteReleaseSemver(receipt.Version) || receipt.SetupStageID != deriveSuiteSetupStageID(receipt.ManifestSHA256, receipt.Target) ||
		(SetupCheckpoint{SchemaVersion: 1, Stage: SetupTransportVerified, RequestUID: receipt.RequestUID}).validate() != nil {
		return ErrSuiteTransportReceipt
	}
	_, digest, err := canonicalSuiteTransportDiscovery(receipt.discovery(), bootstrap, receipt.Version)
	if err != nil || digest != receipt.DiscoverySHA256 {
		return ErrSuiteTransportReceipt
	}
	return nil
}

type suiteTransportReceiptLoadDependencies struct {
	ReadFile func(string, os.FileInfo) ([]byte, error)
}

func LoadSuiteTransportReceipt(roots SuiteUserRoots, bootstrap BootstrapConfig) (*SuiteTransportReceipt, error) {
	return loadSuiteTransportReceiptWithDependencies(roots, bootstrap, suiteTransportReceiptLoadDependencies{ReadFile: readSuiteTransportReceiptFile})
}

func loadSuiteTransportReceiptWithDependencies(roots SuiteUserRoots, bootstrap BootstrapConfig, dependencies suiteTransportReceiptLoadDependencies) (*SuiteTransportReceipt, error) {
	if validateSuiteSetupInputs(&bootstrap, roots) != nil || dependencies.ReadFile == nil {
		return nil, ErrSuiteTransportReceipt
	}
	configInfo, configErr := captureSuiteConfigDraftRoot(roots.Config)
	stateInfo, stateErr := captureSuiteConfigDraftRoot(roots.AgentState)
	if configErr != nil || stateErr != nil {
		return nil, ErrSuiteTransportReceipt
	}
	path := filepath.Join(roots.AgentState, SuiteTransportReceiptName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if revalidateSuiteConfigDraftRoot(roots.Config, configInfo) != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil {
			return nil, ErrSuiteTransportReceipt
		}
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > suiteTransportReceiptMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteTransportReceipt
	}
	raw, err := dependencies.ReadFile(path, info)
	if err != nil || revalidateSuiteConfigDraftRoot(roots.Config, configInfo) != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteTransportReceipt
	}
	keys := []string{"schema_version", "request_uid", "setup_stage_id", "bootstrap_sha256", "manifest_sha256", "config_draft_sha256", "target", "version", "deployment_uid", "minimum_suite_version", "minimum_protocol_version", "enrollment_endpoint", "control_endpoint", "supported_capabilities", "endpoint_allowlist", "discovery_sha256"}
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || (!exactFarmClientIPCKeysOptional(top, keys, []string{"update"})) {
		return nil, ErrSuiteTransportReceipt
	}
	if _, err := exactSuiteReleaseJSONObject(top["target"], []string{"os", "arch"}); err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	if update, ok := top["update"]; ok {
		if _, err := exactSuiteReleaseJSONObject(update, []string{"manifest_url", "public_key_ed25519_b64", "channel"}); err != nil {
			return nil, ErrSuiteTransportReceipt
		}
	}
	var receipt SuiteTransportReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || requireJSONEOF(decoder) != nil || receipt.validate(bootstrap) != nil ||
		revalidateSuiteConfigDraftRoot(roots.Config, configInfo) != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil {
		return nil, ErrSuiteTransportReceipt
	}
	return &receipt, nil
}

func readSuiteTransportReceiptFile(path string, initial os.FileInfo) (raw []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteTransportReceipt
	}
	defer func() {
		if err := file.Close(); resultErr == nil && err != nil {
			resultErr = ErrSuiteTransportReceipt
		}
	}()
	handleInfo, err := file.Stat()
	if err != nil || !handleInfo.Mode().IsRegular() || !os.SameFile(initial, handleInfo) || handleInfo.Size() <= 0 || handleInfo.Size() > suiteTransportReceiptMaxBytes {
		return nil, ErrSuiteTransportReceipt
	}
	raw, err = io.ReadAll(io.LimitReader(file, suiteTransportReceiptMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > suiteTransportReceiptMaxBytes || int64(len(raw)) != handleInfo.Size() {
		return nil, ErrSuiteTransportReceipt
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteTransportReceipt
	}
	return raw, nil
}

func marshalSuiteTransportReceipt(receipt SuiteTransportReceipt, bootstrap BootstrapConfig) ([]byte, error) {
	if receipt.validate(bootstrap) != nil {
		return nil, ErrSuiteTransportReceipt
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw)+1 > suiteTransportReceiptMaxBytes {
		return nil, ErrSuiteTransportReceipt
	}
	return append(raw, '\n'), nil
}

func suiteTransportReceiptTempName(receipt SuiteTransportReceipt, bootstrap BootstrapConfig) (string, error) {
	raw, err := marshalSuiteTransportReceipt(receipt, bootstrap)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	stageDigest := sha256.Sum256([]byte(receipt.SetupStageID))
	return suiteTransportTempPrefix + receipt.RequestUID + "-" + hex.EncodeToString(stageDigest[:6]) + "-" + hex.EncodeToString(digest[:16]) + ".tmp", nil
}

func saveSuiteTransportReceipt(roots SuiteUserRoots, bootstrap BootstrapConfig, receipt SuiteTransportReceipt) error {
	raw, err := marshalSuiteTransportReceipt(receipt, bootstrap)
	if err != nil {
		return err
	}
	existing, err := LoadSuiteTransportReceipt(roots, bootstrap)
	if err != nil {
		return err
	}
	if existing != nil {
		if !reflect.DeepEqual(*existing, receipt) {
			return ErrSuiteTransportReceiptConflict
		}
		return nil
	}
	name, err := suiteTransportReceiptTempName(receipt, bootstrap)
	if err != nil {
		return err
	}
	temporaryPath := filepath.Join(roots.AgentState, name)
	temporary, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrSuiteTransportReceipt
	}
	defer os.Remove(temporaryPath)
	if secureSuiteSetupPath(temporaryPath, false) != nil {
		_ = temporary.Close()
		return ErrSuiteTransportReceipt
	}
	if _, err := temporary.Write(raw); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return ErrSuiteTransportReceipt
	}
	if replaceSuiteSetupFile(temporaryPath, filepath.Join(roots.AgentState, SuiteTransportReceiptName)) != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteTransportReceipt
	}
	written, err := LoadSuiteTransportReceipt(roots, bootstrap)
	if err != nil || written == nil || !reflect.DeepEqual(*written, receipt) {
		return ErrSuiteTransportReceipt
	}
	return nil
}

func cleanupSuiteTransportReceiptTemp(roots SuiteUserRoots, name string) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, suiteTransportTempPrefix) || !strings.HasSuffix(name, ".tmp") {
		return ErrSuiteTransportReceipt
	}
	path := filepath.Join(roots.AgentState, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteTransportReceipt
	}
	if os.Remove(path) != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteTransportReceipt
	}
	return nil
}
