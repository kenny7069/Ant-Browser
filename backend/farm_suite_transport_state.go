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
)

const (
	SuiteTransportReceiptName     = "setup-transport-receipt.json"
	suiteTransportReceiptMaxBytes = 64 << 10
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

func saveSuiteTransportReceipt(roots SuiteUserRoots, bootstrap BootstrapConfig, receipt SuiteTransportReceipt) error {
	return saveSuiteTransportReceiptWithDependencies(roots, bootstrap, receipt, suiteTransportReceiptSaveDependencies{
		Open: openSuiteTransportReceiptHandle, Write: writeSuiteTransportReceiptHandle,
	})
}

type suiteTransportReceiptState struct {
	Receipt     *SuiteTransportReceipt
	Recoverable bool
	Info        os.FileInfo
}

func inspectSuiteTransportReceiptState(roots SuiteUserRoots, bootstrap BootstrapConfig, checkpointStage SetupStage) (suiteTransportReceiptState, error) {
	receipt, loadErr := LoadSuiteTransportReceipt(roots, bootstrap)
	if loadErr == nil {
		return suiteTransportReceiptState{Receipt: receipt}, nil
	}
	if checkpointStage != SetupConfigDrafted {
		return suiteTransportReceiptState{}, ErrSuiteTransportReceipt
	}
	path := filepath.Join(roots.AgentState, SuiteTransportReceiptName)
	info, raw, err := readSuiteTransportReceiptRecoveryCandidate(roots, path)
	if err != nil || json.Valid(raw) {
		return suiteTransportReceiptState{}, ErrSuiteTransportReceipt
	}
	return suiteTransportReceiptState{Recoverable: true, Info: info}, nil
}

func readSuiteTransportReceiptRecoveryCandidate(roots SuiteUserRoots, path string) (os.FileInfo, []byte, error) {
	configInfo, configErr := captureSuiteConfigDraftRoot(roots.Config)
	stateInfo, stateErr := captureSuiteConfigDraftRoot(roots.AgentState)
	info, statErr := os.Lstat(path)
	if configErr != nil || stateErr != nil || statErr != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > suiteTransportReceiptMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, nil, ErrSuiteTransportReceipt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, ErrSuiteTransportReceipt
	}
	defer file.Close()
	handleInfo, err := file.Stat()
	if err != nil || !handleInfo.Mode().IsRegular() || !os.SameFile(info, handleInfo) || handleInfo.Size() < 0 || handleInfo.Size() > suiteTransportReceiptMaxBytes {
		return nil, nil, ErrSuiteTransportReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(file, suiteTransportReceiptMaxBytes+1))
	if err != nil || len(raw) > suiteTransportReceiptMaxBytes || int64(len(raw)) != handleInfo.Size() || revalidateSuiteConfigDraftRoot(roots.Config, configInfo) != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil {
		return nil, nil, ErrSuiteTransportReceipt
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, nil, ErrSuiteTransportReceipt
	}
	return handleInfo, raw, nil
}

type suiteTransportReceiptSaveDependencies struct {
	Open      func(string, bool) (*os.File, error)
	Write     func(*os.File, os.FileInfo, []byte) error
	AfterOpen func(string, *os.File) error
}

func saveSuiteTransportReceiptWithDependencies(roots SuiteUserRoots, bootstrap BootstrapConfig, receipt SuiteTransportReceipt, dependencies suiteTransportReceiptSaveDependencies) (resultErr error) {
	raw, err := marshalSuiteTransportReceipt(receipt, bootstrap)
	if err != nil {
		return err
	}
	if dependencies.Open == nil || dependencies.Write == nil {
		return ErrSuiteTransportReceipt
	}
	checkpoint, err := LoadSetupCheckpoint(bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.RequestUID != receipt.RequestUID || (checkpoint.Stage != SetupConfigDrafted && checkpoint.Stage != SetupTransportVerified) {
		return ErrSuiteTransportReceipt
	}
	state, err := inspectSuiteTransportReceiptState(roots, bootstrap, checkpoint.Stage)
	if err != nil {
		return err
	}
	if state.Receipt != nil {
		if !reflect.DeepEqual(*state.Receipt, receipt) {
			return ErrSuiteTransportReceiptConflict
		}
		return nil
	}
	if checkpoint.Stage != SetupConfigDrafted {
		return ErrSuiteTransportReceipt
	}
	path := filepath.Join(roots.AgentState, SuiteTransportReceiptName)
	file, err := dependencies.Open(path, !state.Recoverable)
	if err != nil {
		return ErrSuiteTransportReceipt
	}
	closed := false
	defer func() {
		if !closed {
			if err := file.Close(); resultErr == nil && err != nil {
				resultErr = ErrSuiteTransportReceipt
			}
		}
	}()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || (state.Recoverable && (state.Info == nil || !os.SameFile(state.Info, openedInfo))) || (!state.Recoverable && openedInfo.Size() != 0) {
		return ErrSuiteTransportReceipt
	}
	if dependencies.AfterOpen != nil && dependencies.AfterOpen(path, file) != nil {
		return ErrSuiteTransportReceipt
	}
	if dependencies.Write(file, openedInfo, raw) != nil {
		return ErrSuiteTransportReceipt
	}
	handleInfo, err := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	if err != nil || pathErr != nil || !os.SameFile(openedInfo, handleInfo) || !os.SameFile(handleInfo, pathInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteTransportReceipt
	}
	if err := file.Close(); err != nil {
		return ErrSuiteTransportReceipt
	}
	closed = true
	written, err := LoadSuiteTransportReceipt(roots, bootstrap)
	if err != nil || written == nil || !reflect.DeepEqual(*written, receipt) || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteTransportReceipt
	}
	return nil
}
