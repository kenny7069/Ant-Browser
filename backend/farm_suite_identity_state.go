package backend

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
)

const (
	SuiteIdentityReceiptName     = "setup-identity-receipt.json"
	suiteIdentityReceiptMaxBytes = 16 << 10
)

// suiteIdentityStoreKind records the native store that actually holds the
// device key on this platform (NewFarmClientIdentityStore).
var suiteIdentityStoreKind = suiteIdentityStoreKindFor(runtime.GOOS)

func suiteIdentityStoreKindFor(goos string) string {
	switch goos {
	case "darwin":
		return "MACOS_LOGIN_KEYCHAIN"
	case "linux":
		return "LINUX_SECRET_SERVICE"
	case "windows":
		return "WINDOWS_CURRENT_USER_DPAPI"
	default:
		// Never mislabel a future platform: its receipts cannot validate.
		return "UNSUPPORTED"
	}
}

var (
	ErrSuiteIdentityReceipt         = errors.New("invalid suite identity receipt")
	ErrSuiteIdentityReceiptConflict = errors.New("suite identity receipt conflict")
)

type SuiteIdentityReceipt struct {
	SchemaVersion     int    `json:"schema_version"`
	RequestUID        string `json:"request_uid"`
	SetupStageID      string `json:"setup_stage_id"`
	BootstrapSHA256   string `json:"bootstrap_sha256"`
	ManifestSHA256    string `json:"manifest_sha256"`
	ConfigDraftSHA256 string `json:"config_draft_sha256"`
	DiscoverySHA256   string `json:"discovery_sha256"`
	DeploymentUID     string `json:"deployment_uid"`
	IdentityRef       string `json:"identity_ref"`
	PublicKeySHA256   string `json:"public_key_sha256"`
	StoreKind         string `json:"store_kind"`
}

type suiteIdentityReceiptArtifact struct {
	Present bool
	Receipt *SuiteIdentityReceipt
	Info    os.FileInfo
	Raw     []byte
}

func (receipt SuiteIdentityReceipt) validate() error {
	if receipt.SchemaVersion != 1 || receipt.StoreKind != suiteIdentityStoreKind ||
		!validLowerSHA256(receipt.BootstrapSHA256) || !validLowerSHA256(receipt.ManifestSHA256) ||
		!validLowerSHA256(receipt.ConfigDraftSHA256) || !validLowerSHA256(receipt.DiscoverySHA256) ||
		!validLowerSHA256(receipt.PublicKeySHA256) || receipt.SetupStageID == "" || receipt.DeploymentUID == "" ||
		(SetupCheckpoint{SchemaVersion: 1, Stage: SetupIdentityReady, RequestUID: receipt.RequestUID}).validate() != nil {
		return ErrSuiteIdentityReceipt
	}
	ref, err := NewFarmClientIdentityKeyRef(receipt.IdentityRef)
	if err != nil || string(ref) != receipt.IdentityRef {
		return ErrSuiteIdentityReceipt
	}
	expected, err := suiteBootstrapEnrollmentIdentityRef(receipt.DeploymentUID, receipt.RequestUID)
	if err != nil || expected != ref {
		return ErrSuiteIdentityReceipt
	}
	return nil
}

func LoadSuiteIdentityReceipt(roots SuiteUserRoots) (*SuiteIdentityReceipt, error) {
	if validateSuiteSetupRoots(roots) != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	stateInfo, stateErr := captureSuiteConfigDraftRoot(roots.AgentState)
	if stateErr != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	path := filepath.Join(roots.AgentState, SuiteIdentityReceiptName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil {
			return nil, ErrSuiteIdentityReceipt
		}
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > suiteIdentityReceiptMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	defer file.Close()
	handleInfo, err := file.Stat()
	if err != nil || !os.SameFile(info, handleInfo) || !handleInfo.Mode().IsRegular() || handleInfo.Size() <= 0 || handleInfo.Size() > suiteIdentityReceiptMaxBytes {
		return nil, ErrSuiteIdentityReceipt
	}
	raw, err := io.ReadAll(io.LimitReader(file, suiteIdentityReceiptMaxBytes+1))
	finalInfo, finalErr := os.Lstat(path)
	if err != nil || len(raw) == 0 || len(raw) > suiteIdentityReceiptMaxBytes || int64(len(raw)) != handleInfo.Size() || finalErr != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	keys := []string{"schema_version", "request_uid", "setup_stage_id", "bootstrap_sha256", "manifest_sha256", "config_draft_sha256", "discovery_sha256", "deployment_uid", "identity_ref", "public_key_sha256", "store_kind"}
	if _, err := exactSuiteReleaseJSONObject(raw, keys); err != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	var receipt SuiteIdentityReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || requireJSONEOF(decoder) != nil || receipt.validate() != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, stateInfo) != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	return &receipt, nil
}

func inspectSuiteIdentityReceiptArtifact(roots SuiteUserRoots) (suiteIdentityReceiptArtifact, error) {
	receipt, loadErr := LoadSuiteIdentityReceipt(roots)
	if loadErr == nil {
		return suiteIdentityReceiptArtifact{Present: receipt != nil, Receipt: receipt}, nil
	}
	path := filepath.Join(roots.AgentState, SuiteIdentityReceiptName)
	info, raw, err := readSuiteTransportReceiptRecoveryCandidate(roots, path)
	if err != nil || len(raw) > suiteIdentityReceiptMaxBytes {
		return suiteIdentityReceiptArtifact{}, ErrSuiteIdentityReceipt
	}
	return suiteIdentityReceiptArtifact{Present: true, Info: info, Raw: raw}, nil
}

func marshalSuiteIdentityReceipt(receipt SuiteIdentityReceipt) ([]byte, error) {
	if receipt.validate() != nil {
		return nil, ErrSuiteIdentityReceipt
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw)+1 > suiteIdentityReceiptMaxBytes {
		return nil, ErrSuiteIdentityReceipt
	}
	return append(raw, '\n'), nil
}

func suiteIdentityReceiptRecoveryMatches(raw, canonical []byte) bool {
	return len(raw) == 0 || (len(raw) < len(canonical) && bytes.Equal(raw, canonical[:len(raw)]))
}

type suiteIdentityReceiptSaveDependencies struct {
	Open      func(string, bool) (*os.File, error)
	Write     func(*os.File, os.FileInfo, []byte, *suiteTransportReceiptRecoveryEvidence) error
	AfterOpen func(*os.File) error
}

func saveSuiteIdentityReceipt(roots SuiteUserRoots, receipt SuiteIdentityReceipt) error {
	return saveSuiteIdentityReceiptWithDependencies(roots, receipt, suiteIdentityReceiptSaveDependencies{Open: openSuiteTransportReceiptHandle, Write: writeSuiteTransportReceiptHandle})
}

func saveSuiteIdentityReceiptWithDependencies(roots SuiteUserRoots, receipt SuiteIdentityReceipt, dependencies suiteIdentityReceiptSaveDependencies) error {
	if receipt.validate() != nil {
		return ErrSuiteIdentityReceipt
	}
	if dependencies.Open == nil || dependencies.Write == nil {
		return ErrSuiteIdentityReceipt
	}
	artifact, err := inspectSuiteIdentityReceiptArtifact(roots)
	if err != nil {
		return err
	}
	if artifact.Receipt != nil {
		if *artifact.Receipt != receipt {
			return ErrSuiteIdentityReceiptConflict
		}
		return nil
	}
	raw, err := marshalSuiteIdentityReceipt(receipt)
	if err != nil {
		return err
	}
	path := filepath.Join(roots.AgentState, SuiteIdentityReceiptName)
	create := !artifact.Present
	var recovery *suiteTransportReceiptRecoveryEvidence
	if artifact.Present {
		checkpoint, err := LoadSetupCheckpoint(filepath.Join(roots.AgentState, "setup.json"))
		if err != nil || checkpoint == nil || checkpoint.Stage != SetupTransportVerified || checkpoint.RequestUID != receipt.RequestUID {
			return ErrSuiteIdentityReceipt
		}
		if artifact.Info == nil || !suiteIdentityReceiptRecoveryMatches(artifact.Raw, raw) {
			return ErrSuiteIdentityReceipt
		}
		recovery = &suiteTransportReceiptRecoveryEvidence{Info: artifact.Info, Size: int64(len(artifact.Raw)), Digest: sha256.Sum256(artifact.Raw)}
	}
	file, err := dependencies.Open(path, create)
	if err != nil {
		return ErrSuiteIdentityReceipt
	}
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || (recovery != nil && (recovery.Info == nil || !os.SameFile(recovery.Info, opened))) || (recovery == nil && opened.Size() != 0) {
		_ = file.Close()
		return ErrSuiteIdentityReceipt
	}
	if dependencies.AfterOpen != nil && dependencies.AfterOpen(file) != nil {
		_ = file.Close()
		return ErrSuiteIdentityReceipt
	}
	if err := dependencies.Write(file, opened, raw, recovery); err != nil {
		_ = file.Close()
		return ErrSuiteIdentityReceipt
	}
	handleInfo, statErr := file.Stat()
	pathInfo, pathErr := os.Lstat(path)
	closeErr := file.Close()
	if statErr != nil || pathErr != nil || closeErr != nil || !os.SameFile(opened, handleInfo) || !os.SameFile(handleInfo, pathInfo) || validateSuiteSetupPathSecurity(path, false) != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteIdentityReceipt
	}
	written, err := LoadSuiteIdentityReceipt(roots)
	if err != nil || written == nil || !reflect.DeepEqual(*written, receipt) {
		return ErrSuiteIdentityReceipt
	}
	return nil
}
