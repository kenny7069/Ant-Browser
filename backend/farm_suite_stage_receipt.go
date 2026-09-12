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
	SuiteStageReceiptName       = "setup-stage-receipt.json"
	suiteStageReceiptMaxBytes   = 16 << 10
	suiteStageReceiptTempPrefix = ".suite-stage-receipt-"
	suiteStageAdoptionKind      = "ADMIN_INSTALLED_IMMUTABLE_ROOT"
)

var (
	ErrSuiteCanonicalStage       = errors.New("suite canonical stage failed")
	ErrSuiteStageReceipt         = errors.New("invalid suite stage receipt")
	ErrSuiteStageReceiptConflict = errors.New("suite stage receipt conflicts with installed release")
)

type SuiteStageReceipt struct {
	SchemaVersion      int                `json:"schema_version"`
	RequestUID         string             `json:"request_uid"`
	SetupStageID       string             `json:"setup_stage_id"`
	ManifestSHA256     string             `json:"manifest_sha256"`
	Target             SuiteReleaseTarget `json:"target"`
	Version            string             `json:"version"`
	InstalledSuiteRoot string             `json:"installed_suite_root"`
	AdoptionKind       string             `json:"adoption_kind"`
}

func (receipt SuiteStageReceipt) validate() error {
	if receipt.SchemaVersion != 1 || receipt.AdoptionKind != suiteStageAdoptionKind ||
		!validLowerSHA256(receipt.ManifestSHA256) || !validSuiteReleaseTarget(receipt.Target) ||
		!validSuiteReleaseSemver(receipt.Version) || receipt.SetupStageID != deriveSuiteSetupStageID(receipt.ManifestSHA256, receipt.Target) ||
		receipt.InstalledSuiteRoot == "" || strings.TrimSpace(receipt.InstalledSuiteRoot) != receipt.InstalledSuiteRoot ||
		!filepath.IsAbs(receipt.InstalledSuiteRoot) || filepath.Clean(receipt.InstalledSuiteRoot) != receipt.InstalledSuiteRoot {
		return ErrSuiteStageReceipt
	}
	return SetupCheckpoint{SchemaVersion: 1, Stage: SetupStaged, RequestUID: receipt.RequestUID}.validate()
}

func suiteStageReceiptPath(roots SuiteUserRoots) (string, error) {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return "", err
	}
	if err := validateSuiteSetupPathSecurity(roots.AgentState, true); err != nil {
		return "", ErrSuiteStageReceipt
	}
	return filepath.Join(roots.AgentState, SuiteStageReceiptName), nil
}

func LoadSuiteStageReceipt(roots SuiteUserRoots) (*SuiteStageReceipt, error) {
	path, err := suiteStageReceiptPath(roots)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > suiteStageReceiptMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteStageReceipt
	}
	raw, err := readSuiteStageReceiptFile(path, info)
	if err != nil || len(raw) == 0 || len(raw) > suiteStageReceiptMaxBytes || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteStageReceipt
	}
	top, err := exactSuiteReleaseJSONObject(raw, []string{"schema_version", "request_uid", "setup_stage_id", "manifest_sha256", "target", "version", "installed_suite_root", "adoption_kind"})
	if err != nil {
		return nil, ErrSuiteStageReceipt
	}
	if _, err := exactSuiteReleaseJSONObject(top["target"], []string{"os", "arch"}); err != nil {
		return nil, ErrSuiteStageReceipt
	}
	var receipt SuiteStageReceipt
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || requireJSONEOF(decoder) != nil || receipt.validate() != nil {
		return nil, ErrSuiteStageReceipt
	}
	return &receipt, nil
}

func readSuiteStageReceiptFile(path string, initial os.FileInfo) (raw []byte, resultErr error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteStageReceipt
	}
	defer func() {
		if err := file.Close(); resultErr == nil && err != nil {
			resultErr = ErrSuiteStageReceipt
		}
	}()
	handleInfo, err := file.Stat()
	if err != nil || !handleInfo.Mode().IsRegular() || !os.SameFile(initial, handleInfo) || handleInfo.Size() <= 0 || handleInfo.Size() > suiteStageReceiptMaxBytes {
		return nil, ErrSuiteStageReceipt
	}
	raw, err = io.ReadAll(io.LimitReader(file, suiteStageReceiptMaxBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > suiteStageReceiptMaxBytes || int64(len(raw)) != handleInfo.Size() {
		return nil, ErrSuiteStageReceipt
	}
	finalInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteStageReceipt
	}
	return raw, nil
}

func saveSuiteStageReceipt(roots SuiteUserRoots, receipt SuiteStageReceipt) error {
	if err := receipt.validate(); err != nil {
		return err
	}
	path, err := suiteStageReceiptPath(roots)
	if err != nil {
		return err
	}
	existing, err := LoadSuiteStageReceipt(roots)
	if err != nil {
		return err
	}
	if existing != nil {
		if *existing != receipt {
			return ErrSuiteStageReceiptConflict
		}
		return nil
	}
	raw, err := json.Marshal(receipt)
	if err != nil || len(raw)+1 > suiteStageReceiptMaxBytes {
		return ErrSuiteStageReceipt
	}
	temporaryName, err := suiteStageReceiptTempName(receipt)
	if err != nil {
		return ErrSuiteStageReceipt
	}
	temporaryPath := filepath.Join(roots.AgentState, temporaryName)
	temporary, err := os.OpenFile(temporaryPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ErrSuiteStageReceipt
	}
	defer os.Remove(temporaryPath)
	if secureSuiteSetupPath(temporaryPath, false) != nil {
		_ = temporary.Close()
		return ErrSuiteStageReceipt
	}
	if _, err := temporary.Write(append(raw, '\n')); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		_ = temporary.Close()
		return ErrSuiteStageReceipt
	}
	if err := replaceSuiteSetupFile(temporaryPath, path); err != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteStageReceipt
	}
	written, err := LoadSuiteStageReceipt(roots)
	if err != nil || written == nil || *written != receipt {
		return ErrSuiteStageReceipt
	}
	return nil
}

func suiteStageReceiptTempName(receipt SuiteStageReceipt) (string, error) {
	if err := receipt.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return "", ErrSuiteStageReceipt
	}
	digest := sha256.Sum256(raw)
	return suiteStageReceiptTempPrefix + hex.EncodeToString(digest[:16]) + ".tmp", nil
}

func cleanupSuiteStageReceiptTemp(roots SuiteUserRoots, name string) error {
	if filepath.Base(name) != name || !strings.HasPrefix(name, suiteStageReceiptTempPrefix) || !strings.HasSuffix(name, ".tmp") {
		return ErrSuiteStageReceipt
	}
	path := filepath.Join(roots.AgentState, name)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteStageReceipt
	}
	if err := os.Remove(path); err != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteStageReceipt
	}
	return nil
}
