package backend

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

var (
	ErrSuiteSetupPlan         = errors.New("invalid immutable suite setup plan")
	ErrSuiteSetupPlanConflict = errors.New("suite setup plan conflicts with existing plan")
)

const (
	suiteSetupPlanName     = "setup-plan.json"
	maxSuiteSetupPlanBytes = 16 << 10
)

// SuiteSetupPlan pins preparation and release identity before any staging
// mutation. It contains identifiers and digests only, never enrollment or key
// material.
type SuiteSetupPlan struct {
	SchemaVersion         int                `json:"schema_version"`
	PreparationRequestUID string             `json:"preparation_request_uid"`
	BootstrapSHA256       string             `json:"bootstrap_sha256"`
	ManifestSHA256        string             `json:"manifest_sha256"`
	Target                SuiteReleaseTarget `json:"target"`
	StageID               string             `json:"stage_id"`
}

func NewSuiteSetupPlan(preparation SetupPreparationCheckpoint, manifestSHA256 string, target SuiteReleaseTarget) (SuiteSetupPlan, error) {
	if err := preparation.validate(); err != nil || preparation.Stage != SetupBootstrapDrafted {
		return SuiteSetupPlan{}, fmt.Errorf("%w: preparation checkpoint", ErrSuiteSetupPlan)
	}
	plan := SuiteSetupPlan{
		SchemaVersion: 1, PreparationRequestUID: preparation.RequestUID,
		BootstrapSHA256: preparation.BootstrapSHA256, ManifestSHA256: manifestSHA256,
		Target: target, StageID: deriveSuiteSetupStageID(manifestSHA256, target),
	}
	if err := plan.Validate(); err != nil {
		return SuiteSetupPlan{}, err
	}
	return plan, nil
}

func (p SuiteSetupPlan) Validate() error {
	if p.SchemaVersion != 1 || !validLowerSHA256(p.BootstrapSHA256) || !validLowerSHA256(p.ManifestSHA256) ||
		!validSuiteReleaseTarget(p.Target) || p.StageID != deriveSuiteSetupStageID(p.ManifestSHA256, p.Target) {
		return ErrSuiteSetupPlan
	}
	checkpoint := SetupPreparationCheckpoint{
		SchemaVersion: 1, Stage: SetupBootstrapDrafted, RequestUID: p.PreparationRequestUID,
		BootstrapSHA256: p.BootstrapSHA256,
	}
	if err := checkpoint.validate(); err != nil {
		return ErrSuiteSetupPlan
	}
	return nil
}

func LoadSuiteSetupPlan(roots SuiteUserRoots) (*SuiteSetupPlan, error) {
	path, err := suiteSetupPlanPath(roots)
	if err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil && info.Size() > maxSuiteSetupPlanBytes {
		return nil, fmt.Errorf("%w: plan exceeds size limit", ErrSuiteSetupPlan)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	raw, exists, err := readOwnerFile(path)
	if err != nil || !exists {
		return nil, err
	}
	var plan SuiteSetupPlan
	if err := decodeSuiteReleaseStrictJSON(raw, &plan); err != nil {
		return nil, fmt.Errorf("%w: decode", ErrSuiteSetupPlan)
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return &plan, nil
}

// SaveSuiteSetupPlan is create-or-confirm. Once a valid plan exists at path,
// only a byte-equivalent typed plan is accepted.
func SaveSuiteSetupPlan(roots SuiteUserRoots, plan SuiteSetupPlan) error {
	path, err := suiteSetupPlanPath(roots)
	if err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := ensureOwnerDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	lock, err := acquireSuiteSetupLock(path + ".lock")
	if err != nil {
		return err
	}
	defer lock.release()
	existing, err := LoadSuiteSetupPlan(roots)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if existing != nil {
		if *existing != plan {
			return ErrSuiteSetupPlanConflict
		}
		return nil
	}
	raw, err := jsonMarshalSuiteSetupPlan(plan)
	if err != nil {
		return err
	}
	return writeOwnerAtomic(path, raw)
}

func suiteSetupPlanPath(roots SuiteUserRoots) (string, error) {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return "", err
	}
	if info, err := os.Lstat(roots.AgentState); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.IsDir()) {
		return "", fmt.Errorf("%w: agent state root is redirected", ErrFarmClientRoots)
	} else if err == nil {
		if err := validateSuiteSetupPathSecurity(roots.AgentState, true); err != nil {
			return "", fmt.Errorf("%w: agent state root is not owner-only", ErrFarmClientRoots)
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	return filepath.Join(roots.AgentState, suiteSetupPlanName), nil
}

func deriveSuiteSetupStageID(manifestSHA256 string, target SuiteReleaseTarget) string {
	material := manifestSHA256 + "\n" + target.OS + "\n" + target.Arch
	digest := sha256.Sum256([]byte(material))
	return "stage-" + fmt.Sprintf("%x", digest[:])
}

func jsonMarshalSuiteSetupPlan(plan SuiteSetupPlan) ([]byte, error) {
	raw, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
