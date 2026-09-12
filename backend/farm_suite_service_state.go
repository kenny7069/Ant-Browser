package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const SuiteActivationJournalName = "service-activation.json"

type SuiteActivationStage string

const (
	SuiteActivationValidated         SuiteActivationStage = "ADMISSION_VALIDATED"
	SuiteActivationRegisterDisabled  SuiteActivationStage = "REGISTER_DISABLED"
	SuiteActivationTaskAudited       SuiteActivationStage = "TASK_AUDITED"
	SuiteActivationEnabled           SuiteActivationStage = "TASK_ENABLED"
	SuiteActivationStartRequested    SuiteActivationStage = "START_REQUESTED"
	SuiteActivationResidentProved    SuiteActivationStage = "RESIDENT_PROVED"
	SuiteActivationCheckpointWritten SuiteActivationStage = "CHECKPOINT_WRITTEN"
	SuiteActivationReconcileRequired SuiteActivationStage = "RECONCILE_REQUIRED"
)

var ErrSuiteServiceActivation = errors.New("suite service activation failed")

type SuiteActivationJournal struct {
	SchemaVersion      int                  `json:"schema_version"`
	Stage              SuiteActivationStage `json:"stage"`
	RequestUID         string               `json:"request_uid"`
	Generation         uint64               `json:"generation"`
	ClientConfigSHA256 string               `json:"client_config_sha256"`
	ManifestSHA256     string               `json:"manifest_sha256"`
	SetupStageID       string               `json:"setup_stage_id"`
	TaskIdentityDigest string               `json:"task_identity_digest"`
}

func (j SuiteActivationJournal) validate() error {
	validStage := false
	for _, stage := range []SuiteActivationStage{SuiteActivationValidated, SuiteActivationRegisterDisabled, SuiteActivationTaskAudited, SuiteActivationEnabled, SuiteActivationStartRequested, SuiteActivationResidentProved, SuiteActivationCheckpointWritten, SuiteActivationReconcileRequired} {
		validStage = validStage || j.Stage == stage
	}
	if j.SchemaVersion != 1 || !validStage || j.Generation != 1 || !validLowerSHA256(j.ClientConfigSHA256) || !validLowerSHA256(j.ManifestSHA256) || !validLowerSHA256(j.TaskIdentityDigest) || j.SetupStageID == "" {
		return ErrSuiteServiceActivation
	}
	return SetupCheckpoint{SchemaVersion: 1, Stage: SetupEnrolled, RequestUID: j.RequestUID}.validate()
}

func suiteActivationStageIndex(stage SuiteActivationStage) int {
	for index, candidate := range []SuiteActivationStage{SuiteActivationValidated, SuiteActivationRegisterDisabled, SuiteActivationTaskAudited, SuiteActivationEnabled, SuiteActivationStartRequested, SuiteActivationResidentProved, SuiteActivationCheckpointWritten} {
		if stage == candidate {
			return index
		}
	}
	return -1
}

func LoadSuiteActivationJournal(roots SuiteUserRoots) (*SuiteActivationJournal, error) {
	if err := validateExistingSuiteOwnerRoot(roots.AgentState); err != nil {
		return nil, err
	}
	raw, exists, err := readOwnerFile(filepath.Join(roots.AgentState, SuiteActivationJournalName))
	if err != nil || !exists {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > 16<<10 || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteServiceActivation
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil || !exactFarmClientIPCKeys(keys, []string{"schema_version", "stage", "request_uid", "generation", "client_config_sha256", "manifest_sha256", "setup_stage_id", "task_identity_digest"}) {
		return nil, ErrSuiteServiceActivation
	}
	var journal SuiteActivationJournal
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&journal) != nil || requireJSONEOF(decoder) != nil || journal.validate() != nil {
		return nil, ErrSuiteServiceActivation
	}
	return &journal, nil
}

func saveSuiteActivationJournal(roots SuiteUserRoots, journal SuiteActivationJournal) error {
	if err := journal.validate(); err != nil {
		return err
	}
	path := filepath.Join(roots.AgentState, SuiteActivationJournalName)
	lock, err := acquireSuiteSetupLock(path + ".lock")
	if err != nil {
		return err
	}
	defer lock.release()
	current, err := LoadSuiteActivationJournal(roots)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if current != nil {
		if current.RequestUID != journal.RequestUID || current.ClientConfigSHA256 != journal.ClientConfigSHA256 || current.ManifestSHA256 != journal.ManifestSHA256 || current.SetupStageID != journal.SetupStageID || current.TaskIdentityDigest != journal.TaskIdentityDigest || current.Generation != journal.Generation {
			return fmt.Errorf("%w: journal conflict", ErrSuiteServiceActivation)
		}
		if current.Stage == journal.Stage {
			return nil
		}
		if current.Stage == SuiteActivationReconcileRequired || (journal.Stage != SuiteActivationReconcileRequired && suiteActivationStageIndex(journal.Stage) != suiteActivationStageIndex(current.Stage)+1) {
			return fmt.Errorf("%w: invalid journal transition", ErrSuiteServiceActivation)
		}
	}
	raw, _ := json.Marshal(journal)
	return writeOwnerAtomic(path, append(raw, '\n'))
}
