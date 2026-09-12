package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
)

type suiteServicePlatform interface {
	ValidateInstall(SuiteOwnershipHandoff) (string, error)
	InspectRegistration(SuiteOwnershipHandoff, string) (suiteServiceRegistrationState, error)
	RegisterDisabled(SuiteOwnershipHandoff, string) error
	Enable(SuiteOwnershipHandoff, string) error
	Start(SuiteOwnershipHandoff, string) error
}

type suiteServiceRegistrationState string

const (
	suiteServiceRegistrationAbsent        suiteServiceRegistrationState = "ABSENT"
	suiteServiceRegistrationExactDisabled suiteServiceRegistrationState = "EXACT_DISABLED"
	suiteServiceRegistrationExactEnabled  suiteServiceRegistrationState = "EXACT_ENABLED"
	suiteServiceRegistrationDrift         suiteServiceRegistrationState = "DRIFT"
)

type SuiteServiceCoordinator struct {
	Platform      suiteServicePlatform
	ResidentProof func(context.Context, string) error
}

func ActivateSuiteService(ctx context.Context, roots SuiteUserRoots) error {
	return (&SuiteServiceCoordinator{Platform: newSuiteServicePlatform(), ResidentProof: suiteResidentProof}).Activate(ctx, roots)
}

func (c *SuiteServiceCoordinator) Activate(ctx context.Context, roots SuiteUserRoots) error {
	if c == nil || c.Platform == nil || c.ResidentProof == nil {
		return ErrSuiteServiceActivation
	}
	lock, err := acquireSuiteSetupLock(filepath.Join(roots.AgentState, SuiteActivationJournalName+".coordinator.lock"))
	if err != nil {
		return err
	}
	defer lock.release()
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		return ErrSuiteServiceActivation
	}
	checkpointPath := filepath.Join(roots.AgentState, "setup.json")
	checkpoint, err := LoadSetupCheckpoint(checkpointPath)
	if err != nil || checkpoint == nil || (checkpoint.Stage != SetupEnrolled && checkpoint.Stage != SetupServiceStarted) || checkpoint.RequestUID != handoff.SetupRequestUID {
		return fmt.Errorf("%w: ENROLLED checkpoint required", ErrSuiteServiceActivation)
	}
	taskIdentity, err := c.Platform.ValidateInstall(*handoff)
	if err != nil || strings.TrimSpace(taskIdentity) == "" {
		return ErrSuiteServiceActivation
	}
	taskHash := sha256.Sum256([]byte(taskIdentity))
	expected := SuiteActivationJournal{SchemaVersion: 1, Stage: SuiteActivationValidated, RequestUID: handoff.SetupRequestUID, Generation: 1, ClientConfigSHA256: handoff.ClientConfigSHA256, ManifestSHA256: handoff.ManifestSHA256, SetupStageID: handoff.SetupStageID, TaskIdentityDigest: hex.EncodeToString(taskHash[:])}
	journal := expected
	current, loadErr := LoadSuiteActivationJournal(roots)
	if loadErr != nil {
		return loadErr
	}
	if current != nil {
		if current.RequestUID != expected.RequestUID || current.Generation != expected.Generation || current.ClientConfigSHA256 != expected.ClientConfigSHA256 || current.ManifestSHA256 != expected.ManifestSHA256 || current.SetupStageID != expected.SetupStageID || current.TaskIdentityDigest != expected.TaskIdentityDigest {
			return fmt.Errorf("%w: journal evidence drift", ErrSuiteServiceActivation)
		}
		journal = *current
	} else if err := saveSuiteActivationJournal(roots, journal); err != nil {
		return err
	}
	if journal.Stage == SuiteActivationReconcileRequired {
		return ErrSuiteServiceActivation
	}
	advance := func(stage SuiteActivationStage) error {
		journal.Stage = stage
		return saveSuiteActivationJournal(roots, journal)
	}
	markReconcile := func() {
		journal.Stage = SuiteActivationReconcileRequired
		_ = saveSuiteActivationJournal(roots, journal)
	}
	revalidate := func() error {
		currentHandoff, err := LoadSuiteOwnershipHandoff(roots)
		if err != nil || currentHandoff == nil || *currentHandoff != *handoff {
			return ErrSuiteServiceActivation
		}
		identity, err := c.Platform.ValidateInstall(*currentHandoff)
		if err != nil || identity != taskIdentity {
			return ErrSuiteServiceActivation
		}
		return nil
	}
	inspectExact := func(expected suiteServiceRegistrationState) error {
		observed, err := c.Platform.InspectRegistration(*handoff, taskIdentity)
		if err != nil || observed != expected {
			return ErrSuiteServiceActivation
		}
		return nil
	}
	ensureEnabledEvidence := func() error {
		if err := revalidate(); err != nil {
			return err
		}
		return inspectExact(suiteServiceRegistrationExactEnabled)
	}
	if journal.Stage == SuiteActivationValidated {
		observed, inspectErr := c.Platform.InspectRegistration(*handoff, taskIdentity)
		if inspectErr != nil || (observed != suiteServiceRegistrationAbsent && observed != suiteServiceRegistrationExactDisabled) {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if observed == suiteServiceRegistrationAbsent {
			if err := c.Platform.RegisterDisabled(*handoff, taskIdentity); err != nil {
				markReconcile()
				return ErrSuiteServiceActivation
			}
		}
		if err := advance(SuiteActivationRegisterDisabled); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationRegisterDisabled {
		if err := inspectExact(suiteServiceRegistrationExactDisabled); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := advance(SuiteActivationTaskAudited); err != nil {
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationTaskAudited {
		if err := revalidate(); err != nil {
			markReconcile()
			return err
		}
		if err := inspectExact(suiteServiceRegistrationExactDisabled); err != nil {
			markReconcile()
			return err
		}
		if err := c.Platform.Enable(*handoff, taskIdentity); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := advance(SuiteActivationEnabled); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationEnabled {
		if err := ensureEnabledEvidence(); err != nil {
			markReconcile()
			return err
		}
		if err := c.Platform.Start(*handoff, taskIdentity); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := advance(SuiteActivationStartRequested); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationStartRequested {
		if err := ensureEnabledEvidence(); err != nil {
			markReconcile()
			return err
		}
		if err := c.ResidentProof(ctx, handoff.ClientConfigPath); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := advance(SuiteActivationResidentProved); err != nil {
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationResidentProved {
		if err := ensureEnabledEvidence(); err != nil {
			markReconcile()
			return err
		}
		if err := c.ResidentProof(ctx, handoff.ClientConfigPath); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := SaveSetupCheckpoint(checkpointPath, SetupCheckpoint{SchemaVersion: 1, Stage: SetupServiceStarted, RequestUID: journal.RequestUID}); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
		if err := advance(SuiteActivationCheckpointWritten); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
	}
	if journal.Stage == SuiteActivationCheckpointWritten {
		if err := ensureEnabledEvidence(); err != nil {
			markReconcile()
			return err
		}
		if err := c.ResidentProof(ctx, handoff.ClientConfigPath); err != nil {
			markReconcile()
			return ErrSuiteServiceActivation
		}
	}
	return nil
}

func suiteResidentProof(ctx context.Context, configPath string) error {
	client, err := NewFarmClientIPCClient(configPath)
	if err != nil {
		return err
	}
	_, err = client.ProfileList(ctx)
	return err
}
