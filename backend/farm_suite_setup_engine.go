package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

const (
	suiteSetupLockName      = "setup.lock"
	suiteBootstrapDraftName = "bootstrap.json"
)

var (
	ErrSuiteSetupLocked        = errors.New("suite setup is already running")
	ErrSuiteSetupCorrupt       = errors.New("suite setup state is corrupt")
	ErrSuiteSetupExistingState = errors.New("existing suite state requires explicit handling")
)

// SuiteSetupClassification describes the state observed before a setup run.
// Existing includes both a completed draft and valid, resumable checkpoints.
type SuiteSetupClassification string

const (
	SuiteSetupFresh    SuiteSetupClassification = "fresh"
	SuiteSetupExisting SuiteSetupClassification = "existing"
	SuiteSetupCorrupt  SuiteSetupClassification = "corrupt"
)

// SuiteSetupResult reports the initial state and the last durable stage.
type SuiteSetupResult struct {
	Classification SuiteSetupClassification
	Checkpoint     SetupCheckpoint
	BootstrapPath  string
}

// SuiteSetupCoordinator performs the local, pre-enrollment portion of setup.
// FailAfter is a test seam invoked only after a stage is durably committed.
type SuiteSetupCoordinator struct {
	Roots     SuiteUserRoots
	Bootstrap BootstrapConfig
	FailAfter func(SetupStage) error
}

// NewSuiteSetupCoordinator resolves the mutable roots for the current user.
func NewSuiteSetupCoordinator(config BootstrapConfig) (*SuiteSetupCoordinator, error) {
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		return nil, err
	}
	return NewSuiteSetupCoordinatorWithRoots(config, roots)
}

// NewSuiteSetupCoordinatorWithRoots allows installers and tests to supply an
// already resolved set of per-user roots.
func NewSuiteSetupCoordinatorWithRoots(config BootstrapConfig, roots SuiteUserRoots) (*SuiteSetupCoordinator, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if err := validateSuiteSetupRoots(roots); err != nil {
		return nil, err
	}
	return &SuiteSetupCoordinator{Roots: roots, Bootstrap: config}, nil
}

// RunSuiteSetup executes setup through CONFIG_DRAFTED using current-user roots.
func RunSuiteSetup(config BootstrapConfig) (SuiteSetupResult, error) {
	coordinator, err := NewSuiteSetupCoordinator(config)
	if err != nil {
		return SuiteSetupResult{}, err
	}
	return coordinator.Run()
}

func (c *SuiteSetupCoordinator) bootstrapPath() string {
	return filepath.Join(c.Roots.Config, suiteBootstrapDraftName)
}

func (c *SuiteSetupCoordinator) lockPath() string {
	return filepath.Join(c.Roots.AgentState, suiteSetupLockName)
}

// Run is restart-idempotent. It never advances a checkpoint until the work for
// that stage is durable, and it refuses inconsistent state instead of repairing
// or overwriting it implicitly.
func (c *SuiteSetupCoordinator) Run() (SuiteSetupResult, error) {
	if c == nil {
		return SuiteSetupResult{}, fmt.Errorf("%w: coordinator is nil", ErrSuiteSetupCorrupt)
	}
	config := c.Bootstrap
	if err := config.Validate(); err != nil {
		return SuiteSetupResult{}, err
	}
	if err := validateSuiteSetupRoots(c.Roots); err != nil {
		return SuiteSetupResult{}, err
	}
	// AgentState must exist before its lock can be created. The remaining roots
	// are created only when the STAGED step runs.
	if err := ensureOwnerDirectory(c.Roots.AgentState); err != nil {
		return SuiteSetupResult{}, err
	}
	lock, err := acquireSuiteSetupLock(c.lockPath())
	if err != nil {
		return SuiteSetupResult{}, err
	}
	defer lock.release()

	classification, checkpoint, err := classifySuiteSetup(c.Roots, config)
	result := SuiteSetupResult{Classification: classification, BootstrapPath: c.bootstrapPath()}
	if err != nil {
		return result, err
	}
	if classification == SuiteSetupExisting && checkpoint == nil {
		return result, fmt.Errorf("%w: %w", ErrSuiteSetupCorrupt, ErrSuiteSetupExistingState)
	}

	requestUID := uuid.NewString()
	if checkpoint != nil {
		requestUID = checkpoint.RequestUID
	}
	commit := func(stage SetupStage) error {
		next := SetupCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: requestUID}
		if err := SaveSetupCheckpoint(config.StatePath, next); err != nil {
			return err
		}
		result.Checkpoint = next
		if c.FailAfter != nil {
			return c.FailAfter(stage)
		}
		return nil
	}

	if checkpoint == nil {
		if err := commit(SetupPrecheck); err != nil {
			return result, err
		}
		checkpoint = &result.Checkpoint
	} else {
		result.Checkpoint = *checkpoint
	}
	if setupStageIndex(checkpoint.Stage) < setupStageIndex(SetupStaged) {
		if err := ensureSuiteOwnerRoots(c.Roots); err != nil {
			return result, err
		}
		if err := commit(SetupStaged); err != nil {
			return result, err
		}
		checkpoint = &result.Checkpoint
	}
	if setupStageIndex(checkpoint.Stage) < setupStageIndex(SetupConfigDrafted) {
		if err := ensureSuiteOwnerRoots(c.Roots); err != nil {
			return result, err
		}
		draft, exists, err := loadBootstrapDraft(c.bootstrapPath())
		if err != nil {
			return result, err
		}
		if !exists || *draft != config {
			if err := writeBootstrapDraft(c.bootstrapPath(), config); err != nil {
				return result, err
			}
		}
		if err := commit(SetupConfigDrafted); err != nil {
			return result, err
		}
	}
	return result, nil
}

// ClassifySuiteSetup distinguishes a new install, valid resumable state, and
// state that must be handled explicitly by an operator.
func ClassifySuiteSetup(roots SuiteUserRoots, config BootstrapConfig) (SuiteSetupClassification, error) {
	if err := config.Validate(); err != nil {
		return SuiteSetupCorrupt, err
	}
	if err := validateSuiteSetupRoots(roots); err != nil {
		return SuiteSetupCorrupt, err
	}
	classification, _, err := classifySuiteSetup(roots, config)
	return classification, err
}

func classifySuiteSetup(roots SuiteUserRoots, config BootstrapConfig) (SuiteSetupClassification, *SetupCheckpoint, error) {
	checkpoint, checkpointErr := LoadSetupCheckpoint(config.StatePath)
	if checkpointErr != nil {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: checkpoint: %v", ErrSuiteSetupCorrupt, checkpointErr)
	}
	draft, draftExists, draftErr := loadBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName))
	if draftErr != nil {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: bootstrap draft: %v", ErrSuiteSetupCorrupt, draftErr)
	}
	if checkpoint == nil {
		if draftExists {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: bootstrap draft has no checkpoint", ErrSuiteSetupCorrupt)
		}
		hasFootprint, err := suiteSetupHasFootprint(roots)
		if err != nil {
			return SuiteSetupCorrupt, nil, err
		}
		if hasFootprint {
			return SuiteSetupExisting, nil, nil
		}
		return SuiteSetupFresh, nil, nil
	}

	if setupStageIndex(checkpoint.Stage) >= setupStageIndex(SetupConfigDrafted) {
		if !draftExists || *draft != config {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: CONFIG_DRAFTED does not match bootstrap draft", ErrSuiteSetupCorrupt)
		}
	} else if draftExists && *draft != config {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: pending bootstrap draft does not match request", ErrSuiteSetupCorrupt)
	}
	return SuiteSetupExisting, checkpoint, nil
}

func validateSuiteSetupRoots(roots SuiteUserRoots) error {
	for label, path := range map[string]string{
		"config": roots.Config, "browser data": roots.BrowserData,
		"agent state": roots.AgentState, "logs": roots.Logs,
	} {
		if _, err := validateAbsoluteFarmClientRoot(path, label+" root"); err != nil {
			return err
		}
	}
	return nil
}

func ensureSuiteOwnerRoots(roots SuiteUserRoots) error {
	for _, path := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		if err := ensureOwnerDirectory(path); err != nil {
			return err
		}
	}
	return nil
}

func ensureOwnerDirectory(path string) error {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("%w: root is not a directory", ErrFarmClientRoots)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm()&0o077 != 0 {
			return fmt.Errorf("%w: root is not owner-only", ErrFarmClientRoots)
		}
	}
	return nil
}

type suiteSetupLock struct{ lock *FarmClientInstanceLock }

func acquireSuiteSetupLock(path string) (*suiteSetupLock, error) {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%w: setup lock is a symlink", ErrFarmClientRoots)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	lock, err := acquireFarmClientFileLock(path)
	if errors.Is(err, ErrFarmClientAlreadyRun) {
		return nil, ErrSuiteSetupLocked
	}
	if err != nil {
		return nil, err
	}
	if err := lock.file.Chmod(0o600); err != nil {
		lock.Release()
		return nil, err
	}
	if err := lock.file.Truncate(0); err != nil {
		lock.Release()
		return nil, err
	}
	if _, err := lock.file.WriteAt([]byte(fmt.Sprintf("%d\n", os.Getpid())), 0); err != nil {
		lock.Release()
		return nil, err
	}
	if err := lock.file.Sync(); err != nil {
		lock.Release()
		return nil, err
	}
	return &suiteSetupLock{lock: lock}, nil
}

func (l *suiteSetupLock) release() {
	if l != nil && l.lock != nil {
		_ = l.lock.Release()
	}
}

func writeBootstrapDraft(path string, config BootstrapConfig) error {
	if err := config.Validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return writeOwnerAtomic(path, append(data, '\n'))
}

func loadBootstrapDraft(path string) (*BootstrapConfig, bool, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config BootstrapConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, true, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, true, errors.New("trailing data")
	}
	if err := config.Validate(); err != nil {
		return nil, true, err
	}
	return &config, true, nil
}

func writeOwnerAtomic(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := ensureOwnerDirectory(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: bootstrap draft is a symlink", ErrFarmClientRoots)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".suite-bootstrap-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}

func suiteSetupHasFootprint(roots SuiteUserRoots) (bool, error) {
	for _, root := range []string{roots.Config, roots.BrowserData, roots.AgentState, roots.Logs} {
		entries, err := os.ReadDir(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return false, fmt.Errorf("%w: inspect root: %v", ErrSuiteSetupCorrupt, err)
		}
		for _, entry := range entries {
			if root == roots.AgentState && strings.EqualFold(entry.Name(), suiteSetupLockName) {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}
