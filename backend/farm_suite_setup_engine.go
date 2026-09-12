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
	"strings"

	"github.com/google/uuid"
)

const (
	suiteSetupLockName        = "setup.lock"
	suitePreparationStateName = "setup-preparation.json"
	suiteBootstrapDraftName   = "bootstrap.json"

	// Preparation stages are deliberately outside setupStageOrder. They record
	// only local input/storage preparation and cannot satisfy canonical gates.
	SetupInputValidated   SetupStage = "INPUT_VALIDATED"
	SetupUserRootsReady   SetupStage = "USER_ROOTS_READY"
	SetupBootstrapDrafted SetupStage = "BOOTSTRAP_DRAFTED"
)

var (
	ErrSuiteSetupLocked        = errors.New("suite setup is already running")
	ErrSuiteSetupCorrupt       = errors.New("suite setup state is corrupt")
	ErrSuiteSetupExistingState = errors.New("existing suite state requires explicit handling")
)

var setupPreparationStageOrder = []SetupStage{SetupInputValidated, SetupUserRootsReady, SetupBootstrapDrafted}

type SuiteSetupClassification string

const (
	SuiteSetupFresh    SuiteSetupClassification = "fresh"
	SuiteSetupExisting SuiteSetupClassification = "existing"
	SuiteSetupCorrupt  SuiteSetupClassification = "corrupt"
)

// SetupPreparationCheckpoint is intentionally incompatible with
// SetupCheckpoint. Its separate file cannot advance canonical setup state.
type SetupPreparationCheckpoint struct {
	SchemaVersion   int        `json:"schema_version"`
	Stage           SetupStage `json:"stage"`
	RequestUID      string     `json:"request_uid"`
	BootstrapSHA256 string     `json:"bootstrap_sha256"`
}

func preparationStageIndex(stage SetupStage) int {
	for index, candidate := range setupPreparationStageOrder {
		if candidate == stage {
			return index
		}
	}
	return -1
}

func (c SetupPreparationCheckpoint) validate() error {
	if c.SchemaVersion != 1 || preparationStageIndex(c.Stage) < 0 || strings.TrimSpace(c.RequestUID) != c.RequestUID {
		return ErrSuiteSetupCorrupt
	}
	if parsed, err := uuid.Parse(c.RequestUID); err != nil || parsed.String() != c.RequestUID {
		return ErrSuiteSetupCorrupt
	}
	digest, err := hex.DecodeString(c.BootstrapSHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != c.BootstrapSHA256 {
		return ErrSuiteSetupCorrupt
	}
	return nil
}

type SuiteSetupResult struct {
	Classification SuiteSetupClassification
	Checkpoint     SetupPreparationCheckpoint
	BootstrapPath  string
}

type SuiteSetupCoordinator struct {
	Roots     SuiteUserRoots
	Bootstrap BootstrapConfig
	// FailAfter is a test seam invoked after a preparation stage is durable.
	FailAfter func(SetupStage) error
}

func NewSuiteSetupCoordinator(config BootstrapConfig) (*SuiteSetupCoordinator, error) {
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		return nil, err
	}
	return NewSuiteSetupCoordinatorWithRoots(config, roots)
}

func NewSuiteSetupCoordinatorWithRoots(config BootstrapConfig, roots SuiteUserRoots) (*SuiteSetupCoordinator, error) {
	if err := validateSuiteSetupInputs(&config, roots); err != nil {
		return nil, err
	}
	return &SuiteSetupCoordinator{Roots: roots, Bootstrap: config}, nil
}

// RunSuiteSetup performs local preparation only. Transport verification and
// every canonical SetupCheckpoint transition remain the caller's responsibility.
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

func (c *SuiteSetupCoordinator) preparationPath() string {
	return filepath.Join(c.Roots.AgentState, suitePreparationStateName)
}

func (c *SuiteSetupCoordinator) lockPath() string {
	return filepath.Join(c.Roots.AgentState, suiteSetupLockName)
}

func (c *SuiteSetupCoordinator) Run() (SuiteSetupResult, error) {
	if c == nil {
		return SuiteSetupResult{}, fmt.Errorf("%w: coordinator is nil", ErrSuiteSetupCorrupt)
	}
	config := c.Bootstrap
	if err := validateSuiteSetupInputs(&config, c.Roots); err != nil {
		return SuiteSetupResult{}, err
	}
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

	digest, err := bootstrapConfigDigest(config)
	if err != nil {
		return result, err
	}
	requestUID := uuid.NewString()
	if checkpoint != nil {
		requestUID = checkpoint.RequestUID
		result.Checkpoint = *checkpoint
	}
	commit := func(stage SetupStage) error {
		next := SetupPreparationCheckpoint{SchemaVersion: 1, Stage: stage, RequestUID: requestUID, BootstrapSHA256: digest}
		if err := saveSetupPreparationCheckpoint(c.preparationPath(), next); err != nil {
			return err
		}
		result.Checkpoint = next
		if c.FailAfter != nil {
			return c.FailAfter(stage)
		}
		return nil
	}

	if checkpoint == nil {
		if err := commit(SetupInputValidated); err != nil {
			return result, err
		}
		checkpoint = &result.Checkpoint
	}
	if preparationStageIndex(checkpoint.Stage) < preparationStageIndex(SetupUserRootsReady) {
		if err := ensureSuiteOwnerRoots(c.Roots); err != nil {
			return result, err
		}
		if err := commit(SetupUserRootsReady); err != nil {
			return result, err
		}
		checkpoint = &result.Checkpoint
	}
	if preparationStageIndex(checkpoint.Stage) < preparationStageIndex(SetupBootstrapDrafted) {
		if err := ensureSuiteOwnerRoots(c.Roots); err != nil {
			return result, err
		}
		draft, exists, err := loadBootstrapDraft(c.bootstrapPath())
		if err != nil {
			return result, err
		}
		if !exists {
			if err := writeBootstrapDraft(c.bootstrapPath(), config); err != nil {
				return result, err
			}
		} else if *draft != config {
			return result, fmt.Errorf("%w: pending bootstrap draft does not match request", ErrSuiteSetupCorrupt)
		}
		if err := commit(SetupBootstrapDrafted); err != nil {
			return result, err
		}
	}
	return result, nil
}

func ClassifySuiteSetup(roots SuiteUserRoots, config BootstrapConfig) (SuiteSetupClassification, error) {
	if err := validateSuiteSetupInputs(&config, roots); err != nil {
		return SuiteSetupCorrupt, err
	}
	classification, _, err := classifySuiteSetup(roots, config)
	return classification, err
}

func classifySuiteSetup(roots SuiteUserRoots, config BootstrapConfig) (SuiteSetupClassification, *SetupPreparationCheckpoint, error) {
	// The canonical checkpoint is not read or advanced here. Rejecting a
	// redirected destination still prevents a later canonical phase from
	// following a setup-created symlink.
	for _, path := range []string{config.StatePath, config.StatePath + ".bak"} {
		if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: canonical checkpoint is a symlink", ErrSuiteSetupCorrupt)
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: canonical checkpoint metadata unavailable", ErrSuiteSetupCorrupt)
		}
	}
	checkpoint, checkpointErr := loadSetupPreparationCheckpoint(filepath.Join(roots.AgentState, suitePreparationStateName))
	if checkpointErr != nil {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: preparation checkpoint: %v", ErrSuiteSetupCorrupt, checkpointErr)
	}
	draft, draftExists, draftErr := loadBootstrapDraft(filepath.Join(roots.Config, suiteBootstrapDraftName))
	if draftErr != nil {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: bootstrap draft: %v", ErrSuiteSetupCorrupt, draftErr)
	}
	if checkpoint == nil {
		if draftExists {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: bootstrap draft has no preparation checkpoint", ErrSuiteSetupCorrupt)
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
	digest, err := bootstrapConfigDigest(config)
	if err != nil || checkpoint.BootstrapSHA256 != digest {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: preparation input mismatch", ErrSuiteSetupCorrupt)
	}
	if checkpoint.Stage == SetupBootstrapDrafted {
		if !draftExists || *draft != config {
			return SuiteSetupCorrupt, nil, fmt.Errorf("%w: BOOTSTRAP_DRAFTED does not match bootstrap draft", ErrSuiteSetupCorrupt)
		}
	} else if draftExists && *draft != config {
		return SuiteSetupCorrupt, nil, fmt.Errorf("%w: pending bootstrap draft does not match request", ErrSuiteSetupCorrupt)
	}
	return SuiteSetupExisting, checkpoint, nil
}

func validateSuiteSetupInputs(config *BootstrapConfig, roots SuiteUserRoots) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := validateSuiteSetupRoots(roots); err != nil {
		return err
	}
	if filepath.Clean(filepath.Dir(config.StatePath)) != filepath.Clean(roots.AgentState) {
		return fmt.Errorf("%w: setup state must be a direct child of the agent state root", ErrFarmClientRoots)
	}
	return nil
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
	if err := secureSuiteSetupPath(path, true); err != nil {
		return fmt.Errorf("%w: secure owner directory: %v", ErrFarmClientRoots, err)
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
	if err := secureSuiteSetupPath(path, false); err != nil {
		lock.Release()
		return nil, fmt.Errorf("%w: secure setup lock: %v", ErrFarmClientRoots, err)
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

func bootstrapConfigDigest(config BootstrapConfig) (string, error) {
	if err := config.Validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func saveSetupPreparationCheckpoint(path string, next SetupPreparationCheckpoint) error {
	if err := next.validate(); err != nil {
		return err
	}
	previous, err := loadSetupPreparationCheckpoint(path)
	if err != nil {
		return err
	}
	if previous == nil {
		if next.Stage != SetupInputValidated {
			return fmt.Errorf("%w: first preparation stage must be INPUT_VALIDATED", ErrSuiteSetupCorrupt)
		}
	} else {
		if previous.RequestUID != next.RequestUID || previous.BootstrapSHA256 != next.BootstrapSHA256 ||
			preparationStageIndex(next.Stage) < preparationStageIndex(previous.Stage) ||
			preparationStageIndex(next.Stage) > preparationStageIndex(previous.Stage)+1 {
			return fmt.Errorf("%w: invalid preparation transition", ErrSuiteSetupCorrupt)
		}
		if previous.Stage == next.Stage {
			return nil
		}
	}
	raw, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return writeOwnerAtomic(path, append(raw, '\n'))
}

func loadSetupPreparationCheckpoint(path string) (*SetupPreparationCheckpoint, error) {
	raw, exists, err := readOwnerFile(path)
	if err != nil || !exists {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var checkpoint SetupPreparationCheckpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		return nil, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, err
	}
	if err := checkpoint.validate(); err != nil {
		return nil, err
	}
	return &checkpoint, nil
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
	raw, exists, err := readOwnerFile(path)
	if err != nil || !exists {
		return nil, exists, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var config BootstrapConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, true, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, true, err
	}
	if err := config.Validate(); err != nil {
		return nil, true, err
	}
	return &config, true, nil
}

func readOwnerFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, true, errors.New("owner file is not a regular file")
	}
	if err := validateSuiteSetupPathSecurity(path, false); err != nil {
		return nil, true, err
	}
	raw, err := os.ReadFile(path)
	return raw, true, err
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing data")
	}
	return nil
}

func writeOwnerAtomic(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := ensureOwnerDirectory(parent); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil && (info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular()) {
		return fmt.Errorf("%w: destination is not a regular file", ErrFarmClientRoots)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".suite-setup-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := secureSuiteSetupPath(tmpPath, false); err != nil {
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
	if err := replaceSuiteSetupFile(tmpPath, path); err != nil {
		return err
	}
	return syncSuiteSetupDirectory(parent)
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
			if root == roots.AgentState && (strings.EqualFold(entry.Name(), suiteSetupLockName) ||
				strings.EqualFold(entry.Name(), suitePreparationStateName)) {
				continue
			}
			return true, nil
		}
	}
	return false, nil
}
