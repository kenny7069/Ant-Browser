package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

type SetupStage string

const (
	SetupPrecheck             SetupStage = "PRECHECK"
	SetupStaged               SetupStage = "STAGED"
	SetupConfigDrafted        SetupStage = "CONFIG_DRAFTED"
	SetupTransportVerified    SetupStage = "TRANSPORT_VERIFIED"
	SetupIdentityReady        SetupStage = "IDENTITY_READY"
	SetupEnrolled             SetupStage = "ENROLLED"
	SetupServiceStarted       SetupStage = "SERVICE_STARTED"
	SetupControlAuthenticated SetupStage = "CONTROL_AUTHENTICATED"
	SetupBrowserSmokePassed   SetupStage = "BROWSER_SMOKE_PASSED"
	SetupReadyForManagement   SetupStage = "READY_FOR_MANAGEMENT"
)

var setupStageOrder = []SetupStage{SetupPrecheck, SetupStaged, SetupConfigDrafted,
	SetupTransportVerified, SetupIdentityReady, SetupEnrolled, SetupServiceStarted,
	SetupControlAuthenticated, SetupBrowserSmokePassed, SetupReadyForManagement}

var ErrSetupCheckpoint = errors.New("invalid suite setup checkpoint")
var errSetupCheckpointUnknownField = errors.New("unknown suite setup checkpoint field")
var errSetupCheckpointUnsafeFile = errors.New("unsafe suite setup checkpoint file")
var errSetupCheckpointDuplicateField = errors.New("duplicate suite setup checkpoint field")
var errSetupCheckpointTrailingData = errors.New("trailing suite setup checkpoint data")
var errSetupCheckpointSchema = errors.New("invalid suite setup checkpoint schema")

const maxSetupCheckpointBytes = 16 << 10

// SetupCheckpoint records confirmed progress only. RequestUID is a stable,
// non-secret idempotency token reused after an enrollment response is lost.
type SetupCheckpoint struct {
	SchemaVersion int        `json:"schema_version"`
	Stage         SetupStage `json:"stage"`
	RequestUID    string     `json:"request_uid"`
}

func setupStageIndex(stage SetupStage) int {
	for i, candidate := range setupStageOrder {
		if candidate == stage {
			return i
		}
	}
	return -1
}

func (c SetupCheckpoint) validate() error {
	if c.SchemaVersion != 1 || setupStageIndex(c.Stage) < 0 || strings.TrimSpace(c.RequestUID) != c.RequestUID {
		return ErrSetupCheckpoint
	}
	if parsed, err := uuid.Parse(c.RequestUID); err != nil || parsed.String() != c.RequestUID {
		return ErrSetupCheckpoint
	}
	return nil
}

// LoadSetupCheckpoint returns nil when no setup has begun. A previous valid
// checkpoint is retained beside the primary, allowing recovery if a Windows
// replacement was interrupted. Unknown fields are never silently accepted.
func LoadSetupCheckpoint(path string) (*SetupCheckpoint, error) {
	if _, err := validateAbsoluteFarmClientRoot(path, "setup state path"); err != nil {
		return nil, err
	}
	primary, primaryErr := readSetupCheckpointFile(path)
	backup, backupErr := readSetupCheckpointFile(path + ".bak")
	for _, candidateErr := range []error{primaryErr, backupErr} {
		if setupCheckpointErrorMustFailClosed(candidateErr) {
			return nil, candidateErr
		}
	}
	if primary != nil {
		if backupErr != nil {
			return nil, backupErr
		}
		if backup != nil {
			if err := validateSetupCheckpointPair(*primary, *backup); err != nil {
				return nil, err
			}
		}
		return primary, nil
	}
	if backup != nil {
		return backup, nil
	}
	if primaryErr != nil {
		return nil, primaryErr
	}
	if backupErr != nil {
		return nil, backupErr
	}
	return nil, nil
}

func readSetupCheckpointFile(path string) (*SetupCheckpoint, error) {
	data, exists, err := readSetupCheckpointOwnerFile(path)
	if err != nil || !exists {
		return nil, err
	}
	duplicateErr := rejectSuiteReleaseDuplicateJSONKeys(data)
	if keyErr := setupCheckpointClosedKeyError(data); keyErr != nil {
		return nil, keyErr
	}
	if duplicateErr != nil && strings.Contains(duplicateErr.Error(), "duplicate or case-folded JSON key") {
		return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointDuplicateField)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var checkpoint SetupCheckpoint
	if err := decoder.Decode(&checkpoint); err != nil {
		if strings.HasPrefix(err.Error(), "json: unknown field") {
			return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnknownField)
		}
		return nil, fmt.Errorf("%w: decode", ErrSetupCheckpoint)
	}
	if duplicateErr != nil {
		return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointTrailingData)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointTrailingData)
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(data, &keys) != nil || len(keys) != 3 {
		return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointSchema)
	}
	for _, key := range []string{"schema_version", "stage", "request_uid"} {
		if _, ok := keys[key]; !ok {
			return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnknownField)
		}
	}
	if err := checkpoint.validate(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointSchema)
	}
	return &checkpoint, nil
}

func setupCheckpointClosedKeyError(raw []byte) error {
	allowed := map[string]struct{}{"schema_version": {}, "stage": {}, "request_uid": {}}
	seen := map[string]struct{}{}
	for offset := 0; offset < len(raw); {
		if raw[offset] != '"' {
			offset++
			continue
		}
		start := offset
		offset++
		closed := false
		for offset < len(raw) {
			if raw[offset] == '\\' {
				offset += 2
				continue
			}
			if raw[offset] == '"' {
				offset++
				closed = true
				break
			}
			offset++
		}
		if !closed || offset > len(raw) {
			return nil
		}
		decoded, err := strconv.Unquote(string(raw[start:offset]))
		if err != nil {
			return nil
		}
		next := offset
		for next < len(raw) && (raw[next] == ' ' || raw[next] == '\t' || raw[next] == '\r' || raw[next] == '\n') {
			next++
		}
		if next >= len(raw) || raw[next] != ':' {
			continue
		}
		if _, ok := allowed[decoded]; !ok {
			return fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnknownField)
		}
		folded := strings.ToLower(decoded)
		if _, ok := seen[folded]; ok {
			return fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointDuplicateField)
		}
		seen[folded] = struct{}{}
	}
	return nil
}

func readSetupCheckpointOwnerFile(path string) ([]byte, bool, error) {
	initial, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || initial.Mode()&os.ModeSymlink != 0 || !initial.Mode().IsRegular() || initial.Size() > maxSetupCheckpointBytes {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	if err := validateSuiteSetupPathSecurity(path, false); err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(initial, opened) || opened.Size() != initial.Size() {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxSetupCheckpointBytes+1))
	if err != nil || len(data) > maxSetupCheckpointBytes || int64(len(data)) != opened.Size() {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	confirmed, err := io.ReadAll(io.LimitReader(file, maxSetupCheckpointBytes+1))
	if err != nil || !bytes.Equal(data, confirmed) {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	current, err := os.Lstat(path)
	if err != nil || current.Mode()&os.ModeSymlink != 0 || !current.Mode().IsRegular() || !os.SameFile(opened, current) || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrSetupCheckpoint, errSetupCheckpointUnsafeFile)
	}
	return data, true, nil
}

func setupCheckpointErrorMustFailClosed(err error) bool {
	return errors.Is(err, errSetupCheckpointUnsafeFile) || errors.Is(err, errSetupCheckpointUnknownField) ||
		errors.Is(err, errSetupCheckpointDuplicateField) || errors.Is(err, errSetupCheckpointTrailingData) || errors.Is(err, errSetupCheckpointSchema)
}

func validateSetupCheckpointPair(primary, backup SetupCheckpoint) error {
	primaryStage, backupStage := setupStageIndex(primary.Stage), setupStageIndex(backup.Stage)
	if primary.RequestUID != backup.RequestUID || backupStage > primaryStage || primaryStage-backupStage > 1 ||
		(backupStage == primaryStage && primary != backup) {
		return fmt.Errorf("%w: inconsistent primary and backup", ErrSetupCheckpoint)
	}
	return nil
}

// SaveSetupCheckpoint writes a single confirmed step. Callers must serialize
// setup invocations for the same path; this function enforces order and stable
// request identity, then replaces the on-disk checkpoint. The previous
// checkpoint remains in .bak because Go does not promise atomic Rename on
// non-Unix systems, even though Windows can replace an existing file.
func SaveSetupCheckpoint(path string, next SetupCheckpoint) error {
	path, err := validateAbsoluteFarmClientRoot(path, "setup state path")
	if err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	previous, err := LoadSetupCheckpoint(path)
	if err != nil {
		return err
	}
	sameStage := false
	if previous == nil {
		if next.Stage != SetupPrecheck {
			return fmt.Errorf("%w: first stage must be PRECHECK", ErrSetupCheckpoint)
		}
	} else {
		if previous.RequestUID != next.RequestUID || setupStageIndex(next.Stage) < setupStageIndex(previous.Stage) ||
			setupStageIndex(next.Stage) > setupStageIndex(previous.Stage)+1 {
			return fmt.Errorf("%w: invalid stage transition", ErrSetupCheckpoint)
		}
		sameStage = previous.Stage == next.Stage
	}
	if previous != nil {
		// If loading recovered a valid backup, restore the primary before
		// rotating that backup. An interruption cannot then damage both copies.
		primary, err := readSetupCheckpointFile(path)
		if err != nil || primary == nil {
			if err := writeSetupCheckpointFile(path, *previous); err != nil {
				return err
			}
		}
		if sameStage {
			return nil
		}
		if err := writeSetupCheckpointFile(path+".bak", *previous); err != nil {
			return err
		}
	}
	return writeSetupCheckpointFile(path, next)
}

func writeSetupCheckpointFile(path string, next SetupCheckpoint) error {
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	return writeOwnerAtomic(path, append(data, '\n'))
}
