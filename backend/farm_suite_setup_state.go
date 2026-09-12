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
	if primaryErr == nil && primary != nil {
		return primary, nil
	}
	if errors.Is(primaryErr, errSetupCheckpointUnknownField) {
		return nil, primaryErr
	}
	backup, backupErr := readSetupCheckpointFile(path + ".bak")
	if backupErr == nil && backup != nil {
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
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
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
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data", ErrSetupCheckpoint)
	}
	if err := checkpoint.validate(); err != nil {
		return nil, err
	}
	return &checkpoint, nil
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
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(parent, ".suite-checkpoint-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer dir.Close()
	// Windows does not expose a portable directory fsync handle through os.Open.
	// The checkpoint file itself was synced before the atomic rename.
	if err := dir.Sync(); err != nil && runtime.GOOS != "windows" {
		return err
	}
	return nil
}
