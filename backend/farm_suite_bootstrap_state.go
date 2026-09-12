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
	SuiteBootstrapEnrollmentAttemptName   = "setup-enrollment-attempt.json"
	suiteBootstrapEnrollmentLockName      = "setup-enrollment-attempt.lock"
	suiteBootstrapEnrollmentSchema        = 1
	maxSuiteBootstrapEnrollmentStateBytes = 16 << 10
)

type SuiteBootstrapEnrollmentStage string

const (
	SuiteBootstrapIdentityReady SuiteBootstrapEnrollmentStage = "IDENTITY_READY"
	SuiteBootstrapRequestReady  SuiteBootstrapEnrollmentStage = "REQUEST_READY"
	SuiteBootstrapAcknowledged  SuiteBootstrapEnrollmentStage = "ACKNOWLEDGED"
)

var (
	ErrSuiteBootstrapEnrollmentState     = errors.New("suite bootstrap enrollment state invalid")
	errSuiteBootstrapEnrollmentUnknown   = errors.New("suite bootstrap enrollment state has unknown fields")
	errSuiteBootstrapEnrollmentDuplicate = errors.New("suite bootstrap enrollment state has duplicate fields")
	errSuiteBootstrapEnrollmentUnsafe    = errors.New("suite bootstrap enrollment state is unsafe")
)

type SuiteBootstrapEnrollmentAttempt struct {
	SchemaVersion         int                           `json:"schema_version"`
	Stage                 SuiteBootstrapEnrollmentStage `json:"stage"`
	PreparationRequestUID string                        `json:"preparation_request_uid"`
	DeploymentUID         string                        `json:"deployment_uid"`
	DiscoverySHA256       string                        `json:"discovery_sha256"`
	MetadataSHA256        string                        `json:"metadata_sha256"`
	IdentityRef           string                        `json:"identity_ref"`
	PublicKeySHA256       string                        `json:"public_key_sha256"`
	EnrollmentCodeSHA256  string                        `json:"enrollment_code_sha256"`
	RequestSHA256         string                        `json:"request_sha256"`
	IdempotencySHA256     string                        `json:"idempotency_sha256"`
	NodeUID               string                        `json:"node_uid,omitempty"`
	EnrollmentState       string                        `json:"enrollment_state,omitempty"`
	ControlEndpoint       string                        `json:"control_endpoint,omitempty"`
}

func (attempt SuiteBootstrapEnrollmentAttempt) String() string {
	stage := "UNKNOWN"
	if suiteBootstrapEnrollmentStageIndex(attempt.Stage) >= 0 {
		stage = string(attempt.Stage)
	}
	return "SuiteBootstrapEnrollmentAttempt{stage=" + stage + "}"
}

func suiteBootstrapEnrollmentStageIndex(stage SuiteBootstrapEnrollmentStage) int {
	switch stage {
	case SuiteBootstrapIdentityReady:
		return 0
	case SuiteBootstrapRequestReady:
		return 1
	case SuiteBootstrapAcknowledged:
		return 2
	default:
		return -1
	}
}

func (attempt SuiteBootstrapEnrollmentAttempt) validate() error {
	if attempt.SchemaVersion != suiteBootstrapEnrollmentSchema || suiteBootstrapEnrollmentStageIndex(attempt.Stage) < 0 {
		return ErrSuiteBootstrapEnrollmentState
	}
	if parsed, err := uuid.Parse(attempt.PreparationRequestUID); err != nil || parsed.String() != attempt.PreparationRequestUID {
		return ErrSuiteBootstrapEnrollmentState
	}
	if parsed, err := uuid.Parse(attempt.DeploymentUID); err != nil || parsed.String() != attempt.DeploymentUID {
		return ErrSuiteBootstrapEnrollmentState
	}
	if _, err := NewFarmClientIdentityKeyRef(attempt.IdentityRef); err != nil {
		return ErrSuiteBootstrapEnrollmentState
	}
	for _, digest := range []string{attempt.DiscoverySHA256, attempt.MetadataSHA256, attempt.PublicKeySHA256, attempt.EnrollmentCodeSHA256, attempt.RequestSHA256, attempt.IdempotencySHA256} {
		if !validLowerSHA256(digest) {
			return ErrSuiteBootstrapEnrollmentState
		}
	}
	if attempt.Stage == SuiteBootstrapAcknowledged {
		if !validSuiteBootstrapEnrollmentNodeUID(attempt.NodeUID) || (attempt.EnrollmentState != "ENROLLED" && attempt.EnrollmentState != "ALREADY_ENROLLED") {
			return ErrSuiteBootstrapEnrollmentState
		}
		if _, err := validateSuiteBootstrapEndpoint(attempt.ControlEndpoint, "wss", "/control/ws"); err != nil {
			return ErrSuiteBootstrapEnrollmentState
		}
	} else if attempt.NodeUID != "" || attempt.EnrollmentState != "" || attempt.ControlEndpoint != "" {
		return ErrSuiteBootstrapEnrollmentState
	}
	return nil
}

func suiteBootstrapEnrollmentAttemptPath(roots SuiteUserRoots) (string, error) {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return "", ErrSuiteBootstrapEnrollmentState
	}
	return filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName), nil
}

func loadSuiteBootstrapEnrollmentAttempt(roots SuiteUserRoots) (*SuiteBootstrapEnrollmentAttempt, error) {
	path, err := suiteBootstrapEnrollmentAttemptPath(roots)
	if err != nil {
		return nil, err
	}
	primary, primaryErr := readSuiteBootstrapEnrollmentAttemptFile(path)
	backup, backupErr := readSuiteBootstrapEnrollmentAttemptFile(path + ".bak")
	for _, candidateErr := range []error{primaryErr, backupErr} {
		if errors.Is(candidateErr, errSuiteBootstrapEnrollmentUnsafe) || errors.Is(candidateErr, errSuiteBootstrapEnrollmentUnknown) || errors.Is(candidateErr, errSuiteBootstrapEnrollmentDuplicate) {
			return nil, candidateErr
		}
	}
	if primaryErr == nil && primary != nil {
		if backupErr != nil {
			return nil, backupErr
		}
		return primary, nil
	}
	if backupErr == nil && backup != nil {
		return backup, nil
	}
	if primaryErr == nil && primary == nil && backupErr != nil {
		return nil, backupErr
	}
	if primaryErr != nil {
		return nil, primaryErr
	}
	if backupErr != nil {
		return nil, backupErr
	}
	return nil, nil
}

func readSuiteBootstrapEnrollmentAttemptFile(path string) (*SuiteBootstrapEnrollmentAttempt, error) {
	raw, exists, err := readSuiteBootstrapEnrollmentOwnerFile(path)
	if err != nil || !exists {
		return nil, err
	}
	if suiteBootstrapEnrollmentRawContainsSecret(raw) {
		return nil, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentUnsafe)
	}
	if duplicateErr := rejectSuiteReleaseDuplicateJSONKeys(raw); duplicateErr != nil && strings.Contains(duplicateErr.Error(), "duplicate or case-folded JSON key") {
		return nil, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentDuplicate)
	}
	var keys map[string]json.RawMessage
	if json.Unmarshal(raw, &keys) != nil {
		return nil, ErrSuiteBootstrapEnrollmentState
	}
	base := []string{"schema_version", "stage", "preparation_request_uid", "deployment_uid", "discovery_sha256", "metadata_sha256", "identity_ref", "public_key_sha256", "enrollment_code_sha256", "request_sha256", "idempotency_sha256"}
	allowed := append(append([]string{}, base...), "node_uid", "enrollment_state", "control_endpoint")
	if !exactFarmClientIPCKeysOptional(keys, base, allowed[len(base):]) {
		return nil, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentUnknown)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var attempt SuiteBootstrapEnrollmentAttempt
	if decoder.Decode(&attempt) != nil || requireJSONEOF(decoder) != nil || attempt.validate() != nil {
		return nil, ErrSuiteBootstrapEnrollmentState
	}
	if attempt.Stage == SuiteBootstrapAcknowledged {
		for _, key := range []string{"node_uid", "enrollment_state", "control_endpoint"} {
			if _, ok := keys[key]; !ok {
				return nil, ErrSuiteBootstrapEnrollmentState
			}
		}
	} else if len(keys) != len(base) {
		return nil, ErrSuiteBootstrapEnrollmentState
	}
	return &attempt, nil
}

func readSuiteBootstrapEnrollmentOwnerFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || validateSuiteSetupPathSecurity(path, false) != nil || info.Size() > maxSuiteBootstrapEnrollmentStateBytes {
		return nil, true, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentUnsafe)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, true, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentUnsafe)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxSuiteBootstrapEnrollmentStateBytes+1))
	if err != nil || len(raw) > maxSuiteBootstrapEnrollmentStateBytes {
		return nil, true, fmt.Errorf("%w: %w", ErrSuiteBootstrapEnrollmentState, errSuiteBootstrapEnrollmentUnsafe)
	}
	return raw, true, nil
}

func suiteBootstrapEnrollmentRawContainsSecret(raw []byte) bool {
	lower := strings.ToLower(string(raw))
	for _, field := range []string{`"enrollment_code"`, `"private_key"`, `"device_public_key_ed25519_b64"`, `"public_key"`, `"password"`, `"cookie"`, `"token"`, `"access_token"`, `"refresh_token"`} {
		if strings.Contains(lower, field) {
			return true
		}
	}
	return false
}

func validSuiteBootstrapEnrollmentNodeUID(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func saveSuiteBootstrapEnrollmentAttempt(roots SuiteUserRoots, next SuiteBootstrapEnrollmentAttempt) error {
	path, err := suiteBootstrapEnrollmentAttemptPath(roots)
	if err != nil || next.validate() != nil {
		return ErrSuiteBootstrapEnrollmentState
	}
	previous, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil {
		return err
	}
	if previous == nil {
		if next.Stage != SuiteBootstrapIdentityReady {
			return ErrSuiteBootstrapEnrollmentState
		}
	} else {
		if !sameSuiteBootstrapEnrollmentBinding(*previous, next) || suiteBootstrapEnrollmentStageIndex(next.Stage) < suiteBootstrapEnrollmentStageIndex(previous.Stage) || suiteBootstrapEnrollmentStageIndex(next.Stage) > suiteBootstrapEnrollmentStageIndex(previous.Stage)+1 {
			return ErrSuiteBootstrapEnrollmentState
		}
		if previous.Stage == next.Stage {
			if *previous != next {
				return ErrSuiteBootstrapEnrollmentState
			}
			return nil
		}
		if current, readErr := readSuiteBootstrapEnrollmentAttemptFile(path); readErr != nil || current == nil {
			if err := writeSuiteBootstrapEnrollmentAttemptFile(path, *previous); err != nil {
				return err
			}
		}
		if err := writeSuiteBootstrapEnrollmentAttemptFile(path+".bak", *previous); err != nil {
			return err
		}
	}
	return writeSuiteBootstrapEnrollmentAttemptFile(path, next)
}

func sameSuiteBootstrapEnrollmentBinding(left, right SuiteBootstrapEnrollmentAttempt) bool {
	return left.SchemaVersion == right.SchemaVersion && left.PreparationRequestUID == right.PreparationRequestUID && left.DeploymentUID == right.DeploymentUID &&
		left.DiscoverySHA256 == right.DiscoverySHA256 && left.MetadataSHA256 == right.MetadataSHA256 && left.IdentityRef == right.IdentityRef &&
		left.PublicKeySHA256 == right.PublicKeySHA256 && left.EnrollmentCodeSHA256 == right.EnrollmentCodeSHA256 && left.RequestSHA256 == right.RequestSHA256 && left.IdempotencySHA256 == right.IdempotencySHA256
}

func writeSuiteBootstrapEnrollmentAttemptFile(path string, attempt SuiteBootstrapEnrollmentAttempt) error {
	raw, err := json.Marshal(attempt)
	if err != nil {
		return ErrSuiteBootstrapEnrollmentState
	}
	return writeOwnerAtomic(path, append(raw, '\n'))
}

func suiteBootstrapSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
