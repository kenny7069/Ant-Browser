package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

const (
	SuiteApplicationInitStateName  = "setup-application-init-state.json"
	suiteApplicationInitNextName   = "setup-application-init-state.next.json"
	suiteApplicationInitBackupName = SuiteApplicationInitStateName + ".bak"
	suiteApplicationInitMaxBytes   = 16 << 10
	SuiteApplicationInitPlanned    = "PLANNED"
	SuiteApplicationInitialized    = "INITIALIZED"
)

var ErrSuiteApplicationInitState = errors.New("invalid suite application initialization state")

type SuiteApplicationInitState struct {
	SchemaVersion           int    `json:"schema_version"`
	Stage                   string `json:"stage"`
	RequestUID              string `json:"request_uid"`
	SetupStageID            string `json:"setup_stage_id"`
	BootstrapSHA256         string `json:"bootstrap_sha256"`
	ManifestSHA256          string `json:"manifest_sha256"`
	ConfigDraftSHA256       string `json:"config_draft_sha256"`
	DiscoverySHA256         string `json:"discovery_sha256"`
	IdentityRef             string `json:"identity_ref"`
	PublicKeySHA256         string `json:"public_key_sha256"`
	EnrollmentAttemptSHA256 string `json:"enrollment_attempt_sha256"`
	NodeUID                 string `json:"node_uid"`
	ApplicationRoot         string `json:"application_root"`
	AntConfigPath           string `json:"ant_config_path"`
	DatabasePath            string `json:"database_path"`
	ChromiumPath            string `json:"chromium_path"`
	ChromiumVersion         string `json:"chromium_version"`
	StagingConfigPath       string `json:"staging_config_path"`
	StagingDatabasePath     string `json:"staging_database_path"`
}

func (state SuiteApplicationInitState) validate() error {
	if state.SchemaVersion != 1 || (state.Stage != SuiteApplicationInitPlanned && state.Stage != SuiteApplicationInitialized) ||
		(SetupCheckpoint{SchemaVersion: 1, Stage: SetupIdentityReady, RequestUID: state.RequestUID}).validate() != nil ||
		state.SetupStageID == "" || !validLowerSHA256(state.BootstrapSHA256) || !validLowerSHA256(state.ManifestSHA256) ||
		!validLowerSHA256(state.ConfigDraftSHA256) || !validLowerSHA256(state.DiscoverySHA256) || !validLowerSHA256(state.PublicKeySHA256) ||
		!validLowerSHA256(state.EnrollmentAttemptSHA256) || !validSuiteBootstrapEnrollmentNodeUID(state.NodeUID) || state.ChromiumVersion == "" {
		return ErrSuiteApplicationInitState
	}
	for _, path := range []string{state.ApplicationRoot, state.AntConfigPath, state.DatabasePath, state.ChromiumPath, state.StagingConfigPath, state.StagingDatabasePath} {
		if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return ErrSuiteApplicationInitState
		}
	}
	if state.AntConfigPath != filepath.Join(state.ApplicationRoot, "config.yaml") || state.DatabasePath != filepath.Join(state.ApplicationRoot, "data", "app.db") || state.IdentityRef == "" {
		return ErrSuiteApplicationInitState
	}
	if filepath.Dir(state.StagingConfigPath) != state.ApplicationRoot || filepath.Dir(state.StagingDatabasePath) != filepath.Join(state.ApplicationRoot, "data") || filepath.Base(state.StagingConfigPath) == filepath.Base(state.AntConfigPath) || filepath.Base(state.StagingDatabasePath) == filepath.Base(state.DatabasePath) {
		return ErrSuiteApplicationInitState
	}
	stagingID := suiteBootstrapSHA256([]byte(state.RequestUID + "\x00" + state.ManifestSHA256))
	if filepath.Base(state.StagingConfigPath) != ".suite-init-"+stagingID+"-config.staging" || filepath.Base(state.StagingDatabasePath) != ".suite-init-"+stagingID+"-app.db.staging" {
		return ErrSuiteApplicationInitState
	}
	return nil
}

func LoadSuiteApplicationInitState(roots SuiteUserRoots) (*SuiteApplicationInitState, error) {
	if validateSuiteSetupRoots(roots) != nil || validateSuiteSetupPathSecurity(roots.AgentState, true) != nil {
		return nil, ErrSuiteApplicationInitState
	}
	rootInfo, err := captureSuiteConfigDraftRoot(roots.AgentState)
	if err != nil {
		return nil, ErrSuiteApplicationInitState
	}
	primary, primaryErr := readSuiteApplicationInitStateFile(filepath.Join(roots.AgentState, SuiteApplicationInitStateName), roots.AgentState, rootInfo)
	backup, backupErr := readSuiteApplicationInitStateFile(filepath.Join(roots.AgentState, suiteApplicationInitBackupName), roots.AgentState, rootInfo)
	if primaryErr != nil || backupErr != nil || revalidateSuiteConfigDraftRoot(roots.AgentState, rootInfo) != nil {
		return nil, ErrSuiteApplicationInitState
	}
	if primary == nil {
		if backup != nil && backup.Stage != SuiteApplicationInitPlanned {
			return nil, ErrSuiteApplicationInitState
		}
		return backup, nil
	}
	if primary.Stage == SuiteApplicationInitPlanned {
		if backup != nil && (*backup != *primary || !sameSuiteApplicationInitBinding(*backup, *primary)) {
			return nil, ErrSuiteApplicationInitState
		}
		return primary, nil
	}
	if backup == nil || backup.Stage != SuiteApplicationInitPlanned || !sameSuiteApplicationInitBinding(*backup, *primary) {
		return nil, ErrSuiteApplicationInitState
	}
	if _, err := os.Lstat(filepath.Join(roots.AgentState, suiteApplicationInitNextName)); !errors.Is(err, os.ErrNotExist) {
		return nil, ErrSuiteApplicationInitState
	}
	return primary, nil
}

func readSuiteApplicationInitStateFile(path, root string, rootInfo os.FileInfo) (*SuiteApplicationInitState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if revalidateSuiteConfigDraftRoot(root, rootInfo) != nil {
			return nil, ErrSuiteApplicationInitState
		}
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > suiteApplicationInitMaxBytes || validateSuiteSetupPathSecurity(path, false) != nil {
		return nil, ErrSuiteApplicationInitState
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteApplicationInitState
	}
	defer file.Close()
	handleInfo, err := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, suiteApplicationInitMaxBytes+1))
	finalInfo, finalErr := os.Lstat(path)
	if err != nil || readErr != nil || len(raw) == 0 || len(raw) > suiteApplicationInitMaxBytes || int64(len(raw)) != handleInfo.Size() || !os.SameFile(info, handleInfo) || finalErr != nil || !os.SameFile(handleInfo, finalInfo) || validateSuiteSetupPathSecurity(path, false) != nil || revalidateSuiteConfigDraftRoot(root, rootInfo) != nil || rejectSuiteReleaseDuplicateJSONKeys(raw) != nil {
		return nil, ErrSuiteApplicationInitState
	}
	keys := []string{"schema_version", "stage", "request_uid", "setup_stage_id", "bootstrap_sha256", "manifest_sha256", "config_draft_sha256", "discovery_sha256", "identity_ref", "public_key_sha256", "enrollment_attempt_sha256", "node_uid", "application_root", "ant_config_path", "database_path", "chromium_path", "chromium_version", "staging_config_path", "staging_database_path"}
	if _, err := exactSuiteReleaseJSONObject(raw, keys); err != nil {
		return nil, ErrSuiteApplicationInitState
	}
	var state SuiteApplicationInitState
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&state) != nil || requireJSONEOF(decoder) != nil || state.validate() != nil || revalidateSuiteConfigDraftRoot(root, rootInfo) != nil {
		return nil, ErrSuiteApplicationInitState
	}
	return &state, nil
}

func saveSuiteApplicationInitState(roots SuiteUserRoots, next SuiteApplicationInitState) error {
	if next.validate() != nil {
		return ErrSuiteApplicationInitState
	}
	previous, err := LoadSuiteApplicationInitState(roots)
	if err != nil {
		return err
	}
	restorePrimary := false
	if previous == nil {
		if next.Stage != SuiteApplicationInitPlanned {
			return ErrSuiteApplicationInitState
		}
	} else {
		expected := *previous
		expected.Stage = next.Stage
		if !reflect.DeepEqual(expected, next) || (previous.Stage == SuiteApplicationInitialized && next.Stage != SuiteApplicationInitialized) {
			return ErrSuiteApplicationInitState
		}
		if *previous == next {
			if _, statErr := os.Lstat(filepath.Join(roots.AgentState, SuiteApplicationInitStateName)); statErr == nil {
				if next.Stage == SuiteApplicationInitPlanned && validateSuiteApplicationInitNextIntent(roots, next) != nil {
					return ErrSuiteApplicationInitState
				}
				return nil
			} else if !errors.Is(statErr, os.ErrNotExist) {
				return ErrSuiteApplicationInitState
			}
			restorePrimary = true
		}
		if !restorePrimary && (previous.Stage != SuiteApplicationInitPlanned || next.Stage != SuiteApplicationInitialized) {
			return ErrSuiteApplicationInitState
		}
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw)+1 > suiteApplicationInitMaxBytes {
		return ErrSuiteApplicationInitState
	}
	raw = append(raw, '\n')
	path := filepath.Join(roots.AgentState, SuiteApplicationInitStateName)
	nextPath := filepath.Join(roots.AgentState, suiteApplicationInitNextName)
	backupPath := filepath.Join(roots.AgentState, suiteApplicationInitBackupName)
	if previous != nil && previous.Stage == SuiteApplicationInitPlanned {
		rootInfo, captureErr := captureSuiteConfigDraftRoot(roots.AgentState)
		if captureErr != nil {
			return ErrSuiteApplicationInitState
		}
		primary, primaryErr := readSuiteApplicationInitStateFile(path, roots.AgentState, rootInfo)
		if primaryErr != nil {
			return ErrSuiteApplicationInitState
		}
		if primary == nil {
			if err := publishSuiteApplicationFileNoReplace(backupPath, path, func() error {
				backupRoot, rootErr := captureSuiteConfigDraftRoot(roots.AgentState)
				if rootErr != nil {
					return rootErr
				}
				loaded, loadErr := readSuiteApplicationInitStateFile(backupPath, roots.AgentState, backupRoot)
				if loadErr != nil || loaded == nil || *loaded != *previous {
					return ErrSuiteApplicationInitState
				}
				return nil
			}); err != nil {
				return ErrSuiteApplicationInitState
			}
			if restorePrimary {
				return nil
			}
		}
		if next.Stage == SuiteApplicationInitialized {
			if err := ensureSuiteApplicationStateBackup(path, backupPath, *previous); err != nil {
				return ErrSuiteApplicationInitState
			}
		}
	}
	if err := writeSuiteApplicationInitNext(nextPath, raw); err != nil {
		return ErrSuiteApplicationInitState
	}
	if err := replaceSuiteSetupFile(nextPath, path); err != nil || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteApplicationInitState
	}
	written, err := LoadSuiteApplicationInitState(roots)
	if err != nil || written == nil || *written != next || syncSuiteSetupDirectory(roots.AgentState) != nil {
		return ErrSuiteApplicationInitState
	}
	return nil
}

func validateSuiteApplicationInitNextIntent(roots SuiteUserRoots, current SuiteApplicationInitState) error {
	path := filepath.Join(roots.AgentState, suiteApplicationInitNextName)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	successor := current
	successor.Stage = SuiteApplicationInitialized
	expected, marshalErr := json.Marshal(successor)
	expected = append(expected, '\n')
	if err != nil || marshalErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > int64(len(expected)) || validateSuiteSetupPathSecurity(path, false) != nil {
		return ErrSuiteApplicationInitState
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrSuiteApplicationInitState
	}
	defer file.Close()
	handleInfo, statErr := file.Stat()
	raw, readErr := io.ReadAll(io.LimitReader(file, int64(len(expected)+1)))
	finalInfo, finalErr := os.Lstat(path)
	if statErr != nil || readErr != nil || finalErr != nil || len(raw) == 0 || int64(len(raw)) != handleInfo.Size() || !bytes.Equal(raw, expected[:len(raw)]) || !os.SameFile(info, handleInfo) || !os.SameFile(handleInfo, finalInfo) {
		return ErrSuiteApplicationInitState
	}
	return nil
}

func ensureSuiteApplicationStateBackup(primary, backup string, expected SuiteApplicationInitState) error {
	if existing, err := os.Lstat(backup); err == nil {
		primaryInfo, primaryErr := os.Lstat(primary)
		if primaryErr != nil || !os.SameFile(existing, primaryInfo) {
			loadedRoot := filepath.Dir(backup)
			rootInfo, captureErr := captureSuiteConfigDraftRoot(loadedRoot)
			if captureErr != nil {
				return ErrSuiteApplicationInitState
			}
			loaded, loadErr := readSuiteApplicationInitStateFile(backup, loadedRoot, rootInfo)
			if loadErr != nil || loaded == nil || *loaded != expected {
				return ErrSuiteApplicationInitState
			}
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrSuiteApplicationInitState
	}
	return publishSuiteApplicationFileNoReplace(primary, backup, func() error {
		rootInfo, err := captureSuiteConfigDraftRoot(filepath.Dir(primary))
		if err != nil {
			return err
		}
		loaded, err := readSuiteApplicationInitStateFile(primary, filepath.Dir(primary), rootInfo)
		if err != nil || loaded == nil || *loaded != expected {
			return ErrSuiteApplicationInitState
		}
		return nil
	})
}

func writeSuiteApplicationInitNext(path string, expected []byte) error {
	if err := writeSuiteApplicationRecoverableFile(path, expected); err != nil {
		return ErrSuiteApplicationInitState
	}
	return nil
}
