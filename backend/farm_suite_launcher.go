package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
)

var ErrSuiteLauncherRevalidation = errors.New("suite launcher revalidation failed")

// suiteLauncherValidator is deliberately injectable only for focused tests.
// Production validation always uses the durable Suite evidence and platform
// adapter; callers cannot provide a path, digest, generation, or pass flag.
type suiteLauncherValidator func(string, string) error

type suiteLauncherPathMatcher func(string, string) bool

// ClassifySuiteFarmClientLaunch decides whether the default invocation belongs
// to the canonical Suite launcher. Alternate paths with a Suite footprint are
// rejected before the legacy launcher can acquire a lock, mutate activation
// state, or spawn a child.
func ClassifySuiteFarmClientLaunch(roots SuiteUserRoots, configPath string) (bool, error) {
	return classifySuiteFarmClientLaunch(roots, configPath, sameSuiteHandoffPath)
}

func classifySuiteFarmClientLaunch(roots SuiteUserRoots, configPath string, samePath suiteLauncherPathMatcher) (bool, error) {
	if err := validateSuiteSetupRoots(roots); err != nil || samePath == nil || !filepath.IsAbs(configPath) {
		return false, ErrSuiteLauncherRevalidation
	}
	canonicalConfig := filepath.Join(roots.Config, SuiteClientConfigName)
	if samePath(configPath, canonicalConfig) {
		return true, nil
	}
	if err := rejectRawAutostartForSuiteFootprintAtRoots(configPath, roots); err != nil {
		return false, ErrSuiteLauncherRevalidation
	}
	return false, nil
}

func RunSuiteFarmClientLauncher(ctx context.Context, roots SuiteUserRoots, configPath, launcherPath string, stdout, stderr io.Writer) error {
	validate := func(configPath, launcherPath string) error {
		return validateSuiteLauncherStart(roots, configPath, launcherPath)
	}
	return runSuiteFarmClientLauncher(ctx, configPath, launcherPath, stdout, stderr, validate)
}

func runSuiteFarmClientLauncher(ctx context.Context, configPath, launcherPath string, stdout, stderr io.Writer, validate suiteLauncherValidator) error {
	if validate == nil || validate(configPath, launcherPath) != nil {
		return ErrSuiteLauncherRevalidation
	}
	return runFarmClientLauncherWithValidation(ctx, configPath, launcherPath, stdout, stderr, validate)
}

func validateSuiteLauncherStart(roots SuiteUserRoots, configPath, launcherPath string) error {
	return validateSuiteLauncherStartWithPlatform(roots, configPath, launcherPath, newSuiteServicePlatform())
}

func validateSuiteLauncherStartWithPlatform(roots SuiteUserRoots, configPath, launcherPath string, platform suiteServicePlatform) error {
	if err := validateSuiteSetupRoots(roots); err != nil {
		return ErrSuiteLauncherRevalidation
	}
	canonicalConfig := filepath.Join(roots.Config, SuiteClientConfigName)
	if !sameSuiteHandoffPath(configPath, canonicalConfig) {
		return ErrSuiteLauncherRevalidation
	}
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil || !sameSuiteHandoffPath(handoff.ClientConfigPath, canonicalConfig) {
		return ErrSuiteLauncherRevalidation
	}
	config, digest, err := loadSuiteHandoffClientConfig(canonicalConfig)
	if err != nil || digest != handoff.ClientConfigSHA256 || !sameSuiteHandoffPath(config.StateRoot, handoff.AgentStateRoot) || !sameSuiteHandoffPath(config.ApplicationRoot, handoff.ApplicationRoot) || !sameSuiteHandoffPath(config.AntConfigPath, handoff.AntConfigPath) {
		return ErrSuiteLauncherRevalidation
	}
	checkpoint, err := LoadSetupCheckpoint(filepath.Join(roots.AgentState, "setup.json"))
	if err != nil || checkpoint == nil || (checkpoint.Stage != SetupEnrolled && checkpoint.Stage != SetupServiceStarted) || checkpoint.RequestUID != handoff.SetupRequestUID {
		return ErrSuiteLauncherRevalidation
	}
	journal, err := LoadSuiteActivationJournal(roots)
	if err != nil || journal == nil || journal.Stage == SuiteActivationReconcileRequired || journal.Generation != 1 || journal.RequestUID != handoff.SetupRequestUID || journal.ClientConfigSHA256 != handoff.ClientConfigSHA256 || journal.ManifestSHA256 != handoff.ManifestSHA256 || journal.SetupStageID != handoff.SetupStageID {
		return ErrSuiteLauncherRevalidation
	}
	if journal.Stage != SuiteActivationEnabled && journal.Stage != SuiteActivationStartRequested && journal.Stage != SuiteActivationResidentProved && journal.Stage != SuiteActivationCheckpointWritten {
		return ErrSuiteLauncherRevalidation
	}
	if platform == nil {
		return ErrSuiteLauncherRevalidation
	}
	taskIdentity, err := platform.ValidateInstall(*handoff)
	if err != nil || strings.TrimSpace(taskIdentity) == "" {
		return ErrSuiteLauncherRevalidation
	}
	taskHash := sha256.Sum256([]byte(taskIdentity))
	if journal.TaskIdentityDigest != hex.EncodeToString(taskHash[:]) {
		return ErrSuiteLauncherRevalidation
	}
	registration, err := platform.InspectRegistration(*handoff, taskIdentity)
	if err != nil || registration != suiteServiceRegistrationExactEnabled {
		return ErrSuiteLauncherRevalidation
	}
	expectedLauncher := filepath.Join(handoff.SuiteBinaryRoot, filepath.FromSlash(suiteCurrentReleaseLayout().Client))
	if !sameSuiteHandoffPath(launcherPath, expectedLauncher) {
		return ErrSuiteLauncherRevalidation
	}
	return nil
}
