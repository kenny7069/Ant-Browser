//go:build windows

package backend

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validateSuiteStagePlatformInstall(installedSuiteRoot string, plan SuiteSetupPlan, version string) (suiteStageInstallEvidence, error) {
	programFiles, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFilesX64, 0)
	if err != nil {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	canonicalRoot := filepath.Clean(filepath.Join(programFiles, "Ant Browser Suite", "versions", version))
	if !strings.EqualFold(installedSuiteRoot, canonicalRoot) {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	handoff := SuiteOwnershipHandoff{
		SuiteBinaryRoot: installedSuiteRoot,
		ManifestSHA256:  plan.ManifestSHA256,
		ReleaseTarget:   plan.Target,
	}
	if err := validateCanonicalSuiteInstallRoot(handoff); err != nil {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	callerInfo, callerErr := os.Lstat(installedSuiteRoot)
	canonicalInfo, canonicalErr := os.Lstat(canonicalRoot)
	if callerErr != nil || canonicalErr != nil || !suiteStageWindowsInstallIdentityMatches(callerInfo, canonicalInfo) {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	return suiteStageInstallEvidence{CanonicalRoot: canonicalRoot, RootInfo: canonicalInfo}, nil
}

func suiteStageWindowsInstallIdentityMatches(caller, canonical os.FileInfo) bool {
	return caller != nil && canonical != nil && caller.IsDir() && canonical.IsDir() && os.SameFile(caller, canonical)
}
