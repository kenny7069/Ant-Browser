//go:build darwin

package backend

import (
	"os"
	"path/filepath"
)

func validateSuiteStagePlatformInstall(installedSuiteRoot string, plan SuiteSetupPlan, version string) (suiteStageInstallEvidence, error) {
	canonicalRoot := filepath.Clean(filepath.Join(suiteDarwinInstallBase, "versions", version))
	if filepath.Clean(installedSuiteRoot) != canonicalRoot {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	handoff := SuiteOwnershipHandoff{
		SuiteBinaryRoot: canonicalRoot,
		ManifestSHA256:  plan.ManifestSHA256,
		ReleaseTarget:   plan.Target,
	}
	if err := validateCanonicalSuiteInstallRoot(handoff); err != nil {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	callerInfo, callerErr := os.Lstat(installedSuiteRoot)
	canonicalInfo, canonicalErr := os.Lstat(canonicalRoot)
	if callerErr != nil || canonicalErr != nil || !callerInfo.IsDir() || !canonicalInfo.IsDir() || !os.SameFile(callerInfo, canonicalInfo) {
		return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
	}
	return suiteStageInstallEvidence{CanonicalRoot: canonicalRoot, RootInfo: canonicalInfo}, nil
}
