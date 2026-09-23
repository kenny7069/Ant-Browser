//go:build !windows && !darwin

package backend

func validateSuiteStagePlatformInstall(string, SuiteSetupPlan, string) (suiteStageInstallEvidence, error) {
	return suiteStageInstallEvidence{}, ErrSuiteCanonicalStage
}
