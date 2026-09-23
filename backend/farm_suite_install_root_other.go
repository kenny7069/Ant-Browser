//go:build !windows && !darwin

package backend

func validateCanonicalSuiteInstallRoot(SuiteOwnershipHandoff) error { return ErrSuiteServiceActivation }
