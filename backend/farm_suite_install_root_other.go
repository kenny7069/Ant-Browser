//go:build !windows

package backend

func validateCanonicalSuiteInstallRoot(SuiteOwnershipHandoff) error { return ErrSuiteServiceActivation }
