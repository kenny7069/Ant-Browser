//go:build !windows

package backend

import "fmt"

type unsupportedSuiteServicePlatform struct{}

func newSuiteServicePlatform() suiteServicePlatform { return unsupportedSuiteServicePlatform{} }
func (unsupportedSuiteServicePlatform) ValidateInstall(SuiteOwnershipHandoff) (string, error) {
	return "", fmt.Errorf("%w: unsupported platform", ErrSuiteServiceActivation)
}
func (unsupportedSuiteServicePlatform) RegisterDisabled(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
func (unsupportedSuiteServicePlatform) Audit(SuiteOwnershipHandoff, string, bool) error {
	return ErrSuiteServiceActivation
}
func (unsupportedSuiteServicePlatform) Enable(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
func (unsupportedSuiteServicePlatform) Start(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
