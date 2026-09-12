//go:build windows

package backend

import (
	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/sys/windows"
)

type windowsSuiteServicePlatform struct{}

func newSuiteServicePlatform() suiteServicePlatform { return windowsSuiteServicePlatform{} }
func (windowsSuiteServicePlatform) ValidateInstall(h SuiteOwnershipHandoff) (string, error) {
	if err := validateCanonicalSuiteInstallRoot(h); err != nil {
		return "", err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(user.User.Sid.String()))
	return "AntBrowserSuite-Agent-" + hex.EncodeToString(hash[:8]), nil
}
func (windowsSuiteServicePlatform) RegisterDisabled(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
func (windowsSuiteServicePlatform) InspectRegistration(SuiteOwnershipHandoff, string) (suiteServiceRegistrationState, error) {
	return suiteServiceRegistrationDrift, ErrSuiteServiceActivation
}
func (windowsSuiteServicePlatform) Enable(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
func (windowsSuiteServicePlatform) Start(SuiteOwnershipHandoff, string) error {
	return ErrSuiteServiceActivation
}
