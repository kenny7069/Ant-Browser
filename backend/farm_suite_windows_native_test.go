//go:build windows

package backend

import (
	"os"
	"testing"
)

// This read-only native test requires a fully installed signed Suite and an
// existing exact per-user task. It performs no registration or mutation.
func TestSuiteWindowsNativeInstallAndTaskEvidence(t *testing.T) {
	if os.Getenv("ANT_SUITE_WINDOWS_NATIVE") != "1" {
		t.Skip("NOT_RUN: set ANT_SUITE_WINDOWS_NATIVE=1 on the dedicated Windows x64 acceptance runner")
	}
	roots, err := ResolveSuiteUserRoots()
	if err != nil {
		t.Fatal(err)
	}
	handoff, err := LoadSuiteOwnershipHandoff(roots)
	if err != nil || handoff == nil {
		t.Fatalf("load handoff: %v", err)
	}
	platform := newSuiteServicePlatform()
	identity, err := platform.ValidateInstall(*handoff)
	if err != nil {
		t.Fatalf("immutable install evidence: %v", err)
	}
	observed, err := platform.InspectRegistration(*handoff, identity)
	if err != nil || (observed != suiteServiceRegistrationExactDisabled && observed != suiteServiceRegistrationExactEnabled) {
		t.Fatalf("scheduled task evidence state=%s err=%v", observed, err)
	}
}
