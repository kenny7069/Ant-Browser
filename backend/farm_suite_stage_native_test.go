//go:build windows

package backend

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSuiteStageWindowsCanonicalAndCallerIdentityMustMatch(t *testing.T) {
	base := t.TempDir()
	caller := filepath.Join(base, "caller")
	canonical := filepath.Join(base, "canonical")
	if err := os.Mkdir(caller, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(canonical, 0o700); err != nil {
		t.Fatal(err)
	}
	callerInfo, err := os.Lstat(caller)
	if err != nil {
		t.Fatal(err)
	}
	canonicalInfo, err := os.Lstat(canonical)
	if err != nil {
		t.Fatal(err)
	}
	if suiteStageWindowsInstallIdentityMatches(callerInfo, canonicalInfo) {
		t.Fatal("different install-root identities accepted")
	}
	if !suiteStageWindowsInstallIdentityMatches(callerInfo, callerInfo) {
		t.Fatal("same install-root identity rejected")
	}
}
