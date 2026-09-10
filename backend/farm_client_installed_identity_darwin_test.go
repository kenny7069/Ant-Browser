//go:build darwin && cgo

package backend

import (
	"crypto/ed25519"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func assertC8NativeIdentityBackend(t *testing.T, stateRoot string, _ FarmClientIdentityKeyRef, _ ed25519.PublicKey) {
	t.Helper()
	if _, err := os.Stat(filepath.Join(stateRoot, farmClientIdentityStoreDir)); !os.IsNotExist(err) {
		t.Fatalf("Keychain identity unexpectedly created a file-store directory: %v", err)
	}
}

func cleanupC8NativeIdentity(t *testing.T, _ string, ref FarmClientIdentityKeyRef) {
	t.Helper()
	output, err := exec.Command("security", "delete-generic-password", "-s", farmClientIdentityKeychainService, "-a", string(ref)).CombinedOutput()
	if err != nil {
		t.Errorf("delete installed native identity %q: %v output=%s", ref, err, strings.TrimSpace(string(output)))
	}
}
