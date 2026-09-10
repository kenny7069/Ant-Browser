//go:build linux

package backend

import (
	"crypto/ed25519"
	"errors"
	"os"
	"testing"
)

func assertC8NativeIdentityBackend(t *testing.T, stateRoot string, ref FarmClientIdentityKeyRef, _ ed25519.PublicKey) {
	t.Helper()
	path, err := farmClientIdentityFilePath(stateRoot, ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Secret Service evidence fell back to the local seed file: %v", err)
	}
}

func cleanupC8NativeIdentity(t *testing.T, stateRoot string, ref FarmClientIdentityKeyRef) {
	t.Helper()
	store, err := NewFarmClientIdentityStore(stateRoot)
	if err != nil {
		t.Errorf("open installed native identity store for cleanup: %v", err)
		return
	}
	if err := store.Delete(ref); err != nil {
		t.Errorf("delete installed native identity: %v", err)
	}
}
