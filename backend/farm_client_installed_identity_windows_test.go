//go:build windows

package backend

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"testing"
)

func assertC8NativeIdentityBackend(t *testing.T, stateRoot string, ref FarmClientIdentityKeyRef, publicKey ed25519.PublicKey) {
	t.Helper()
	path, err := farmClientIdentityFilePath(stateRoot, ref)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(path)
	if err != nil || len(ciphertext) == 0 {
		t.Fatalf("DPAPI ciphertext is unavailable: %v", err)
	}
	if bytes.Contains(ciphertext, publicKey) {
		t.Fatal("Windows identity ciphertext unexpectedly contains the raw public identity")
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
