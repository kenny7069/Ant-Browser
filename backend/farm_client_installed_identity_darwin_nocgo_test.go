//go:build darwin && !cgo

package backend

import (
	"crypto/ed25519"
	"testing"
)

func assertC8NativeIdentityBackend(t *testing.T, _ string, _ FarmClientIdentityKeyRef, _ ed25519.PublicKey) {
	t.Helper()
	t.Fatal("native macOS Keychain evidence requires CGO")
}

func cleanupC8NativeIdentity(t *testing.T, _ string, _ FarmClientIdentityKeyRef) {
	t.Helper()
	t.Fatal("native macOS Keychain cleanup requires CGO")
}
