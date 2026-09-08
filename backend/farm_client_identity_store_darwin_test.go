//go:build darwin && cgo

package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func TestFarmClientDarwinKeychainNativeOptIn(t *testing.T) {
	if os.Getenv("ANT_FARM_CLIENT_NATIVE_STORE_E2E") != "1" {
		t.Skip("set ANT_FARM_CLIENT_NATIVE_STORE_E2E=1 to exercise the current user's Keychain")
	}
	ref := randomNativeFarmClientIdentityRef(t, "darwin")
	store, err := NewFarmClientIdentityStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Delete(ref) })
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := store.Save(ref, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ref)
	if err != nil || !equalBytes(loaded, key) {
		t.Fatalf("Keychain round trip failed: %v", err)
	}
	clearBytes(loaded)
}

func randomNativeFarmClientIdentityRef(t *testing.T, platform string) FarmClientIdentityKeyRef {
	t.Helper()
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	ref, err := NewFarmClientIdentityKeyRef("native-e2e-" + platform + "-" + hex.EncodeToString(random))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
