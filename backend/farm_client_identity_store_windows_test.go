//go:build windows

package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func TestFarmClientWindowsDPAPINativeOptIn(t *testing.T) {
	if os.Getenv("ANT_FARM_CLIENT_NATIVE_STORE_E2E") != "1" {
		t.Skip("set ANT_FARM_CLIENT_NATIVE_STORE_E2E=1 to exercise current-user DPAPI")
	}
	ref := windowsNativeFarmClientIdentityRef(t)
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
		t.Fatalf("DPAPI round trip failed: %v", err)
	}
	clearBytes(loaded)
}

func windowsNativeFarmClientIdentityRef(t *testing.T) FarmClientIdentityKeyRef {
	t.Helper()
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	ref, err := NewFarmClientIdentityKeyRef("native-e2e-windows-" + hex.EncodeToString(random))
	if err != nil {
		t.Fatal(err)
	}
	return ref
}
