//go:build linux

package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
)

func TestFarmClientLinuxSecretServiceNativeOptIn(t *testing.T) {
	if os.Getenv("ANT_FARM_CLIENT_NATIVE_STORE_E2E") != "1" {
		t.Skip("set ANT_FARM_CLIENT_NATIVE_STORE_E2E=1 to exercise Secret Service")
	}
	random := make([]byte, 12)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	ref, err := NewFarmClientIdentityKeyRef("native-e2e-linux-" + hex.EncodeToString(random))
	if err != nil {
		t.Fatal(err)
	}
	store := newLinuxFarmClientSecretServiceStore()
	t.Cleanup(func() { _ = store.Delete(ref) })
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	if err := store.Save(ref, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ref)
	if err != nil || !equalBytes(loaded, key) {
		t.Fatalf("Secret Service round trip failed: %v", err)
	}
	clearBytes(loaded)
}
