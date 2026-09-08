//go:build linux

package backend

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	keyring "github.com/zalando/go-keyring"
)

func TestFarmClientLinuxIdentityFileFallbackPermissionsAndCorruption(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-node")
	seed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store, err := NewFarmClientIdentityStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ref, seed); err != nil {
		t.Fatal(err)
	}
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != farmClientIdentityFileMode {
		t.Fatalf("identity file mode = %o, want %o", info.Mode().Perm(), farmClientIdentityFileMode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != farmClientIdentityDirMode {
		t.Fatalf("identity directory mode = %o, want %o", dirInfo.Mode().Perm(), farmClientIdentityDirMode)
	}
	loaded, err := store.Load(ref)
	if err != nil || !equalBytes(loaded[:ed25519.SeedSize], seed[:ed25519.SeedSize]) {
		t.Fatalf("load error=%v key match=%v", err, loaded != nil && equalBytes(loaded[:ed25519.SeedSize], seed[:ed25519.SeedSize]))
	}
	clearBytes(loaded)
	if err := os.WriteFile(path, []byte("short"), farmClientIdentityFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); !errors.Is(err, ErrFarmClientIdentityKeyCorrupt) {
		t.Fatalf("corrupt file error = %v", err)
	}
}

func TestFarmClientLinuxIdentityFileRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-symlink")
	store, err := NewFarmClientIdentityStore(root)
	if err != nil {
		t.Fatal(err)
	}
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), farmClientIdentityDirMode); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, make([]byte, ed25519.SeedSize), farmClientIdentityFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); !errors.Is(err, ErrFarmClientIdentityKeyCorrupt) {
		t.Fatalf("symlink load error = %v", err)
	}
}

func TestFarmClientLinuxIdentityFileConcurrentFirstSaveAndConflict(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-race")
	seed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	store, err := NewFarmClientIdentityStore(root)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 24
	errs := make(chan error, writers)
	var group sync.WaitGroup
	for index := 0; index < writers; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			errs <- store.Save(ref, seed)
		}()
	}
	group.Wait()
	close(errs)
	for saveErr := range errs {
		if saveErr != nil {
			t.Fatalf("same-key concurrent save error = %v", saveErr)
		}
	}
	different := ed25519.NewKeyFromSeed(bytesWithByte(0x42))
	if err := store.Save(ref, different); !errors.Is(err, ErrFarmClientIdentityKeyConflict) {
		t.Fatalf("different-key overwrite error = %v", err)
	}
}

func TestFarmClientLinuxNativeSecretServiceSeamAndFallback(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-native")
	seed := ed25519.NewKeyFromSeed(bytesWithByte(0x11))
	native := &linuxNativeIdentityFake{err: ErrFarmClientIdentityStoreUnsupported}
	store, err := NewFarmClientIdentityStoreWithNative(root, native)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(ref, seed); err != nil {
		t.Fatal(err)
	}
	if native.saves != 1 {
		t.Fatalf("native save count = %d, want one attempt", native.saves)
	}
	loaded, err := store.Load(ref)
	if err != nil || !equalBytes(loaded[:ed25519.SeedSize], seed[:ed25519.SeedSize]) {
		t.Fatalf("fallback load error = %v", err)
	}
	clearBytes(loaded)
}

func TestFarmClientLinuxNativeDoesNotSupersedeFallbackIdentity(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-fallback-migration")
	fallbackKey := ed25519.NewKeyFromSeed(bytesWithByte(0x21))
	if err := linuxFarmClientIdentityFileSave(root, ref, fallbackKey[:ed25519.SeedSize]); err != nil {
		t.Fatal(err)
	}
	native := &linuxNativeIdentityFake{err: ErrFarmClientIdentityKeyNotFound}
	store, err := NewFarmClientIdentityStoreWithNative(root, native)
	if err != nil {
		t.Fatal(err)
	}
	different := ed25519.NewKeyFromSeed(bytesWithByte(0x22))
	if err := store.Save(ref, different); !errors.Is(err, ErrFarmClientIdentityKeyConflict) {
		t.Fatalf("different key replaced fallback identity: %v", err)
	}
	if native.saves != 0 {
		t.Fatalf("native store was written before fallback conflict check: %d", native.saves)
	}
}

func TestFarmClientLinuxSecretServiceRoundTripConflictAndErrors(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	values := make(map[string]string)
	store := &linuxFarmClientSecretServiceStore{
		get: func(service, user string) (string, error) {
			value, ok := values[service+"\x00"+user]
			if !ok {
				return "", keyring.ErrNotFound
			}
			return value, nil
		},
		set: func(service, user, value string) error {
			values[service+"\x00"+user] = value
			return nil
		},
		delete: func(service, user string) error {
			key := service + "\x00" + user
			if _, ok := values[key]; !ok {
				return keyring.ErrNotFound
			}
			delete(values, key)
			return nil
		},
	}
	ref, _ := NewFarmClientIdentityKeyRef("secret-service-node")
	key := ed25519.NewKeyFromSeed(bytesWithByte(0x33))
	if err := store.Save(ref, key); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load(ref)
	if err != nil || !equalBytes(loaded, key) {
		t.Fatalf("secret service round trip err=%v", err)
	}
	clearBytes(loaded)
	if err := store.Save(ref, key); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	if err := store.Save(ref, ed25519.NewKeyFromSeed(bytesWithByte(0x44))); !errors.Is(err, ErrFarmClientIdentityKeyConflict) {
		t.Fatalf("overwrite error=%v", err)
	}
	values[linuxFarmClientSecretServiceName+"\x00"+string(ref)] = base64.StdEncoding.EncodeToString([]byte("short"))
	if _, err := store.Load(ref); !errors.Is(err, ErrFarmClientIdentityKeyCorrupt) {
		t.Fatalf("corrupt secret service key error=%v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatalf("idempotent delete: %v", err)
	}
}

func TestFarmClientLinuxLockedNativeStoreFailsClosedWithoutFallback(t *testing.T) {
	root := t.TempDir()
	ref, _ := NewFarmClientIdentityKeyRef("linux-locked")
	native := &linuxNativeIdentityFake{err: ErrFarmClientIdentityStoreUnavailable}
	store, err := NewFarmClientIdentityStoreWithNative(root, native)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytesWithByte(0x55))
	if err := store.Save(ref, key); !errors.Is(err, ErrFarmClientIdentityStoreUnavailable) {
		t.Fatalf("locked native store error=%v", err)
	}
	if native.saves != 1 {
		t.Fatalf("native save attempts=%d", native.saves)
	}
	path, _ := farmClientIdentityFilePath(root, ref)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("locked native store created fallback: %v", err)
	}
}

func TestFarmClientLinuxSecretServiceCrossStoreFirstSaveIsAtomic(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	values := make(map[string]string)
	get := func(service, user string) (string, error) {
		value, ok := values[service+"\x00"+user]
		if !ok {
			return "", keyring.ErrNotFound
		}
		return value, nil
	}
	set := func(service, user, value string) error {
		values[service+"\x00"+user] = value
		return nil
	}
	deleteValue := func(service, user string) error {
		delete(values, service+"\x00"+user)
		return nil
	}
	first := &linuxFarmClientSecretServiceStore{get: get, set: set, delete: deleteValue}
	second := &linuxFarmClientSecretServiceStore{get: get, set: set, delete: deleteValue}
	ref, _ := NewFarmClientIdentityKeyRef("cross-store-race")
	keys := [][]byte{
		ed25519.NewKeyFromSeed(bytesWithByte(0x61)),
		ed25519.NewKeyFromSeed(bytesWithByte(0x62)),
	}
	errorsByWriter := make(chan error, 2)
	go func() { errorsByWriter <- first.Save(ref, keys[0]) }()
	go func() { errorsByWriter <- second.Save(ref, keys[1]) }()
	errA, errB := <-errorsByWriter, <-errorsByWriter
	results := []error{errA, errB}
	successes, conflicts := 0, 0
	for _, err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrFarmClientIdentityKeyConflict):
			conflicts++
		default:
			t.Fatalf("unexpected race error: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

type linuxNativeIdentityFake struct {
	err   error
	saves int
}

func (s *linuxNativeIdentityFake) Load(FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	return nil, s.err
}

func (s *linuxNativeIdentityFake) Save(FarmClientIdentityKeyRef, []byte) error {
	s.saves++
	return s.err
}

func (s *linuxNativeIdentityFake) Delete(FarmClientIdentityKeyRef) error {
	return s.err
}

func bytesWithByte(value byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = value
	}
	return seed
}
