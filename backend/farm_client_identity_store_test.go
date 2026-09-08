package backend

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeFarmClientIdentityStore struct {
	mu   sync.Mutex
	keys map[FarmClientIdentityKeyRef][]byte
	err  error
}

func (s *fakeFarmClientIdentityStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	if s.err != nil {
		return nil, s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	seed, ok := s.keys[ref]
	if !ok {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	key, _, err := normalizeFarmClientIdentityKey(seed)
	return key, err
}

func (s *fakeFarmClientIdentityStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	if s.err != nil {
		return s.err
	}
	_, seed, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	defer clearBytes(seed)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.keys[ref]; ok {
		if equalBytes(existing, seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	}
	s.keys[ref] = append([]byte(nil), seed...)
	return nil
}

func (s *fakeFarmClientIdentityStore) Delete(ref FarmClientIdentityKeyRef) error {
	if s.err != nil {
		return s.err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, ref)
	return nil
}

func TestFarmClientIdentityKeyRefValidation(t *testing.T) {
	if valid, err := NewFarmClientIdentityKeyRef("node-a/device-key"); err == nil || valid != "" {
		t.Fatal("path-like key reference accepted")
	}
	values := []string{"", " ", strings.Repeat("a", farmClientIdentityMaxRefLen+1), "node" + string(rune(92)) + "key"}
	values = append(values, "node"+string([]byte{0})+"key")
	for _, value := range values {
		if _, err := NewFarmClientIdentityKeyRef(value); !errors.Is(err, ErrFarmClientIdentityKeyRef) {
			t.Fatalf("key ref %q error = %v", value, err)
		}
	}
	ref, err := NewFarmClientIdentityKeyRef(" node-a ")
	if err != nil || ref != "node-a" {
		t.Fatalf("trimmed key ref = %q, err=%v", ref, err)
	}
}

func TestFarmClientIdentityFakeRoundTripOverwriteDelete(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(index + 1)
	}
	ref, _ := NewFarmClientIdentityKeyRef("node-a")
	store := &fakeFarmClientIdentityStore{keys: make(map[FarmClientIdentityKeyRef][]byte)}
	if err := store.Save(ref, seed); err != nil {
		t.Fatal(err)
	}
	key, err := store.Load(ref)
	if err != nil || len(key) != ed25519.PrivateKeySize || !equalBytes(key[:ed25519.SeedSize], seed) {
		t.Fatalf("round trip key len=%d err=%v", len(key), err)
	}
	clearBytes(key)
	if err := store.Save(ref, seed); err != nil {
		t.Fatalf("same-key retry: %v", err)
	}
	other := append([]byte(nil), seed...)
	other[0] ^= 0xff
	if err := store.Save(ref, other); !errors.Is(err, ErrFarmClientIdentityKeyConflict) {
		t.Fatalf("different-key overwrite error = %v", err)
	}
	if err := store.Delete(ref); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(ref); !errors.Is(err, ErrFarmClientIdentityKeyNotFound) {
		t.Fatalf("deleted key error = %v", err)
	}
}

func TestFarmClientIdentityRejectsCorruptAndWrongLength(t *testing.T) {
	ref, _ := NewFarmClientIdentityKeyRef("node-a")
	store := &fakeFarmClientIdentityStore{keys: make(map[FarmClientIdentityKeyRef][]byte)}
	for _, key := range [][]byte{nil, make([]byte, 31), make([]byte, 33), make([]byte, 63)} {
		if err := store.Save(ref, key); !errors.Is(err, ErrFarmClientIdentityKeyCorrupt) {
			t.Fatalf("length %d error = %v", len(key), err)
		}
	}
	badExpanded := make([]byte, ed25519.PrivateKeySize)
	if err := store.Save(ref, badExpanded); !errors.Is(err, ErrFarmClientIdentityKeyCorrupt) {
		t.Fatalf("bad expanded key error = %v", err)
	}
}

func TestFarmClientIdentityConcurrentFirstSaveIsIdempotent(t *testing.T) {
	seed := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	ref, _ := NewFarmClientIdentityKeyRef("node-concurrent")
	store := &fakeFarmClientIdentityStore{keys: make(map[FarmClientIdentityKeyRef][]byte)}
	const writers = 32
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
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent same-key save error = %v", err)
		}
	}
}

func TestFarmClientIdentityStableErrorsNeverLeakNativeCanary(t *testing.T) {
	canary := "private-key-canary /secret/path native failure token=canary"
	for _, err := range []error{
		farmClientIdentityStoreError(fmt.Errorf("%s", canary)),
		farmClientIdentityStableError(fmt.Errorf("%s", canary)),
	} {
		if strings.Contains(err.Error(), "canary") || strings.Contains(err.Error(), "/secret/path") {
			t.Fatalf("stable error leaked native details: %q", err)
		}
	}
}
