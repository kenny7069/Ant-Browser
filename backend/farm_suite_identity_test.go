package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"testing"
)

type suiteIdentityTestStore struct {
	mu                   sync.Mutex
	keys                 map[FarmClientIdentityKeyRef][]byte
	loadErr              error
	saveErr              error
	persistBeforeSaveErr bool
	missingAfterSave     bool
	saves                int
	deletes              int
}

func newSuiteIdentityTestStore() *suiteIdentityTestStore {
	return &suiteIdentityTestStore{keys: make(map[FarmClientIdentityKeyRef][]byte)}
}

func (store *suiteIdentityTestStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.loadErr != nil {
		return nil, store.loadErr
	}
	raw, ok := store.keys[ref]
	if !ok || store.missingAfterSave {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	return append(ed25519.PrivateKey(nil), raw...), nil
}

func (store *suiteIdentityTestStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	store.saves++
	key, seed, err := normalizeFarmClientIdentityKey(raw)
	if seed != nil {
		clearBytes(seed)
	}
	if err != nil {
		return err
	}
	if store.saveErr == nil || store.persistBeforeSaveErr {
		store.keys[ref] = append([]byte(nil), key...)
	}
	clearBytes(key)
	return store.saveErr
}

func (store *suiteIdentityTestStore) Delete(FarmClientIdentityKeyRef) error {
	store.mu.Lock()
	store.deletes++
	store.mu.Unlock()
	return errors.New("delete must not be called")
}

type suiteIdentityFixture struct {
	suiteTransportFixture
	store *suiteIdentityTestStore
}

func newSuiteIdentityFixture(t *testing.T) suiteIdentityFixture {
	t.Helper()
	fixture := newSuiteTransportFixture(t)
	if _, err := runSuiteCanonicalTransportWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteTransportTestDependencies(fixture.discovery)); err != nil {
		t.Fatal(err)
	}
	return suiteIdentityFixture{suiteTransportFixture: fixture, store: newSuiteIdentityTestStore()}
}

func suiteIdentityTestDependencies(store FarmClientIdentityStore) suiteCanonicalIdentityDependencies {
	stage := suiteStageTestDependencies()
	return suiteCanonicalIdentityDependencies{
		NewStore:          func(string) (FarmClientIdentityStore, error) { return store, nil },
		Random:            bytes.NewReader(bytes.Repeat([]byte{0x5a}, ed25519.SeedSize)),
		ValidateInstall:   stage.ValidateInstall,
		AcquireInstance:   func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:    func(string) error { return nil },
		EnsureApplication: ensureSuiteConfigDraftApplicationRoot,
		SaveReceipt:       saveSuiteIdentityReceipt, SaveCheckpoint: SaveSetupCheckpoint,
	}
}

func TestSuiteCanonicalIdentityCreatesAndConfirmsSameKey(t *testing.T) {
	fixture := newSuiteIdentityFixture(t)
	deps := suiteIdentityTestDependencies(fixture.store)
	var first SuiteCanonicalIdentityResult
	for attempt := 0; attempt < 2; attempt++ {
		result, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
		if err != nil || result.Stage != SetupIdentityReady || result.RequestUID != fixture.preparation.RequestUID || !validLowerSHA256(result.PublicKeySHA256) {
			t.Fatalf("attempt=%d result=%+v err=%v", attempt, result, err)
		}
		if attempt == 0 {
			first = result
		} else if result != first {
			t.Fatalf("identity changed: first=%+v second=%+v", first, result)
		}
	}
	if fixture.store.saves != 1 {
		t.Fatalf("identity regenerated: saves=%d", fixture.store.saves)
	}
	receipt, err := LoadSuiteIdentityReceipt(fixture.roots)
	if err != nil || receipt == nil || receipt.IdentityRef != first.IdentityRef || receipt.PublicKeySHA256 != first.PublicKeySHA256 || receipt.StoreKind != suiteIdentityStoreKind {
		t.Fatalf("receipt=%+v err=%v", receipt, err)
	}
	assertSuiteTransportCheckpoint(t, fixture.suiteTransportFixture, SetupIdentityReady)
	assertSuiteIdentityNoLaterArtifacts(t, fixture)
}

func TestSuiteCanonicalIdentityProductionIsClosedOffWindows(t *testing.T) {
	production := suiteCanonicalIdentityProductionDependencies()
	if reflect.ValueOf(production.NewStore).Pointer() != reflect.ValueOf(NewFarmClientIdentityStore).Pointer() || production.Random == nil || production.ValidateInstall == nil {
		t.Fatal("production identity dependencies are not fixed")
	}
	if runtime.GOOS == "windows" {
		t.Skip("native Windows DPAPI/install evidence not run")
	}
	fixture := newSuiteIdentityFixture(t)
	if _, err := RunSuiteCanonicalIdentity(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source); !errors.Is(err, ErrSuiteCanonicalIdentity) {
		t.Fatalf("unsupported production platform err=%v", err)
	}
	if receipt, _ := LoadSuiteIdentityReceipt(fixture.roots); receipt != nil {
		t.Fatal("off-Windows production wrote identity receipt")
	}
	assertSuiteTransportCheckpoint(t, fixture.suiteTransportFixture, SetupTransportVerified)
}

func TestSuiteCanonicalIdentityRecoversPersistedSaveAndCheckpointFaults(t *testing.T) {
	t.Run("store committed then returned error", func(t *testing.T) {
		fixture := newSuiteIdentityFixture(t)
		fixture.store.saveErr = errors.New("commit unknown")
		fixture.store.persistBeforeSaveErr = true
		deps := suiteIdentityTestDependencies(fixture.store)
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("commit-unknown save reported success")
		}
		fixture.store.saveErr = nil
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err != nil {
			t.Fatalf("persisted identity was not recovered: %v", err)
		}
		if fixture.store.saves != 1 {
			t.Fatalf("persisted identity was regenerated: saves=%d", fixture.store.saves)
		}
		if fixture.store.deletes != 0 {
			t.Fatalf("persisted identity was deleted: deletes=%d", fixture.store.deletes)
		}
	})
	t.Run("receipt durable checkpoint failed", func(t *testing.T) {
		fixture := newSuiteIdentityFixture(t)
		deps := suiteIdentityTestDependencies(fixture.store)
		deps.SaveCheckpoint = func(string, SetupCheckpoint) error { return errors.New("injected") }
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("checkpoint fault reported success")
		}
		if receipt, err := LoadSuiteIdentityReceipt(fixture.roots); err != nil || receipt == nil {
			t.Fatalf("durable receipt missing: %+v %v", receipt, err)
		}
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err != nil {
			t.Fatalf("checkpoint recovery: %v", err)
		}
	})
	t.Run("empty receipt birth recovered", func(t *testing.T) {
		fixture := newSuiteIdentityFixture(t)
		deps := suiteIdentityTestDependencies(fixture.store)
		deps.SaveReceipt = func(roots SuiteUserRoots, _ SuiteIdentityReceipt) error {
			file, err := openSuiteTransportReceiptHandle(filepath.Join(roots.AgentState, SuiteIdentityReceiptName), true)
			if err == nil {
				_ = file.Close()
			}
			return errors.New("injected receipt crash")
		}
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
			t.Fatal("receipt birth fault reported success")
		}
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err != nil {
			t.Fatalf("empty receipt recovery: %v", err)
		}
		if fixture.store.saves != 1 {
			t.Fatalf("receipt recovery regenerated identity: saves=%d", fixture.store.saves)
		}
	})
}

func TestSuiteIdentityReceiptHandleRechecksCreateAndRecoveryBytes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows handle/DACL evidence not run")
	}
	for _, recovery := range []bool{false, true} {
		t.Run(map[bool]string{false: "create", true: "recovery"}[recovery], func(t *testing.T) {
			fixture := newSuiteIdentityFixture(t)
			path := filepath.Join(fixture.roots.AgentState, SuiteIdentityReceiptName)
			if recovery {
				if err := os.WriteFile(path, []byte(`{"x":`), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			changed := []byte(`{"secret":"keep"}`)
			deps := suiteIdentityTestDependencies(fixture.store)
			deps.SaveReceipt = func(roots SuiteUserRoots, receipt SuiteIdentityReceipt) error {
				return saveSuiteIdentityReceiptWithDependencies(roots, receipt, suiteIdentityReceiptSaveDependencies{
					Open: openSuiteTransportReceiptHandle, Write: writeSuiteTransportReceiptHandle,
					AfterOpen: func(file *os.File) error {
						if err := file.Truncate(0); err != nil {
							return err
						}
						if _, err := file.Seek(0, 0); err != nil {
							return err
						}
						if _, err := file.Write(changed); err != nil {
							return err
						}
						return file.Chmod(0o400)
					},
				})
			}
			if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("receipt same-handle drift accepted")
			}
			if raw, err := os.ReadFile(path); err != nil || string(raw) != string(changed) {
				t.Fatalf("receipt drift mutated=%q err=%v", raw, err)
			}
			if info, err := os.Lstat(path); err != nil || info.Mode().Perm() != 0o400 {
				t.Fatalf("receipt security mutated before byte recheck: info=%v err=%v", info, err)
			}
			assertSuiteTransportCheckpoint(t, fixture.suiteTransportFixture, SetupTransportVerified)
		})
	}
}

func TestSuiteCanonicalIdentityRejectsStoreAndRandomFailures(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*suiteIdentityFixture, *suiteCanonicalIdentityDependencies)
	}{
		{"store unavailable", func(f *suiteIdentityFixture, _ *suiteCanonicalIdentityDependencies) {
			f.store.loadErr = ErrFarmClientIdentityStoreUnavailable
		}},
		{"missing after save", func(f *suiteIdentityFixture, _ *suiteCanonicalIdentityDependencies) { f.store.missingAfterSave = true }},
		{"random short read", func(_ *suiteIdentityFixture, d *suiteCanonicalIdentityDependencies) {
			d.Random = bytes.NewReader([]byte{1})
		}},
		{"instance locked", func(_ *suiteIdentityFixture, d *suiteCanonicalIdentityDependencies) {
			d.AcquireInstance = func(string) (suitePrecheckInstanceLock, error) { return nil, errors.New("locked") }
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSuiteIdentityFixture(t)
			deps := suiteIdentityTestDependencies(fixture.store)
			test.edit(&fixture, &deps)
			if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps); err == nil {
				t.Fatal("fault accepted")
			}
			assertSuiteTransportCheckpoint(t, fixture.suiteTransportFixture, SetupTransportVerified)
		})
	}
}

func TestSuiteIdentityReceiptClosedAndKeyDriftFailClosed(t *testing.T) {
	fixture := newSuiteIdentityFixture(t)
	if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(fixture.roots.AgentState, SuiteIdentityReceiptName)
	for _, raw := range [][]byte{[]byte(`{"schema_version":1,"schema_version":1}`), []byte(`{"secret":"x"}`), []byte(`[]`), bytes.Repeat([]byte("x"), suiteIdentityReceiptMaxBytes+1)} {
		if err := writeOwnerAtomic(path, raw); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSuiteIdentityReceipt(fixture.roots); err == nil {
			t.Fatalf("closed receipt accepted %q", raw[:min(len(raw), 40)])
		}
	}

	fixture = newSuiteIdentityFixture(t)
	result, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store))
	if err != nil {
		t.Fatal(err)
	}
	ref, _ := NewFarmClientIdentityKeyRef(result.IdentityRef)
	fixture.store.mu.Lock()
	fixture.store.keys[ref] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
	fixture.store.mu.Unlock()
	if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err == nil {
		t.Fatal("key drift accepted")
	}
}

func TestSuiteCanonicalIdentityRejectsChainAndStoredKeyCorruption(t *testing.T) {
	t.Run("transport drift before store", func(t *testing.T) {
		fixture := newSuiteIdentityFixture(t)
		path := filepath.Join(fixture.roots.AgentState, SuiteTransportReceiptName)
		if err := writeOwnerAtomic(path, []byte(`{"schema_version":1,"unknown":true}`)); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err == nil {
			t.Fatal("transport drift accepted")
		}
		if fixture.store.saves != 0 {
			t.Fatal("identity saved before chain validation")
		}
	})
	t.Run("corrupt existing key", func(t *testing.T) {
		fixture := newSuiteIdentityFixture(t)
		transport, _ := LoadSuiteTransportReceipt(fixture.roots, fixture.bootstrap)
		ref, _ := suiteBootstrapEnrollmentIdentityRef(transport.DeploymentUID, fixture.preparation.RequestUID)
		fixture.store.keys[ref] = []byte("short")
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err == nil {
			t.Fatal("corrupt stored key accepted")
		}
		if fixture.store.saves != 0 {
			t.Fatal("corrupt key was rotated")
		}
	})
}

func TestSuiteCanonicalIdentityRejectsEnrollmentAttemptFootprint(t *testing.T) {
	for _, name := range []string{SuiteBootstrapEnrollmentAttemptName, SuiteBootstrapEnrollmentAttemptName + ".bak", "setup-enrollment-attempt.lock"} {
		fixture := newSuiteIdentityFixture(t)
		if err := os.WriteFile(filepath.Join(fixture.roots.AgentState, name), []byte("foreign"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err == nil {
			t.Fatalf("later artifact %s accepted", name)
		}
		if fixture.store.saves != 0 {
			t.Fatalf("identity saved before rejecting %s", name)
		}
	}
}

func TestSuiteIdentityStoreArtifactRequiresExactOwnerOnlyShape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows DACL evidence not run")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ref, err := NewFarmClientIdentityKeyRef("suite-v3-" + string(bytes.Repeat([]byte("a"), 64)))
	if err != nil {
		t.Fatal(err)
	}
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil || os.Mkdir(filepath.Dir(path), 0o700) != nil || os.WriteFile(path, []byte("opaque"), 0o600) != nil {
		t.Fatalf("fixture: path=%s err=%v", path, err)
	}
	if err := validateSuiteIdentityStoreDirectory(filepath.Dir(path), root, ref); err != nil {
		t.Fatalf("exact store artifact rejected: %v", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := validateSuiteIdentityStoreDirectory(filepath.Dir(path), root, ref); err == nil {
		t.Fatal("insecure store directory accepted")
	}
}

func TestSuiteCanonicalIdentityHundredCallers(t *testing.T) {
	fixture := newSuiteIdentityFixture(t)
	deps := suiteIdentityTestDependencies(fixture.store)
	var wait sync.WaitGroup
	results := make(chan error, 100)
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, deps)
			results <- err
		}()
	}
	wait.Wait()
	close(results)
	wins := 0
	for err := range results {
		if err == nil {
			wins++
		} else if !errors.Is(err, ErrSuiteSetupLocked) {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if wins == 0 || fixture.store.saves != 1 {
		t.Fatalf("wins=%d saves=%d", wins, fixture.store.saves)
	}
	assertSuiteTransportCheckpoint(t, fixture.suiteTransportFixture, SetupIdentityReady)
}

func assertSuiteIdentityNoLaterArtifacts(t *testing.T, fixture suiteIdentityFixture) {
	t.Helper()
	for _, name := range []string{SuiteBootstrapEnrollmentAttemptName, SuiteBootstrapEnrollmentAttemptName + ".bak", SuiteClientConfigName, SuiteOwnershipHandoffName, SuiteActivationJournalName} {
		root := fixture.roots.AgentState
		if name == SuiteClientConfigName {
			root = fixture.roots.Config
		}
		if _, err := os.Lstat(filepath.Join(root, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact %s exists: %v", name, err)
		}
	}
}
