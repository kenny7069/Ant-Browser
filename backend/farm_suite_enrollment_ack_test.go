package backend

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func newSuiteEnrollmentACKFixture(t *testing.T) suiteIdentityFixture {
	t.Helper()
	fixture := newSuiteIdentityFixture(t)
	if _, err := runSuiteCanonicalIdentityWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteIdentityTestDependencies(fixture.store)); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func suiteEnrollmentACKSuccessResponse(discovery SuiteBootstrapDiscovery, state string) *http.Response {
	raw, _ := json.Marshal(suiteBootstrapEnrollmentResponse{NodeUID: "node-accepted-by-server", EnrollmentState: state, ControlEndpoint: discovery.ControlEndpoint})
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}
}

func suiteEnrollmentACKDependencies(fixture suiteIdentityFixture, roundTrip suiteEnrollmentRoundTripper) suiteCanonicalEnrollmentACKDependencies {
	stage := suiteStageTestDependencies()
	return suiteCanonicalEnrollmentACKDependencies{
		CurrentSuiteVersion: "3.0.0",
		Fetch:               func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) { return fixture.discovery, nil },
		NewStore:            func(string) (FarmClientIdentityStore, error) { return fixture.store, nil },
		Client:              &http.Client{Transport: roundTrip},
		ValidateInstall:     stage.ValidateInstall,
		AcquireInstance:     func(string) (suitePrecheckInstanceLock, error) { return &suitePrecheckTestLock{}, nil },
		SecureInstance:      func(string) error { return nil },
		EnsureApplication:   ensureSuiteConfigDraftApplicationRoot,
	}
}

func TestSuiteCanonicalEnrollmentACKRefetchesAndKeepsIdentityCheckpoint(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	checkpointBytes := make(map[string][]byte)
	for _, path := range []string{fixture.bootstrap.StatePath, fixture.bootstrap.StatePath + ".bak"} {
		raw, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatal(err)
		}
		checkpointBytes[path] = raw
	}
	var fetches, posts atomic.Int32
	deps := suiteEnrollmentACKDependencies(fixture, func(request *http.Request) (*http.Response, error) {
		posts.Add(1)
		if request.Header.Get("Idempotency-Key") == "" {
			t.Fatal("missing idempotency key")
		}
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		fetches.Add(1)
		return fixture.discovery, nil
	}
	code := suiteEnrollmentCode(0x51)
	first, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, code, deps)
	if err != nil || first.EnrollmentState != "ENROLLED" {
		t.Fatalf("first=%+v err=%v", first, err)
	}
	second, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, "", deps)
	if err != nil || second != first {
		t.Fatalf("second=%+v err=%v", second, err)
	}
	if fetches.Load() != 2 || posts.Load() != 1 {
		t.Fatalf("fetches=%d posts=%d", fetches.Load(), posts.Load())
	}
	for path, before := range checkpointBytes {
		after, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) || !equalBytes(before, after) {
			t.Fatalf("canonical setup checkpoint artifact changed: %s", path)
		}
	}
	checkpoint, err := LoadSetupCheckpoint(fixture.bootstrap.StatePath)
	if err != nil || checkpoint == nil || checkpoint.Stage != SetupIdentityReady {
		t.Fatalf("checkpoint=%+v err=%v", checkpoint, err)
	}
	for _, path := range []string{filepath.Join(fixture.roots.Config, SuiteClientConfigName), filepath.Join(fixture.roots.AgentState, SuiteOwnershipHandoffName), filepath.Join(fixture.roots.AgentState, SuiteActivationJournalName)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("later artifact exists: %s", path)
		}
	}
}

func TestSuiteCanonicalEnrollmentACKRequiresExistingBoundIdentityAndDiscovery(t *testing.T) {
	t.Run("missing identity", func(t *testing.T) {
		fixture := newSuiteEnrollmentACKFixture(t)
		fixture.store.keys = map[FarmClientIdentityKeyRef][]byte{}
		called := false
		deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
			called = true
			return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
		})
		if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(1), deps); !errors.Is(err, ErrSuiteCanonicalEnrollmentACK) || called || fixture.store.saves != 1 {
			t.Fatalf("err=%v called=%v saves=%d", err, called, fixture.store.saves)
		}
	})
	t.Run("discovery drift", func(t *testing.T) {
		fixture := newSuiteEnrollmentACKFixture(t)
		deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
			t.Fatal("POST after discovery drift")
			return nil, nil
		})
		changed := fixture.discovery
		changed.SupportedCapabilities = append([]string(nil), changed.SupportedCapabilities...)
		changed.SupportedCapabilities[0] = "browser.open"
		deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) { return changed, nil }
		if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(1), deps); !errors.Is(err, ErrSuiteCanonicalEnrollmentACK) {
			t.Fatalf("err=%v", err)
		}
	})
}

func TestSuiteCanonicalEnrollmentACKProductionWiringAndVersionGate(t *testing.T) {
	production := suiteCanonicalEnrollmentACKProductionDependencies()
	if reflect.ValueOf(production.Fetch).Pointer() != reflect.ValueOf(FetchSuiteBootstrapDiscovery).Pointer() || reflect.ValueOf(production.NewStore).Pointer() != reflect.ValueOf(NewFarmClientIdentityStore).Pointer() {
		t.Fatal("production trust dependencies are injectable")
	}
	fixture := newSuiteEnrollmentACKFixture(t)
	deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	deps.CurrentSuiteVersion = "2.9.9"
	called := false
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		called = true
		return fixture.discovery, nil
	}
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(1), deps); !errors.Is(err, ErrSuiteCanonicalEnrollmentACK) || called {
		t.Fatalf("err=%v called=%v", err, called)
	}
}

func TestSuiteCanonicalEnrollmentACKACKLossReusesExactRequest(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	var bodies, keys []string
	deps := suiteEnrollmentACKDependencies(fixture, func(request *http.Request) (*http.Response, error) {
		raw, _ := io.ReadAll(request.Body)
		bodies = append(bodies, string(raw))
		keys = append(keys, request.Header.Get("Idempotency-Key"))
		if len(bodies) < 3 {
			return nil, errors.New("ack lost")
		}
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ALREADY_ENROLLED"), nil
	})
	result, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x52), deps)
	if err != nil || result.EnrollmentState != "ALREADY_ENROLLED" || len(bodies) != 3 || bodies[0] != bodies[1] || bodies[1] != bodies[2] || keys[0] == "" || keys[0] != keys[1] || keys[1] != keys[2] || strings.Contains(bodies[0], fixture.bootstrap.ServerURL) {
		t.Fatalf("result=%+v err=%v bodies=%d keys=%v", result, err, len(bodies), keys)
	}
}

func TestSuiteCanonicalEnrollmentACKRevalidatesIdentityAfterResponse(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		fixture.store.mu.Lock()
		for ref := range fixture.store.keys {
			fixture.store.keys[ref] = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, ed25519.SeedSize))
		}
		fixture.store.mu.Unlock()
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x53), deps); !errors.Is(err, ErrSuiteBootstrapEnrollmentIdentity) {
		t.Fatalf("identity drift err=%v", err)
	}
	attempt, err := loadSuiteBootstrapEnrollmentAttempt(fixture.roots)
	if err != nil || attempt == nil || attempt.Stage != SuiteBootstrapRequestReady {
		t.Fatalf("attempt=%+v err=%v", attempt, err)
	}
}

func TestSuiteCanonicalEnrollmentACKHundredCallersUseLocks(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	var wait sync.WaitGroup
	results := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x54), deps)
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
	if wins == 0 {
		t.Fatal("no caller completed enrollment")
	}
}

func TestSuiteCanonicalEnrollmentACKActiveAttemptLockStopsStoreAndNetwork(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	held, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteBootstrapEnrollmentLockName))
	if err != nil {
		t.Fatal(err)
	}
	defer held.release()
	var stores, fetches, posts atomic.Int32
	deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		posts.Add(1)
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	deps.AcquireInstance = func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) }
	deps.NewStore = func(string) (FarmClientIdentityStore, error) { stores.Add(1); return fixture.store, nil }
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		fetches.Add(1)
		return fixture.discovery, nil
	}
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x55), deps); !errors.Is(err, ErrSuiteSetupLocked) {
		t.Fatalf("err=%v", err)
	}
	if stores.Load()+fetches.Load()+posts.Load() != 0 {
		t.Fatalf("store=%d fetch=%d post=%d", stores.Load(), fetches.Load(), posts.Load())
	}
	setup, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName))
	if err != nil {
		t.Fatalf("setup lock leaked: %v", err)
	}
	setup.release()
	instance, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState)
	if err != nil {
		t.Fatalf("instance lock leaked: %v", err)
	}
	instance.Release()
}

func TestSuiteCanonicalEnrollmentACKHoldsAllLocksAcrossExternalSteps(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	deps := suiteEnrollmentACKDependencies(fixture, nil)
	deps.AcquireInstance = func(root string) (suitePrecheckInstanceLock, error) { return AcquireFarmClientInstanceLock(root) }
	assertHeld := func() error {
		if lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteSetupLockName)); err == nil {
			lock.release()
			return errors.New("setup lock not held")
		}
		if lock, err := AcquireFarmClientInstanceLock(fixture.roots.AgentState); err == nil {
			lock.Release()
			return errors.New("instance lock not held")
		}
		if lock, err := acquireSuiteSetupLock(filepath.Join(fixture.roots.AgentState, suiteBootstrapEnrollmentLockName)); err == nil {
			lock.release()
			return errors.New("attempt lock not held")
		}
		return nil
	}
	deps.Fetch = func(context.Context, BootstrapConfig) (SuiteBootstrapDiscovery, error) {
		if err := assertHeld(); err != nil {
			return SuiteBootstrapDiscovery{}, err
		}
		return fixture.discovery, nil
	}
	deps.Client = &http.Client{Transport: suiteEnrollmentRoundTripper(func(*http.Request) (*http.Response, error) {
		if err := assertHeld(); err != nil {
			return nil, err
		}
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})}
	deps.AfterResponse = assertHeld
	deps.BeforeFinalReadback = assertHeld
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x56), deps); err != nil {
		t.Fatal(err)
	}
}

func TestSuiteCanonicalEnrollmentACKFinalReadbackRejectsReplacement(t *testing.T) {
	fixture := newSuiteEnrollmentACKFixture(t)
	deps := suiteEnrollmentACKDependencies(fixture, func(*http.Request) (*http.Response, error) {
		return suiteEnrollmentACKSuccessResponse(fixture.discovery, "ENROLLED"), nil
	})
	deps.BeforeFinalReadback = func() error {
		attempt, err := loadSuiteBootstrapEnrollmentAttempt(fixture.roots)
		if err != nil || attempt == nil {
			return errors.New("missing attempt")
		}
		attempt.NodeUID = "different-node"
		return writeSuiteBootstrapEnrollmentAttemptFile(filepath.Join(fixture.roots.AgentState, SuiteBootstrapEnrollmentAttemptName), *attempt)
	}
	if _, err := runSuiteCanonicalEnrollmentACKWithDependencies(context.Background(), fixture.bootstrap, fixture.roots, fixture.release, fixture.source, suiteEnrollmentCode(0x57), deps); err == nil {
		t.Fatal("replaced final attempt accepted")
	}
}
