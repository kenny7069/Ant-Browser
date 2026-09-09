//go:build windows

package backend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestWriteFarmClientUpdateStateRetriesWindowsSharingViolation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "updates")
	path := filepath.Join(directory, "health")
	if err := writeFarmClientUpdateState(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		_ = locked.Close()
		close(released)
	}()
	if err := writeFarmClientUpdateState(path, []byte("second"), 0o600); err != nil {
		t.Fatalf("replace after transient sharing violation: %v", err)
	}
	<-released
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "second" {
		t.Fatalf("published state=%q err=%v", raw, err)
	}
	assertNoFarmClientUpdateTemporaryState(t, directory)
}

func TestWriteFarmClientUpdateStateBoundsWindowsSharingViolation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "updates")
	path := filepath.Join(directory, "activation.json")
	if err := writeFarmClientUpdateState(path, []byte("stable"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	started := time.Now()
	err = writeFarmClientUpdateState(path, []byte("pending"), 0o600)
	if !errors.Is(err, ErrFarmClientUpdateApply) ||
		(!errors.Is(err, windows.ERROR_SHARING_VIOLATION) && !errors.Is(err, windows.ERROR_LOCK_VIOLATION)) {
		t.Fatalf("bounded sharing violation err=%v", err)
	}
	if elapsed := time.Since(started); elapsed < farmClientUpdateWindowsReplaceRetryWindow || elapsed > 2*time.Second {
		t.Fatalf("sharing retry elapsed=%s", elapsed)
	}
	raw, readErr := os.ReadFile(path)
	if readErr != nil || string(raw) != "stable" {
		t.Fatalf("failed replacement changed state=%q err=%v", raw, readErr)
	}
	assertNoFarmClientUpdateTemporaryState(t, directory)
}

func assertNoFarmClientUpdateTemporaryState(t *testing.T, directory string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(directory, ".state-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary state files remained: %v", matches)
	}
}
