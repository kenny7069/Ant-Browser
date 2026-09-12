package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSuiteLauncherValidationFailureLeavesStagedActivationUntouched(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+stateRoot+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-mutation-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	updateRoot, err := farmClientUpdateRoot(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("pending"))
	activation := FarmClientUpdateActivation{Version: 1, Phase: farmClientUpdatePhaseStaged, Pending: &FarmClientUpdateSlot{Version: "1.1.0", Target: "darwin-arm64", SHA256: hex.EncodeToString(digest[:]), Size: 7}}
	if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
		t.Fatal(err)
	}
	launcher, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	validate := func(SuiteUserRoots, string, string) error { return ErrSuiteLauncherRevalidation }
	if err := runFarmClientLauncherWithValidation(context.Background(), configPath, launcher, nil, nil, func(_ SuiteUserRoots, config, executable string) error {
		return validate(SuiteUserRoots{}, config, executable)
	}); !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	loaded, err := LoadFarmClientUpdateActivation(stateRoot)
	if err != nil || loaded.Phase != farmClientUpdatePhaseStaged || loaded.Pending == nil || loaded.Pending.SHA256 != activation.Pending.SHA256 {
		t.Fatalf("activation mutated: %#v err=%v", loaded, err)
	}
}

func TestSuiteLauncherStrictWrapperRejectsBeforeLegacyLauncher(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+filepath.Join(root, "state")+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-wrapper-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(root, "launcher")
	if err := os.WriteFile(launcher, []byte("fixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	called := 0
	validate := func(SuiteUserRoots, string, string) error {
		called++
		return ErrSuiteLauncherRevalidation
	}
	if err := runSuiteFarmClientLauncher(context.Background(), SuiteUserRoots{Config: root}, configPath, launcher, nil, nil, validate); !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	if called != 1 {
		t.Fatalf("strict validator calls=%d, want 1 before legacy launcher", called)
	}
}

func TestSuiteLauncherRevalidatesAtRestartBoundaryBeforeSpawn(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("application_root: "+filepath.Join(root, "app")+"\nstate_root: "+stateRoot+"\ncontrol_url: ws://127.0.0.1:1\nnode_uid: suite-boundary-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := 0
	validate := func(SuiteUserRoots, string, string) error {
		called++
		if called >= 2 {
			return ErrSuiteLauncherRevalidation
		}
		return nil
	}
	ctx := context.Background()
	launcher, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	err = runFarmClientLauncherWithValidation(ctx, configPath, launcher, nil, nil, func(_ SuiteUserRoots, config, launcher string) error {
		return validate(SuiteUserRoots{}, config, launcher)
	})
	if !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("err=%v", err)
	}
	if called != 2 {
		t.Fatalf("strict validator calls=%d, want entry and restart boundary", called)
	}
}
