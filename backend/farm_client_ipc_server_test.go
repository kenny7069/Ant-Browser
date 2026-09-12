package backend

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"ant-chrome/backend/internal/browser"
)

func newFarmClientIPCTestHost(t *testing.T) *FarmClientHost {
	t.Helper()
	root, err := os.MkdirTemp("", "af-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	manager := browser.NewManager(DefaultConfig(), root)
	manager.Profiles["profile-1"] = &browser.Profile{
		ProfileId: "profile-1", ProfileName: "Safe profile", IncarnationID: "incarnation-1",
		CreatedAt: "2026-09-12T00:00:00Z",
	}
	runtimeService := NewBrowserRuntimeService(BrowserRuntimeServiceConfig{
		Manager: manager,
		Config:  DefaultConfig(),
		Host: BrowserRuntimeHost{
			StartProcess:  func(*BrowserRuntimeLaunchPlan) (*BrowserRuntimeProcess, error) { return nil, nil },
			StopProcess:   func(*exec.Cmd) error { return nil },
			DetectRuntime: func(string) (BrowserRuntimeDetection, bool) { return BrowserRuntimeDetection{}, false },
		},
	})
	return &FarmClientHost{config: FarmClientConfig{StateRoot: root}, manager: manager, runtime: runtimeService}
}

func TestFarmClientIPCClientServerListAndStatus(t *testing.T) {
	host := newFarmClientIPCTestHost(t)
	server, err := StartFarmClientIPCServer(host)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := &FarmClientIPCClient{stateRoot: host.config.StateRoot, timeout: time.Second}
	profiles, err := client.ProfileList(context.Background())
	if err != nil || len(profiles) != 1 || profiles[0].ProfileID != "profile-1" {
		t.Fatalf("profiles=%+v err=%v", profiles, err)
	}
	status, err := client.ProfileStatus(context.Background(), "profile-1")
	if err != nil || status.Running || status.ProfileID != "profile-1" {
		t.Fatalf("status=%+v err=%v", status, err)
	}
	raw, _ := json.Marshal(status)
	for _, forbidden := range []string{"userDataDir", "debugPort", "pid", "proxyConfig", "launchArgs"} {
		if string(raw) != "" && containsFoldASCII(string(raw), forbidden) {
			t.Fatalf("status leaked %q: %s", forbidden, raw)
		}
	}
}

func TestFarmClientIPCConcurrentCallsUseOneHost(t *testing.T) {
	host := newFarmClientIPCTestHost(t)
	server, err := StartFarmClientIPCServer(host)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client := &FarmClientIPCClient{stateRoot: host.config.StateRoot, timeout: time.Second}
	var wait sync.WaitGroup
	errorsFound := make(chan error, 100)
	for index := 0; index < 100; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			profiles, err := client.ProfileList(context.Background())
			if err != nil || len(profiles) != 1 {
				errorsFound <- err
			}
		}()
	}
	wait.Wait()
	close(errorsFound)
	for err := range errorsFound {
		t.Fatalf("concurrent call failed: %v", err)
	}
}

func TestFarmClientIPCSlowClientIsBoundedDuringShutdown(t *testing.T) {
	host := newFarmClientIPCTestHost(t)
	host.config.CommandTimeoutMs = 100
	server, err := StartFarmClientIPCServer(host)
	if err != nil {
		t.Fatal(err)
	}
	connection, err := dialFarmClientIPC(context.Background(), host.config.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	started := time.Now()
	if err := server.Close(); err != nil {
		t.Fatalf("bounded close error=%v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("slow client delayed shutdown for %v", elapsed)
	}
}

func TestFarmClientIPCOpenReturnKeepsResidentOwnedProcess(t *testing.T) {
	host := newFarmClientIPCTestHost(t)
	process, command := newStartedRuntimeProcess(t, &blockingRuntimeMonitor{}, nil)
	t.Cleanup(func() {
		if command.Process != nil {
			_ = command.Process.Kill()
		}
		<-process.owner.Done()
	})
	host.manager.Mutex.Lock()
	profile := host.manager.Profiles["profile-1"]
	host.manager.Mutex.Unlock()
	identity := host.runtime.markRunning("profile-1", profile, command, command.Process.Pid, 9222, true, "")
	host.runtime.trackProcess("profile-1", process, identity)
	server, err := StartFarmClientIPCServer(host)
	if err != nil {
		t.Fatal(err)
	}
	client := &FarmClientIPCClient{stateRoot: host.config.StateRoot, timeout: time.Second}
	opened, err := client.ProfileOpen(context.Background(), "profile-1")
	if err != nil || !opened.Running || opened.Generation == 0 {
		t.Fatalf("opened=%+v err=%v", opened, err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.owner.Done():
		t.Fatal("closing CLI/IPC stopped the resident-owned process")
	default:
	}
}

func containsFoldASCII(value, target string) bool {
	if len(target) == 0 {
		return true
	}
	for index := 0; index+len(target) <= len(value); index++ {
		match := true
		for offset := range target {
			left, right := value[index+offset], target[offset]
			if left >= 'A' && left <= 'Z' {
				left += 'a' - 'A'
			}
			if right >= 'A' && right <= 'Z' {
				right += 'a' - 'A'
			}
			if left != right {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
