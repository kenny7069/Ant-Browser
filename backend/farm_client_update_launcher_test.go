package backend

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestFarmClientLauncherSurvivesTwoSuccessorBoundaries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a small child-process fixture")
	}
	root := t.TempDir()
	source := filepath.Join(root, "fixture.go")
	executable := filepath.Join(root, "fixture")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	program := `package main
import "os"
func main() {
	path := os.Getenv("ANT_FARM_LAUNCHER_COUNT_FILE")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil { _, _ = file.Write([]byte("x")); _ = file.Close() }
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", executable, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	countPath := filepath.Join(root, "starts")
	t.Setenv("ANT_FARM_LAUNCHER_COUNT_FILE", countPath)
	config := FarmClientConfig{
		ApplicationRoot: root,
		StateRoot:       filepath.Join(root, "state"),
		ControlURL:      "ws://127.0.0.1:1",
		NodeUID:         "node-launcher-test",
	}
	raw, _ := json.Marshal(config)
	configPath := filepath.Join(root, "client.json")
	if err := os.WriteFile(configPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- RunFarmClientLauncher(ctx, configPath, executable, nil, nil) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		value, _ := os.ReadFile(countPath)
		if len(value) >= 3 {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("launcher exited or stalled after %d child boundaries", len(value))
		}
		time.Sleep(25 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("launcher did not stop after context cancellation")
	}
}

func startFarmClientProbationTestProcess(t *testing.T) *farmClientLauncherProcess {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("process probation fixture uses the POSIX shell")
	}
	command := exec.Command("sh", "-c", "sleep 5")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &farmClientLauncherProcess{command: command, done: make(chan struct{})}
	go func() {
		process.resultMu.Lock()
		process.result = command.Wait()
		process.resultMu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() {
		_ = process.command.Process.Kill()
		select {
		case <-process.done:
		case <-time.After(time.Second):
		}
	})
	return process
}

func TestFarmClientUpdateProbationRequiresContinuousHealth(t *testing.T) {
	process := startFarmClientProbationTestProcess(t)
	stateRoot := t.TempDir()
	healthPath := filepath.Join(stateRoot, "updates", "health")
	config := FarmClientConfig{StateRoot: stateRoot}
	nonce := strings.Repeat("a", 64)
	if err := WriteFarmClientUpdateHealthMarker(config, healthPath, nonce); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		ticker := time.NewTicker(40 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				_ = WriteFarmClientUpdateHealthMarker(config, healthPath, nonce)
			}
		}
	}()
	// The health timeout only bounds the first authenticated marker. Once the
	// marker is live, a longer probation is governed by continuous freshness.
	err := waitFarmClientUpdateProbation(context.Background(), process, healthPath, nonce, 400*time.Millisecond, 700*time.Millisecond)
	close(stop)
	<-stopped
	if err != nil {
		t.Fatal(err)
	}
}

func TestStopFarmClientAgentDoesNotConsumeCompletionTwice(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process fixture uses the POSIX shell")
	}
	command := exec.Command("sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &farmClientLauncherProcess{command: command, done: make(chan struct{})}
	go func() {
		result := command.Wait()
		process.resultMu.Lock()
		process.result = result
		process.resultMu.Unlock()
		close(process.done)
	}()
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("child did not exit")
	}
	started := time.Now()
	if err := stopFarmClientAgent(process, true); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("completed child stop blocked for %v", elapsed)
	}
}

func TestFarmClientUpdateProbationRejectsExitedChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process probation fixture uses the POSIX shell")
	}
	command := exec.Command("sh", "-c", "exit 0")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	process := &farmClientLauncherProcess{command: command, done: make(chan struct{})}
	go func() {
		process.resultMu.Lock()
		process.result = command.Wait()
		process.resultMu.Unlock()
		close(process.done)
	}()
	healthPath := filepath.Join(t.TempDir(), "health")
	if err := os.WriteFile(healthPath, []byte(strings.Repeat("b", 64)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := waitFarmClientUpdateProbation(context.Background(), process, healthPath, strings.Repeat("b", 64), time.Second, 100*time.Millisecond); err == nil {
		t.Fatal("exited child passed probation")
	}
}
