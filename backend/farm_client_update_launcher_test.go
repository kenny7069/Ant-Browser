package backend

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func buildFarmClientLauncherExitFixture(t *testing.T) string {
	t.Helper()
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
import (
    "os"
    "strconv"
)
func main() {
	path := os.Getenv("ANT_FARM_LAUNCHER_COUNT_FILE")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err == nil { _, _ = file.Write([]byte("x")); _ = file.Close() }
	code, _ := strconv.Atoi(os.Getenv("ANT_FARM_LAUNCHER_EXIT_CODE"))
	os.Exit(code)
}`
	if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", executable, source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture: %v: %s", err, output)
	}
	return executable
}

func writeFarmClientLauncherTestConfig(t *testing.T, root string) string {
	t.Helper()
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
	return configPath
}

func TestFarmClientLauncherSurvivesTwoSuccessorBoundaries(t *testing.T) {
	root := t.TempDir()
	executable := buildFarmClientLauncherExitFixture(t)
	countPath := filepath.Join(root, "starts")
	t.Setenv("ANT_FARM_LAUNCHER_COUNT_FILE", countPath)
	t.Setenv("ANT_FARM_LAUNCHER_EXIT_CODE", "1")
	configPath := writeFarmClientLauncherTestConfig(t, root)
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

func TestFarmClientLauncherControlledStopDoesNotRestart(t *testing.T) {
	root := t.TempDir()
	executable := buildFarmClientLauncherExitFixture(t)
	countPath := filepath.Join(root, "starts")
	t.Setenv("ANT_FARM_LAUNCHER_COUNT_FILE", countPath)
	t.Setenv("ANT_FARM_LAUNCHER_EXIT_CODE", strconv.Itoa(FarmClientInternalControlledStopExitCode))
	configPath := writeFarmClientLauncherTestConfig(t, root)
	if err := RunFarmClientLauncher(context.Background(), configPath, executable, nil, nil); err != nil {
		t.Fatal(err)
	}
	if value, err := os.ReadFile(countPath); err != nil || string(value) != "x" {
		t.Fatalf("controlled stop restarted child: starts=%q err=%v", value, err)
	}
}

func farmClientLauncherExitError(t *testing.T, code string) error {
	t.Helper()
	executable := buildFarmClientLauncherExitFixture(t)
	command := exec.Command(executable)
	command.Env = append(os.Environ(), "ANT_FARM_LAUNCHER_COUNT_FILE="+filepath.Join(t.TempDir(), "starts"), "ANT_FARM_LAUNCHER_EXIT_CODE="+code)
	return command.Run()
}

func TestFarmClientControlledStopExitEvidenceIsExactAndWrapped(t *testing.T) {
	controlled := farmClientLauncherExitError(t, strconv.Itoa(FarmClientInternalControlledStopExitCode))
	if !farmClientAgentControlledStop(controlled) || !farmClientAgentControlledStop(errors.Join(ErrFarmClientUpdateApply, controlled)) {
		t.Fatalf("controlled stop exit was not recognized: %v", controlled)
	}
	for _, err := range []error{nil, errors.New("exit status 23"), farmClientLauncherExitError(t, "1")} {
		if farmClientAgentControlledStop(err) {
			t.Fatalf("non-controlled exit was accepted: %v", err)
		}
	}
}

func TestFarmClientProbationControlledStopPreservesPendingActivation(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil || activation.Pending == nil {
		t.Fatalf("activation=%+v err=%v", activation, err)
	}
	if err := AuthorizeFarmClientUpdateActivation(config); err != nil {
		t.Fatal(err)
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	activationPath := farmClientUpdateActivationPath(updateRoot)
	before, err := os.ReadFile(activationPath)
	if err != nil {
		t.Fatal(err)
	}
	exitErr := farmClientLauncherExitError(t, strconv.Itoa(FarmClientInternalControlledStopExitCode))
	controlledStop, err := reconcileFarmClientPendingExit(config, "/config", "/launcher", *activation.Pending, errors.Join(ErrFarmClientUpdateApply, exitErr), nil)
	if err != nil || !controlledStop {
		t.Fatalf("controlled=%t err=%v", controlledStop, err)
	}
	after, err := os.ReadFile(activationPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("probation activation mutated: before=%q after=%q err=%v", before, after, err)
	}
	current, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || current.Phase != farmClientUpdatePhaseProbation || current.Pending == nil || *current.Pending != *activation.Pending {
		t.Fatalf("pending activation not preserved: %+v err=%v", current, err)
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

func TestFarmClientUpdateProbationToleratesTransientMarkerObservationGap(t *testing.T) {
	process := startFarmClientProbationTestProcess(t)
	stateRoot := t.TempDir()
	healthPath := filepath.Join(stateRoot, "updates", "health")
	config := FarmClientConfig{StateRoot: stateRoot}
	nonce := strings.Repeat("b", 64)
	if err := WriteFarmClientUpdateHealthMarker(config, healthPath, nonce); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- waitFarmClientUpdateProbation(context.Background(), process, healthPath, nonce, 400*time.Millisecond, 1200*time.Millisecond)
	}()
	// The first 250 ms poll observes health and starts probation. Removing the
	// marker across multiple later polls deterministically exercises the
	// transient observation path that Windows file sharing can trigger.
	time.Sleep(350 * time.Millisecond)
	if err := os.Remove(healthPath); err != nil {
		t.Fatal(err)
	}
	time.Sleep(600 * time.Millisecond)
	if err := WriteFarmClientUpdateHealthMarker(config, healthPath, nonce); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("transient marker observation gap failed probation: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("probation did not complete after transient marker observation gap")
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

func TestFarmClientUpdateRevalidationFailureStopsProbationChild(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("process fixture uses the POSIX shell")
	}
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("sh", "-c", "cat >/dev/null")
	command.Stdin = controlReader
	if err := command.Start(); err != nil {
		_ = controlReader.Close()
		_ = controlWriter.Close()
		t.Fatal(err)
	}
	_ = controlReader.Close()
	process := &farmClientLauncherProcess{command: command, done: make(chan struct{}), control: controlWriter}
	go func() {
		process.resultMu.Lock()
		process.result = command.Wait()
		process.resultMu.Unlock()
		close(process.done)
	}()
	t.Cleanup(func() { _ = process.command.Process.Kill() })
	err = revalidateFarmClientLauncherProcess(process, true, "/config", "/launcher", func(string, string) error {
		return ErrSuiteLauncherRevalidation
	})
	if !errors.Is(err, ErrSuiteLauncherRevalidation) {
		t.Fatalf("revalidation error=%v", err)
	}
	select {
	case <-process.done:
	case <-time.After(time.Second):
		t.Fatal("probation child remained live after revalidation failure")
	}
}
