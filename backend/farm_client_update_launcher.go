package backend

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const farmClientUpdateHealthNonceEnvironment = "ANT_FARM_CLIENT_UPDATE_HEALTH_NONCE"

const (
	farmClientControlStop     byte = 'S'
	farmClientControlPreserve byte = 'P'
)

type farmClientLauncherProcess struct {
	command   *exec.Cmd
	done      chan struct{}
	resultMu  sync.Mutex
	result    error
	controlMu sync.Mutex
	control   *os.File
}

// RunFarmClientUpdateSupervisor only stages a signed per-user payload. Closing
// the authenticated transport performs the existing drain fence and lets the
// immutable parent launcher observe the pending activation after child exit.
func RunFarmClientUpdateSupervisor(ctx context.Context, host *FarmClientHost, _ string, _ string) {
	if host == nil || strings.TrimSpace(host.config.UpdateManifestURL) == "" {
		return
	}
	timer := time.NewTimer(host.config.updateCheckInterval())
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			staged, err := FetchAndStageFarmClientUpdate(ctx, nil, host.config, FarmClientVersion, time.Now())
			if err == nil {
				if _, err = PrepareFarmClientUpdateActivation(staged, host.config, FarmClientVersion, time.Now()); err == nil {
					if host.PrepareForUpdateAndAuthorize(func() error { return AuthorizeFarmClientUpdateActivation(host.config) }) == nil {
						return
					}
					_ = RollbackFarmClientUpdateActivation(host.config)
				}
			}
			timer.Reset(host.config.updateCheckInterval())
		}
	}
}

// RunFarmClientLauncher is the only process supervised by Scheduled Task,
// LaunchAgent or systemd --user. It never mutates launcherPath. Every startup
// first recovers pending activation state, re-verifies the signed payload and
// supervises Agent children for the lifetime of the service. A normal child
// exit is never allowed to terminate the immutable launcher: it may be the
// hand-off boundary for this or a later update.
func RunFarmClientLauncher(ctx context.Context, configPath, launcherPath string, stdout, stderr io.Writer) error {
	config, err := LoadFarmClientConfig(configPath)
	if err != nil || config.ValidateFarmClientConfig() != nil {
		return ErrFarmClientUpdateApply
	}
	launcherPath, err = filepath.Abs(filepath.Clean(launcherPath))
	if err != nil || requireFarmClientUpdateRegularFile(launcherPath) != nil {
		return ErrFarmClientUpdateApply
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return err
	}
	launcherLock, err := acquireFarmClientFileLock(filepath.Join(updateRoot, "activation.lock"))
	if err != nil {
		return err
	}
	defer launcherLock.Release()
	for {
		if ctx.Err() != nil {
			return nil
		}
		activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
		if err != nil {
			return err
		}
		if activation.Phase == farmClientUpdatePhaseStaged {
			if err := RollbackFarmClientUpdateActivation(config); err != nil {
				return err
			}
			continue
		}
		if activation.Phase == farmClientUpdatePhaseProbation && activation.Pending != nil {
			pending := *activation.Pending
			runErr := runFarmClientPendingActivation(ctx, config, configPath, stdout, stderr, pending)
			if ctx.Err() != nil {
				return nil
			}
			current, loadErr := LoadFarmClientUpdateActivation(config.StateRoot)
			if loadErr != nil {
				return loadErr
			}
			// Roll back only the same uncommitted candidate. Once probation was
			// committed, a later child exit is a restart boundary, not failure.
			if runErr != nil && current.Phase == farmClientUpdatePhaseProbation && current.Pending != nil && current.Pending.SHA256 == pending.SHA256 {
				if rollbackErr := RollbackFarmClientUpdateActivation(config); rollbackErr != nil {
					return rollbackErr
				}
			}
			continue
		}

		executablePath := launcherPath
		var executableSlot *FarmClientUpdateSlot
		if activation.Active != nil {
			if verified, verifyErr := VerifyFarmClientUpdateSlot(config, *activation.Active); verifyErr == nil {
				executablePath = verified
				executableSlot = activation.Active
			} else if activation.Previous != nil {
				if previous, previousErr := VerifyFarmClientUpdateSlot(config, *activation.Previous); previousErr == nil {
					executablePath = previous
					activation.Active = activation.Previous
					activation.Previous = nil
					activation.Pending = nil
					activation.Phase = farmClientUpdatePhaseStable
					executableSlot = activation.Active
					if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
						return err
					}
				} else {
					activation.Active = nil
					activation.Previous = nil
					if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
						return err
					}
				}
			} else {
				activation.Active = nil
				if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
					return err
				}
			}
		}
		process, startErr := startFarmClientAgent(config, configPath, executablePath, executableSlot, "", "", stdout, stderr)
		if startErr != nil {
			return startErr
		}
		_ = waitFarmClientAgent(ctx, process)
		if ctx.Err() != nil {
			return nil
		}
		// Give unexpected crashes a bounded backoff, but skip it when an
		// update hand-off has already made durable progress.
		latest, loadErr := LoadFarmClientUpdateActivation(config.StateRoot)
		if loadErr != nil {
			return loadErr
		}
		if latest.Phase == farmClientUpdatePhaseStable {
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Second):
			}
		}
	}
}

func runFarmClientPendingActivation(ctx context.Context, config FarmClientConfig, configPath string, stdout, stderr io.Writer, slot FarmClientUpdateSlot) error {
	executablePath, err := verifyFarmClientPendingUpdateSlot(config, slot, time.Now())
	if err != nil {
		return err
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return err
	}
	healthPath := filepath.Join(updateRoot, "health-"+slot.SHA256[:16])
	_ = os.Remove(healthPath)
	nonceRaw := make([]byte, 32)
	if _, err := rand.Read(nonceRaw); err != nil {
		return ErrFarmClientUpdateApply
	}
	nonce := hex.EncodeToString(nonceRaw)
	process, err := startFarmClientAgent(config, configPath, executablePath, &slot, healthPath, nonce, stdout, stderr)
	if err != nil {
		return err
	}
	if err := waitFarmClientUpdateProbation(ctx, process, healthPath, nonce, config.updateHealthTimeout(), config.updateProbation()); err != nil {
		_ = stopFarmClientAgent(process, ctx.Err() == nil)
		return err
	}
	if err := CommitFarmClientUpdateActivation(config); err != nil {
		_ = stopFarmClientAgent(process, true)
		return err
	}
	return waitFarmClientAgent(ctx, process)
}

func startFarmClientAgent(config FarmClientConfig, configPath, executablePath string, slot *FarmClientUpdateSlot, healthPath, nonce string, stdout, stderr io.Writer) (*farmClientLauncherProcess, error) {
	arguments := []string{"-config", configPath, "-farm-agent"}
	if healthPath != "" {
		arguments = append(arguments, "-update-health-file", healthPath)
	}
	var pinned *farmClientPinnedPayload
	if slot != nil {
		updateRoot, err := farmClientUpdateRoot(config.StateRoot)
		if err != nil {
			return nil, err
		}
		pinned, err = openFarmClientPinnedPayload(updateRoot, executablePath, *slot)
		if err != nil {
			return nil, err
		}
		defer pinned.Close()
		executablePath = pinned.path
	}
	command := exec.Command(executablePath, arguments...)
	if pinned != nil {
		command.ExtraFiles = pinned.extraFiles
	}
	command.Stdout = stdout
	command.Stderr = stderr
	controlReader, controlWriter, err := os.Pipe()
	if err != nil {
		return nil, ErrFarmClientUpdateApply
	}
	command.Stdin = controlReader
	command.Env = os.Environ()
	if nonce != "" {
		command.Env = append(command.Env, farmClientUpdateHealthNonceEnvironment+"="+nonce)
	}
	if err := command.Start(); err != nil {
		_ = controlReader.Close()
		_ = controlWriter.Close()
		return nil, ErrFarmClientUpdateApply
	}
	_ = controlReader.Close()
	process := &farmClientLauncherProcess{command: command, done: make(chan struct{}), control: controlWriter}
	go func() {
		result := command.Wait()
		process.resultMu.Lock()
		process.result = result
		process.resultMu.Unlock()
		close(process.done)
	}()
	return process, nil
}

func farmClientAgentResult(process *farmClientLauncherProcess) error {
	process.resultMu.Lock()
	defer process.resultMu.Unlock()
	return process.result
}

func waitFarmClientUpdateProbation(ctx context.Context, process *farmClientLauncherProcess, healthPath, nonce string, healthTimeout, probation time.Duration) error {
	if process == nil || process.command == nil || healthTimeout <= 0 || probation <= 0 {
		return ErrFarmClientUpdateApply
	}
	healthDeadline := time.NewTimer(healthTimeout)
	defer healthDeadline.Stop()
	healthDeadlineChannel := healthDeadline.C
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	var probationStarted time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-process.done:
			closeFarmClientAgentControl(process)
			err := farmClientAgentResult(process)
			if err == nil {
				return ErrFarmClientUpdateApply
			}
			return errors.Join(ErrFarmClientUpdateApply, err)
		case <-healthDeadlineChannel:
			return errors.Join(ErrFarmClientUpdateApply, context.DeadlineExceeded)
		case <-ticker.C:
			raw, err := os.ReadFile(healthPath)
			info, statErr := os.Stat(healthPath)
			fresh := err == nil && statErr == nil && strings.TrimSpace(string(raw)) == nonce && time.Since(info.ModTime()) <= 3*time.Second
			if !fresh {
				if !probationStarted.IsZero() {
					return ErrFarmClientUpdateApply
				}
				continue
			}
			if probationStarted.IsZero() {
				if !healthDeadline.Stop() {
					select {
					case <-healthDeadline.C:
					default:
					}
				}
				healthDeadlineChannel = nil
				probationStarted = time.Now()
			}
			if time.Since(probationStarted) >= probation {
				select {
				case <-process.done:
					return ErrFarmClientUpdateApply
				default:
				}
				return nil
			}
		}
	}
}

func waitFarmClientAgent(ctx context.Context, process *farmClientLauncherProcess) error {
	if process == nil || process.command == nil {
		return ErrFarmClientUpdateApply
	}
	select {
	case <-ctx.Done():
		_ = stopFarmClientAgent(process, false)
		return nil
	case <-process.done:
		closeFarmClientAgentControl(process)
		return farmClientAgentResult(process)
	}
}

func closeFarmClientAgentControl(process *farmClientLauncherProcess) {
	if process == nil {
		return
	}
	process.controlMu.Lock()
	defer process.controlMu.Unlock()
	if process.control != nil {
		_ = process.control.Close()
		process.control = nil
	}
}

func stopFarmClientAgent(process *farmClientLauncherProcess, preserve bool) error {
	if process == nil || process.command == nil || process.command.Process == nil {
		return ErrFarmClientUpdateApply
	}
	select {
	case <-process.done:
		closeFarmClientAgentControl(process)
		return nil
	default:
	}
	control := farmClientControlStop
	if preserve {
		control = farmClientControlPreserve
	}
	process.controlMu.Lock()
	if process.control != nil {
		_, _ = process.control.Write([]byte{control})
		_ = process.control.Close()
		process.control = nil
	}
	process.controlMu.Unlock()
	select {
	case <-process.done:
		return nil
	case <-time.After(10 * time.Second):
		err := process.command.Process.Kill()
		if err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		select {
		case <-process.done:
			return nil
		case <-time.After(2 * time.Second):
			return context.DeadlineExceeded
		}
	}
}

// WriteFarmClientUpdateHealthMarker is called repeatedly by a healthy child;
// atomic replacement makes ModTime a continuous liveness signal, not a stale
// one-shot success token.
func WriteFarmClientUpdateHealthMarker(config FarmClientConfig, path, nonce string) error {
	path = filepath.Clean(strings.TrimSpace(path))
	nonce = strings.TrimSpace(nonce)
	root := filepath.Join(filepath.Clean(config.StateRoot), "updates")
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.Dir(relative) != "." {
		return ErrFarmClientUpdateApply
	}
	if len(nonce) != 64 {
		return ErrFarmClientUpdateApply
	}
	if _, err := hex.DecodeString(nonce); err != nil {
		return ErrFarmClientUpdateApply
	}
	if err := secureFarmClientUpdateDirectory(root); err != nil {
		return err
	}
	// The nonce is immutable for one probation process. Refreshing the existing
	// marker's timestamp avoids replacing the same pathname every second. On
	// Windows that replacement races the launcher's os.ReadFile handle, which
	// intentionally does not grant FILE_SHARE_DELETE.
	if raw, err := os.ReadFile(path); err == nil {
		if strings.TrimSpace(string(raw)) != nonce {
			return ErrFarmClientUpdateApply
		}
		now := time.Now()
		if err := os.Chtimes(path, now, now); err != nil {
			return errors.Join(ErrFarmClientUpdateApply, err)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return errors.Join(ErrFarmClientUpdateApply, err)
	}
	return writeFarmClientUpdateState(path, []byte(nonce), 0o600)
}
