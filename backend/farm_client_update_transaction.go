package backend

// Crash-safe activation state for the Farm Client's immutable launcher. The
// installed launcher is never overwritten: verified payloads live in a
// private content-addressed directory and one atomic record selects them.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var ErrFarmClientUpdateApply = errors.New("farm client update apply failed")

const (
	farmClientUpdateActivationVersion = 1
	farmClientUpdatePhaseStable       = "stable"
	farmClientUpdatePhaseStaged       = "staged"
	farmClientUpdatePhaseProbation    = "probation"
)

type FarmClientUpdateSlot struct {
	Version string `json:"version"`
	Target  string `json:"target"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

type FarmClientUpdateActivation struct {
	Version  int                   `json:"version"`
	Phase    string                `json:"phase"`
	Active   *FarmClientUpdateSlot `json:"active,omitempty"`
	Previous *FarmClientUpdateSlot `json:"previous,omitempty"`
	Pending  *FarmClientUpdateSlot `json:"pending,omitempty"`
}

func farmClientUpdateRoot(stateRoot string) (string, error) {
	root, err := ValidateFarmClientStateRoot(stateRoot)
	if err != nil {
		return "", ErrFarmClientUpdateApply
	}
	updates := filepath.Join(root, "updates")
	if err := secureFarmClientUpdateDirectory(updates); err != nil {
		return "", ErrFarmClientUpdateApply
	}
	return updates, nil
}

func farmClientUpdateSlotPaths(updateRoot string, slot FarmClientUpdateSlot) (string, string, error) {
	if _, err := parseFarmClientSemver(slot.Version); err != nil {
		return "", "", ErrFarmClientUpdateApply
	}
	if len(slot.SHA256) != sha256.Size*2 || slot.SHA256 != strings.ToLower(slot.SHA256) {
		return "", "", ErrFarmClientUpdateApply
	}
	if _, err := hex.DecodeString(slot.SHA256); err != nil {
		return "", "", ErrFarmClientUpdateApply
	}
	if _, ok := farmClientUpdateTargets[slot.Target]; !ok || slot.Size <= 0 || slot.Size > farmClientUpdateArtifactLimit {
		return "", "", ErrFarmClientUpdateApply
	}
	extension := ""
	if strings.HasPrefix(slot.Target, "windows-") {
		extension = ".exe"
	}
	directory := filepath.Join(updateRoot, "versions", slot.Version+"-"+slot.SHA256)
	return filepath.Join(directory, "ant-farm-client"+extension), filepath.Join(directory, "manifest.json"), nil
}

func farmClientUpdateActivationPath(updateRoot string) string {
	return filepath.Join(updateRoot, "activation.json")
}

func LoadFarmClientUpdateActivation(stateRoot string) (FarmClientUpdateActivation, error) {
	updateRoot, err := farmClientUpdateRoot(stateRoot)
	if err != nil {
		return FarmClientUpdateActivation{}, err
	}
	raw, err := os.ReadFile(farmClientUpdateActivationPath(updateRoot))
	if os.IsNotExist(err) {
		return FarmClientUpdateActivation{Version: farmClientUpdateActivationVersion, Phase: farmClientUpdatePhaseStable}, nil
	}
	if err != nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	var activation FarmClientUpdateActivation
	if err := decodeStrictFarmClientUpdateJSON(raw, &activation); err != nil || activation.Version != farmClientUpdateActivationVersion {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	if activation.Phase != farmClientUpdatePhaseStable && activation.Phase != farmClientUpdatePhaseStaged && activation.Phase != farmClientUpdatePhaseProbation {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	if (activation.Phase == farmClientUpdatePhaseStaged || activation.Phase == farmClientUpdatePhaseProbation) && activation.Pending == nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	if activation.Phase == farmClientUpdatePhaseStable && activation.Pending != nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	return activation, nil
}

func writeFarmClientUpdateActivation(updateRoot string, activation FarmClientUpdateActivation) error {
	value, err := json.Marshal(activation)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	return writeFarmClientUpdateState(farmClientUpdateActivationPath(updateRoot), value, 0o600)
}

// PrepareFarmClientUpdateActivation re-verifies the signed envelope, promotes
// the staged binary into an immutable version directory, then atomically marks
// it pending. The launcher performs the same verification before execution.
func PrepareFarmClientUpdateActivation(staged FarmClientStagedUpdate, config FarmClientConfig, currentVersion string, now time.Time) (FarmClientUpdateActivation, error) {
	if len(staged.Candidate.Envelope) == 0 && staged.EnvelopePath != "" {
		value, err := os.ReadFile(staged.EnvelopePath)
		if err != nil {
			return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
		}
		staged.Candidate.Envelope = value
	}
	candidate, err := VerifyFarmClientUpdateEnvelope(
		staged.Candidate.Envelope, config.UpdatePublicKey, currentVersion,
		FarmClientControlProtocolVersion, config.UpdateChannel,
		runtime.GOOS, runtime.GOARCH, config.AllowUpdateDowngrade, now,
	)
	if err != nil || candidate.Target != staged.Candidate.Target || candidate.Artifact != staged.Candidate.Artifact {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateIntegrity
	}
	if err := verifyFarmClientUpdateFile(staged.Path, candidate.Artifact.SHA256, candidate.Artifact.Size); err != nil {
		return FarmClientUpdateActivation{}, err
	}
	parts := strings.SplitN(candidate.Target, "-", 2)
	if len(parts) != 2 || !farmClientBinaryMatchesTarget(staged.Path, parts[0], parts[1]) {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateTarget
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return FarmClientUpdateActivation{}, err
	}
	versionsRoot := filepath.Join(updateRoot, "versions")
	if err := secureFarmClientUpdateDirectory(versionsRoot); err != nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	slot := FarmClientUpdateSlot{Version: candidate.Manifest.Version, Target: candidate.Target, SHA256: candidate.Artifact.SHA256, Size: candidate.Artifact.Size}
	executablePath, envelopePath, err := farmClientUpdateSlotPaths(updateRoot, slot)
	if err != nil {
		return FarmClientUpdateActivation{}, err
	}
	versionRoot := filepath.Dir(executablePath)
	if err := secureFarmClientUpdateDirectory(versionRoot); err != nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	if _, err := os.Lstat(executablePath); os.IsNotExist(err) {
		if err := copyFarmClientUpdateCandidate(staged.Path, executablePath, candidate.Artifact.Size); err != nil {
			return FarmClientUpdateActivation{}, err
		}
	} else if err != nil || verifyFarmClientUpdateFile(executablePath, candidate.Artifact.SHA256, candidate.Artifact.Size) != nil {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateIntegrity
	}
	if existing, readErr := os.ReadFile(envelopePath); readErr == nil {
		if !bytesEqual(existing, staged.Candidate.Envelope) {
			return FarmClientUpdateActivation{}, ErrFarmClientUpdateIntegrity
		}
	} else if !os.IsNotExist(readErr) {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	} else if err := writeFarmClientUpdateState(envelopePath, staged.Candidate.Envelope, 0o600); err != nil {
		return FarmClientUpdateActivation{}, err
	}
	activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil {
		return FarmClientUpdateActivation{}, err
	}
	if activation.Pending != nil && *activation.Pending != slot {
		return FarmClientUpdateActivation{}, ErrFarmClientUpdateApply
	}
	activation.Version = farmClientUpdateActivationVersion
	activation.Phase = farmClientUpdatePhaseStaged
	activation.Pending = &slot
	if err := writeFarmClientUpdateActivation(updateRoot, activation); err != nil {
		return FarmClientUpdateActivation{}, err
	}
	return activation, nil
}

func AuthorizeFarmClientUpdateActivation(config FarmClientConfig) error {
	return authorizeFarmClientUpdateActivationAt(config, time.Now())
}

func authorizeFarmClientUpdateActivationAt(config FarmClientConfig, now time.Time) error {
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return err
	}
	activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || activation.Phase != farmClientUpdatePhaseStaged || activation.Pending == nil {
		return ErrFarmClientUpdateApply
	}
	if _, err := verifyFarmClientPendingUpdateSlot(config, *activation.Pending, now); err != nil {
		return err
	}
	activation.Phase = farmClientUpdatePhaseProbation
	return writeFarmClientUpdateActivation(updateRoot, activation)
}

// VerifyFarmClientUpdateSlot accepts no caller-controlled path. Both paths are
// derived from the trusted state root and signed artifact digest.
func VerifyFarmClientUpdateSlot(config FarmClientConfig, slot FarmClientUpdateSlot) (string, error) {
	return verifyFarmClientUpdateSlotAt(config, slot, time.Time{})
}

func verifyFarmClientPendingUpdateSlot(config FarmClientConfig, slot FarmClientUpdateSlot, now time.Time) (string, error) {
	if now.IsZero() {
		return "", ErrFarmClientUpdateIntegrity
	}
	return verifyFarmClientUpdateSlotAt(config, slot, now)
}

func verifyFarmClientUpdateSlotAt(config FarmClientConfig, slot FarmClientUpdateSlot, policyTime time.Time) (string, error) {
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return "", err
	}
	executablePath, envelopePath, err := farmClientUpdateSlotPaths(updateRoot, slot)
	if err != nil {
		return "", err
	}
	for _, path := range []string{filepath.Dir(executablePath), executablePath, envelopePath} {
		info, statErr := os.Lstat(path)
		if statErr != nil || info.Mode()&os.ModeSymlink != 0 {
			return "", ErrFarmClientUpdateIntegrity
		}
	}
	if err := verifyFarmClientUpdateFile(executablePath, slot.SHA256, slot.Size); err != nil {
		return "", err
	}
	raw, err := os.ReadFile(envelopePath)
	if err != nil {
		return "", ErrFarmClientUpdateIntegrity
	}
	manifestTime, err := farmClientStoredManifestTime(raw)
	if err != nil {
		return "", ErrFarmClientUpdateIntegrity
	}
	verificationTime := manifestTime
	if !policyTime.IsZero() {
		verificationTime = policyTime
	}
	manifest, err := verifyFarmClientUpdateEnvelopeManifest(raw, config.UpdatePublicKey, verificationTime)
	if err != nil {
		if !policyTime.IsZero() && errors.Is(err, ErrFarmClientUpdatePolicy) {
			return "", err
		}
		return "", ErrFarmClientUpdateIntegrity
	}
	if manifest.Version != slot.Version || manifest.Channel != config.UpdateChannel {
		return "", ErrFarmClientUpdateIntegrity
	}
	currentProtocol, currentErr := parseFarmClientProtocol(FarmClientControlProtocolVersion)
	minimumProtocol, minimumErr := parseFarmClientProtocol(manifest.MinimumProtocolVersion)
	if currentErr != nil || minimumErr != nil || currentProtocol.major != minimumProtocol.major || compareFarmClientProtocol(currentProtocol, minimumProtocol) < 0 {
		return "", ErrFarmClientUpdateTarget
	}
	artifact, ok := manifest.Artifacts[slot.Target]
	if !ok || artifact.SHA256 != slot.SHA256 || artifact.Size != slot.Size {
		return "", ErrFarmClientUpdateIntegrity
	}
	parts := strings.SplitN(slot.Target, "-", 2)
	if len(parts) != 2 || parts[0] != runtime.GOOS || parts[1] != runtime.GOARCH || !farmClientBinaryMatchesTarget(executablePath, parts[0], parts[1]) {
		return "", ErrFarmClientUpdateTarget
	}
	return executablePath, nil
}

func farmClientStoredManifestTime(raw []byte) (time.Time, error) {
	var envelope FarmClientUpdateEnvelope
	if err := decodeStrictFarmClientUpdateJSON(raw, &envelope); err != nil || envelope.Version != FarmClientUpdateEnvelopeVersion {
		return time.Time{}, ErrFarmClientUpdateInvalid
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return time.Time{}, ErrFarmClientUpdateInvalid
	}
	var manifest FarmClientUpdateManifest
	if err := decodeStrictFarmClientUpdateJSON(payload, &manifest); err != nil {
		return time.Time{}, err
	}
	published, err := time.Parse(time.RFC3339, manifest.PublishedAt)
	if err != nil {
		return time.Time{}, ErrFarmClientUpdateInvalid
	}
	return published.Add(time.Nanosecond), nil
}

func CommitFarmClientUpdateActivation(config FarmClientConfig) error {
	return commitFarmClientUpdateActivationAt(config, time.Now())
}

func commitFarmClientUpdateActivationAt(config FarmClientConfig, now time.Time) error {
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return err
	}
	activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || activation.Phase != farmClientUpdatePhaseProbation || activation.Pending == nil {
		return ErrFarmClientUpdateApply
	}
	if _, err := verifyFarmClientPendingUpdateSlot(config, *activation.Pending, now); err != nil {
		return err
	}
	activation.Previous = activation.Active
	activation.Active = activation.Pending
	activation.Pending = nil
	activation.Phase = farmClientUpdatePhaseStable
	return writeFarmClientUpdateActivation(updateRoot, activation)
}

func RollbackFarmClientUpdateActivation(config FarmClientConfig) error {
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		return err
	}
	activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil {
		return err
	}
	activation.Pending = nil
	activation.Phase = farmClientUpdatePhaseStable
	return writeFarmClientUpdateActivation(updateRoot, activation)
}

func requireFarmClientUpdateRegularFile(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return ErrFarmClientUpdateApply
	}
	return nil
}

func verifyFarmClientUpdateFile(path, expectedHash string, expectedSize int64) error {
	if err := requireFarmClientUpdateRegularFile(path); err != nil {
		return ErrFarmClientUpdateIntegrity
	}
	file, err := os.Open(path)
	if err != nil {
		return ErrFarmClientUpdateIntegrity
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, farmClientUpdateArtifactLimit+1))
	if err != nil || written > farmClientUpdateArtifactLimit || (expectedSize >= 0 && written != expectedSize) {
		return ErrFarmClientUpdateIntegrity
	}
	if hex.EncodeToString(hasher.Sum(nil)) != strings.ToLower(expectedHash) {
		return ErrFarmClientUpdateIntegrity
	}
	return nil
}

func copyFarmClientUpdateCandidate(source, destination string, expectedSize int64) error {
	input, err := os.Open(source)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return ErrFarmClientUpdateApply
	}
	keep := false
	defer func() {
		_ = output.Close()
		if !keep {
			_ = os.Remove(destination)
		}
	}()
	written, err := io.Copy(output, io.LimitReader(input, expectedSize+1))
	if err != nil || written != expectedSize || output.Sync() != nil || output.Close() != nil {
		return ErrFarmClientUpdateApply
	}
	if err := secureFarmClientUpdateFilePlatform(destination); err != nil {
		return ErrFarmClientUpdateApply
	}
	keep = true
	return syncFarmClientUpdateDirectory(filepath.Dir(destination))
}

func farmClientBinaryMatchesTarget(path, goos, goarch string) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	header := make([]byte, 4096)
	count, _ := io.ReadFull(file, header)
	header = header[:count]
	switch goos {
	case "linux":
		if len(header) < 20 || !bytesEqual(header[:4], []byte{0x7f, 'E', 'L', 'F'}) || header[5] != 1 {
			return false
		}
		machine := binary.LittleEndian.Uint16(header[18:20])
		return (goarch == "amd64" && machine == 62) || (goarch == "arm64" && machine == 183)
	case "windows":
		if goarch != "amd64" || len(header) < 64 || header[0] != 'M' || header[1] != 'Z' {
			return false
		}
		offset := int(binary.LittleEndian.Uint32(header[0x3c:0x40]))
		return offset >= 0 && offset+6 <= len(header) && bytesEqual(header[offset:offset+4], []byte{'P', 'E', 0, 0}) && binary.LittleEndian.Uint16(header[offset+4:offset+6]) == 0x8664
	case "darwin":
		if len(header) < 8 {
			return false
		}
		magic := binary.LittleEndian.Uint32(header[:4])
		cpu := binary.LittleEndian.Uint32(header[4:8])
		return magic == 0xfeedfacf && ((goarch == "amd64" && cpu == 0x01000007) || (goarch == "arm64" && cpu == 0x0100000c))
	default:
		return false
	}
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
