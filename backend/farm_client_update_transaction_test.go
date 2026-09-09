package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func farmClientUpdateBinaryFixture(goos, goarch string) []byte {
	value := make([]byte, 512)
	switch goos {
	case "linux":
		copy(value, []byte{0x7f, 'E', 'L', 'F', 2, 1})
		machine := uint16(62)
		if goarch == "arm64" {
			machine = 183
		}
		binary.LittleEndian.PutUint16(value[18:20], machine)
	case "windows":
		copy(value, []byte{'M', 'Z'})
		binary.LittleEndian.PutUint32(value[0x3c:0x40], 128)
		copy(value[128:], []byte{'P', 'E', 0, 0})
		binary.LittleEndian.PutUint16(value[132:134], 0x8664)
	case "darwin":
		binary.LittleEndian.PutUint32(value[:4], 0xfeedfacf)
		cpu := uint32(0x01000007)
		if goarch == "arm64" {
			cpu = 0x0100000c
		}
		binary.LittleEndian.PutUint32(value[4:8], cpu)
	}
	return value
}

func preparedFarmClientActivation(t *testing.T) (FarmClientConfig, FarmClientStagedUpdate) {
	t.Helper()
	artifact := farmClientUpdateBinaryFixture(runtime.GOOS, runtime.GOARCH)
	digest := sha256.Sum256(artifact)
	now := time.Now().UTC()
	entry := FarmClientUpdateArtifact{URL: "https://updates.example.invalid/client", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))}
	manifest := FarmClientUpdateManifest{
		Version: "1.1.0", ProtocolVersion: FarmClientControlProtocolVersion,
		MinimumProtocolVersion: FarmClientControlProtocolVersion, Channel: "stable",
		PublishedAt: now.Add(-time.Minute).Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		Artifacts: map[string]FarmClientUpdateArtifact{},
	}
	for target := range farmClientUpdateTargets {
		manifest.Artifacts[target] = entry
	}
	payload, _ := json.Marshal(manifest)
	publicKey, privateKey, _ := ed25519.GenerateKey(rand.Reader)
	envelope, _ := json.Marshal(FarmClientUpdateEnvelope{
		Version: FarmClientUpdateEnvelopeVersion, Payload: base64.StdEncoding.EncodeToString(payload),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	})
	candidate, err := VerifyFarmClientUpdateEnvelope(envelope, base64.StdEncoding.EncodeToString(publicKey), "1.0.0", FarmClientControlProtocolVersion, "stable", runtime.GOOS, runtime.GOARCH, false, now)
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	path := filepath.Join(stateRoot, "staged")
	if err := os.WriteFile(path, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	config := FarmClientConfig{StateRoot: stateRoot, UpdatePublicKey: base64.StdEncoding.EncodeToString(publicKey), UpdateChannel: "stable"}
	return config, FarmClientStagedUpdate{Candidate: candidate, Path: path}
}

func TestFarmClientUpdateBinaryTargetValidation(t *testing.T) {
	for _, target := range [][2]string{{"linux", "amd64"}, {"linux", "arm64"}, {"windows", "amd64"}, {"darwin", "amd64"}, {"darwin", "arm64"}} {
		path := filepath.Join(t.TempDir(), "binary")
		if err := os.WriteFile(path, farmClientUpdateBinaryFixture(target[0], target[1]), 0o600); err != nil {
			t.Fatal(err)
		}
		if !farmClientBinaryMatchesTarget(path, target[0], target[1]) {
			t.Fatalf("target %v rejected", target)
		}
	}
}

func TestFarmClientUpdateActivationNeverWritesInstallRoot(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	installRoot := t.TempDir()
	launcher := filepath.Join(installRoot, "ant-farm-client")
	if err := os.WriteFile(launcher, []byte("immutable launcher"), 0o500); err != nil {
		t.Fatal(err)
	}
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if activation.Pending == nil || activation.Active != nil || activation.Phase != farmClientUpdatePhaseStaged {
		t.Fatalf("activation=%+v", activation)
	}
	executable, err := VerifyFarmClientUpdateSlot(config, *activation.Pending)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(executable, filepath.Join(config.StateRoot, "updates", "versions")+string(filepath.Separator)) {
		t.Fatalf("payload path=%q", executable)
	}
	if value, _ := os.ReadFile(launcher); string(value) != "immutable launcher" {
		t.Fatalf("launcher changed=%q", value)
	}
}

func TestFarmClientUpdateActivationCommitAndRollbackAreSingleRecord(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := CommitFarmClientUpdateActivation(config); !errors.Is(err, ErrFarmClientUpdateApply) {
		t.Fatalf("undrained commit err=%v", err)
	}
	if err := AuthorizeFarmClientUpdateActivation(config); err != nil {
		t.Fatal(err)
	}
	if err := CommitFarmClientUpdateActivation(config); err != nil {
		t.Fatal(err)
	}
	committed, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || committed.Active == nil || *committed.Active != *activation.Pending || committed.Pending != nil || committed.Phase != farmClientUpdatePhaseStable {
		t.Fatalf("committed=%+v err=%v", committed, err)
	}
	committed.Pending = committed.Active
	committed.Phase = farmClientUpdatePhaseProbation
	root, _ := farmClientUpdateRoot(config.StateRoot)
	if err := writeFarmClientUpdateActivation(root, committed); err != nil {
		t.Fatal(err)
	}
	if err := RollbackFarmClientUpdateActivation(config); err != nil {
		t.Fatal(err)
	}
	rolledBack, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || rolledBack.Active == nil || rolledBack.Pending != nil || rolledBack.Phase != farmClientUpdatePhaseStable {
		t.Fatalf("rolledBack=%+v err=%v", rolledBack, err)
	}
}

func TestFarmClientUpdateStagedCrashRecoversOldActivation(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	if _, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := RollbackFarmClientUpdateActivation(config); err != nil {
		t.Fatal(err)
	}
	activation, err := LoadFarmClientUpdateActivation(config.StateRoot)
	if err != nil || activation.Phase != farmClientUpdatePhaseStable || activation.Pending != nil || activation.Active != nil {
		t.Fatalf("activation=%+v err=%v", activation, err)
	}
}

func TestFarmClientUpdateStartupReverifiesEnvelopeAndArtifact(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	executable, envelope, _ := farmClientUpdateSlotPaths(filepath.Join(config.StateRoot, "updates"), *activation.Pending)
	if err := os.WriteFile(envelope, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFarmClientUpdateSlot(config, *activation.Pending); !errors.Is(err, ErrFarmClientUpdateIntegrity) {
		t.Fatalf("envelope err=%v", err)
	}
	if err := os.WriteFile(executable, []byte("tampered"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyFarmClientUpdateSlot(config, *activation.Pending); !errors.Is(err, ErrFarmClientUpdateIntegrity) {
		t.Fatalf("artifact err=%v", err)
	}
}

func TestFarmClientPendingActivationRechecksCurrentExpiry(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expiredAt := time.Now().Add(2 * time.Hour)
	if _, err := verifyFarmClientPendingUpdateSlot(config, *activation.Pending, expiredAt); !errors.Is(err, ErrFarmClientUpdatePolicy) {
		t.Fatalf("expired pending slot err=%v", err)
	}
	// Once committed, expiry of the release envelope must not brick ordinary
	// restarts of the already-installed active or rollback version.
	if _, err := VerifyFarmClientUpdateSlot(config, *activation.Pending); err != nil {
		t.Fatalf("installed-slot trust recheck failed: %v", err)
	}
	if err := authorizeFarmClientUpdateActivationAt(config, expiredAt); !errors.Is(err, ErrFarmClientUpdatePolicy) {
		t.Fatalf("expired authorization err=%v", err)
	}
}

func TestFarmClientUpdatePinnedPayloadRejectsHardlinkAlias(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	executable, _, err := farmClientUpdateSlotPaths(filepath.Join(config.StateRoot, "updates"), *activation.Pending)
	if err != nil {
		t.Fatal(err)
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	pinned, err := openFarmClientPinnedPayload(updateRoot, executable, *activation.Pending)
	if err != nil {
		t.Fatal(err)
	}
	pinned.Close()
	alias := filepath.Join(filepath.Dir(executable), "payload-hardlink")
	if err := os.Link(executable, alias); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if pinned, err = openFarmClientPinnedPayload(updateRoot, executable, *activation.Pending); err == nil {
		pinned.Close()
		t.Fatal("hardlinked update payload was accepted")
	}
}

func TestFarmClientUpdatePinnedPayloadRejectsSymlinkedVersionDirectory(t *testing.T) {
	config, staged := preparedFarmClientActivation(t)
	activation, err := PrepareFarmClientUpdateActivation(staged, config, "1.0.0", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	executable, _, err := farmClientUpdateSlotPaths(filepath.Join(config.StateRoot, "updates"), *activation.Pending)
	if err != nil {
		t.Fatal(err)
	}
	versionRoot := filepath.Dir(executable)
	realRoot := versionRoot + "-real"
	if err := os.Rename(versionRoot, realRoot); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realRoot, versionRoot); err != nil {
		t.Skipf("directory symlinks unavailable: %v", err)
	}
	updateRoot, err := farmClientUpdateRoot(config.StateRoot)
	if err != nil {
		t.Fatal(err)
	}
	if pinned, pinErr := openFarmClientPinnedPayload(updateRoot, executable, *activation.Pending); pinErr == nil {
		pinned.Close()
		t.Fatal("symlinked version directory was accepted")
	}
}

func TestFarmClientUpdateHealthMarkerCannotEscapePrivateUpdateRoot(t *testing.T) {
	root := t.TempDir()
	config := FarmClientConfig{StateRoot: root}
	nonce := strings.Repeat("a", 64)
	valid := filepath.Join(root, "updates", "health-test")
	if err := WriteFarmClientUpdateHealthMarker(config, valid, nonce); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(valid); err != nil || string(raw) != nonce {
		t.Fatalf("raw=%q err=%v", raw, err)
	}
	before, err := os.Stat(valid)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if err := WriteFarmClientUpdateHealthMarker(config, valid, nonce); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(valid)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) || !after.ModTime().After(before.ModTime()) {
		t.Fatalf("health refresh replaced the marker or did not advance mtime: before=%v after=%v", before.ModTime(), after.ModTime())
	}
	if err := WriteFarmClientUpdateHealthMarker(config, filepath.Join(root, "outside"), nonce); !errors.Is(err, ErrFarmClientUpdateApply) {
		t.Fatalf("escape err=%v", err)
	}
}

func TestFarmClientUpdateHealthRequiresExplicitSnapshotCompletion(t *testing.T) {
	adapter := &FarmRuntimeControlAdapter{health: farmClientUpdateHealthObservation{connectionGeneration: 7}}
	inventory := []FarmRuntime{{FarmRuntimeIdentity: FarmRuntimeIdentity{NodeUID: "node-a", ProfileID: "profile-a", RuntimeUID: "old-runtime", ProviderInstanceID: "provider-a", Generation: 2}}}
	digest := farmRuntimeInventoryDigest(inventory)
	adapter.observeFarmClientUpdateHealth(7, "inventory_handoff", FarmRuntimeInventorySnapshot{ConnectionGeneration: 7, InventoryDigest: digest, Inventory: inventory})
	if adapter.FarmClientUpdateHealthReady() {
		t.Fatal("health passed before Server completion")
	}
	adapter.observeFarmClientUpdateHealth(7, "handoff_reconcile_complete", FarmRuntimeHandoffCompletion{Status: "completed", ConnectionGeneration: 7, InventoryDigest: strings.Repeat("0", 64), InventoryCount: 1})
	if adapter.FarmClientUpdateHealthReady() {
		t.Fatal("health passed for a different inventory")
	}
	adapter.observeFarmClientUpdateHealth(6, "handoff_reconcile_complete", FarmRuntimeHandoffCompletion{Status: "completed", ConnectionGeneration: 6, InventoryDigest: digest, InventoryCount: 1})
	if adapter.FarmClientUpdateHealthReady() {
		t.Fatal("health passed for a stale connection")
	}
	adapter.observeFarmClientUpdateHealth(7, "handoff_reconcile_complete", FarmRuntimeHandoffCompletion{Status: "completed", ConnectionGeneration: 7, InventoryDigest: digest, InventoryCount: 1})
	if !adapter.FarmClientUpdateHealthReady() {
		t.Fatal("health rejected matching explicit completion")
	}
}

func TestFarmClientUpdateZeroInventoryStillRequiresCompletion(t *testing.T) {
	adapter := &FarmRuntimeControlAdapter{health: farmClientUpdateHealthObservation{connectionGeneration: 9}}
	digest := farmRuntimeInventoryDigest(nil)
	adapter.observeFarmClientUpdateHealth(9, "inventory_handoff", FarmRuntimeInventorySnapshot{ConnectionGeneration: 9, InventoryDigest: digest})
	if adapter.FarmClientUpdateHealthReady() {
		t.Fatal("empty inventory bypassed Server completion")
	}
	adapter.observeFarmClientUpdateHealth(9, "handoff_reconcile_complete", FarmRuntimeHandoffCompletion{Status: "completed", ConnectionGeneration: 9, InventoryDigest: digest, InventoryCount: 0})
	if !adapter.FarmClientUpdateHealthReady() {
		t.Fatal("empty inventory completion was rejected")
	}
}
