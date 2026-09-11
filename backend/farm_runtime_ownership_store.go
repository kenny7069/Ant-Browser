package backend

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var ErrFarmRuntimeOwnershipProvenance = errors.New("invalid farm runtime ownership provenance")

// FarmRuntimeOwnershipProvenance is the minimum durable evidence needed to
// recover Agent ownership after an Agent process restart. It deliberately
// contains no proxy secret, CDP token, port-based locator authority, or raw
// browser arguments.
type FarmRuntimeOwnershipProvenance struct {
	Runtime              FarmRuntimeIdentity `json:"runtime"`
	PID                  int                 `json:"pid"`
	DebugPort            int                 `json:"debug_port"`
	ProcessStartIdentity string              `json:"process_start_identity"`
	LaunchMode           string              `json:"launch_mode,omitempty"`
	ProfileCreatedAt     string              `json:"profile_created_at"`
}

type FarmRuntimeOwnershipStore interface {
	Load() ([]FarmRuntimeOwnershipProvenance, error)
	Save([]FarmRuntimeOwnershipProvenance) error
}

type fileFarmRuntimeOwnershipStore struct {
	mu    sync.Mutex
	path  string
	key   []byte
	chmod func(*os.File, os.FileMode) error
	write func(*os.File, []byte) (int, error)
}

type farmRuntimeOwnershipEnvelope struct {
	Version int                              `json:"version"`
	Entries []FarmRuntimeOwnershipProvenance `json:"entries"`
	MAC     string                           `json:"mac"`
}

// NewFileFarmRuntimeOwnershipStore creates an authenticated, atomic local
// provenance store. Callers should derive key from the enrolled Agent device
// secret; a distinct 32-byte key prevents a copied/edited JSON file from
// becoming ownership authority.
func NewFileFarmRuntimeOwnershipStore(path string, key []byte) (FarmRuntimeOwnershipStore, error) {
	path = strings.TrimSpace(path)
	if !filepath.IsAbs(path) || len(key) < 32 {
		return nil, ErrFarmRuntimeOwnershipProvenance
	}
	return &fileFarmRuntimeOwnershipStore{path: filepath.Clean(path), key: append([]byte(nil), key...), chmod: func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) }, write: func(file *os.File, value []byte) (int, error) { return file.Write(value) }}, nil
}

func ownershipPayload(entries []FarmRuntimeOwnershipProvenance) ([]byte, error) {
	copyEntries := append([]FarmRuntimeOwnershipProvenance(nil), entries...)
	sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].Runtime.ProfileID < copyEntries[j].Runtime.ProfileID })
	return json.Marshal(struct {
		Version int                              `json:"version"`
		Entries []FarmRuntimeOwnershipProvenance `json:"entries"`
	}{Version: 1, Entries: copyEntries})
}

func ownershipMAC(key, payload []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func (s *fileFarmRuntimeOwnershipStore) Load() ([]FarmRuntimeOwnershipProvenance, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	file, err := os.Open(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	const maxOwnershipBytes = 1 << 20
	raw, err := io.ReadAll(io.LimitReader(file, maxOwnershipBytes+1))
	if err != nil || len(raw) > maxOwnershipBytes {
		return nil, ErrFarmRuntimeOwnershipProvenance
	}
	var envelope farmRuntimeOwnershipEnvelope
	if json.Unmarshal(raw, &envelope) != nil || envelope.Version != 1 {
		return nil, ErrFarmRuntimeOwnershipProvenance
	}
	payload, err := ownershipPayload(envelope.Entries)
	if err != nil {
		return nil, err
	}
	expected, decodeErr := hex.DecodeString(envelope.MAC)
	actual, _ := hex.DecodeString(ownershipMAC(s.key, payload))
	if decodeErr != nil || !hmac.Equal(expected, actual) {
		return nil, ErrFarmRuntimeOwnershipProvenance
	}
	profiles, runtimes := make(map[string]struct{}), make(map[string]struct{})
	for _, entry := range envelope.Entries {
		if _, duplicate := profiles[entry.Runtime.ProfileID]; duplicate {
			return nil, ErrFarmRuntimeOwnershipProvenance
		}
		if _, duplicate := runtimes[entry.Runtime.RuntimeUID]; duplicate {
			return nil, ErrFarmRuntimeOwnershipProvenance
		}
		profiles[entry.Runtime.ProfileID], runtimes[entry.Runtime.RuntimeUID] = struct{}{}, struct{}{}
	}
	return append([]FarmRuntimeOwnershipProvenance(nil), envelope.Entries...), nil
}

func (s *fileFarmRuntimeOwnershipStore) Save(entries []FarmRuntimeOwnershipProvenance) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	payload, err := ownershipPayload(entries)
	if err != nil {
		return err
	}
	var body struct {
		Version int                              `json:"version"`
		Entries []FarmRuntimeOwnershipProvenance `json:"entries"`
	}
	if err := json.Unmarshal(payload, &body); err != nil {
		return err
	}
	raw, err := json.Marshal(farmRuntimeOwnershipEnvelope{Version: body.Version, Entries: body.Entries, MAC: ownershipMAC(s.key, payload)})
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".farm-ownership-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err = s.chmod(temp, 0o600); err == nil {
		var written int
		written, err = s.write(temp, raw)
		if err == nil && written != len(raw) {
			err = io.ErrShortWrite
		}
	}
	if err == nil {
		err = temp.Sync()
	}
	if closeErr := temp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tempPath, s.path); err != nil {
		return fmt.Errorf("replace ownership provenance: %w", err)
	}
	return nil
}

func (s *FarmRuntimeService) restoreOwnershipProvenance() error {
	if s == nil || s.ownershipStore == nil {
		return nil
	}
	entries, err := s.ownershipStore.Load()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFarmRuntimeOwnershipProvenance, err)
	}
	for _, entry := range entries {
		identity := entry.Runtime
		if identity.NodeUID != s.nodeUID || identity.ProviderInstanceID != s.providerInstance || identity.FencingEpoch != s.fencingEpoch ||
			strings.TrimSpace(identity.ProfileID) == "" || strings.TrimSpace(identity.RuntimeUID) == "" || strings.TrimSpace(identity.ConfigHash) == "" ||
			identity.Generation == 0 || entry.PID <= 0 || entry.DebugPort <= 0 || strings.TrimSpace(entry.ProcessStartIdentity) == "" || strings.TrimSpace(entry.ProfileCreatedAt) == "" {
			continue
		}
		currentStart, readErr := s.readProcessStartIdentity(entry.PID)
		if readErr != nil || currentStart != entry.ProcessStartIdentity {
			continue
		}
		incarnation, restoreErr := s.runtimeService.RestoreProvenRuntimeIdentity(identity.ProfileID, identity.Generation, entry.PID, entry.DebugPort, entry.ProfileCreatedAt)
		if restoreErr != nil {
			continue
		}
		identity.ControllerID = s.controllerID
		identity.ControllerGeneration = s.controllerGeneration
		s.records[identity.ProfileID] = farmRuntimeRecord{
			runtime:            FarmRuntime{FarmRuntimeIdentity: identity, State: FarmRuntimeStateIdle, PID: entry.PID, DebugPort: entry.DebugPort, DebugReady: true, LaunchMode: entry.LaunchMode, ProcessStartIdentity: entry.ProcessStartIdentity, ProfileIncarnation: incarnation},
			profileIncarnation: incarnation, processStartIdentity: entry.ProcessStartIdentity, launchMode: entry.LaunchMode, profileCreatedAt: entry.ProfileCreatedAt,
		}
	}
	return s.persistOwnershipProvenance()
}

func (s *FarmRuntimeService) persistOwnershipProvenance() error {
	if s == nil || s.ownershipStore == nil {
		return nil
	}
	s.ownershipMu.Lock()
	defer s.ownershipMu.Unlock()
	s.recordsMu.RLock()
	entries := make([]FarmRuntimeOwnershipProvenance, 0, len(s.records))
	for _, record := range s.records {
		if record.runtime.State != FarmRuntimeStateIdle && record.runtime.State != FarmRuntimeStateStarting && record.runtime.State != FarmRuntimeStateQuarantined {
			continue
		}
		if record.runtime.PID <= 0 || record.runtime.DebugPort <= 0 || record.processStartIdentity == "" || record.profileCreatedAt == "" {
			continue
		}
		entries = append(entries, FarmRuntimeOwnershipProvenance{
			Runtime: record.runtime.FarmRuntimeIdentity, PID: record.runtime.PID, DebugPort: record.runtime.DebugPort,
			ProcessStartIdentity: record.processStartIdentity, LaunchMode: record.launchMode, ProfileCreatedAt: record.profileCreatedAt,
		})
	}
	s.recordsMu.RUnlock()
	if err := s.ownershipStore.Save(entries); err != nil {
		return fmt.Errorf("%w: %v", ErrFarmRuntimeOwnershipProvenance, err)
	}
	return nil
}
