//go:build linux

package backend

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	dbus "github.com/godbus/dbus/v5"
	keyring "github.com/zalando/go-keyring"
)

const linuxFarmClientSecretServiceName = "ant-browser/farm-client/device-key/v1"

// The upstream keyring implementation talks to org.freedesktop.secrets over
// D-Bus. A process mutex prevents its replace-on-save behavior from violating
// our no-overwrite identity contract within one client process. The CLI also
// holds the state-root instance lock to cover separate client processes.
type linuxFarmClientSecretServiceStore struct {
	mu     sync.Mutex
	get    func(string, string) (string, error)
	set    func(string, string, string) error
	delete func(string, string) error
}

func newLinuxFarmClientSecretServiceStore() FarmClientNativeIdentityStore {
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return nil
	}
	return &linuxFarmClientSecretServiceStore{get: keyring.Get, set: keyring.Set, delete: keyring.Delete}
}

func (s *linuxFarmClientSecretServiceStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load(ref)
}

func (s *linuxFarmClientSecretServiceStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	key, seed, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	defer clearBytes(key)
	defer clearBytes(seed)
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, err := acquireLinuxFarmClientIdentityGlobalLock(ref)
	if err != nil {
		return err
	}
	defer releaseLinuxFarmClientIdentityGlobalLock(lock)
	existing, loadErr := s.load(ref)
	if loadErr == nil {
		defer clearBytes(existing)
		if equalBytes(existing[:ed25519.SeedSize], seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	}
	if !errors.Is(loadErr, ErrFarmClientIdentityKeyNotFound) {
		return farmClientIdentityStoreError(loadErr)
	}
	encoded := base64.StdEncoding.EncodeToString(seed)
	if err := s.set(linuxFarmClientSecretServiceName, string(ref), encoded); err != nil {
		return linuxFarmClientSecretServiceError(err)
	}
	return nil
}

func (s *linuxFarmClientSecretServiceStore) Delete(ref FarmClientIdentityKeyRef) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	lock, lockErr := acquireLinuxFarmClientIdentityGlobalLock(ref)
	if lockErr != nil {
		return lockErr
	}
	defer releaseLinuxFarmClientIdentityGlobalLock(lock)
	err := s.delete(linuxFarmClientSecretServiceName, string(ref))
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return linuxFarmClientSecretServiceError(err)
}

func (s *linuxFarmClientSecretServiceStore) load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	encoded, err := s.get(linuxFarmClientSecretServiceName, string(ref))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	if err != nil {
		return nil, linuxFarmClientSecretServiceError(err)
	}
	seed, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(seed) != ed25519.SeedSize || base64.StdEncoding.EncodeToString(seed) != encoded {
		clearBytes(seed)
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	key := ed25519.NewKeyFromSeed(seed)
	clearBytes(seed)
	return key, nil
}

func linuxFarmClientSecretServiceError(err error) error {
	if err == nil {
		return nil
	}
	if strings.TrimSpace(os.Getenv("DBUS_SESSION_BUS_ADDRESS")) == "" {
		return ErrFarmClientIdentityStoreUnsupported
	}
	var dbusErr *dbus.Error
	if errors.As(err, &dbusErr) {
		switch dbusErr.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner":
			return ErrFarmClientIdentityStoreUnsupported
		}
	}
	return ErrFarmClientIdentityStoreUnavailable
}

func acquireLinuxFarmClientIdentityGlobalLock(ref FarmClientIdentityKeyRef) (*os.File, error) {
	dir := filepath.Join("/tmp", "ant-farm-client-"+strconv.Itoa(os.Getuid())+"-identity-locks")
	if err := os.MkdirAll(dir, farmClientIdentityDirMode); err != nil {
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	if info, err := os.Lstat(dir); err != nil || !linuxFarmClientIdentityDirOK(info) {
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	digest := sha256.Sum256([]byte(ref))
	path := filepath.Join(dir, hex.EncodeToString(digest[:])+".lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, farmClientIdentityFileMode)
	if err != nil {
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		_ = file.Close()
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	return file, nil
}

func releaseLinuxFarmClientIdentityGlobalLock(file *os.File) {
	if file == nil {
		return
	}
	_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
	_ = file.Close()
}
