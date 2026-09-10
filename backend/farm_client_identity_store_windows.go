//go:build windows

package backend

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NewFarmClientIdentityStore stores only a DPAPI-protected seed. DPAPI's
// default user scope binds decryption to the current Windows user; there is no
// plaintext fallback and the ciphertext file is not itself an identity source.
func NewFarmClientIdentityStore(root string) (FarmClientIdentityStore, error) {
	if err := validateFarmClientIdentityStoreRoot(root); err != nil {
		return nil, err
	}
	return &windowsFarmClientIdentityStore{root: filepath.Clean(root)}, nil
}

type windowsFarmClientIdentityStore struct {
	root string
}

func (s *windowsFarmClientIdentityStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	path, err := farmClientIdentityFilePath(s.root, ref)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	if err != nil {
		return nil, ErrFarmClientIdentityStore
	}
	decrypted, decryptErr := windowsFarmClientDPAPIUnprotect(data)
	clearBytes(data)
	if decryptErr != nil {
		return nil, decryptErr
	}
	key, seed, normalizeErr := normalizeFarmClientIdentityKey(decrypted)
	clearBytes(decrypted)
	if seed != nil {
		clearBytes(seed)
	}
	if normalizeErr != nil {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	return key, nil
}

func (s *windowsFarmClientIdentityStore) Save(ref FarmClientIdentityKeyRef, raw []byte) error {
	path, err := farmClientIdentityFilePath(s.root, ref)
	if err != nil {
		return err
	}
	normalized, seed, err := normalizeFarmClientIdentityKey(raw)
	if err != nil {
		return err
	}
	defer clearBytes(normalized)
	defer clearBytes(seed)
	if existing, loadErr := s.Load(ref); loadErr == nil {
		defer clearBytes(existing)
		if equalBytes(existing[:ed25519.SeedSize], seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	} else if !errors.Is(loadErr, ErrFarmClientIdentityKeyNotFound) {
		return farmClientIdentityStoreError(loadErr)
	}
	if err := os.MkdirAll(filepath.Dir(path), farmClientIdentityDirMode); err != nil {
		return ErrFarmClientIdentityStore
	}
	protected, err := windowsFarmClientDPAPIProtect(seed)
	if err != nil {
		return err
	}
	defer clearBytes(protected)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, farmClientIdentityFileMode)
	if errors.Is(err, os.ErrExist) {
		return s.Save(ref, seed)
	}
	if err != nil {
		return ErrFarmClientIdentityStore
	}
	written, err := file.Write(protected)
	if err != nil || written != len(protected) {
		_ = file.Close()
		_ = os.Remove(path)
		return ErrFarmClientIdentityStore
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return ErrFarmClientIdentityStore
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return ErrFarmClientIdentityStore
	}
	return nil
}

func (s *windowsFarmClientIdentityStore) Delete(ref FarmClientIdentityKeyRef) error {
	path, err := farmClientIdentityFilePath(s.root, ref)
	if err != nil {
		return err
	}
	if info, statErr := os.Lstat(path); statErr == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return ErrFarmClientIdentityKeyCorrupt
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrFarmClientIdentityStore
	}
	return nil
}

func windowsFarmClientDPAPIProtect(seed []byte) ([]byte, error) {
	in, entropy, err := windowsFarmClientDPAPIInputs(seed)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil || out.Data == nil || out.Size == 0 {
		return nil, ErrFarmClientIdentityStoreUnavailable
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func windowsFarmClientDPAPIUnprotect(ciphertext []byte) ([]byte, error) {
	in, entropy, err := windowsFarmClientDPAPIInputs(ciphertext)
	if err != nil {
		return nil, err
	}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil || out.Data == nil || out.Size == 0 {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func windowsFarmClientDPAPIInputs(data []byte) (windows.DataBlob, windows.DataBlob, error) {
	if len(data) == 0 {
		return windows.DataBlob{}, windows.DataBlob{}, ErrFarmClientIdentityKeyCorrupt
	}
	entropy := []byte("ant-farm-client-device-key-v1")
	return windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}, windows.DataBlob{Size: uint32(len(entropy)), Data: &entropy[0]}, nil
}
