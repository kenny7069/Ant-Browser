//go:build linux

package backend

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// NewFarmClientIdentityStore prefers the current user's Secret Service over
// D-Bus and falls back to the strict owner-only file store when the desktop
// secret service is absent or unavailable.
func NewFarmClientIdentityStore(root string) (FarmClientIdentityStore, error) {
	return NewFarmClientIdentityStoreWithNative(root, newLinuxFarmClientSecretServiceStore())
}

func NewFarmClientIdentityStoreWithNative(root string, native FarmClientNativeIdentityStore) (FarmClientIdentityStore, error) {
	if err := validateFarmClientIdentityStoreRoot(root); err != nil {
		return nil, err
	}
	return &linuxFarmClientIdentityStore{root: filepath.Clean(root), native: native}, nil
}

type linuxFarmClientIdentityStore struct {
	root   string
	native FarmClientNativeIdentityStore
}

func (s *linuxFarmClientIdentityStore) Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return nil, err
	}
	// An existing fallback file is an explicit backend pin. Never let a later
	// Secret Service appearance silently change the selected device identity.
	if key, err := linuxFarmClientIdentityFileLoad(s.root, ref); err == nil {
		return key, nil
	} else if !errors.Is(err, ErrFarmClientIdentityKeyNotFound) {
		return nil, farmClientIdentityStoreError(err)
	}
	if s.native != nil {
		key, err := s.native.Load(ref)
		switch {
		case err == nil:
			return normalizeLoadedFarmClientIdentityKey(key)
		case errors.Is(err, ErrFarmClientIdentityKeyNotFound), errors.Is(err, ErrFarmClientIdentityStoreUnsupported):
			return nil, ErrFarmClientIdentityKeyNotFound
		default:
			return nil, farmClientIdentityStoreError(err)
		}
	}
	return nil, ErrFarmClientIdentityKeyNotFound
}

func (s *linuxFarmClientIdentityStore) Save(ref FarmClientIdentityKeyRef, key []byte) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	normalized, seed, err := normalizeFarmClientIdentityKey(key)
	if err != nil {
		return err
	}
	defer clearBytes(normalized)
	defer clearBytes(seed)
	// Check the pinned fallback before writing anywhere. This prevents a newly
	// available Secret Service from superseding an earlier fallback identity.
	if existing, loadErr := linuxFarmClientIdentityFileLoad(s.root, ref); loadErr == nil {
		defer clearBytes(existing)
		if equalBytes(existing[:ed25519.SeedSize], seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	} else if !errors.Is(loadErr, ErrFarmClientIdentityKeyNotFound) {
		return farmClientIdentityStoreError(loadErr)
	}
	if s.native != nil {
		err = s.native.Save(ref, seed)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrFarmClientIdentityStoreUnsupported) {
			return farmClientIdentityStoreError(err)
		}
	}
	return linuxFarmClientIdentityFileSave(s.root, ref, seed)
}

func (s *linuxFarmClientIdentityStore) Delete(ref FarmClientIdentityKeyRef) error {
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return err
	}
	if _, fileErr := linuxFarmClientIdentityFileLoad(s.root, ref); fileErr == nil {
		return linuxFarmClientIdentityFileDelete(s.root, ref)
	} else if !errors.Is(fileErr, ErrFarmClientIdentityKeyNotFound) {
		return farmClientIdentityStoreError(fileErr)
	}
	if s.native != nil {
		err := s.native.Delete(ref)
		if err == nil || errors.Is(err, ErrFarmClientIdentityKeyNotFound) || errors.Is(err, ErrFarmClientIdentityStoreUnsupported) {
			return nil
		}
		return farmClientIdentityStoreError(err)
	}
	return nil
}

func normalizeLoadedFarmClientIdentityKey(key ed25519.PrivateKey) (ed25519.PrivateKey, error) {
	normalized, seed, err := normalizeFarmClientIdentityKey(key)
	if seed != nil {
		clearBytes(seed)
	}
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func linuxFarmClientIdentityFileLoad(root string, ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error) {
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		return nil, err
	}
	if dirInfo, dirErr := os.Lstat(filepath.Dir(path)); dirErr == nil {
		if !linuxFarmClientIdentityDirOK(dirInfo) {
			return nil, ErrFarmClientIdentityKeyCorrupt
		}
	} else if errors.Is(dirErr, os.ErrNotExist) {
		return nil, ErrFarmClientIdentityKeyNotFound
	} else {
		return nil, ErrFarmClientIdentityStore
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrFarmClientIdentityKeyNotFound
	}
	if err != nil || !farmClientIdentityFileModeOK(info) || !linuxFarmClientIdentityOwnerOK(info) {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) != ed25519.SeedSize {
		clearBytes(data)
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	key, seed, normalizeErr := normalizeFarmClientIdentityKey(data)
	clearBytes(data)
	if seed != nil {
		clearBytes(seed)
	}
	if normalizeErr != nil {
		return nil, ErrFarmClientIdentityKeyCorrupt
	}
	return key, nil
}

func linuxFarmClientIdentityFileSave(root string, ref FarmClientIdentityKeyRef, seed []byte) error {
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, farmClientIdentityDirMode); err != nil {
		return ErrFarmClientIdentityStore
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil || !linuxFarmClientIdentityDirOK(dirInfo) {
		return ErrFarmClientIdentityStore
	}
	if err := os.Chmod(dir, farmClientIdentityDirMode); err != nil {
		return ErrFarmClientIdentityStore
	}
	file, err := os.CreateTemp(dir, ".identity-*.tmp")
	if err != nil {
		return ErrFarmClientIdentityStore
	}
	tempPath := file.Name()
	defer os.Remove(tempPath)
	if err := file.Chmod(farmClientIdentityFileMode); err != nil {
		_ = file.Close()
		return ErrFarmClientIdentityStore
	}
	written, err := file.Write(seed)
	if err != nil || written != len(seed) {
		_ = file.Close()
		return ErrFarmClientIdentityStore
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return ErrFarmClientIdentityStore
	}
	if err := file.Close(); err != nil {
		return ErrFarmClientIdentityStore
	}
	if err := os.Link(tempPath, path); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return ErrFarmClientIdentityStore
		}
		existing, loadErr := linuxFarmClientIdentityFileLoad(root, ref)
		if loadErr != nil {
			return farmClientIdentityStoreError(loadErr)
		}
		defer clearBytes(existing)
		if equalBytes(existing[:ed25519.SeedSize], seed) {
			return nil
		}
		return ErrFarmClientIdentityKeyConflict
	}
	return linuxFarmClientIdentitySyncDir(dir)
}

func linuxFarmClientIdentityFileDelete(root string, ref FarmClientIdentityKeyRef) error {
	path, err := farmClientIdentityFilePath(root, ref)
	if err != nil {
		return err
	}
	if dirInfo, dirErr := os.Lstat(filepath.Dir(path)); dirErr != nil {
		if errors.Is(dirErr, os.ErrNotExist) {
			return nil
		}
		return ErrFarmClientIdentityStore
	} else if !linuxFarmClientIdentityDirOK(dirInfo) {
		return ErrFarmClientIdentityKeyCorrupt
	}
	info, statErr := os.Lstat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		return nil
	}
	if statErr != nil || !farmClientIdentityFileModeOK(info) || !linuxFarmClientIdentityOwnerOK(info) {
		return ErrFarmClientIdentityKeyCorrupt
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return ErrFarmClientIdentityStore
	}
	return linuxFarmClientIdentitySyncDir(filepath.Dir(path))
}

func linuxFarmClientIdentitySyncDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return ErrFarmClientIdentityStore
	}
	defer file.Close()
	if err := file.Sync(); err != nil {
		return ErrFarmClientIdentityStore
	}
	return nil
}

func linuxFarmClientIdentityOwnerOK(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint32(stat.Uid) == uint32(os.Getuid())
}

func linuxFarmClientIdentityDirOK(info os.FileInfo) bool {
	return info != nil && info.IsDir() && info.Mode().Perm() == farmClientIdentityDirMode &&
		info.Mode()&os.ModeSymlink == 0 && linuxFarmClientIdentityOwnerOK(info)
}
