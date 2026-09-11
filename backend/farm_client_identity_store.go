package backend

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

var (
	ErrFarmClientIdentityStore            = errors.New("farm client identity store error")
	ErrFarmClientIdentityKeyRef           = errors.New("invalid farm client identity key reference")
	ErrFarmClientIdentityKeyNotFound      = errors.New("farm client identity key not found")
	ErrFarmClientIdentityKeyCorrupt       = errors.New("farm client identity key is corrupt")
	ErrFarmClientIdentityKeyConflict      = errors.New("farm client identity key conflicts with existing identity")
	ErrFarmClientIdentityStoreUnavailable = errors.New("farm client identity store unavailable")
	// Unsupported is an internal capability signal used to select the Linux
	// file fallback. It is collapsed to StoreUnavailable at public boundaries.
	ErrFarmClientIdentityStoreUnsupported = errors.New("farm client identity store unsupported")
)

const (
	farmClientIdentityStoreDir  = ".ant-farm-client-identities"
	farmClientIdentityFileMode  = 0o600
	farmClientIdentityDirMode   = 0o700
	farmClientIdentityMaxRefLen = 128
)

// FarmClientIdentityKeyRef is an opaque, validated account label. It is not a
// path and never contains key material. Native stores use it as their account
// identity; the Linux file fallback hashes it before constructing a filename.
type FarmClientIdentityKeyRef string

// FarmClientIdentityStore persists one Ed25519 identity per validated opaque
// reference. Implementations must store a 32-byte seed (never plaintext on
// native stores) and return a copied expanded private key from Load.
type FarmClientIdentityStore interface {
	Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error)
	Save(ref FarmClientIdentityKeyRef, key []byte) error
	Delete(ref FarmClientIdentityKeyRef) error
}

// FarmClientNativeIdentityStore is the injectable native Secret Service seam
// used by Linux. Production supplies its D-Bus backend when a session bus is
// present; tests can inject capability, lock and failure states precisely.
type FarmClientNativeIdentityStore interface {
	Load(ref FarmClientIdentityKeyRef) (ed25519.PrivateKey, error)
	Save(ref FarmClientIdentityKeyRef, key []byte) error
	Delete(ref FarmClientIdentityKeyRef) error
}

func NewFarmClientIdentityKeyRef(value string) (FarmClientIdentityKeyRef, error) {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > farmClientIdentityMaxRefLen || !utf8.ValidString(value) {
		return "", ErrFarmClientIdentityKeyRef
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '/' || r == rune(92) {
			return "", ErrFarmClientIdentityKeyRef
		}
	}
	return FarmClientIdentityKeyRef(value), nil
}

func validateFarmClientIdentityKeyRef(ref FarmClientIdentityKeyRef) error {
	parsed, err := NewFarmClientIdentityKeyRef(string(ref))
	if err != nil || parsed != ref {
		return ErrFarmClientIdentityKeyRef
	}
	return nil
}

// normalizeFarmClientIdentityKey validates either a seed or an expanded key,
// verifies expanded-key consistency, and returns a fresh 64-byte key plus a
// fresh 32-byte seed. Callers should clear both returned buffers when done.
func normalizeFarmClientIdentityKey(raw []byte) (ed25519.PrivateKey, []byte, error) {
	switch len(raw) {
	case ed25519.SeedSize:
		seed := append([]byte(nil), raw...)
		return ed25519.NewKeyFromSeed(seed), seed, nil
	case ed25519.PrivateKeySize:
		key := append(ed25519.PrivateKey(nil), raw...)
		derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
		if !equalBytes(derived[ed25519.SeedSize:], key[ed25519.SeedSize:]) {
			clearBytes(derived)
			clearBytes(key)
			return nil, nil, ErrFarmClientIdentityKeyCorrupt
		}
		return key, append([]byte(nil), key[:ed25519.SeedSize]...), nil
	default:
		return nil, nil, ErrFarmClientIdentityKeyCorrupt
	}
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	var diff byte
	for index := range left {
		diff |= left[index] ^ right[index]
	}
	return diff == 0
}

func clearBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func validateFarmClientIdentityStoreRoot(root string) error {
	root = strings.TrimSpace(root)
	if root == "" || !filepath.IsAbs(root) {
		return ErrFarmClientIdentityStore
	}
	return nil
}

func farmClientIdentityFilePath(root string, ref FarmClientIdentityKeyRef) (string, error) {
	if err := validateFarmClientIdentityStoreRoot(root); err != nil {
		return "", err
	}
	if err := validateFarmClientIdentityKeyRef(ref); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(ref))
	return filepath.Join(filepath.Clean(root), farmClientIdentityStoreDir, hex.EncodeToString(digest[:])+".seed"), nil
}

func farmClientIdentityStoreError(err error) error {
	switch {
	case errors.Is(err, ErrFarmClientIdentityKeyRef):
		return ErrFarmClientIdentityKeyRef
	case errors.Is(err, ErrFarmClientIdentityKeyNotFound):
		return ErrFarmClientIdentityKeyNotFound
	case errors.Is(err, ErrFarmClientIdentityKeyCorrupt):
		return ErrFarmClientIdentityKeyCorrupt
	case errors.Is(err, ErrFarmClientIdentityKeyConflict):
		return ErrFarmClientIdentityKeyConflict
	case errors.Is(err, ErrFarmClientIdentityStoreUnavailable):
		return ErrFarmClientIdentityStoreUnavailable
	case errors.Is(err, ErrFarmClientIdentityStoreUnsupported):
		return ErrFarmClientIdentityStoreUnavailable
	default:
		return ErrFarmClientIdentityStore
	}
}

func farmClientIdentityStableError(err error) error {
	if err == nil {
		return nil
	}
	return farmClientIdentityStoreError(fmt.Errorf("%w", err))
}

func farmClientIdentityPublicKey(key ed25519.PrivateKey) ed25519.PublicKey {
	if len(key) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), key[ed25519.SeedSize:]...)
}

func farmClientIdentityFileModeOK(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm() == farmClientIdentityFileMode
}
