package proxy

import (
	"ant-chrome/backend/internal/apppath"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func (identity secureRuntimeProcessIdentity) valid() bool {
	return identity.PID > 0 && len(identity.Start) > 0 && len(identity.Start) <= 128 && !strings.ContainsAny(identity.Start, "\x00/\\")
}

func secureRuntimePersistentSecurityDir(appRoot string) (string, string, error) {
	stateRoot := filepath.Clean(strings.TrimSpace(apppath.StateRoot(appRoot)))
	if stateRoot == "." || !filepath.IsAbs(stateRoot) {
		return "", "", fmt.Errorf("%w: invalid application state root", ErrSecureRuntimePath)
	}
	info, err := os.Lstat(stateRoot)
	if err != nil {
		return "", "", fmt.Errorf("inspect application state root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", "", fmt.Errorf("%w: application state root is not a directory", ErrSecureRuntimePath)
	}
	securityDir := filepath.Join(stateRoot, secureRuntimeRegistryDirName)
	if err := secureRuntimeEnsurePrivateDirectory(securityDir); err != nil {
		return "", "", err
	}
	appPath, err := filepath.Abs(strings.TrimSpace(appRoot))
	if err != nil {
		return "", "", fmt.Errorf("resolve application identity: %w", err)
	}
	identity := sha256.Sum256([]byte(filepath.Clean(appPath)))
	return securityDir, hex.EncodeToString(identity[:]), nil
}

func secureRuntimeEnsurePrivateDirectory(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		if err := secureRuntimeCreateDirectory(path); err != nil && !os.IsExist(err) {
			return fmt.Errorf("create secure proxy state directory: %w", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fmt.Errorf("inspect secure proxy state directory after create: %w", err)
		}
	}
	if err != nil {
		return fmt.Errorf("inspect secure proxy state directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: secure proxy state path is not a directory", ErrSecureRuntimePath)
	}
	if err := secureRuntimeRejectReparsePoint(path); err != nil {
		return err
	}
	if err := secureRuntimeCheckOwnerAndMode(path, info.Mode(), true); err != nil {
		return err
	}
	return nil
}

func secureRuntimeLoadOrCreateKey(securityDir string) ([]byte, error) {
	path := filepath.Join(securityDir, secureRuntimeRegistryKeyName)
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fmt.Errorf("%w: secure proxy key is not a regular file", ErrSecureRuntimeAuth)
		}
		if err := secureRuntimeCheckOwnerAndMode(path, info.Mode(), false); err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read secure proxy key: %w", err)
		}
		if len(data) != 32 {
			return nil, fmt.Errorf("%w: invalid secure proxy key length", ErrSecureRuntimeAuth)
		}
		return append([]byte(nil), data...), nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("inspect secure proxy key: %w", err)
	}
	key, err := secureRuntimeRandomBytes(32)
	if err != nil {
		return nil, fmt.Errorf("create secure proxy key: %w", err)
	}
	file, err := secureRuntimeCreateExclusiveFile(path)
	if err != nil {
		if os.IsExist(err) {
			return secureRuntimeLoadOrCreateKey(securityDir)
		}
		return nil, fmt.Errorf("create secure proxy key: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write secure proxy key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync secure proxy key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close secure proxy key: %w", err)
	}
	return key, nil
}

func secureRuntimeRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("invalid random byte size")
	}
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, err
	}
	return data, nil
}

func secureRuntimeMetadataMAC(value interface{}, key []byte) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func secureRuntimeMarkerMAC(marker secureRuntimeMarker, key []byte) (string, error) {
	marker.MAC = ""
	return secureRuntimeMetadataMAC(marker, key)
}

func secureRuntimeRegistryMAC(registry secureRuntimeRegistry, key []byte) (string, error) {
	registry.MAC = ""
	return secureRuntimeMetadataMAC(registry, key)
}

func secureRuntimeVerifyMarker(marker secureRuntimeMarker, key []byte) error {
	if marker.Version != secureRuntimeMarkerVersion || !isSecureRuntimeStack(marker.Stack) || strings.TrimSpace(marker.Root) == "" || !isSecureRuntimeToken(marker.Token) || !marker.Owner.valid() || marker.Pending < 0 || marker.Children == nil || marker.Entries == nil {
		return fmt.Errorf("%w: malformed runtime marker", ErrSecureRuntimeAuth)
	}
	for childKey, child := range marker.Children {
		if !isSecureRuntimeChildKey(childKey) || !child.valid() {
			return fmt.Errorf("%w: malformed child identity", ErrSecureRuntimeAuth)
		}
	}
	for keyName, names := range marker.Entries {
		if err := validateSecureRuntimeKey(keyName); err != nil {
			return err
		}
		seen := make(map[string]struct{}, len(names))
		for _, name := range names {
			if err := validateSecureRuntimeName(name); err != nil {
				return err
			}
			if _, ok := seen[name]; ok {
				return fmt.Errorf("%w: duplicate managed runtime file", ErrSecureRuntimeAuth)
			}
			seen[name] = struct{}{}
		}
	}
	expected, err := secureRuntimeMarkerMAC(marker, key)
	if err != nil || !hmac.Equal([]byte(strings.ToLower(marker.MAC)), []byte(expected)) {
		return ErrSecureRuntimeAuth
	}
	return nil
}

func secureRuntimeVerifyRegistry(registry secureRuntimeRegistry, appID string, key []byte) error {
	if registry.Version != secureRuntimeRegistryVersion || strings.TrimSpace(registry.AppID) == "" || registry.AppID != appID || registry.Roots == nil {
		return fmt.Errorf("%w: malformed runtime registry", ErrSecureRuntimeAuth)
	}
	expected, err := secureRuntimeRegistryMAC(registry, key)
	if err != nil || !hmac.Equal([]byte(strings.ToLower(registry.MAC)), []byte(expected)) {
		return ErrSecureRuntimeAuth
	}
	for root, entry := range registry.Roots {
		if filepath.Base(root) != root || !strings.HasPrefix(root, "ant-proxy-") || !isSecureRuntimeStack(entry.Stack) || !isSecureRuntimeToken(entry.Token) || len(entry.MarkerMAC) != sha256.Size*2 {
			return fmt.Errorf("%w: malformed runtime registry entry", ErrSecureRuntimeAuth)
		}
	}
	return nil
}

func isSecureRuntimeToken(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func isSecureRuntimeChildKey(value string) bool {
	if len(value) != 16 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func secureRuntimeReadMetadata(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > secureRuntimeMaxMetadataBytes {
		return nil, fmt.Errorf("%w: invalid secure proxy metadata file", ErrSecureRuntimeAuth)
	}
	if err := secureRuntimeCheckOwnerAndMode(path, info.Mode(), false); err != nil {
		return nil, err
	}
	return os.ReadFile(path)
}

func secureRuntimeWriteMetadata(path string, data []byte) error {
	parent := filepath.Dir(path)
	parentInfo, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("inspect secure proxy metadata parent: %w", err)
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("%w: metadata parent is not a directory", ErrSecureRuntimeAuth)
	}
	if err := secureRuntimeCheckOwnerAndMode(parent, parentInfo.Mode(), true); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: metadata target is not regular", ErrSecureRuntimeAuth)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	suffix, err := secureRuntimeRandomSuffix()
	if err != nil {
		return err
	}
	tmpPath := filepath.Join(parent, "."+filepath.Base(path)+".tmp-"+suffix)
	tmp, err := secureRuntimeCreateExclusiveFile(tmpPath)
	if err != nil {
		return err
	}
	remove := true
	defer func() {
		_ = tmp.Close()
		if remove {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := secureRuntimeRename(tmpPath, path); err != nil {
		return err
	}
	remove = false
	return nil
}

func secureRuntimeEnsureRegistry(path, appID string, key []byte) error {
	if strings.TrimSpace(path) == "" || strings.TrimSpace(appID) == "" {
		return fmt.Errorf("%w: missing secure proxy registry path", ErrSecureRuntimeAuth)
	}
	data, err := secureRuntimeReadMetadata(path)
	if os.IsNotExist(err) {
		registry := secureRuntimeRegistry{Version: secureRuntimeRegistryVersion, AppID: appID, Roots: map[string]secureRuntimeRegistryEntry{}}
		mac, macErr := secureRuntimeRegistryMAC(registry, key)
		if macErr != nil {
			return macErr
		}
		registry.MAC = mac
		encoded, encodeErr := json.Marshal(registry)
		if encodeErr != nil {
			return encodeErr
		}
		return secureRuntimeWriteMetadata(path, encoded)
	}
	if err != nil {
		return err
	}
	var registry secureRuntimeRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return fmt.Errorf("%w: decode secure proxy registry", ErrSecureRuntimeAuth)
	}
	return secureRuntimeVerifyRegistry(registry, appID, key)
}

func secureRuntimeReadRegistry(path, appID string, key []byte) (secureRuntimeRegistry, error) {
	data, err := secureRuntimeReadMetadata(path)
	if err != nil {
		return secureRuntimeRegistry{}, err
	}
	var registry secureRuntimeRegistry
	if err := json.Unmarshal(data, &registry); err != nil {
		return secureRuntimeRegistry{}, fmt.Errorf("%w: decode secure proxy registry", ErrSecureRuntimeAuth)
	}
	if err := secureRuntimeVerifyRegistry(registry, appID, key); err != nil {
		return secureRuntimeRegistry{}, err
	}
	return registry, nil
}

func secureRuntimeWriteRegistry(path string, registry secureRuntimeRegistry, key []byte) error {
	registry.MAC = ""
	mac, err := secureRuntimeRegistryMAC(registry, key)
	if err != nil {
		return err
	}
	registry.MAC = mac
	data, err := json.Marshal(registry)
	if err != nil {
		return err
	}
	return secureRuntimeWriteMetadata(path, data)
}

func (w *secureRuntimeWriter) initializeAuthenticatedRoot() error {
	if w == nil || !w.sweepEnabled {
		return nil
	}
	tokenBytes, err := secureRuntimeRandomBytes(32)
	if err != nil {
		return fmt.Errorf("create secure proxy runtime ownership token: %w", err)
	}
	rootName := filepath.Base(w.root)
	marker := secureRuntimeMarker{
		Version:  secureRuntimeMarkerVersion,
		Root:     rootName,
		Stack:    w.stack,
		Token:    hex.EncodeToString(tokenBytes),
		Owner:    w.processIdentity,
		Children: map[string]secureRuntimeProcessIdentity{},
		Entries:  map[string][]string{},
	}
	mac, err := secureRuntimeMarkerMAC(marker, w.key)
	if err != nil {
		return err
	}
	marker.MAC = mac
	data, err := json.Marshal(marker)
	if err != nil {
		return err
	}
	markerPath := filepath.Join(w.root, secureRuntimeMarkerName)
	if err := secureRuntimeWriteMetadata(markerPath, data); err != nil {
		return fmt.Errorf("write secure proxy runtime marker: %w", err)
	}
	registry, err := secureRuntimeReadRegistry(w.registryPath, w.appID, w.key)
	if err != nil {
		return err
	}
	if registry.Roots == nil {
		registry.Roots = map[string]secureRuntimeRegistryEntry{}
	}
	registry.Roots[rootName] = secureRuntimeRegistryEntry{Stack: w.stack, Token: marker.Token, MarkerMAC: marker.MAC}
	if err := secureRuntimeWriteRegistry(w.registryPath, registry, w.key); err != nil {
		return fmt.Errorf("register secure proxy runtime root: %w", err)
	}
	w.rootToken = marker.Token
	return nil
}

func (w *secureRuntimeWriter) updateRootMetadata(mutator func(*secureRuntimeMarker)) error {
	if w == nil || !w.sweepEnabled {
		return nil
	}
	lock, err := secureRuntimeAcquireSweepLock(w.lockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	markerPath := filepath.Join(w.root, secureRuntimeMarkerName)
	data, err := secureRuntimeReadMetadata(markerPath)
	if err != nil {
		return err
	}
	var marker secureRuntimeMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("%w: decode secure proxy runtime marker", ErrSecureRuntimeAuth)
	}
	if marker.Root != filepath.Base(w.root) || marker.Stack != w.stack || marker.Token != w.rootToken {
		return ErrSecureRuntimeAuth
	}
	if err := secureRuntimeVerifyMarker(marker, w.key); err != nil {
		return err
	}
	if mutator != nil {
		mutator(&marker)
	}
	if marker.Children == nil {
		marker.Children = map[string]secureRuntimeProcessIdentity{}
	}
	if marker.Entries == nil {
		marker.Entries = map[string][]string{}
	}
	marker.MAC, err = secureRuntimeMarkerMAC(marker, w.key)
	if err != nil {
		return err
	}
	data, err = json.Marshal(marker)
	if err != nil {
		return err
	}
	if err := secureRuntimeWriteMetadata(markerPath, data); err != nil {
		return err
	}
	registry, err := secureRuntimeReadRegistry(w.registryPath, w.appID, w.key)
	if err != nil {
		return err
	}
	entry, ok := registry.Roots[marker.Root]
	if !ok || entry.Stack != marker.Stack || entry.Token != marker.Token {
		return ErrSecureRuntimeAuth
	}
	entry.MarkerMAC = marker.MAC
	registry.Roots[marker.Root] = entry
	return secureRuntimeWriteRegistry(w.registryPath, registry, w.key)
}

func secureRuntimeSweepLocked(tempParent, stack, appID, registryPath string, key []byte, processLiveness func(secureRuntimeProcessIdentity) secureRuntimeProcessState, ownerCheck func(string, os.FileMode, bool) error) error {
	if !secureRuntimeOrphanSweepSupported() {
		return ErrSecureRuntimeSweepUnsupported
	}
	if strings.TrimSpace(registryPath) == "" || len(key) == 0 {
		return ErrSecureRuntimeAuth
	}
	registry, err := secureRuntimeReadRegistry(registryPath, appID, key)
	if err != nil {
		return err
	}
	parentInfo, err := os.Lstat(tempParent)
	if err != nil {
		return err
	}
	if parentInfo.Mode()&os.ModeSymlink != 0 || !parentInfo.IsDir() {
		return fmt.Errorf("%w: secure proxy temp parent is not a directory", ErrSecureRuntimePath)
	}
	entries, err := os.ReadDir(tempParent)
	if err != nil {
		return err
	}
	prefix := "ant-proxy-" + stack + "-"
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, prefix) || name == prefix || filepath.Base(name) != name {
			continue
		}
		rootPath := filepath.Join(tempParent, name)
		rootInfo, statErr := os.Lstat(rootPath)
		if statErr != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
			continue
		}
		if ownerCheck == nil || ownerCheck(rootPath, rootInfo.Mode(), true) != nil {
			continue
		}
		registryEntry, registered := registry.Roots[name]
		if !registered || registryEntry.Stack != stack || !isSecureRuntimeToken(registryEntry.Token) {
			continue
		}
		markerPath := filepath.Join(rootPath, secureRuntimeMarkerName)
		markerData, markerErr := secureRuntimeReadMetadata(markerPath)
		if markerErr != nil {
			continue
		}
		var marker secureRuntimeMarker
		if json.Unmarshal(markerData, &marker) != nil || marker.Root != name || marker.Stack != stack || marker.Token != registryEntry.Token || marker.MAC != registryEntry.MarkerMAC || secureRuntimeVerifyMarker(marker, key) != nil {
			continue
		}
		if processLiveness == nil || secureRuntimeProcessTerminal(marker.Owner, processLiveness) != true || marker.Pending != 0 {
			continue
		}
		allChildrenTerminal := true
		for _, child := range marker.Children {
			if !secureRuntimeProcessTerminal(child, processLiveness) {
				allChildrenTerminal = false
				break
			}
		}
		if !allChildrenTerminal {
			continue
		}
		if !secureRuntimeRemoveAuthenticatedRoot(rootPath, marker, ownerCheck) {
			continue
		}
		delete(registry.Roots, name)
	}
	// Registry update is itself authenticated and atomic. A failure here can
	// only leave a stale registry entry; it never broadens deletion scope.
	return secureRuntimeWriteRegistry(registryPath, registry, key)
}

func secureRuntimeProcessTerminal(identity secureRuntimeProcessIdentity, liveness func(secureRuntimeProcessIdentity) secureRuntimeProcessState) bool {
	if !identity.valid() || liveness == nil {
		return false
	}
	return liveness(identity) == secureRuntimeProcessExited
}

func secureRuntimeRemoveAuthenticatedRoot(rootPath string, marker secureRuntimeMarker, ownerCheck func(string, os.FileMode, bool) error) bool {
	rootInfo, err := os.Lstat(rootPath)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() || ownerCheck == nil || ownerCheck(rootPath, rootInfo.Mode(), true) != nil {
		return false
	}
	rootEntries, err := os.ReadDir(rootPath)
	if err != nil {
		return false
	}
	knownDirs := make(map[string]struct{}, len(marker.Entries))
	for keyName := range marker.Entries {
		knownDirs[keyName] = struct{}{}
	}
	for _, entry := range rootEntries {
		name := entry.Name()
		if name == secureRuntimeMarkerName {
			continue
		}
		if _, ok := knownDirs[name]; !ok {
			return false
		}
	}
	for keyName, names := range marker.Entries {
		dir := filepath.Join(rootPath, keyName)
		dirInfo, err := os.Lstat(dir)
		if err != nil || dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() || ownerCheck(dir, dirInfo.Mode(), true) != nil {
			return false
		}
		allowed := make(map[string]struct{}, len(names))
		for _, name := range names {
			allowed[name] = struct{}{}
		}
		fileEntries, err := os.ReadDir(dir)
		if err != nil {
			return false
		}
		for _, entry := range fileEntries {
			if _, ok := allowed[entry.Name()]; !ok {
				return false
			}
		}
		for _, name := range names {
			path := filepath.Join(dir, name)
			info, err := os.Lstat(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || ownerCheck(path, info.Mode(), false) != nil {
				return false
			}
			if err := os.Remove(path); err != nil {
				return false
			}
		}
		if remaining, err := os.ReadDir(dir); err != nil || len(remaining) != 0 || os.Remove(dir) != nil {
			return false
		}
	}
	markerInfo, err := os.Lstat(filepath.Join(rootPath, secureRuntimeMarkerName))
	if err != nil || markerInfo.Mode()&os.ModeSymlink != 0 || !markerInfo.Mode().IsRegular() || ownerCheck(filepath.Join(rootPath, secureRuntimeMarkerName), markerInfo.Mode(), false) != nil {
		return false
	}
	if err := os.Remove(filepath.Join(rootPath, secureRuntimeMarkerName)); err != nil {
		return false
	}
	return os.Remove(rootPath) == nil
}

func (w *secureRuntimeWriter) removeRootIfEmpty() error {
	if w == nil || !w.sweepEnabled {
		return nil
	}
	lock, err := secureRuntimeAcquireSweepLock(w.lockPath)
	if err != nil {
		return err
	}
	defer lock.Close()
	markerPath := filepath.Join(w.root, secureRuntimeMarkerName)
	data, err := secureRuntimeReadMetadata(markerPath)
	if err != nil {
		return err
	}
	var marker secureRuntimeMarker
	if err := json.Unmarshal(data, &marker); err != nil {
		return fmt.Errorf("%w: decode secure proxy runtime marker", ErrSecureRuntimeAuth)
	}
	if marker.Root != filepath.Base(w.root) || marker.Stack != w.stack || marker.Token != w.rootToken || marker.Pending != 0 || len(marker.Children) != 0 || len(marker.Entries) != 0 {
		return nil
	}
	if err := secureRuntimeVerifyMarker(marker, w.key); err != nil {
		return err
	}
	entries, err := os.ReadDir(w.root)
	if err != nil {
		return err
	}
	if len(entries) != 1 || entries[0].Name() != secureRuntimeMarkerName {
		return nil
	}
	if err := os.Remove(markerPath); err != nil {
		return err
	}
	if err := os.Remove(w.root); err != nil {
		return err
	}
	registry, err := secureRuntimeReadRegistry(w.registryPath, w.appID, w.key)
	if err != nil {
		return err
	}
	delete(registry.Roots, filepath.Base(w.root))
	return secureRuntimeWriteRegistry(w.registryPath, registry, w.key)
}
