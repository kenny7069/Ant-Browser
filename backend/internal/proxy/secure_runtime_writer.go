package proxy

import (
	"crypto/rand"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

const (
	secureRuntimeDirMode  = 0o700
	secureRuntimeFileMode = 0o600
	secureRuntimeMaxKey   = 128
	secureRuntimeMaxName  = 128
)

var (
	// ErrSecureRuntimeActive prevents cleanup from removing files while a core
	// process may still have the runtime config open.
	ErrSecureRuntimeActive = errors.New("secure proxy runtime is still active")
	ErrSecureRuntimePath   = errors.New("invalid secure proxy runtime path")
	ErrSecureRuntimeStack  = errors.New("invalid secure proxy connector stack")
)

var sensitiveLogValuePattern = regexp.MustCompile(`(?i)(password|passwd|pass|token|secret|credential|auth(?:[_-]?str)?|access[_-]?token|api[_-]?key)(\s*[=:]\s*)(?:"[^"]*"|'[^']*'|[^\s&,;]+)`)
var sensitiveJSONValuePattern = regexp.MustCompile(`(?i)((?:"|')(?:password|passwd|pass|token|secret|credential|auth(?:[_-]?str)?|access[_-]?token|api[_-]?key)(?:"|')\s*:\s*)(?:"[^"]*"|'[^']*'|[^,\s}]+)`)
var proxyURIValuePattern = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]{1,31})://[^\s"'<>]+`)

// secureRuntimeWriter owns one isolated temporary runtime root for exactly
// one connector stack. It deliberately does not accept an application data
// directory: proxy credentials must never be written into a user profile.
type secureRuntimeWriter struct {
	stack string
	root  string

	mu      sync.Mutex
	entries map[string]*secureRuntimeHandle
}

// secureRuntimeHandle is the only cleanup capability returned by the writer.
// A path alone is not sufficient to authorize deletion.
type secureRuntimeHandle struct {
	writer *secureRuntimeWriter
	key    string
	dir    string

	mu          sync.Mutex
	files       map[string]struct{}
	active      bool
	activeToken uint64
	nextToken   uint64
	cleaned     bool
}

func newSecureRuntimeWriter(stack string) (*secureRuntimeWriter, error) {
	stack = strings.ToLower(strings.TrimSpace(stack))
	if !isSecureRuntimeStack(stack) {
		return nil, fmt.Errorf("%w: %q", ErrSecureRuntimeStack, stack)
	}

	tempParent := filepath.Clean(os.TempDir())
	if tempParent == "." || !filepath.IsAbs(tempParent) {
		return nil, fmt.Errorf("%w: invalid system temporary directory", ErrSecureRuntimePath)
	}
	var root string
	for attempt := 0; attempt < 8; attempt++ {
		suffix, suffixErr := secureRuntimeRandomSuffix()
		if suffixErr != nil {
			return nil, fmt.Errorf("create secure proxy runtime name: %w", suffixErr)
		}
		candidate := filepath.Join(tempParent, "ant-proxy-"+stack+"-"+suffix)
		if createErr := secureRuntimeCreateDirectory(candidate); createErr != nil {
			if os.IsExist(createErr) {
				continue
			}
			return nil, fmt.Errorf("create secure proxy runtime root: %w", createErr)
		}
		root = candidate
		break
	}
	if root == "" {
		return nil, fmt.Errorf("create secure proxy runtime root: too many name collisions")
	}
	return &secureRuntimeWriter{
		stack:   stack,
		root:    root,
		entries: make(map[string]*secureRuntimeHandle),
	}, nil
}

func isSecureRuntimeStack(stack string) bool {
	switch strings.ToLower(strings.TrimSpace(stack)) {
	case "xray", "singbox", "mihomo":
		return true
	default:
		return false
	}
}

func (w *secureRuntimeWriter) runtimeDir(key string) (string, error) {
	handle, err := w.ensureHandle(key)
	if err != nil {
		return "", err
	}
	return handle.dir, nil
}

// runtimeDirIfExists resolves an already-owned runtime directory for
// diagnostics without creating a new credentials-bearing directory as a side
// effect of a read-only request.
func (w *secureRuntimeWriter) runtimeDirIfExists(key string) string {
	if w == nil || validateSecureRuntimeKey(key) != nil {
		return ""
	}
	w.mu.Lock()
	handle := w.entries[key]
	w.mu.Unlock()
	if handle != nil && !handle.isCleaned() {
		if info, err := os.Lstat(handle.dir); err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return handle.dir
		}
		return ""
	}
	rootInfo, err := os.Lstat(w.root)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return ""
	}
	dir := filepath.Join(w.root, key)
	if err := w.validateOwnedPath(dir, true); err != nil {
		return ""
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ""
	}
	return dir
}

func (w *secureRuntimeWriter) handle(key string) (*secureRuntimeHandle, error) {
	if w == nil {
		return nil, ErrSecureRuntimePath
	}
	if err := validateSecureRuntimeKey(key); err != nil {
		return nil, err
	}
	w.mu.Lock()
	handle := w.entries[key]
	w.mu.Unlock()
	if handle == nil || handle.isCleaned() {
		return w.ensureHandle(key)
	}
	return handle, nil
}

func (w *secureRuntimeWriter) ensureHandle(key string) (*secureRuntimeHandle, error) {
	if w == nil || strings.TrimSpace(w.root) == "" {
		return nil, ErrSecureRuntimePath
	}
	if err := validateSecureRuntimeKey(key); err != nil {
		return nil, err
	}
	if err := w.verifyRoot(); err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.verifyRoot(); err != nil {
		return nil, err
	}
	if existing := w.entries[key]; existing != nil {
		return existing, nil
	}

	dir := filepath.Join(w.root, key)
	if err := w.validateOwnedPath(dir, true); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(dir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("%w: runtime directory is not an owned directory", ErrSecureRuntimePath)
		}
		if err := secureRuntimeApplyPermissions(dir, true); err != nil {
			return nil, err
		}
	} else if os.IsNotExist(err) {
		if err := secureRuntimeCreateDirectory(dir); err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("inspect secure proxy runtime directory: %w", err)
	}

	handle := &secureRuntimeHandle{
		writer: w,
		key:    key,
		dir:    dir,
		files:  make(map[string]struct{}),
	}
	w.entries[key] = handle
	return handle, nil
}

func (w *secureRuntimeWriter) verifyRoot() error {
	info, err := os.Lstat(w.root)
	if os.IsNotExist(err) {
		if createErr := secureRuntimeCreateDirectory(w.root); createErr != nil && !os.IsExist(createErr) {
			return fmt.Errorf("recreate secure proxy runtime root: %w", createErr)
		}
		info, err = os.Lstat(w.root)
	}
	if err != nil {
		return fmt.Errorf("inspect secure proxy runtime root: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("%w: runtime root is not a directory", ErrSecureRuntimePath)
	}
	return nil
}

func (w *secureRuntimeWriter) validateOwnedPath(path string, allowDirectory bool) error {
	if w == nil || strings.TrimSpace(w.root) == "" {
		return ErrSecureRuntimePath
	}
	rel, err := filepath.Rel(w.root, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return fmt.Errorf("%w: path escapes runtime root", ErrSecureRuntimePath)
	}
	if !allowDirectory && strings.ContainsRune(rel, filepath.Separator) {
		return fmt.Errorf("%w: nested runtime file path", ErrSecureRuntimePath)
	}
	return nil
}

func (w *secureRuntimeWriter) validateRuntimeFilePath(path string, runtimeDir string) error {
	if err := w.validateOwnedPath(path, true); err != nil {
		return err
	}
	rootInfo, err := os.Lstat(w.root)
	if err != nil {
		return fmt.Errorf("inspect secure proxy runtime root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("%w: runtime root is not a directory", ErrSecureRuntimePath)
	}
	dirInfo, err := os.Lstat(runtimeDir)
	if err != nil {
		return fmt.Errorf("inspect secure proxy runtime directory: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("%w: runtime directory is not a directory", ErrSecureRuntimePath)
	}
	rel, err := filepath.Rel(runtimeDir, path)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) || strings.ContainsRune(rel, filepath.Separator) {
		return fmt.Errorf("%w: path escapes runtime directory", ErrSecureRuntimePath)
	}
	return nil
}

func validateSecureRuntimeKey(key string) error {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > secureRuntimeMaxKey || key == "." || key == ".." {
		return fmt.Errorf("%w: invalid runtime key", ErrSecureRuntimePath)
	}
	for _, r := range key {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("%w: invalid runtime key", ErrSecureRuntimePath)
	}
	return nil
}

func validateSecureRuntimeName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > secureRuntimeMaxName || name == "." || name == ".." || filepath.Base(name) != name {
		return fmt.Errorf("%w: invalid runtime file name", ErrSecureRuntimePath)
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("%w: invalid runtime file name", ErrSecureRuntimePath)
	}
	return nil
}

func secureRuntimeRandomSuffix() (string, error) {
	buf := make([]byte, 12)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	var out strings.Builder
	out.Grow(len(buf) * 2)
	for _, b := range buf {
		out.WriteByte(alphabet[int(b>>3)%len(alphabet)])
		out.WriteByte(alphabet[int(b&7)])
	}
	return out.String(), nil
}

func (w *secureRuntimeWriter) writeAtomic(key string, name string, data []byte) (string, error) {
	if err := validateSecureRuntimeName(name); err != nil {
		return "", err
	}
	handle, err := w.handle(key)
	if err != nil {
		return "", err
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.cleaned {
		return "", ErrSecureRuntimePath
	}

	path := filepath.Join(handle.dir, name)
	if err := w.validateRuntimeFilePath(path, handle.dir); err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("%w: refuse non-regular config target", ErrSecureRuntimePath)
		}
		if _, owned := handle.files[name]; !owned {
			return "", fmt.Errorf("%w: refuse overwrite of unowned config target", ErrSecureRuntimePath)
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect secure proxy config target: %w", statErr)
	}

	suffix, err := secureRuntimeRandomSuffix()
	if err != nil {
		return "", fmt.Errorf("create secure proxy config temp name: %w", err)
	}
	tmpPath := filepath.Join(handle.dir, "."+name+".tmp-"+suffix)
	tmpFile, err := secureRuntimeCreateExclusiveFile(tmpPath)
	if err != nil {
		return "", fmt.Errorf("create secure proxy config temp: %w", err)
	}
	removeTemp := true
	defer func() {
		_ = tmpFile.Close()
		if removeTemp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmpFile.Write(data); err != nil {
		return "", fmt.Errorf("write secure proxy config temp: %w", err)
	}
	if err := tmpFile.Sync(); err != nil {
		return "", fmt.Errorf("sync secure proxy config temp: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return "", fmt.Errorf("close secure proxy config temp: %w", err)
	}
	if err := secureRuntimeRename(tmpPath, path); err != nil {
		return "", fmt.Errorf("atomically install secure proxy config: %w", err)
	}
	removeTemp = false
	// The exclusive temp file was created with the final restrictive mode and
	// platform ACL before any bytes were written. Do not chmod the destination
	// after rename: a concurrent path replacement could turn a post-rename
	// chmod into an operation on an attacker-selected symlink target.
	handle.files[name] = struct{}{}
	return path, nil
}

func (w *secureRuntimeWriter) ensureLog(key string, name string) (string, error) {
	if err := validateSecureRuntimeName(name); err != nil {
		return "", err
	}
	handle, err := w.handle(key)
	if err != nil {
		return "", err
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.cleaned {
		return "", ErrSecureRuntimePath
	}
	path := filepath.Join(handle.dir, name)
	if err := w.validateRuntimeFilePath(path, handle.dir); err != nil {
		return "", err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", fmt.Errorf("%w: refuse non-regular runtime log target", ErrSecureRuntimePath)
		}
		if _, owned := handle.files[name]; !owned {
			return "", fmt.Errorf("%w: refuse overwrite of unowned runtime log target", ErrSecureRuntimePath)
		}
		// Recreate a tracked log instead of truncating it in place. If an
		// attacker swapped the path for a hard link, removing the link cannot
		// modify the outside inode; exclusive creation below gives us a fresh
		// app-owned inode and still rejects symlink races.
		if err := os.Remove(path); err != nil {
			return "", fmt.Errorf("replace secure proxy runtime log: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return "", fmt.Errorf("inspect secure proxy runtime log target: %w", statErr)
	}
	file, err := secureRuntimeCreateExclusiveFile(path)
	if err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	handle.files[name] = struct{}{}
	return path, nil
}

func (w *secureRuntimeWriter) openLog(key string, name string) (*os.File, string, error) {
	if err := validateSecureRuntimeName(name); err != nil {
		return nil, "", err
	}
	handle, err := w.handle(key)
	if err != nil {
		return nil, "", err
	}
	handle.mu.Lock()
	defer handle.mu.Unlock()
	if handle.cleaned {
		return nil, "", ErrSecureRuntimePath
	}
	path := filepath.Join(handle.dir, name)
	if err := w.validateRuntimeFilePath(path, handle.dir); err != nil {
		return nil, "", err
	}
	info, statErr := os.Lstat(path)
	if statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, "", fmt.Errorf("%w: refuse non-regular runtime log target", ErrSecureRuntimePath)
		}
		if _, owned := handle.files[name]; !owned {
			return nil, "", fmt.Errorf("%w: refuse open of unowned runtime log target", ErrSecureRuntimePath)
		}
		// Do not truncate an inode in place. Removing the tracked path first
		// makes a hard-link swap harmless, while exclusive creation prevents a
		// symlink/path race from redirecting writes outside this directory.
		if err := os.Remove(path); err != nil {
			return nil, "", fmt.Errorf("replace secure proxy runtime log: %w", err)
		}
	} else if !os.IsNotExist(statErr) {
		return nil, "", fmt.Errorf("inspect secure proxy runtime log target: %w", statErr)
	}
	file, err := secureRuntimeCreateExclusiveFile(path)
	if err != nil {
		return nil, "", err
	}
	handle.files[name] = struct{}{}
	return file, path, nil
}

func (h *secureRuntimeHandle) markProcessStarted() uint64 {
	if h == nil {
		return 0
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.cleaned {
		h.nextToken++
		if h.nextToken == 0 {
			h.nextToken++
		}
		h.activeToken = h.nextToken
		h.active = true
	}
	return h.activeToken
}

func (h *secureRuntimeHandle) markProcessTerminated(tokens ...uint64) {
	if h == nil {
		return
	}
	h.mu.Lock()
	if h.cleaned {
		h.mu.Unlock()
		return
	}
	if len(tokens) == 0 || tokens[0] == 0 || tokens[0] == h.activeToken {
		h.active = false
		h.activeToken = 0
	}
	h.mu.Unlock()
}

func (h *secureRuntimeHandle) isCleaned() bool {
	if h == nil {
		return true
	}
	h.mu.Lock()
	cleaned := h.cleaned
	h.mu.Unlock()
	return cleaned
}

func (h *secureRuntimeHandle) cleanup() error {
	if h == nil || h.writer == nil {
		return nil
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cleaned {
		return nil
	}
	if h.active {
		return ErrSecureRuntimeActive
	}
	rootInfo, rootErr := os.Lstat(h.writer.root)
	if rootErr != nil && !os.IsNotExist(rootErr) {
		return fmt.Errorf("inspect secure proxy cleanup root: %w", rootErr)
	}
	if rootErr == nil && (rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir()) {
		return fmt.Errorf("%w: refuse cleanup through non-directory root", ErrSecureRuntimePath)
	}
	dirInfo, err := os.Lstat(h.dir)
	if err != nil {
		if os.IsNotExist(err) {
			h.cleaned = true
			h.writer.mu.Lock()
			delete(h.writer.entries, h.key)
			h.writer.mu.Unlock()
			return nil
		}
		return fmt.Errorf("inspect secure proxy cleanup directory: %w", err)
	}
	if dirInfo.Mode()&os.ModeSymlink != 0 || !dirInfo.IsDir() {
		return fmt.Errorf("%w: refuse cleanup through non-directory", ErrSecureRuntimePath)
	}

	h.writer.mu.Lock()
	defer h.writer.mu.Unlock()
	if current := h.writer.entries[h.key]; current != h {
		return fmt.Errorf("%w: runtime handle is not current", ErrSecureRuntimePath)
	}
	fileNames := make([]string, 0, len(h.files))
	for name := range h.files {
		fileNames = append(fileNames, name)
	}
	sort.Strings(fileNames)
	for _, name := range fileNames {
		path := filepath.Join(h.dir, name)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			delete(h.files, name)
			continue
		}
		if err != nil {
			return fmt.Errorf("inspect secure proxy cleanup target: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("%w: refuse cleanup of non-regular target", ErrSecureRuntimePath)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove secure proxy runtime file: %w", err)
		}
		delete(h.files, name)
	}
	// Only remove the exact per-key directory, and only when it is empty. This
	// intentionally leaves unexpected files for forensic review.
	entries, err := os.ReadDir(h.dir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect secure proxy runtime directory: %w", err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("%w: runtime directory contains unowned entries", ErrSecureRuntimePath)
	}
	if err := os.Remove(h.dir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove secure proxy runtime directory: %w", err)
	}
	h.cleaned = true
	delete(h.writer.entries, h.key)
	if rootEntries, readErr := os.ReadDir(h.writer.root); readErr == nil && len(rootEntries) == 0 {
		_ = os.Remove(h.writer.root)
	}
	return nil
}

func (w *secureRuntimeWriter) cleanup(key string) error {
	if w == nil {
		return nil
	}
	if err := validateSecureRuntimeKey(key); err != nil {
		return nil
	}
	w.mu.Lock()
	handle := w.entries[key]
	w.mu.Unlock()
	if handle == nil {
		return nil
	}
	return handle.cleanup()
}

func maskProxySensitiveText(raw string) string {
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	masked := proxyURIValuePattern.ReplaceAllString(raw, `$1://<redacted>`)
	masked = sensitiveJSONValuePattern.ReplaceAllString(masked, `${1}<redacted>`)
	return sensitiveLogValuePattern.ReplaceAllString(masked, `${1}${2}<redacted>`)
}

// MaskProxySensitiveText is the public boundary helper for callers outside the
// proxy package that must return or log proxy-related errors safely.
func MaskProxySensitiveText(raw string) string {
	return maskProxySensitiveText(raw)
}

func safeProxyError(err error) string {
	if err == nil {
		return ""
	}
	return maskProxySensitiveText(err.Error())
}

func safeProxyURI(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.Scheme != "" {
		return strings.ToLower(parsed.Scheme) + "://<redacted>"
	}
	return maskProxySensitiveText(trimmed)
}
