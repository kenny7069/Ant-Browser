package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const maxSuiteSymlinkResolutionDepth = 16

// validateInstalledSuiteEntries proves every manifest entry exists on disk
// exactly as signed: regular files by type, size and SHA-256; macOS bundle
// symlinks by the digest of their exact target and by resolving, through
// other covered links only, to a covered file or directory inside the root.
func validateInstalledSuiteEntries(root string, manifest SuiteReleaseManifest) error {
	links := map[string]string{}
	files := map[string]struct{}{}
	directories := map[string]struct{}{".": {}}
	for _, entry := range manifest.Entries {
		candidate, err := safeSuiteReleaseEntryPath(root, entry.Path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			return fmt.Errorf("%w: installed entry missing", ErrSuiteOwnershipHandoff)
		}
		if entry.Role == SuiteReleaseEntrySymlink {
			if manifest.Target.OS != "darwin" || info.Mode()&os.ModeSymlink == 0 {
				return fmt.Errorf("%w: installed entry shape mismatch", ErrSuiteOwnershipHandoff)
			}
			target, err := os.Readlink(candidate)
			digest := sha256.Sum256([]byte(target))
			if err != nil || target == "" || filepath.IsAbs(target) || strings.ContainsAny(target, "\x00\\") ||
				len(target) > maxSuiteReleasePathBytes || hex.EncodeToString(digest[:]) != entry.SHA256 {
				return fmt.Errorf("%w: installed symlink target mismatch", ErrSuiteOwnershipHandoff)
			}
			links[entry.Path] = target
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != entry.Size {
			return fmt.Errorf("%w: installed entry shape mismatch", ErrSuiteOwnershipHandoff)
		}
		resolved, err := filepath.EvalSymlinks(candidate)
		if err != nil || !sameSuiteHandoffPath(resolved, candidate) {
			return fmt.Errorf("%w: redirected installed entry", ErrSuiteOwnershipHandoff)
		}
		entryDigest, err := streamSuiteInstalledEntryDigest(candidate, entry.Size)
		if err != nil || entryDigest != entry.SHA256 {
			return fmt.Errorf("%w: installed entry digest mismatch", ErrSuiteOwnershipHandoff)
		}
		files[entry.Path] = struct{}{}
		for directory := path.Dir(entry.Path); directory != "."; directory = path.Dir(directory) {
			directories[directory] = struct{}{}
		}
	}
	for link := range links {
		final, err := resolveSuiteManifestLink(link, links)
		if err != nil {
			return err
		}
		if _, ok := files[final]; ok {
			continue
		}
		if _, ok := directories[final]; ok && final != "." {
			continue
		}
		return fmt.Errorf("%w: symlink does not reach a covered entry", ErrSuiteOwnershipHandoff)
	}
	return nil
}

// resolveSuiteManifestLink resolves a covered link one path segment at a
// time, exactly like the kernel: a covered link met on the way is expanded
// before any following "..", and no step may leave the Suite root.  Only
// covered links are expanded; on-disk links outside the manifest never are.
func resolveSuiteManifestLink(link string, links map[string]string) (string, error) {
	stack := []string{}
	if parent := path.Dir(link); parent != "." {
		stack = strings.Split(parent, "/")
	}
	pending := strings.Split(links[link], "/")
	expansions := 0
	for len(pending) > 0 {
		segment := pending[0]
		pending = pending[1:]
		switch segment {
		case "", ".":
			continue
		case "..":
			if len(stack) == 0 {
				return "", fmt.Errorf("%w: symlink escapes Suite root", ErrSuiteOwnershipHandoff)
			}
			stack = stack[:len(stack)-1]
			continue
		}
		stack = append(stack, segment)
		target, ok := links[strings.Join(stack, "/")]
		if !ok {
			continue
		}
		expansions++
		if expansions > maxSuiteSymlinkResolutionDepth || path.IsAbs(target) {
			return "", fmt.Errorf("%w: symlink resolution invalid", ErrSuiteOwnershipHandoff)
		}
		stack = stack[:len(stack)-1]
		pending = append(strings.Split(target, "/"), pending...)
	}
	if len(stack) == 0 {
		return ".", nil
	}
	return strings.Join(stack, "/"), nil
}
