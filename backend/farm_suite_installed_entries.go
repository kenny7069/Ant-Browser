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

// resolveSuiteManifestLink resolves a covered link lexically, substituting
// only other covered links, and refuses any escape from the Suite root.
func resolveSuiteManifestLink(link string, links map[string]string) (string, error) {
	current := path.Clean(path.Join(path.Dir(link), links[link]))
	for depth := 0; depth < maxSuiteSymlinkResolutionDepth; depth++ {
		if current == ".." || strings.HasPrefix(current, "../") || path.IsAbs(current) {
			return "", fmt.Errorf("%w: symlink escapes Suite root", ErrSuiteOwnershipHandoff)
		}
		segments := strings.Split(current, "/")
		substituted := false
		for index := 1; index <= len(segments); index++ {
			prefix := strings.Join(segments[:index], "/")
			target, ok := links[prefix]
			if !ok {
				continue
			}
			rest := strings.Join(segments[index:], "/")
			current = path.Clean(path.Join(path.Dir(prefix), target, rest))
			substituted = true
			break
		}
		if !substituted {
			return current, nil
		}
	}
	return "", fmt.Errorf("%w: symlink resolution too deep", ErrSuiteOwnershipHandoff)
}
