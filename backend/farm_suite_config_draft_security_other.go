//go:build !windows

package backend

import "os"

func secureSuiteConfigDraftApplicationRootHandle(path string, expected os.FileInfo) (result os.FileInfo, resultErr error) {
	directory, err := os.Open(path)
	if err != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	defer func() {
		if err := directory.Close(); resultErr == nil && err != nil {
			result, resultErr = nil, ErrSuiteCanonicalConfigDraft
		}
	}()
	opened, err := directory.Stat()
	if err != nil || expected == nil || !opened.IsDir() || !os.SameFile(expected, opened) {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	if err := directory.Chmod(0o700); err != nil || directory.Sync() != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	secured, err := directory.Stat()
	if err != nil || !secured.IsDir() || secured.Mode().Perm() != 0o700 || !os.SameFile(opened, secured) {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	pathInfo, err := os.Lstat(path)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !pathInfo.IsDir() || !os.SameFile(secured, pathInfo) {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	_, resolved, err := suitePrecheckResolvedPath(path)
	if err != nil || resolved == nil || !os.SameFile(secured, resolved) || validateSuiteSetupPathSecurity(path, true) != nil {
		return nil, ErrSuiteCanonicalConfigDraft
	}
	return secured, nil
}
