package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
)

func suiteDarwinLinkEntry(path, target string) SuiteReleaseEntry {
	digest := sha256.Sum256([]byte(target))
	return SuiteReleaseEntry{Path: path, Role: SuiteReleaseEntrySymlink, SHA256: hex.EncodeToString(digest[:])}
}

func TestSuiteReleaseManifestDarwinBundleRules(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	bundleBinary := SuiteReleaseEntry{
		Path: "runtime/chrome/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing",
		Role: SuiteReleaseEntryBinary, Size: 1, SHA256: hex.EncodeToString(digest[:]), Executable: true,
	}
	link := suiteDarwinLinkEntry("runtime/chrome/Current", "Google Chrome for Testing.app")
	helper := bundleBinary
	helper.Path = "runtime/chrome/Google Chrome for Testing.app/Contents/Frameworks/_CodeSignature/Helper (GPU).app/Contents/MacOS/Helper (GPU)"
	helper.Role = SuiteReleaseEntryLibrary
	helper.Executable = false

	darwin := suiteReleaseManifestFixture()
	darwin.Target = SuiteReleaseTarget{OS: "darwin", Arch: "arm64"}
	darwin.Entries = append(darwin.Entries, bundleBinary, link, helper)
	if err := darwin.Validate(); err != nil {
		t.Fatalf("darwin bundle manifest rejected: %v", err)
	}

	// The same entries are never valid for another target.
	for _, os := range []string{"windows", "linux"} {
		other := darwin
		other.Target = SuiteReleaseTarget{OS: os, Arch: "amd64"}
		if err := other.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
			t.Fatalf("%s accepted macOS bundle entries: %v", os, err)
		}
		for _, entry := range []SuiteReleaseEntry{bundleBinary, helper} {
			spaced := suiteReleaseManifestFixture()
			spaced.Target = other.Target
			spaced.Entries = append(spaced.Entries, entry)
			if err := spaced.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("%s accepted a macOS-only path %q: %v", os, entry.Path, err)
			}
		}
	}

	// Spaces only inside a segment; symlinks carry no bytes and are not executable.
	for _, bad := range []SuiteReleaseEntry{
		{Path: "runtime/ leading", Role: SuiteReleaseEntryAsset, Size: 1, SHA256: bundleBinary.SHA256},
		{Path: "runtime/trailing ", Role: SuiteReleaseEntryAsset, Size: 1, SHA256: bundleBinary.SHA256},
		{Path: "runtime/tab\tname", Role: SuiteReleaseEntryAsset, Size: 1, SHA256: bundleBinary.SHA256},
		func() SuiteReleaseEntry { entry := link; entry.Path = "runtime/sized"; entry.Size = 1; return entry }(),
		func() SuiteReleaseEntry {
			entry := link
			entry.Path = "runtime/exec"
			entry.Executable = true
			return entry
		}(),
	} {
		manifest := suiteReleaseManifestFixture()
		manifest.Target = darwin.Target
		manifest.Entries = append(manifest.Entries, bad)
		if err := manifest.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
			t.Fatalf("darwin accepted invalid entry %+v: %v", bad, err)
		}
	}

	// A link path cannot also be an ancestor of covered files.
	collision := darwin
	collision.Entries = append(append([]SuiteReleaseEntry(nil), darwin.Entries...),
		suiteDarwinLinkEntry("runtime/chrome/Google Chrome for Testing.app/Contents", "x"))
	if err := collision.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("link/file ancestor collision accepted: %v", err)
	}
}

func TestSuiteManifestLinkResolutionStaysInsideRoot(t *testing.T) {
	links := map[string]string{
		"F.framework/Versions/Current": "131.0",
		"F.framework/F":                "Versions/Current/F",
		"F.framework/Resources":        "Versions/Current/Resources",
		"loop/a":                       "b",
		"loop/b":                       "a",
		"escape":                       "../outside",
		"deep/escape":                  "../../x",
		// Reviewer case: ".." after a link must apply to the link's target.
		"a/b/c/d/e/L": "../../../../../z",
		"a/b/c/d/e/X": "L/../../../../../Users/Shared",
	}
	for link, want := range map[string]string{
		"F.framework/Versions/Current": "F.framework/Versions/131.0",
		"F.framework/F":                "F.framework/Versions/131.0/F",
		"F.framework/Resources":        "F.framework/Versions/131.0/Resources",
	} {
		got, err := resolveSuiteManifestLink(link, links)
		if err != nil || got != want {
			t.Fatalf("%s resolved to %q, %v; want %q", link, got, err, want)
		}
	}
	if got, err := resolveSuiteManifestLink("a/b/c/d/e/L", links); err != nil || got != "z" {
		t.Fatalf("L resolved to %q, %v", got, err)
	}
	for _, link := range []string{"loop/a", "escape", "deep/escape", "a/b/c/d/e/X"} {
		if _, err := resolveSuiteManifestLink(link, links); !errors.Is(err, ErrSuiteOwnershipHandoff) {
			t.Fatalf("%s resolution was accepted: %v", link, err)
		}
	}
}
