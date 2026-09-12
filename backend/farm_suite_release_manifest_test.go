package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func suiteReleaseManifestFixture() SuiteReleaseManifest {
	digest := sha256.Sum256([]byte("agent binary"))
	commit := "0123456789abcdef0123456789abcdef01234567"
	return SuiteReleaseManifest{
		SchemaVersion: 1,
		Version:       "3.0.0",
		Target:        SuiteReleaseTarget{OS: "linux", Arch: "amd64"},
		Commits:       SuiteReleaseCommits{AntBrowser: commit, FarmAgent: commit, FarmControl: commit},
		ConfigSchema:  3,
		Capabilities:  []string{"setup-plan", "signed-release"},
		CoreVersions:  map[string]string{"chromium": "128.0.0", "xray": "25.1.1"},
		Dependencies:  []SuiteReleaseDependency{{Name: "glibc", Version: "2.31", LicenseRef: "LICENSE"}},
		Entries: []SuiteReleaseEntry{{
			Path: "bin/ant-farm-agent", Role: SuiteReleaseEntryBinary, Size: 12,
			SHA256: hex.EncodeToString(digest[:]), Executable: true,
		}, {Path: "LICENSE", Role: SuiteReleaseEntryLegal, Size: 12, SHA256: hex.EncodeToString(digest[:])}},
	}
}

func TestSuiteReleaseManifestDetachedSignatureUsesCallerTrust(t *testing.T) {
	manifestRaw, err := MarshalSuiteReleaseManifest(suiteReleaseManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := SignSuiteReleaseManifest(manifestRaw, "release-2026", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	anchor := SuiteReleaseTrustAnchor{KeyID: "release-2026", PublicKey: publicKey}
	verified, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, anchor)
	if err != nil || verified.Manifest().Version != "3.0.0" {
		t.Fatalf("verified = %+v, %v", verified, err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, SuiteReleaseTrustAnchor{KeyID: "release-2026", PublicKey: otherPublic}); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("untrusted caller key accepted: %v", err)
	}
	tampered := append([]byte(nil), manifestRaw...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifySuiteReleaseManifest(tampered, envelopeRaw, anchor); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("tampered manifest accepted: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(envelopeRaw, &envelope); err != nil {
		t.Fatal(err)
	}
	if _, exists := envelope["public_key"]; exists {
		t.Fatal("detached envelope contains a self-asserted trust key")
	}
	envelope["public_key"] = "attacker"
	unknownEnvelope, _ := json.Marshal(envelope)
	if _, err := VerifySuiteReleaseManifest(manifestRaw, unknownEnvelope, anchor); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("unknown envelope field accepted: %v", err)
	}
	if _, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, SuiteReleaseTrustAnchor{KeyID: "different-key", PublicKey: publicKey}); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("wrong expected key id accepted: %v", err)
	}
	duplicateEnvelope := strings.Replace(string(envelopeRaw), `"key_id":"release-2026"`, `"Key_ID":"attacker","key_id":"release-2026"`, 1)
	if _, err := VerifySuiteReleaseManifest(manifestRaw, []byte(duplicateEnvelope), anchor); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("duplicate envelope key accepted: %v", err)
	}
	noncanonicalEnvelope := strings.Replace(string(envelopeRaw), `"key_id":"release-2026"`, `"Key_ID":"release-2026"`, 1)
	if _, err := VerifySuiteReleaseManifest(manifestRaw, []byte(noncanonicalEnvelope), anchor); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("noncanonical envelope key accepted: %v", err)
	}
}

func TestSuiteReleaseManifestStrictJSONAndEntryRules(t *testing.T) {
	valid := suiteReleaseManifestFixture()
	raw, _ := MarshalSuiteReleaseManifest(valid)
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["private_key"] = "secret"
	withUnknown, _ := json.Marshal(object)
	if _, err := ParseSuiteReleaseManifest(withUnknown); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("unknown manifest field accepted: %v", err)
	}
	for name, duplicate := range map[string]string{
		"top level": strings.Replace(string(raw), `"version":"3.0.0"`, `"Version":"evil","version":"3.0.0"`, 1),
		"nested":    strings.Replace(string(raw), `"os":"linux"`, `"OS":"windows","os":"linux"`, 1),
	} {
		t.Run("duplicate key "+name, func(t *testing.T) {
			if _, err := ParseSuiteReleaseManifest([]byte(duplicate)); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("duplicate/case-fold key accepted: %v", err)
			}
		})
	}
	for name, noncanonical := range map[string]string{
		"top level": strings.Replace(string(raw), `"version":"3.0.0"`, `"Version":"3.0.0"`, 1),
		"nested":    strings.Replace(string(raw), `"os":"linux"`, `"OS":"linux"`, 1),
	} {
		t.Run("noncanonical key "+name, func(t *testing.T) {
			if _, err := ParseSuiteReleaseManifest([]byte(noncanonical)); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("noncanonical key casing accepted: %v", err)
			}
		})
	}
	legacyLicenseField := strings.Replace(string(raw), `"license_ref":"LICENSE"`, `"spdx_expression":"MIT"`, 1)
	if _, err := ParseSuiteReleaseManifest([]byte(legacyLicenseField)); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("legacy SPDX-shaped dependency accepted: %v", err)
	}

	for _, badPath := range []string{
		"/bin/agent", "../agent", "bin/../agent", `bin\agent.exe`, "bin/agent.exe:stream", "./bin/agent",
		"bad?.txt", "bad\x01.txt", "COM¹", "CON .txt", "caf\u00e9.txt", "cafe\u0301.txt", "legal/LICENSE.",
	} {
		t.Run(badPath, func(t *testing.T) {
			manifest := suiteReleaseManifestFixture()
			manifest.Entries[0].Path = badPath
			if err := manifest.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("path accepted: %q: %v", badPath, err)
			}
		})
	}

	for name, mutate := range map[string]func(*SuiteReleaseManifest){
		"case fold collision": func(manifest *SuiteReleaseManifest) {
			entry := manifest.Entries[0]
			entry.Path = "BIN/ANT-FARM-AGENT"
			manifest.Entries = append(manifest.Entries, entry)
		},
		"duplicate entry": func(manifest *SuiteReleaseManifest) { manifest.Entries = append(manifest.Entries, manifest.Entries[0]) },
		"negative size":   func(manifest *SuiteReleaseManifest) { manifest.Entries[0].Size = -1 },
		"bad digest":      func(manifest *SuiteReleaseManifest) { manifest.Entries[0].SHA256 = "ABC" },
		"config executable": func(manifest *SuiteReleaseManifest) {
			manifest.Entries[0].Role = SuiteReleaseEntryConfig
		},
		"binary non executable": func(manifest *SuiteReleaseManifest) { manifest.Entries[0].Executable = false },
		"duplicate capability": func(manifest *SuiteReleaseManifest) {
			manifest.Capabilities = append(manifest.Capabilities, "SETUP-PLAN")
		},
		"non semver version": func(manifest *SuiteReleaseManifest) { manifest.Version = "dev" },
		"dependency without license ref": func(manifest *SuiteReleaseManifest) {
			manifest.Dependencies[0].LicenseRef = ""
		},
		"dangling license ref": func(manifest *SuiteReleaseManifest) {
			manifest.Dependencies[0].LicenseRef = "NOTICE"
		},
		"nonlegal license ref": func(manifest *SuiteReleaseManifest) {
			manifest.Dependencies[0].LicenseRef = "bin/ant-farm-agent"
		},
		"case equivalent license ref": func(manifest *SuiteReleaseManifest) {
			manifest.Dependencies[0].LicenseRef = "license"
		},
		"missing legal": func(manifest *SuiteReleaseManifest) { manifest.Entries = manifest.Entries[:1] },
		"ancestor collision": func(manifest *SuiteReleaseManifest) {
			entry := manifest.Entries[1]
			entry.Path = "bin"
			manifest.Entries = append(manifest.Entries, entry)
		},
		"windows reserved basename": func(manifest *SuiteReleaseManifest) {
			manifest.Entries[1].Path = "legal/CON.txt"
		},
		"windows trailing dot": func(manifest *SuiteReleaseManifest) {
			manifest.Target.OS = "windows"
			manifest.Entries[1].Path = "legal/LICENSE."
		},
		"long segment": func(manifest *SuiteReleaseManifest) {
			manifest.Entries[1].Path = strings.Repeat("a", maxSuiteReleaseSegmentBytes+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := suiteReleaseManifestFixture()
			mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("invalid manifest accepted: %v", err)
			}
		})
	}
}

func TestSuiteReleaseManifestRequiresAllTypedSections(t *testing.T) {
	for name, mutate := range map[string]func(*SuiteReleaseManifest){
		"capabilities":  func(manifest *SuiteReleaseManifest) { manifest.Capabilities = nil },
		"core versions": func(manifest *SuiteReleaseManifest) { manifest.CoreVersions = nil },
		"dependencies":  func(manifest *SuiteReleaseManifest) { manifest.Dependencies = nil },
		"entries":       func(manifest *SuiteReleaseManifest) { manifest.Entries = nil },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := suiteReleaseManifestFixture()
			mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("missing %s accepted: %v", name, err)
			}
		})
	}
}

func TestSuiteReleaseManifestResourceAndReleasePolicyLimits(t *testing.T) {
	for name, mutate := range map[string]func(*SuiteReleaseManifest){
		"generic version":         func(manifest *SuiteReleaseManifest) { manifest.Version = "release" },
		"prerelease leading zero": func(manifest *SuiteReleaseManifest) { manifest.Version = "1.0.0-01" },
		"oversize entry":          func(manifest *SuiteReleaseManifest) { manifest.Entries[0].Size = maxSuiteReleaseEntryBytes + 1 },
		"too many entries": func(manifest *SuiteReleaseManifest) {
			manifest.Entries = make([]SuiteReleaseEntry, maxSuiteReleaseEntries+1)
		},
		"too many capabilities": func(manifest *SuiteReleaseManifest) {
			manifest.Capabilities = make([]string, maxSuiteReleaseCapabilities+1)
		},
		"dependency license path": func(manifest *SuiteReleaseManifest) { manifest.Dependencies[0].LicenseRef = "LICENSE.txt" },
		"core case fold collision": func(manifest *SuiteReleaseManifest) {
			manifest.CoreVersions["XRAY"] = manifest.CoreVersions["xray"]
		},
		"aggregate unpacked size": func(manifest *SuiteReleaseManifest) {
			manifest.Entries[0].Size = maxSuiteReleaseEntryBytes
			manifest.Entries[1].Size = maxSuiteReleaseEntryBytes
			for index := 0; index < 3; index++ {
				entry := manifest.Entries[1]
				entry.Path = fmt.Sprintf("legal/NOTICE-%d", index)
				entry.Size = maxSuiteReleaseEntryBytes
				manifest.Entries = append(manifest.Entries, entry)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			manifest := suiteReleaseManifestFixture()
			mutate(&manifest)
			if err := manifest.Validate(); !errors.Is(err, ErrSuiteReleaseManifest) {
				t.Fatalf("policy violation accepted: %v", err)
			}
		})
	}
	if _, err := ParseSuiteReleaseManifest(make([]byte, maxSuiteReleaseManifestBytes+1)); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("oversize manifest accepted: %v", err)
	}
	publicKey, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySuiteReleaseManifest([]byte("{}"), make([]byte, maxSuiteReleaseEnvelopeBytes+1), SuiteReleaseTrustAnchor{KeyID: "release-2026", PublicKey: publicKey}); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("oversize envelope accepted: %v", err)
	}
}
