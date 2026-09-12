package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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
		Dependencies:  []SuiteReleaseDependency{{Name: "glibc", Version: "2.31"}},
		Entries: []SuiteReleaseEntry{{
			Path: "bin/ant-farm-agent", Role: SuiteReleaseEntryBinary, Size: 12,
			SHA256: hex.EncodeToString(digest[:]), Executable: true,
		}},
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
	verified, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, publicKey)
	if err != nil || verified.Version != "3.0.0" {
		t.Fatalf("verified = %+v, %v", verified, err)
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, otherPublic); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("untrusted caller key accepted: %v", err)
	}
	tampered := append([]byte(nil), manifestRaw...)
	tampered[len(tampered)-2] ^= 1
	if _, err := VerifySuiteReleaseManifest(tampered, envelopeRaw, publicKey); !errors.Is(err, ErrSuiteReleaseManifest) {
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
	if _, err := VerifySuiteReleaseManifest(manifestRaw, unknownEnvelope, publicKey); !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("unknown envelope field accepted: %v", err)
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

	for _, badPath := range []string{"/bin/agent", "../agent", "bin/../agent", `bin\agent.exe`, "bin/agent.exe:stream", "./bin/agent"} {
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
