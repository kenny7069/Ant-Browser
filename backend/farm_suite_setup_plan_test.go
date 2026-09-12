package backend

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func suiteSetupPlanFixture(t *testing.T) SuiteSetupPlan {
	t.Helper()
	preparation := SetupPreparationCheckpoint{
		SchemaVersion: 1, Stage: SetupBootstrapDrafted,
		RequestUID:      "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6",
		BootstrapSHA256: strings.Repeat("a", 64),
	}
	manifestRaw, err := MarshalSuiteReleaseManifest(suiteReleaseManifestFixture())
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelopeRaw, err := SignSuiteReleaseManifest(manifestRaw, "plan-test", privateKey)
	if err != nil {
		t.Fatal(err)
	}
	release, err := VerifySuiteReleaseManifest(manifestRaw, envelopeRaw, SuiteReleaseTrustAnchor{KeyID: "plan-test", PublicKey: publicKey})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewSuiteSetupPlan(preparation, release)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestSuiteSetupPlanAtomicImmutableRoundTrip(t *testing.T) {
	roots, _ := setupEngineFixture(t)
	path := filepath.Join(roots.AgentState, suiteSetupPlanName)
	plan := suiteSetupPlanFixture(t)
	if err := SaveSuiteSetupPlan(roots, plan); err != nil {
		t.Fatal(err)
	}
	if err := SaveSuiteSetupPlan(roots, plan); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	loaded, err := LoadSuiteSetupPlan(roots)
	if err != nil || *loaded != plan {
		t.Fatalf("loaded = %+v, %v", loaded, err)
	}
	changed := plan
	changed.ManifestSHA256 = strings.Repeat("c", 64)
	changed.StageID = deriveSuiteSetupStageID(changed.ManifestSHA256, changed.Target)
	if err := SaveSuiteSetupPlan(roots, changed); !errors.Is(err, ErrSuiteSetupPlanConflict) {
		t.Fatalf("conflicting plan accepted: %v", err)
	}
	stillLoaded, err := LoadSuiteSetupPlan(roots)
	if err != nil || *stillLoaded != plan {
		t.Fatalf("conflict changed plan: %+v, %v", stillLoaded, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("plan mode = %o", info.Mode().Perm())
		}
	}
	raw, _ := os.ReadFile(path)
	for _, forbidden := range []string{"private_key", "enrollment_code", "password", "cookie"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("plan contains %s", forbidden)
		}
	}
}

func TestSuiteSetupPlanStrictLoadAndValidation(t *testing.T) {
	roots, _ := setupEngineFixture(t)
	if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roots.AgentState, suiteSetupPlanName)
	plan := suiteSetupPlanFixture(t)
	raw, _ := jsonMarshalSuiteSetupPlan(plan)
	raw = append(raw[:len(raw)-2], []byte(",\"private_key\":\"secret\"}\n")...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteSetupPlan(roots); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("unknown secret field accepted: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSuiteSetupPlan(roots); err == nil {
			t.Fatal("permissive plan mode accepted")
		}
	}

	for name, mutate := range map[string]func(*SuiteSetupPlan){
		"request uid":      func(plan *SuiteSetupPlan) { plan.PreparationRequestUID = "not-uuid" },
		"bootstrap digest": func(plan *SuiteSetupPlan) { plan.BootstrapSHA256 = strings.Repeat("A", 64) },
		"manifest digest":  func(plan *SuiteSetupPlan) { plan.ManifestSHA256 = "bad" },
		"target":           func(plan *SuiteSetupPlan) { plan.Target.OS = "freebsd" },
		"stage id":         func(plan *SuiteSetupPlan) { plan.StageID = "../stage" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := suiteSetupPlanFixture(t)
			mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrSuiteSetupPlan) {
				t.Fatalf("invalid plan accepted: %v", err)
			}
		})
	}
	preparation := SetupPreparationCheckpoint{
		SchemaVersion: 1, Stage: SetupUserRootsReady,
		RequestUID: "b3308b52-ae5b-4bc7-9ecd-42fc9e3fc9c6", BootstrapSHA256: strings.Repeat("a", 64),
	}
	verifiedPlan := suiteSetupPlanFixture(t)
	proof := VerifiedSuiteRelease{
		manifest: suiteReleaseManifestFixture(), manifestSHA256: verifiedPlan.ManifestSHA256, verified: true,
	}
	if _, err := NewSuiteSetupPlan(preparation, proof); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("plan accepted before bootstrap draft: %v", err)
	}
	preparation.Stage = SetupBootstrapDrafted
	if _, err := NewSuiteSetupPlan(preparation, VerifiedSuiteRelease{}); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("unverified release accepted: %v", err)
	}
}

func TestSuiteSetupPlanRejectsDuplicateKeysAndRedirectedRoot(t *testing.T) {
	plan := suiteSetupPlanFixture(t)
	raw, _ := jsonMarshalSuiteSetupPlan(plan)
	duplicate := strings.Replace(string(raw), `"stage_id":"`+plan.StageID+`"`, `"Stage_ID":"attacker","stage_id":"`+plan.StageID+`"`, 1)
	roots, _ := setupEngineFixture(t)
	if err := os.MkdirAll(roots.AgentState, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(roots.AgentState, suiteSetupPlanName), []byte(duplicate), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteSetupPlan(roots); !errors.Is(err, ErrSuiteSetupPlan) && !errors.Is(err, ErrSuiteReleaseManifest) {
		t.Fatalf("duplicate plan key accepted: %v", err)
	}
	noncanonical := strings.Replace(string(raw), `"stage_id":"`+plan.StageID+`"`, `"Stage_ID":"`+plan.StageID+`"`, 1)
	if err := os.WriteFile(filepath.Join(roots.AgentState, suiteSetupPlanName), []byte(noncanonical), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteSetupPlan(roots); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("noncanonical plan key accepted: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}
	redirected, _ := setupEngineFixture(t)
	target := filepath.Join(t.TempDir(), "redirected")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, redirected.AgentState); err != nil {
		t.Fatal(err)
	}
	if err := SaveSuiteSetupPlan(redirected, plan); !errors.Is(err, ErrFarmClientRoots) {
		t.Fatalf("redirected plan root accepted: %v", err)
	}
}

func TestSuiteSetupPlanStageIDIsContentAddressed(t *testing.T) {
	plan := suiteSetupPlanFixture(t)
	want := deriveSuiteSetupStageID(plan.ManifestSHA256, plan.Target)
	if plan.StageID != want || plan.StageID == "stage-01" {
		t.Fatalf("stage id = %q, want %q", plan.StageID, want)
	}
	changed := plan
	changed.Target.Arch = "arm64"
	if changed.Validate() == nil {
		t.Fatal("stage id remained valid after target mutation")
	}
	changed = plan
	changed.ManifestSHA256 = strings.Repeat("c", 64)
	if changed.Validate() == nil {
		t.Fatal("stage id remained valid after manifest mutation")
	}
}
