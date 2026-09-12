package backend

import (
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
	plan, err := NewSuiteSetupPlan(preparation, strings.Repeat("b", 64), SuiteReleaseTarget{OS: "linux", Arch: "amd64"}, "stage-01")
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func TestSuiteSetupPlanAtomicImmutableRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "setup-plan.json")
	plan := suiteSetupPlanFixture(t)
	if err := SaveSuiteSetupPlan(path, plan); err != nil {
		t.Fatal(err)
	}
	if err := SaveSuiteSetupPlan(path, plan); err != nil {
		t.Fatalf("idempotent save: %v", err)
	}
	loaded, err := LoadSuiteSetupPlan(path)
	if err != nil || *loaded != plan {
		t.Fatalf("loaded = %+v, %v", loaded, err)
	}
	changed := plan
	changed.ManifestSHA256 = strings.Repeat("c", 64)
	if err := SaveSuiteSetupPlan(path, changed); !errors.Is(err, ErrSuiteSetupPlanConflict) {
		t.Fatalf("conflicting plan accepted: %v", err)
	}
	stillLoaded, err := LoadSuiteSetupPlan(path)
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
	path := filepath.Join(t.TempDir(), "setup-plan.json")
	plan := suiteSetupPlanFixture(t)
	raw, _ := jsonMarshalSuiteSetupPlan(plan)
	raw = append(raw[:len(raw)-2], []byte(",\"private_key\":\"secret\"}\n")...)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuiteSetupPlan(path); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("unknown secret field accepted: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadSuiteSetupPlan(path); err == nil {
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
	if _, err := NewSuiteSetupPlan(preparation, strings.Repeat("b", 64), SuiteReleaseTarget{OS: "linux", Arch: "amd64"}, "stage-01"); !errors.Is(err, ErrSuiteSetupPlan) {
		t.Fatalf("plan accepted before bootstrap draft: %v", err)
	}
}
