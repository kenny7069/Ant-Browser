package backend

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func suiteBootstrapEnrollmentTestRoots(t *testing.T) SuiteUserRoots {
	t.Helper()
	base := t.TempDir()
	return SuiteUserRoots{
		Config: filepath.Join(base, "config"), BrowserData: filepath.Join(base, "browser-data"),
		AgentState: filepath.Join(base, "agent-state"), Logs: filepath.Join(base, "logs"),
	}
}

func suiteBootstrapEnrollmentAttemptFixture(stage SuiteBootstrapEnrollmentStage) SuiteBootstrapEnrollmentAttempt {
	attempt := SuiteBootstrapEnrollmentAttempt{
		SchemaVersion: suiteBootstrapEnrollmentSchema, Stage: stage,
		PreparationRequestUID: "123e4567-e89b-12d3-a456-426614174001",
		DeploymentUID:         "123e4567-e89b-12d3-a456-426614174000",
		DiscoverySHA256:       strings.Repeat("1", 64), MetadataSHA256: strings.Repeat("2", 64),
		IdentityRef: "suite-v3-" + strings.Repeat("3", 64), PublicKeySHA256: strings.Repeat("4", 64),
		EnrollmentCodeSHA256: strings.Repeat("5", 64), RequestSHA256: strings.Repeat("6", 64), IdempotencySHA256: strings.Repeat("7", 64),
	}
	if stage == SuiteBootstrapAcknowledged {
		attempt.NodeUID = "node-1"
		attempt.EnrollmentState = "ENROLLED"
		attempt.ControlEndpoint = "wss://farm.example.test/control/ws"
	}
	return attempt
}

func TestSuiteBootstrapEnrollmentAttemptMonotonicOwnerOnlyAndBackupRecovery(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	identity := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, identity); err != nil {
		t.Fatal(err)
	}
	request := identity
	request.Stage = SuiteBootstrapRequestReady
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, request); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
	for _, candidate := range []string{path, path + ".bak"} {
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("owner file %s info=%v err=%v", filepath.Base(candidate), info, err)
		}
	}
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	recovered, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil || recovered == nil || recovered.Stage != SuiteBootstrapIdentityReady {
		t.Fatalf("recovered=%+v err=%v", recovered, err)
	}
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, request); err != nil {
		t.Fatalf("restore and advance: %v", err)
	}
	loaded, err := loadSuiteBootstrapEnrollmentAttempt(roots)
	if err != nil || loaded.Stage != SuiteBootstrapRequestReady {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
}

func TestSuiteBootstrapEnrollmentAttemptRejectsSkipRollbackDriftAndSecrets(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	identity := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
	ack := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapAcknowledged)
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, ack); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("first-stage skip error=%v", err)
	}
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, identity); err != nil {
		t.Fatal(err)
	}
	request := identity
	request.Stage = SuiteBootstrapRequestReady
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, request); err != nil {
		t.Fatal(err)
	}
	drift := identity
	drift.Stage = SuiteBootstrapRequestReady
	drift.MetadataSHA256 = strings.Repeat("8", 64)
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, drift); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
		t.Fatalf("binding drift error=%v", err)
	}
	path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
	raw, _ := json.Marshal(identity)
	secret := `{"diagnostic":{"nested":{"Private_Key":"secret"}}`
	if err := writeOwnerAtomic(path, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
		t.Fatalf("secret field error=%v", err)
	}
	duplicate := strings.Replace(string(raw), `"stage":"IDENTITY_READY"`, `"stage":"IDENTITY_READY","stage":"IDENTITY_READY"`, 1)
	if err := writeOwnerAtomic(path, []byte(duplicate)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentDuplicate) {
		t.Fatalf("duplicate field error=%v", err)
	}
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, maxSuiteBootstrapEnrollmentStateBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
		t.Fatalf("oversized primary error=%v", err)
	}
}

func TestSuiteBootstrapEnrollmentAttemptRejectsSymlinkAndUnsafeMode(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	if err := ensureOwnerDirectory(roots.AgentState); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); err == nil {
		t.Fatal("symlink accepted")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); err == nil {
		t.Fatal("unsafe mode accepted")
	}
}

func TestSuiteBootstrapEnrollmentAttemptRejectsSecretBackupEvenWithValidPrimary(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	identity := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
	request := identity
	request.Stage = SuiteBootstrapRequestReady
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, identity); err != nil {
		t.Fatal(err)
	}
	if err := saveSuiteBootstrapEnrollmentAttempt(roots, request); err != nil {
		t.Fatal(err)
	}
	backup := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName+".bak")
	if err := writeOwnerAtomic(backup, []byte(`{"nested":{"token":"secret"}}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
		t.Fatalf("secret backup error=%v", err)
	}
}

func TestSuiteBootstrapEnrollmentAttemptRejectsConflictingOrFutureBackup(t *testing.T) {
	for _, test := range []struct {
		name    string
		primary SuiteBootstrapEnrollmentAttempt
		backup  SuiteBootstrapEnrollmentAttempt
	}{
		{
			name:    "conflicting binding",
			primary: suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapRequestReady),
			backup: func() SuiteBootstrapEnrollmentAttempt {
				value := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
				value.MetadataSHA256 = strings.Repeat("8", 64)
				return value
			}(),
		},
		{
			name:    "future backup",
			primary: suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady),
			backup:  suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapRequestReady),
		},
		{
			name:    "same stage different ACK",
			primary: suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapAcknowledged),
			backup: func() SuiteBootstrapEnrollmentAttempt {
				value := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapAcknowledged)
				value.NodeUID = "other-node"
				return value
			}(),
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			roots := suiteBootstrapEnrollmentTestRoots(t)
			if err := writeSuiteBootstrapEnrollmentAttemptFile(filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName), test.primary); err != nil {
				t.Fatal(err)
			}
			if err := writeSuiteBootstrapEnrollmentAttemptFile(filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName+".bak"), test.backup); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
				t.Fatalf("conflicting backup accepted: %v", err)
			}
		})
	}
}
