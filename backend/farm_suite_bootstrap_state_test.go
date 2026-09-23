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
		EnrollmentCodeSHA256: strings.Repeat("5", 64), RequestSHA256: strings.Repeat("6", 64),
	}
	attempt.IdempotencySHA256 = suiteBootstrapSHA256([]byte(suiteBootstrapEnrollmentIdempotencyKey(attempt.PreparationRequestUID)))
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

func TestSuiteBootstrapEnrollmentAttemptSecretDetectorChecksKeysNotValues(t *testing.T) {
	roots := suiteBootstrapEnrollmentTestRoots(t)
	attempt := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
	raw, _ := json.Marshal(attempt)
	withSafeValue := strings.Replace(string(raw), `"identity_ref":"`, `"identity_ref":"token-password-`, 1)
	if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName), []byte(withSafeValue)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); err != nil {
		t.Fatalf("safe value rejected: %v", err)
	}
	validNestedSecret := strings.Replace(string(raw), `"stage":"IDENTITY_READY"`, `"stage":"IDENTITY_READY","diagnostic":{"nested":{"password":"secret"}}`, 1)
	if err := writeOwnerAtomic(filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName), []byte(validNestedSecret)); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
		t.Fatalf("nested secret key error=%v", err)
	}
}

func TestSuiteBootstrapEnrollmentMalformedJSONSecretScanner(t *testing.T) {
	for _, test := range []struct {
		name   string
		raw    string
		unsafe bool
	}{
		{"escaped secret key", `{"\u0074oken":"secret",`, true},
		{"secret word value", `{"node_uid":"token",`, false},
		{"escaped secret word value", `{"node_uid":"\u0074oken",`, false},
		{"unterminated escape", `{"node_uid":"value\`, true},
		{"invalid escape", `{"node_uid":"\q",`, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := suiteBootstrapEnrollmentJSONContainsSecretKey([]byte(test.raw)); got != test.unsafe {
				t.Fatalf("unsafe=%v want=%v", got, test.unsafe)
			}
		})
	}
}

func TestSuiteBootstrapEnrollmentMalformedSecretEvidencePrimaryAndBackup(t *testing.T) {
	valid := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapIdentityReady)
	for _, location := range []string{"primary", "backup"} {
		t.Run(location+" escaped secret key", func(t *testing.T) {
			roots := suiteBootstrapEnrollmentTestRoots(t)
			path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
			malformedPath := path
			validPath := path + ".bak"
			if location == "backup" {
				malformedPath, validPath = validPath, malformedPath
			}
			if err := writeSuiteBootstrapEnrollmentAttemptFile(validPath, valid); err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerAtomic(malformedPath, []byte(`{"\u0074oken":"secret",`)); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
				t.Fatalf("escaped secret key error=%v", err)
			}
		})

		t.Run(location+" unterminated escape", func(t *testing.T) {
			roots := suiteBootstrapEnrollmentTestRoots(t)
			path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
			malformedPath := path
			validPath := path + ".bak"
			if location == "backup" {
				malformedPath, validPath = validPath, malformedPath
			}
			if err := writeSuiteBootstrapEnrollmentAttemptFile(validPath, valid); err != nil {
				t.Fatal(err)
			}
			if err := writeOwnerAtomic(malformedPath, []byte(`{"node_uid":"value\`)); err != nil {
				t.Fatal(err)
			}
			if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
				t.Fatalf("unterminated token error=%v", err)
			}
		})
	}

	t.Run("ordinary corrupt primary falls back", func(t *testing.T) {
		roots := suiteBootstrapEnrollmentTestRoots(t)
		path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		if err := writeOwnerAtomic(path, []byte(`{"node_uid":"token",`)); err != nil {
			t.Fatal(err)
		}
		if err := writeSuiteBootstrapEnrollmentAttemptFile(path+".bak", valid); err != nil {
			t.Fatal(err)
		}
		loaded, err := loadSuiteBootstrapEnrollmentAttempt(roots)
		if err != nil || loaded == nil || *loaded != valid {
			t.Fatalf("loaded=%+v err=%v", loaded, err)
		}
	})

	t.Run("ordinary corrupt backup is not classified secret", func(t *testing.T) {
		roots := suiteBootstrapEnrollmentTestRoots(t)
		path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		if err := writeSuiteBootstrapEnrollmentAttemptFile(path, valid); err != nil {
			t.Fatal(err)
		}
		if err := writeOwnerAtomic(path+".bak", []byte(`{"node_uid":"password",`)); err != nil {
			t.Fatal(err)
		}
		if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) || errors.Is(err, errSuiteBootstrapEnrollmentUnsafe) {
			t.Fatalf("ordinary corruption classification error=%v", err)
		}
	})
}

func TestSuiteBootstrapEnrollmentAttemptACKRequiresRequestBackupAndStableIdempotency(t *testing.T) {
	ack := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapAcknowledged)
	request := suiteBootstrapEnrollmentAttemptFixture(SuiteBootstrapRequestReady)
	for _, test := range []struct {
		name    string
		primary *SuiteBootstrapEnrollmentAttempt
		backup  *SuiteBootstrapEnrollmentAttempt
	}{
		{"isolated ACK primary", &ack, nil},
		{"isolated ACK backup", nil, &ack},
		{"modified hash in both", func() *SuiteBootstrapEnrollmentAttempt {
			value := ack
			value.IdempotencySHA256 = strings.Repeat("8", 64)
			return &value
		}(), func() *SuiteBootstrapEnrollmentAttempt {
			value := request
			value.IdempotencySHA256 = strings.Repeat("8", 64)
			return &value
		}()},
	} {
		t.Run(test.name, func(t *testing.T) {
			roots := suiteBootstrapEnrollmentTestRoots(t)
			path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
			if test.primary != nil {
				if err := writeSuiteBootstrapEnrollmentAttemptFile(path, *test.primary); err != nil {
					t.Fatal(err)
				}
			}
			if test.backup != nil {
				if err := writeSuiteBootstrapEnrollmentAttemptFile(path+".bak", *test.backup); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadSuiteBootstrapEnrollmentAttempt(roots); !errors.Is(err, ErrSuiteBootstrapEnrollmentState) {
				t.Fatalf("invalid ACK evidence accepted: %v", err)
			}
		})
	}

	t.Run("corrupt primary recovers request backup", func(t *testing.T) {
		roots := suiteBootstrapEnrollmentTestRoots(t)
		path := filepath.Join(roots.AgentState, SuiteBootstrapEnrollmentAttemptName)
		if err := writeOwnerAtomic(path, []byte("{")); err != nil {
			t.Fatal(err)
		}
		if err := writeSuiteBootstrapEnrollmentAttemptFile(path+".bak", request); err != nil {
			t.Fatal(err)
		}
		loaded, err := loadSuiteBootstrapEnrollmentAttempt(roots)
		if err != nil || loaded == nil || loaded.Stage != SuiteBootstrapRequestReady {
			t.Fatalf("recovered=%+v err=%v", loaded, err)
		}
	})
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
