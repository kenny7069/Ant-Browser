package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticsCLIUsesAllowlist(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "client.yaml")
	secret := "PRIVATE_KEY_AND_ENROLLMENT_CODE_CANARY"
	config := "application_root: " + root + "\nstate_root: " + filepath.Join(root, "state") +
		"\ncontrol_url: ws://127.0.0.1:1\nenrollment_url: http://127.0.0.1:2/enroll\nallow_loopback_http_enrollment: true\n" +
		"identity:\n  node_uid: node-a\n  private_key: " + secret + "\n"
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := protectedMain([]string{"-config", configPath, "-diagnostics"}, strings.NewReader(""), &stdout, &stderr); code != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	if strings.Contains(stdout.String(), secret) || strings.Contains(stdout.String(), "node-a") || strings.Contains(stdout.String(), root) {
		t.Fatalf("diagnostics leaked configured value: %s", stdout.String())
	}
}

func TestProtectedMainDoesNotPrintPanicValue(t *testing.T) {
	secret := "PANIC_PRIVATE_KEY_CANARY"
	var stderr bytes.Buffer
	code := protectedRun(&stderr, func() int {
		panic(secret)
	})
	if code != 1 || strings.Contains(stderr.String(), secret) {
		t.Fatalf("panic output=%q code=%d", stderr.String(), code)
	}
}

func TestEnrollmentCodeReaderIsBoundedAndTrims(t *testing.T) {
	code, err := readEnrollmentCode(strings.NewReader("  code-value  \nignored"), &bytes.Buffer{})
	if err != nil || code != "code-value" {
		t.Fatalf("code=%q err=%v", code, err)
	}
}
