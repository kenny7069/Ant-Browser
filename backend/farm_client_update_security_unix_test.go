//go:build !windows

package backend

import (
	"os"
	"testing"
)

func assertFarmClientStagedFileSecurity(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		if err != nil {
			t.Fatalf("stat staged update security: %v", err)
		}
		t.Fatalf("mode=%v, want 0600", info.Mode().Perm())
	}
}
