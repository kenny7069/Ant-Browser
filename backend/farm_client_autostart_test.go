package backend

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFarmClientAutostartInputsRequireExistingAbsoluteFiles(t *testing.T) {
	root := t.TempDir()
	executable := filepath.Join(root, "ant-farm-client")
	config := filepath.Join(root, "client.yaml")
	if err := os.WriteFile(executable, []byte("binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("config"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotExecutable, gotConfig, err := farmClientAutostartInputs(executable, config)
	if err != nil || gotExecutable != executable || gotConfig != config {
		t.Fatalf("inputs=(%q,%q) err=%v", gotExecutable, gotConfig, err)
	}
	if _, _, err := farmClientAutostartInputs("relative", config); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("relative executable error=%v", err)
	}
	if _, _, err := farmClientAutostartInputs(executable, filepath.Join(root, "missing")); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("missing config error=%v", err)
	}
}

func TestFarmClientAtomicWriteRejectsSymlinkDirectory(t *testing.T) {
	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := farmClientAtomicWrite(filepath.Join(linkedDirectory, "unit"), []byte("value"), 0o600); !errors.Is(err, ErrFarmClientAutostart) {
		t.Fatalf("symlink directory error=%v", err)
	}
}
