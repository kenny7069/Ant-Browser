//go:build windows

package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestFarmClientWindowsPinnedHandleBlocksReplacement(t *testing.T) {
	root := t.TempDir()
	artifact := farmClientUpdateBinaryFixture("windows", "amd64")
	digest := sha256.Sum256(artifact)
	updateRoot := filepath.Join(root, "updates")
	versionRoot := filepath.Join(updateRoot, "versions", "1.1.0-"+hex.EncodeToString(digest[:]))
	for _, directory := range []string{updateRoot, filepath.Dir(versionRoot), versionRoot} {
		if err := secureFarmClientUpdateDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(versionRoot, "ant-farm-client.exe")
	if err := os.WriteFile(executable, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := secureFarmClientUpdateFilePlatform(executable); err != nil {
		t.Fatal(err)
	}
	slot := FarmClientUpdateSlot{Version: "1.1.0", Target: "windows-amd64", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))}
	pinned, err := openFarmClientPinnedPayload(updateRoot, executable, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	replacement := filepath.Join(root, "replacement.exe")
	if err := os.WriteFile(replacement, artifact, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, executable); err == nil {
		t.Fatal("pathname replacement succeeded while verified handles were held")
	}
}
