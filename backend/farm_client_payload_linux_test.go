//go:build linux

package backend

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFarmClientLinuxPinnedFDExecIgnoresPathSwap(t *testing.T) {
	root := t.TempDir()
	build := func(name, value string) string {
		source := filepath.Join(root, name+".go")
		binary := filepath.Join(root, name)
		program := "package main\nimport \"fmt\"\nfunc main(){fmt.Print(\"" + value + "\")}\n"
		if err := os.WriteFile(source, []byte(program), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.Command("go", "build", "-o", binary, source)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", name, err, output)
		}
		return binary
	}
	original := build("original", "verified")
	replacement := build("replacement", "replacement")
	artifact, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(artifact)
	updateRoot := filepath.Join(root, "updates")
	versionRoot := filepath.Join(updateRoot, "versions", "1.1.0-"+hex.EncodeToString(digest[:]))
	for _, directory := range []string{updateRoot, filepath.Dir(versionRoot), versionRoot} {
		if err := secureFarmClientUpdateDirectory(directory); err != nil {
			t.Fatal(err)
		}
	}
	executable := filepath.Join(versionRoot, "ant-farm-client")
	if err := os.Rename(original, executable); err != nil {
		t.Fatal(err)
	}
	if err := secureFarmClientUpdateFilePlatform(executable); err != nil {
		t.Fatal(err)
	}
	slot := FarmClientUpdateSlot{Version: "1.1.0", Target: "linux-" + runtime.GOARCH, SHA256: hex.EncodeToString(digest[:]), Size: int64(len(artifact))}
	pinned, err := openFarmClientPinnedPayload(updateRoot, executable, slot)
	if err != nil {
		t.Fatal(err)
	}
	defer pinned.Close()
	if err := os.Rename(replacement, executable); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(pinned.path)
	command.ExtraFiles = pinned.extraFiles
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(output)) != "verified" {
		t.Fatalf("executed swapped pathname: %q", output)
	}
}
