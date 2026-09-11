package backend_test

import (
	"ant-chrome/backend"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBrowserRuntimeLocalProcessFactoryIsExternallyCallable(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "started")
	script := filepath.Join(t.TempDir(), "browser-fixture")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf started > \"$1\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	process, err := backend.NewBrowserRuntimeLocalProcess(backend.BrowserRuntimeLaunchSpec{
		ChromeBinaryPath: script,
		Args:             []string{marker},
	})
	if err != nil || process == nil {
		t.Fatalf("external local process factory = process:%v err:%v", process, err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(marker); err == nil {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("external local process fixture did not execute")
}
