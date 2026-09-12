//go:build windows

package backend

import (
	"context"
	"os"
	"testing"
)

func TestFarmClientIPCWindowsProtectedPipeAndSameSIDPeer(t *testing.T) {
	root := t.TempDir()
	listener, err := listenFarmClientIPC(root)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan error, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			_ = connection.Close()
		}
		accepted <- err
	}()
	connection, err := dialFarmClientIPC(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()
	if err := <-accepted; err != nil {
		t.Fatalf("same-SID connection rejected: %v", err)
	}
	name, _, err := farmClientIPCPipeName(root)
	if err != nil || name == "" {
		t.Fatalf("pipe name=%q err=%v", name, err)
	}
	other, _, err := farmClientIPCPipeName(root + string(os.PathSeparator) + "other")
	if err != nil || other == name {
		t.Fatalf("state-root isolation failed: %q %q err=%v", name, other, err)
	}
}
