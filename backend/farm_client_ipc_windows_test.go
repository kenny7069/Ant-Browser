//go:build windows

package backend

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/windows"
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

func TestFarmClientIPCPendingHandleCompareAndClear(t *testing.T) {
	listener := &farmClientIPCPipeListener{pending: windows.Handle(101)}
	if listener.compareAndClearPending(windows.Handle(102)) {
		t.Fatal("mismatched handle cleared pending ownership")
	}
	if listener.pending != windows.Handle(101) {
		t.Fatalf("mismatched clear changed pending handle to %v", listener.pending)
	}
	if !listener.compareAndClearPending(windows.Handle(101)) {
		t.Fatal("matching handle did not clear pending ownership")
	}
	if listener.pending != 0 {
		t.Fatalf("matching clear left pending handle %v", listener.pending)
	}
}
