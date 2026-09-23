//go:build darwin || linux

package backend

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFarmClientIPCUnixOwnerOnlyAndPeerUID(t *testing.T) {
	root := newShortFarmClientIPCRoot(t)
	listener, err := listenFarmClientIPC(root)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	for _, path := range []string{filepath.Join(root, "ipc"), farmClientIPCSocketPath(root)} {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0o700)
		if path == farmClientIPCSocketPath(root) {
			want = 0o600
		}
		if info.Mode().Perm() != want {
			t.Fatalf("%s mode=%o want=%o", path, info.Mode().Perm(), want)
		}
	}
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
		t.Fatalf("same-user peer rejected: %v", err)
	}
}

func TestFarmClientIPCUnixCloseDoesNotDeleteReplacement(t *testing.T) {
	root := newShortFarmClientIPCRoot(t)
	listener, err := listenFarmClientIPC(root)
	if err != nil {
		t.Fatal(err)
	}
	path := farmClientIPCSocketPath(root)
	if err := os.Rename(path, path+".old"); err != nil {
		t.Fatal(err)
	}
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	if _, err := os.Lstat(path); err != nil {
		t.Fatalf("replacement socket was removed: %v", err)
	}
}

func TestFarmClientIPCUnixPostBindFailureDoesNotDeleteReplacement(t *testing.T) {
	root := newShortFarmClientIPCRoot(t)
	path := farmClientIPCSocketPath(root)
	var replacement *net.UnixListener
	_, err := listenFarmClientIPCWithPostBindValidation(root, func(string) error {
		if err := os.Rename(path, path+".original"); err != nil {
			return err
		}
		var listenErr error
		replacement, listenErr = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if listenErr != nil {
			return listenErr
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		return errors.New("forced post-bind verification failure")
	})
	if replacement != nil {
		defer replacement.Close()
	}
	if err == nil {
		t.Fatal("forced post-bind validation failure was accepted")
	}
	if _, statErr := os.Lstat(path); statErr != nil {
		t.Fatalf("replacement socket was removed on listen failure: %v", statErr)
	}
}

func TestFarmClientIPCUnixRejectsUnsafeRootAndSocket(t *testing.T) {
	root := newShortFarmClientIPCRoot(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := listenFarmClientIPC(root); err == nil {
		t.Fatal("world-readable state root accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "ipc"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(farmClientIPCSocketPath(root), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenFarmClientIPC(root); err == nil {
		t.Fatal("regular file endpoint accepted")
	}
}

func newShortFarmClientIPCRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "af-ipc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}
