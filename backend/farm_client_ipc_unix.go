//go:build darwin || linux

package backend

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const farmClientIPCSocketName = "agent.sock"

type farmClientIPCUnixListener struct {
	*net.UnixListener
	path string
	dev  uint64
	ino  uint64
	uid  uint32
}

func farmClientIPCSocketPath(stateRoot string) string {
	return filepath.Join(stateRoot, "ipc", farmClientIPCSocketName)
}

func listenFarmClientIPC(stateRoot string) (net.Listener, error) {
	uid := uint32(os.Geteuid())
	if err := validateFarmClientIPCUnixDirectory(stateRoot, uid, false); err != nil {
		return nil, err
	}
	directory := filepath.Join(stateRoot, "ipc")
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return nil, fmt.Errorf("%w: create IPC directory", ErrFarmClientIPCUnavailable)
	}
	if err := validateFarmClientIPCUnixDirectory(directory, uid, true); err != nil {
		return nil, err
	}
	path := farmClientIPCSocketPath(stateRoot)
	if len([]byte(path)) > 100 {
		return nil, fmt.Errorf("%w: socket path is too long", ErrFarmClientIPCUnavailable)
	}
	if info, err := os.Lstat(path); err == nil {
		dev, ino, owner, ok := farmClientIPCUnixIdentity(info)
		_ = dev
		_ = ino
		if !ok || owner != uid || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
			return nil, fmt.Errorf("%w: unsafe existing socket", ErrFarmClientIPCUnavailable)
		}
		connection, dialErr := net.DialTimeout("unix", path, 100*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			return nil, fmt.Errorf("%w: IPC endpoint is active", ErrFarmClientIPCUnavailable)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("%w: remove stale socket", ErrFarmClientIPCUnavailable)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: inspect IPC socket", ErrFarmClientIPCUnavailable)
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("%w: listen", ErrFarmClientIPCUnavailable)
	}
	// net.UnixListener otherwise unlinks by pathname during Close, which can
	// delete an attacker-replaced socket. Cleanup below is inode-fenced.
	listener.SetUnlinkOnClose(false)
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = listener.Close()
			_ = os.Remove(path)
		}
	}()
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("%w: secure socket", ErrFarmClientIPCUnavailable)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o600 {
		return nil, fmt.Errorf("%w: verify socket", ErrFarmClientIPCUnavailable)
	}
	dev, ino, owner, ok := farmClientIPCUnixIdentity(info)
	if !ok || owner != uid {
		return nil, fmt.Errorf("%w: socket owner", ErrFarmClientIPCUnavailable)
	}
	closeOnError = false
	return &farmClientIPCUnixListener{UnixListener: listener, path: path, dev: dev, ino: ino, uid: uid}, nil
}

func (listener *farmClientIPCUnixListener) Accept() (net.Conn, error) {
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			return nil, err
		}
		peer, err := farmClientIPCPeerUID(connection)
		if err == nil && peer == listener.uid {
			return connection, nil
		}
		_ = connection.Close()
	}
}

func (listener *farmClientIPCUnixListener) Close() error {
	err := listener.UnixListener.Close()
	if info, statErr := os.Lstat(listener.path); statErr == nil {
		dev, ino, _, ok := farmClientIPCUnixIdentity(info)
		if ok && dev == listener.dev && ino == listener.ino {
			_ = os.Remove(listener.path)
		}
	}
	return err
}

func dialFarmClientIPC(ctx context.Context, stateRoot string) (net.Conn, error) {
	uid := uint32(os.Geteuid())
	if err := validateFarmClientIPCUnixDirectory(stateRoot, uid, false); err != nil {
		return nil, err
	}
	directory := filepath.Join(stateRoot, "ipc")
	if err := validateFarmClientIPCUnixDirectory(directory, uid, true); err != nil {
		return nil, err
	}
	path := farmClientIPCSocketPath(stateRoot)
	before, err := os.Lstat(path)
	if err != nil || before.Mode()&os.ModeSocket == 0 || before.Mode().Perm() != 0o600 {
		return nil, ErrFarmClientIPCUnavailable
	}
	beforeDev, beforeIno, owner, ok := farmClientIPCUnixIdentity(before)
	if !ok || owner != uid {
		return nil, ErrFarmClientIPCUnavailable
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", path)
	if err != nil {
		return nil, err
	}
	unixConnection, ok := connection.(*net.UnixConn)
	if !ok {
		_ = connection.Close()
		return nil, ErrFarmClientIPCUnavailable
	}
	peer, peerErr := farmClientIPCPeerUID(unixConnection)
	after, statErr := os.Lstat(path)
	if peerErr != nil || peer != uid || statErr != nil {
		_ = connection.Close()
		return nil, ErrFarmClientIPCUnavailable
	}
	afterDev, afterIno, afterOwner, identityOK := farmClientIPCUnixIdentity(after)
	if !identityOK || afterOwner != uid || beforeDev != afterDev || beforeIno != afterIno {
		_ = connection.Close()
		return nil, ErrFarmClientIPCUnavailable
	}
	return connection, nil
}

func validateFarmClientIPCUnixDirectory(path string, uid uint32, exact bool) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%w: unsafe IPC directory", ErrFarmClientIPCUnavailable)
	}
	_, _, owner, ok := farmClientIPCUnixIdentity(info)
	if !ok || owner != uid || info.Mode().Perm()&0o077 != 0 || (exact && info.Mode().Perm() != 0o700) {
		return fmt.Errorf("%w: IPC directory is not owner-only", ErrFarmClientIPCUnavailable)
	}
	return nil
}

func farmClientIPCUnixIdentity(info os.FileInfo) (uint64, uint64, uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return 0, 0, 0, false
	}
	return uint64(stat.Dev), uint64(stat.Ino), stat.Uid, true
}
