//go:build darwin

package backend

import (
	"net"

	"golang.org/x/sys/unix"
)

func farmClientIPCPeerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, err := unix.GetsockoptXucred(int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
		if err != nil {
			socketErr = err
			return
		}
		uid = credential.Uid
	}); err != nil {
		return 0, err
	}
	return uid, socketErr
}
