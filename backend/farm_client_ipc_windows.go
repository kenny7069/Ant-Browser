//go:build windows

package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type farmClientIPCPipeListener struct {
	name    string
	sid     *windows.SID
	mu      sync.Mutex
	first   bool
	closed  bool
	pending windows.Handle
}

type farmClientIPCPipeConn struct {
	*os.File
	server bool
}

type farmClientIPCPipeAddr string

func (address farmClientIPCPipeAddr) Network() string { return "npipe" }
func (address farmClientIPCPipeAddr) String() string  { return string(address) }

func farmClientIPCPipeName(stateRoot string) (string, *windows.SID, error) {
	if !filepath.IsAbs(stateRoot) {
		return "", nil, ErrFarmClientIPCUnavailable
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return "", nil, ErrFarmClientIPCUnavailable
	}
	canonical := strings.ToLower(filepath.Clean(stateRoot))
	digest := sha256.Sum256([]byte(user.User.Sid.String() + "\x00" + canonical))
	return `\\.\pipe\AntSuite.Agent.` + hex.EncodeToString(digest[:16]), user.User.Sid, nil
}

func listenFarmClientIPC(stateRoot string) (net.Listener, error) {
	name, sid, err := farmClientIPCPipeName(stateRoot)
	if err != nil {
		return nil, err
	}
	return &farmClientIPCPipeListener{name: name, sid: sid, first: true}, nil
}

func (listener *farmClientIPCPipeListener) Accept() (net.Conn, error) {
	for {
		listener.mu.Lock()
		if listener.closed {
			listener.mu.Unlock()
			return nil, net.ErrClosed
		}
		flags := uint32(windows.PIPE_ACCESS_DUPLEX)
		if listener.first {
			flags |= windows.FILE_FLAG_FIRST_PIPE_INSTANCE
			listener.first = false
		}
		descriptor, err := windows.SecurityDescriptorFromString("O:" + listener.sid.String() + "G:" + listener.sid.String() + "D:P(A;;GRGW;;;" + listener.sid.String() + ")")
		if err != nil {
			listener.mu.Unlock()
			return nil, ErrFarmClientIPCUnavailable
		}
		security := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: descriptor}
		name, err := windows.UTF16PtrFromString(listener.name)
		if err != nil {
			listener.mu.Unlock()
			return nil, ErrFarmClientIPCUnavailable
		}
		handle, err := windows.CreateNamedPipe(name, flags, windows.PIPE_TYPE_BYTE|windows.PIPE_READMODE_BYTE|windows.PIPE_WAIT|windows.PIPE_REJECT_REMOTE_CLIENTS, windows.PIPE_UNLIMITED_INSTANCES, farmClientIPCMaxFrameBytes, farmClientIPCMaxFrameBytes, 0, &security)
		runtime.KeepAlive(descriptor)
		if err != nil {
			listener.mu.Unlock()
			return nil, fmt.Errorf("%w: create named pipe", ErrFarmClientIPCUnavailable)
		}
		listener.pending = handle
		listener.mu.Unlock()
		if err := validateFarmClientIPCPipeDACL(handle, listener.sid); err != nil {
			listener.closePendingHandle(handle)
			return nil, err
		}
		connectErr := windows.ConnectNamedPipe(handle, nil)
		if connectErr != nil && connectErr != windows.ERROR_PIPE_CONNECTED {
			listener.closePendingHandle(handle)
			return nil, connectErr
		}
		if !listener.compareAndClearPending(handle) {
			return nil, net.ErrClosed
		}
		if err := validateFarmClientIPCPipePeer(handle, true, listener.sid); err != nil {
			windows.DisconnectNamedPipe(handle)
			windows.CloseHandle(handle)
			continue
		}
		return &farmClientIPCPipeConn{File: os.NewFile(uintptr(handle), listener.name), server: true}, nil
	}
}

func (listener *farmClientIPCPipeListener) compareAndClearPending(handle windows.Handle) bool {
	listener.mu.Lock()
	defer listener.mu.Unlock()
	if listener.pending != handle {
		return false
	}
	listener.pending = 0
	return true
}

func (listener *farmClientIPCPipeListener) closePendingHandle(handle windows.Handle) {
	if listener.compareAndClearPending(handle) {
		_ = windows.CloseHandle(handle)
	}
}

func (listener *farmClientIPCPipeListener) Close() error {
	listener.mu.Lock()
	if listener.closed {
		listener.mu.Unlock()
		return nil
	}
	listener.closed = true
	pending := listener.pending
	listener.pending = 0
	listener.mu.Unlock()
	if pending != 0 {
		return windows.CloseHandle(pending)
	}
	return nil
}

func (listener *farmClientIPCPipeListener) Addr() net.Addr {
	return farmClientIPCPipeAddr(listener.name)
}

func dialFarmClientIPC(ctx context.Context, stateRoot string) (net.Conn, error) {
	name, sid, err := farmClientIPCPipeName(stateRoot)
	if err != nil {
		return nil, err
	}
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	for {
		handle, openErr := windows.CreateFile(namePointer, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, windows.SECURITY_IDENTIFICATION, 0)
		if openErr == nil {
			if err := validateFarmClientIPCPipePeer(handle, false, sid); err != nil {
				windows.CloseHandle(handle)
				return nil, err
			}
			return &farmClientIPCPipeConn{File: os.NewFile(uintptr(handle), name)}, nil
		}
		if openErr != windows.ERROR_PIPE_BUSY {
			return nil, openErr
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func validateFarmClientIPCPipePeer(pipe windows.Handle, client bool, expected *windows.SID) error {
	var processID uint32
	var err error
	if client {
		err = windows.GetNamedPipeClientProcessId(pipe, &processID)
	} else {
		err = windows.GetNamedPipeServerProcessId(pipe, &processID)
	}
	if err != nil || processID == 0 {
		return ErrFarmClientIPCUnavailable
	}
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, processID)
	if err != nil {
		return ErrFarmClientIPCUnavailable
	}
	defer windows.CloseHandle(process)
	var token windows.Token
	if err := windows.OpenProcessToken(process, windows.TOKEN_QUERY, &token); err != nil {
		return ErrFarmClientIPCUnavailable
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !windows.EqualSid(user.User.Sid, expected) {
		return ErrFarmClientIPCUnavailable
	}
	return nil
}

func validateFarmClientIPCPipeDACL(pipe windows.Handle, expected *windows.SID) error {
	descriptor, err := windows.GetSecurityInfo(pipe, windows.SE_KERNEL_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ErrFarmClientIPCUnavailable
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !windows.EqualSid(owner, expected) {
		return ErrFarmClientIPCUnavailable
	}
	control, _, err := descriptor.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return ErrFarmClientIPCUnavailable
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount != 1 {
		return ErrFarmClientIPCUnavailable
	}
	var ace *windows.ACCESS_ALLOWED_ACE
	if err := windows.GetAce(dacl, 0, &ace); err != nil || ace == nil {
		return ErrFarmClientIPCUnavailable
	}
	aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
	wantGeneric := uint32(windows.GENERIC_READ | windows.GENERIC_WRITE)
	wantFile := uint32(windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE)
	mask := uint32(ace.Mask)
	if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || !windows.EqualSid(aceSID, expected) ||
		(mask&wantGeneric != wantGeneric && mask&wantFile != wantFile) {
		return ErrFarmClientIPCUnavailable
	}
	return nil
}

func (connection *farmClientIPCPipeConn) Close() error {
	if connection.server {
		_ = windows.DisconnectNamedPipe(windows.Handle(connection.Fd()))
	}
	return connection.File.Close()
}

func (connection *farmClientIPCPipeConn) LocalAddr() net.Addr {
	return farmClientIPCPipeAddr(connection.Name())
}
func (connection *farmClientIPCPipeConn) RemoteAddr() net.Addr {
	return farmClientIPCPipeAddr(connection.Name())
}
