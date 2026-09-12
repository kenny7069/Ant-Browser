package backend

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

type FarmClientIPCServer struct {
	listener   net.Listener
	management *farmProfileManagement
	timeout    time.Duration

	closeOnce sync.Once
	stopping  chan struct{}
	closed    chan struct{}
	handlers  sync.WaitGroup
	serveErr  error
	mu        sync.Mutex
}

func StartFarmClientIPCServer(host *FarmClientHost) (*FarmClientIPCServer, error) {
	management, err := newFarmProfileManagement(host)
	if err != nil {
		return nil, err
	}
	listener, err := listenFarmClientIPC(host.config.StateRoot)
	if err != nil {
		return nil, err
	}
	timeout := host.config.commandTimeout()
	if timeout <= 0 || timeout > 30*time.Second {
		timeout = 30 * time.Second
	}
	server := &FarmClientIPCServer{listener: listener, management: management, timeout: timeout, stopping: make(chan struct{}), closed: make(chan struct{})}
	go server.serve()
	return server, nil
}

func (server *FarmClientIPCServer) serve() {
	defer close(server.closed)
	for {
		connection, err := server.listener.Accept()
		if err != nil {
			select {
			case <-server.stopping:
				return
			default:
			}
			server.mu.Lock()
			server.serveErr = err
			server.mu.Unlock()
			return
		}
		server.handlers.Add(1)
		go func(connection net.Conn) {
			defer server.handlers.Done()
			defer connection.Close()
			forceClose := time.AfterFunc(server.timeout, func() { _ = connection.Close() })
			defer forceClose.Stop()
			_ = connection.SetDeadline(time.Now().Add(server.timeout))
			server.handle(connection)
		}(connection)
	}
}

func (server *FarmClientIPCServer) handle(connection net.Conn) {
	raw, err := readFarmClientIPCFrame(connection)
	requestUID := uuid.NewString()
	var result any
	if err == nil {
		var request farmClientIPCRequest
		request, err = decodeFarmClientIPCRequest(raw)
		if err == nil {
			requestUID = request.RequestUID
			ctx, cancel := context.WithTimeout(context.Background(), server.timeout)
			result, err = server.dispatch(ctx, request)
			cancel()
		}
	}
	response := farmClientIPCResponse{ProtocolVersion: FarmClientIPCProtocolVersion, RequestUID: requestUID, OK: err == nil}
	if err == nil {
		response.Result, err = marshalFarmClientIPCResult(result)
	}
	if err != nil {
		response.OK = false
		response.Result = nil
		response.Error = &farmClientIPCError{Code: farmClientIPCErrorCode(err)}
	}
	encoded, marshalErr := json.Marshal(response)
	if marshalErr == nil {
		_ = writeFarmClientIPCFrame(connection, encoded)
	}
}

func (server *FarmClientIPCServer) dispatch(ctx context.Context, request farmClientIPCRequest) (any, error) {
	switch request.Operation {
	case farmClientIPCHealth:
		return struct {
			Status string `json:"status"`
		}{Status: "ready"}, nil
	case farmClientIPCProfileList:
		return server.management.List()
	case farmClientIPCProfileOpen:
		var payload farmClientIPCProfilePayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id"}); err != nil {
			return nil, err
		}
		return server.management.Open(payload.ProfileID)
	case farmClientIPCProfileStop:
		var payload farmClientIPCProfilePayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id"}); err != nil {
			return nil, err
		}
		return server.management.Stop(payload.ProfileID)
	case farmClientIPCProfileState:
		var payload farmClientIPCProfilePayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id"}); err != nil {
			return nil, err
		}
		return server.management.Status(payload.ProfileID)
	case farmClientIPCProfilePair:
		var payload farmClientIPCPairPayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id", "pairing_code"}); err != nil {
			return nil, err
		}
		result, err := server.management.Pair(ctx, payload.ProfileID, payload.PairingCode)
		payload.PairingCode = ""
		return result, err
	case farmClientIPCProfileUnpair:
		var payload farmClientIPCProfilePayload
		if err := decodeFarmClientIPCObject(request.Payload, &payload, []string{"profile_id"}); err != nil {
			return nil, err
		}
		return server.management.Unpair(ctx, payload.ProfileID)
	default:
		return nil, ErrFarmClientIPCInvalid
	}
}

// Close stops admission and waits a bounded period for requests already
// admitted by this server. Host shutdown remains owned by the caller.
func (server *FarmClientIPCServer) Close() error {
	if server == nil {
		return nil
	}
	server.closeOnce.Do(func() {
		close(server.stopping)
		_ = server.listener.Close()
		select {
		case <-server.closed:
		case <-time.After(server.timeout + 250*time.Millisecond):
			server.mu.Lock()
			server.serveErr = errors.Join(server.serveErr, context.DeadlineExceeded)
			server.mu.Unlock()
		}
		waited := make(chan struct{})
		go func() { server.handlers.Wait(); close(waited) }()
		select {
		case <-waited:
		case <-time.After(server.timeout + 250*time.Millisecond):
			server.mu.Lock()
			server.serveErr = errors.Join(server.serveErr, context.DeadlineExceeded)
			server.mu.Unlock()
		}
	})
	server.mu.Lock()
	defer server.mu.Unlock()
	return server.serveErr
}
