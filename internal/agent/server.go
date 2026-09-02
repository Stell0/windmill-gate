package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/nethserver/gate/internal/command"
	gatecore "github.com/nethserver/gate/internal/gate"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/protocol"
)

type Server struct {
	Service     *gatecore.Service
	Transport   string
	Fingerprint string
}

func ListenUnix(path string) (net.Listener, error) {
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("refusing to replace non-socket at %s", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale Gate socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect Gate socket: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create Gate socket directory: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on Gate socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("secure Gate socket permissions: %w", err)
	}
	return listener, nil
}

func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if s.Service == nil {
		return errors.New("Gate service is required")
	}
	var connections sync.WaitGroup
	var connectionMu sync.Mutex
	active := make(map[net.Conn]struct{})
	go func() {
		<-ctx.Done()
		_ = listener.Close()
		connectionMu.Lock()
		for conn := range active {
			_ = conn.Close()
		}
		connectionMu.Unlock()
	}()
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil {
				connections.Wait()
				return nil
			}
			return fmt.Errorf("accept agent connection: %w", err)
		}
		connectionMu.Lock()
		active[conn] = struct{}{}
		connectionMu.Unlock()
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer func() {
				connectionMu.Lock()
				delete(active, conn)
				connectionMu.Unlock()
			}()
			defer conn.Close()
			_ = s.ServeConn(ctx, conn)
		}()
	}
}

func (s *Server) ServeConn(ctx context.Context, conn io.ReadWriteCloser) error {
	decoder := protocol.NewDecoder(conn)
	encoder := protocol.NewEncoder(conn)
	var hello protocol.Request
	if err := decoder.Decode(&hello); err != nil {
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	if err := hello.Validate(); err != nil || hello.Type != "hello" {
		if err == nil {
			err = errors.New("first request must be hello")
		}
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	transport := s.Transport
	if transport == "" {
		transport = "unix"
	}
	session, err := s.Service.OpenSession(ctx, hello.Agent, transport, s.Fingerprint)
	if err != nil {
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	defer session.Close(context.WithoutCancel(ctx))
	if err := encoder.Encode(protocol.Response{Type: "hello", Version: protocol.Version}); err != nil {
		return err
	}

	var request protocol.Request
	if err := decoder.Decode(&request); err != nil {
		if errors.Is(err, io.EOF) {
			return nil
		}
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	if err := request.Validate(); err != nil {
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}
	if request.Type != "exec" {
		err := fmt.Errorf("expected one exec request, got %q", request.Type)
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return err
	}

	execCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	sink := &protocolSink{encoder: encoder}
	go func() { done <- session.Exec(execCtx, []byte(request.Command), sink) }()

	// A second frame can only cancel the one running command. EOF means the
	// agent disconnected, which also cancels execution and remains auditable.
	nextFrame := make(chan protocol.Request, 1)
	readError := make(chan error, 1)
	go func() {
		var next protocol.Request
		if err := decoder.Decode(&next); err != nil {
			readError <- err
			return
		}
		nextFrame <- next
	}()
	select {
	case err := <-done:
		return err
	case err := <-readError:
		cancel()
		<-done
		if errors.Is(err, io.EOF) {
			return nil
		}
		return err
	case next := <-nextFrame:
		if err := next.Validate(); err != nil || next.Type != "cancel" {
			cancel()
			<-done
			if err == nil {
				err = errors.New("only cancel is accepted while a command is running")
			}
			_ = sink.Error(err.Error())
			return err
		}
		if err := s.Service.CancelSessionCommand(session, next.CommandID); err != nil {
			cancel()
			<-done
			_ = sink.Error(err.Error())
			return err
		}
		return <-done
	}
}

type protocolSink struct {
	mu      sync.Mutex
	encoder *protocol.Encoder
}

func (s *protocolSink) send(response protocol.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.encoder.Encode(response)
}

func (s *protocolSink) Accepted(cmd command.Snapshot, result policy.Result) error {
	return s.send(protocol.Response{
		Type: "accepted", CommandID: cmd.ID, Hash: cmd.Hash,
		Policy: string(result.Decision), State: string(cmd.State),
	})
}

func (s *protocolSink) State(cmd command.Snapshot) error {
	return s.send(protocol.Response{Type: "state", CommandID: cmd.ID, State: string(cmd.State)})
}

func (s *protocolSink) Output(stream string, data []byte) error {
	return s.send(protocol.Response{Type: stream, Data: string(data)})
}

func (s *protocolSink) Exit(cmd command.Snapshot, code int) error {
	return s.send(protocol.Response{Type: "exit", CommandID: cmd.ID, State: string(cmd.State), Code: &code})
}

func (s *protocolSink) Error(message string) error {
	return s.send(protocol.Response{Type: "error", Error: message})
}
