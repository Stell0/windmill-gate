package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"

	"github.com/nethserver/gate/internal/command"
	"github.com/nethserver/gate/internal/forward"
	gatecore "github.com/nethserver/gate/internal/gate"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/protocol"
)

type Server struct {
	Service               *gatecore.Service
	Transport             string
	TrustHelloFingerprint bool
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
	fingerprint := ""
	if s.TrustHelloFingerprint {
		fingerprint = hello.Fingerprint
	}
	session, err := s.Service.OpenSession(ctx, hello.Agent, transport, fingerprint)
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
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	sink := &protocolSink{encoder: encoder}
	go func() { done <- s.runRequest(requestCtx, session, request, sink) }()

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
		if commandID := sink.CommandID(); commandID == "" || commandID != next.CommandID {
			cancel()
			<-done
			err := errors.New("cancel command ID does not match the active request")
			_ = sink.Error(err.Error())
			return err
		}
		cancel()
		return <-done
	}
}

func (s *Server) runRequest(ctx context.Context, session *gatecore.Session, request protocol.Request, sink *protocolSink) error {
	zero := 0
	switch request.Type {
	case "exec":
		return session.Exec(ctx, []byte(request.Command), sink)
	case "forward_add":
		info, snapshot, authorized, err := session.AddForward(ctx, request.RemotePort, sink)
		if err != nil || !authorized {
			return err
		}
		if err := sink.Forward(info); err != nil {
			return err
		}
		return sink.Exit(snapshot, zero)
	case "forward_list":
		items, err := session.ListForwards()
		if err != nil {
			_ = sink.Error(err.Error())
			return err
		}
		if err := sink.List("forward_list", items); err != nil {
			return err
		}
		return sink.Exit(command.Snapshot{}, zero)
	case "forward_remove":
		if err := session.RemoveForward(ctx, request.CommandID); err != nil {
			_ = sink.Error(err.Error())
			return err
		}
		if err := sink.send(protocol.Response{Type: "forward_removed", ResourceID: request.CommandID}); err != nil {
			return err
		}
		return sink.Exit(command.Snapshot{}, zero)
	case "host_add":
		info, snapshot, authorized, err := session.AddHostAlias(ctx, request.Hostname, request.RemotePort, sink)
		if err != nil || !authorized {
			return err
		}
		if err := sink.Host(info); err != nil {
			return err
		}
		return sink.Exit(snapshot, zero)
	case "host_list":
		items, err := session.ListHostAliases()
		if err != nil {
			_ = sink.Error(err.Error())
			return err
		}
		if err := sink.List("host_list", items); err != nil {
			return err
		}
		return sink.Exit(command.Snapshot{}, zero)
	case "host_remove":
		if err := session.RemoveHostAlias(ctx, request.Hostname); err != nil {
			_ = sink.Error(err.Error())
			return err
		}
		if err := sink.send(protocol.Response{Type: "host_removed", Hostname: request.Hostname}); err != nil {
			return err
		}
		return sink.Exit(command.Snapshot{}, zero)
	default:
		err := fmt.Errorf("request type %q is unavailable on this channel", request.Type)
		_ = sink.Error(err.Error())
		return err
	}
}

type protocolSink struct {
	mu        sync.Mutex
	encoder   *protocol.Encoder
	commandID string
}

func (s *protocolSink) send(response protocol.Response) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.encoder.Encode(response)
}

func (s *protocolSink) Accepted(cmd command.Snapshot, result policy.Result) error {
	s.mu.Lock()
	s.commandID = cmd.ID
	s.mu.Unlock()
	return s.send(protocol.Response{
		Type: "accepted", CommandID: cmd.ID, Hash: cmd.Hash,
		Policy: string(result.Decision), State: string(cmd.State),
	})
}

func (s *protocolSink) CommandID() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.commandID
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

func (s *protocolSink) Forward(info forward.Info) error {
	return s.send(protocol.Response{
		Type: "forward", ResourceID: info.ID, TargetID: info.TargetID,
		LocalHost: info.LocalHost, LocalPort: info.LocalPort, RemotePort: info.RemotePort,
	})
}

func (s *protocolSink) Host(info forward.AliasInfo) error {
	return s.send(protocol.Response{
		Type: "host", ResourceID: info.ForwardID, TargetID: info.TargetID,
		Hostname: info.Hostname, Address: info.Address, LocalPort: info.LocalPort,
		RemotePort: info.RemotePort, URL: info.URL,
	})
}

func (s *protocolSink) List(kind string, value any) error {
	items, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return s.send(protocol.Response{Type: kind, Items: items})
}
