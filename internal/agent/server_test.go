package agent

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	gatecore "github.com/nethserver/gate/internal/gate"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/protocol"
	"github.com/nethserver/gate/internal/storage"
)

type serverBackend struct {
	mu       sync.Mutex
	calls    int
	block    bool
	started  chan struct{}
	canceled chan struct{}
}

func (b *serverBackend) Name() string                                          { return "test" }
func (b *serverBackend) ListTargets(context.Context) ([]backend.Target, error) { return nil, nil }

func (b *serverBackend) Exec(ctx context.Context, _ string, req backend.ExecRequest) (backend.ExecResult, error) {
	b.mu.Lock()
	b.calls++
	b.mu.Unlock()
	if b.block {
		close(b.started)
		<-ctx.Done()
		close(b.canceled)
		return backend.ExecResult{}, ctx.Err()
	}
	_, _ = io.WriteString(req.Stdout, "server output\\n")
	return backend.ExecResult{ExitCode: 7}, nil
}

func (b *serverBackend) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}
func (b *serverBackend) OpenForward(context.Context, string, backend.ForwardRequest) (backend.Forward, error) {
	return nil, errors.New("not implemented")
}

func TestServerClientEndToEnd(t *testing.T) {
	service, store, implementation := serverService(t)
	defer store.Close()
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- (&Server{Service: service}).ServeConn(context.Background(), serverConn) }()
	var stdout bytes.Buffer
	exitCode, err := (Client{
		Dial:    func(context.Context) (io.ReadWriteCloser, error) { return clientConn, nil },
		AgentID: "codex-1", Stdout: &stdout,
	}).Exec(context.Background(), "uptime")
	if err != nil {
		t.Fatal(err)
	}
	if exitCode != 7 || stdout.String() != "server output\\n" || implementation.callCount() != 1 {
		t.Fatalf("exit=%d stdout=%q calls=%d", exitCode, stdout.String(), implementation.callCount())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAgentDisconnectCancelsRunningCommand(t *testing.T) {
	service, store, implementation := serverService(t)
	defer store.Close()
	implementation.block = true
	implementation.started = make(chan struct{})
	implementation.canceled = make(chan struct{})
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- (&Server{Service: service}).ServeConn(context.Background(), serverConn) }()
	encoder, decoder := protocol.NewEncoder(clientConn), protocol.NewDecoder(clientConn)
	if err := encoder.Encode(protocol.Request{Type: "hello", Version: protocol.Version, Agent: "codex-1"}); err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	if err := decoder.Decode(&response); err != nil || response.Type != "hello" {
		t.Fatalf("hello response: %#v, %v", response, err)
	}
	if err := encoder.Encode(protocol.Request{Type: "exec", Command: "uptime"}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"accepted", "state"} {
		response = protocol.Response{}
		if err := decoder.Decode(&response); err != nil || response.Type != want {
			t.Fatalf("%s response: %#v, %v", want, response, err)
		}
	}
	select {
	case <-implementation.started:
	case <-time.After(time.Second):
		t.Fatal("backend command did not start")
	}
	_ = clientConn.Close()
	select {
	case <-implementation.canceled:
	case <-time.After(time.Second):
		t.Fatal("disconnect did not cancel backend command")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("server did not finish disconnected session")
	}
}

func TestServerRejectsMalformedRequest(t *testing.T) {
	service, store, _ := serverService(t)
	defer store.Close()
	serverConn, clientConn := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- (&Server{Service: service}).ServeConn(context.Background(), serverConn) }()
	if _, err := io.WriteString(clientConn, "not-json\n"); err != nil {
		t.Fatal(err)
	}
	var response protocol.Response
	if err := protocol.NewDecoder(clientConn).Decode(&response); err != nil {
		t.Fatal(err)
	}
	_ = clientConn.Close()
	if response.Type != "error" || response.Error == "" {
		t.Fatalf("unexpected response: %#v", response)
	}
	if err := <-done; err == nil {
		t.Fatal("malformed request did not fail server")
	}
}

func TestUnixListenerPermissionsAndSafeStaleHandling(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "gate.sock")
	if err := os.WriteFile(path, []byte("do not replace"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ListenUnix(path); err == nil {
		t.Fatal("non-socket path was replaced")
	}
	if data, _ := os.ReadFile(path); string(data) != "do not replace" {
		t.Fatal("non-socket path was modified")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	listener, err := ListenUnix(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o", info.Mode().Perm())
	}
}

func serverService(t *testing.T) (*gatecore.Service, *storage.Store, *serverBackend) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(policy.Config{Allow: []string{`^uptime$`}})
	if err != nil {
		t.Fatal(err)
	}
	implementation := &serverBackend{}
	service, err := gatecore.NewService(store, engine, approval.NewBroker(), implementation)
	if err != nil {
		t.Fatal(err)
	}
	public, err := service.AddTarget(context.Background(), "test", backend.Target{ID: "private", DisplayName: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(public.ID, "private") {
		t.Fatal("backend ID leaked into target ID")
	}
	if err := service.Attach("codex-1", public.ID); err != nil {
		t.Fatal(err)
	}
	return service, store, implementation
}
