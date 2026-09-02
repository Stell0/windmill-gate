package gate

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	"github.com/nethserver/gate/internal/command"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/storage"
)

type fakeBackend struct {
	mu        sync.Mutex
	payloads  [][]byte
	targetIDs []string
	stdout    string
	stderr    string
	exitCode  int
	err       error
}

func (b *fakeBackend) Name() string { return "fake" }
func (b *fakeBackend) ListTargets(context.Context) ([]backend.Target, error) {
	return []backend.Target{{ID: "private-1", DisplayName: "customer one"}}, nil
}
func (b *fakeBackend) Exec(_ context.Context, targetID string, req backend.ExecRequest) (backend.ExecResult, error) {
	b.mu.Lock()
	b.payloads = append(b.payloads, append([]byte(nil), req.Payload...))
	b.targetIDs = append(b.targetIDs, targetID)
	b.mu.Unlock()
	_, _ = io.WriteString(req.Stdout, b.stdout)
	_, _ = io.WriteString(req.Stderr, b.stderr)
	return backend.ExecResult{ExitCode: b.exitCode}, b.err
}
func (b *fakeBackend) OpenForward(context.Context, string, backend.ForwardRequest) (backend.Forward, error) {
	return nil, errors.New("not implemented")
}

type recordingSink struct {
	mu       sync.Mutex
	accepted command.Snapshot
	policy   policy.Result
	states   []command.State
	stdout   bytes.Buffer
	stderr   bytes.Buffer
	exitCode int
	errors   []string
}

func (s *recordingSink) Accepted(cmd command.Snapshot, result policy.Result) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accepted, s.policy = cmd, result
	return nil
}
func (s *recordingSink) State(cmd command.Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.states = append(s.states, cmd.State)
	return nil
}
func (s *recordingSink) Output(stream string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if stream == "stdout" {
		_, _ = s.stdout.Write(data)
	} else {
		_, _ = s.stderr.Write(data)
	}
	return nil
}
func (s *recordingSink) Exit(_ command.Snapshot, code int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exitCode = code
	return nil
}
func (s *recordingSink) Error(message string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errors = append(s.errors, message)
	return nil
}

func TestAllowedCommandExecutesExactBytesAndPersistsStreams(t *testing.T) {
	implementation := &fakeBackend{stdout: "healthy\\n", stderr: "warning\\n"}
	service, session, store := seededService(t, implementation, policy.Config{Allow: []string{`^printf .+$`}})
	defer store.Close()
	payload := []byte("printf '%s\\n' 'hello world'")
	sink := &recordingSink{}
	if err := session.Exec(context.Background(), payload, sink); err != nil {
		t.Fatal(err)
	}
	if len(implementation.payloads) != 1 || !bytes.Equal(implementation.payloads[0], payload) {
		t.Fatalf("executed payload changed: %q", implementation.payloads)
	}
	if implementation.targetIDs[0] != "private-1" {
		t.Fatalf("private backend mapping not used: %q", implementation.targetIDs)
	}
	if sink.exitCode != 0 || sink.stdout.String() != "healthy\\n" || sink.stderr.String() != "warning\\n" {
		t.Fatalf("unexpected sink output: %#v", sink)
	}
	history, err := service.Store.History(context.Background(), session.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(history) != 1 || history[0].State != command.Succeeded || history[0].Hash != command.Hash(payload) {
		t.Fatalf("unexpected history: %#v", history)
	}
}

func TestAskWaitsForHashBoundHumanApproval(t *testing.T) {
	implementation := &fakeBackend{}
	service, session, store := seededService(t, implementation, policy.Config{})
	defer store.Close()
	sink := &recordingSink{}
	done := make(chan error, 1)
	go func() { done <- session.Exec(context.Background(), []byte("grep foo /var/log/messages"), sink) }()
	pending := waitPending(t, service.Approvals)
	decision := approval.Decision{
		CommandID: pending.Command.ID, Hash: pending.Command.Hash,
		Action: approval.AllowTarget, Actor: "human-operator",
	}
	if err := service.Approvals.Decide(decision); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(service.Policy.TemporaryRules(session.TargetID)) != 1 {
		t.Fatal("target-scoped approval was not retained")
	}
	if len(implementation.payloads) != 1 {
		t.Fatal("approved command was not executed")
	}
}

func TestDeniedCommandNeverReachesBackend(t *testing.T) {
	implementation := &fakeBackend{}
	_, session, store := seededService(t, implementation, policy.Config{Deny: []string{`^reboot$`}})
	defer store.Close()
	sink := &recordingSink{}
	if err := session.Exec(context.Background(), []byte("reboot"), sink); err != nil {
		t.Fatal(err)
	}
	if len(implementation.payloads) != 0 || sink.exitCode != 126 {
		t.Fatalf("denied command executed or wrong status: calls=%d exit=%d", len(implementation.payloads), sink.exitCode)
	}
}

func TestExistingSessionCannotBeSilentlySwitched(t *testing.T) {
	implementation := &fakeBackend{}
	service, first, store := seededService(t, implementation, policy.Config{Allow: []string{`^uptime$`}})
	defer store.Close()
	secondTarget, err := service.AddTarget(context.Background(), "fake", backend.Target{ID: "private-2", DisplayName: "customer two"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Attach("codex-1", secondTarget.ID); err != nil {
		t.Fatal(err)
	}
	if err := first.Exec(context.Background(), []byte("uptime"), &recordingSink{}); err != nil {
		t.Fatal(err)
	}
	second, err := service.OpenSession(context.Background(), "codex-1", "unix", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := second.Exec(context.Background(), []byte("uptime"), &recordingSink{}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(implementation.targetIDs, ","); got != "private-1,private-2" {
		t.Fatalf("session target changed unexpectedly: %s", got)
	}
}

func TestOutputIsBoundedWithMarker(t *testing.T) {
	implementation := &fakeBackend{stdout: "123456789"}
	service, session, store := seededService(t, implementation, policy.Config{Allow: []string{`^uptime$`}})
	defer store.Close()
	if err := service.SetOutputLimit(5); err != nil {
		t.Fatal(err)
	}
	sink := &recordingSink{}
	if err := session.Exec(context.Background(), []byte("uptime"), sink); err != nil {
		t.Fatal(err)
	}
	if got := sink.stdout.String(); got != "12345\n[gate: output truncated]\n" {
		t.Fatalf("unexpected bounded output: %q", got)
	}
}

func seededService(t *testing.T, implementation *fakeBackend, config policy.Config) (*Service, *Session, *storage.Store) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	engine, err := policy.New(config)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, engine, approval.NewBroker(), implementation)
	if err != nil {
		t.Fatal(err)
	}
	public, err := service.AddTarget(context.Background(), "fake", backend.Target{ID: "private-1", DisplayName: "customer one"})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Attach("codex-1", public.ID); err != nil {
		t.Fatal(err)
	}
	session, err := service.OpenSession(context.Background(), "codex-1", "unix", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close(context.Background()) })
	return service, session, store
}

func waitPending(t *testing.T, broker *approval.Broker) approval.Pending {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		pending := broker.List()
		if len(pending) == 1 {
			return pending[0]
		}
		select {
		case <-broker.Changed():
		case <-deadline:
			t.Fatal("approval did not become pending")
		}
	}
}
