package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	"github.com/nethserver/gate/internal/command"
	gatecore "github.com/nethserver/gate/internal/gate"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/storage"
)

type tuiBackend struct{}

func (tuiBackend) Name() string                                          { return "test" }
func (tuiBackend) ListTargets(context.Context) ([]backend.Target, error) { return nil, nil }
func (tuiBackend) Exec(_ context.Context, _ string, req backend.ExecRequest) (backend.ExecResult, error) {
	_, _ = io.WriteString(req.Stdout, "ok")
	return backend.ExecResult{}, nil
}
func (tuiBackend) OpenForward(context.Context, string, backend.ForwardRequest) (backend.Forward, error) {
	return nil, errors.New("not implemented")
}

func TestApprovalViewShowsSecurityContextAndCanApprove(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ := policy.New(policy.Config{})
	service, _ := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	public, _ := service.AddTarget(context.Background(), "test", backend.Target{ID: "private-id", DisplayName: "customer-a"})
	_ = service.Attach("codex-1", public.ID)
	session, _ := service.OpenSession(context.Background(), "codex-1", "unix", "")
	defer session.Close(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- session.Exec(context.Background(), []byte("grep foo /var/log/messages"), discardSink{})
	}()
	select {
	case <-service.Approvals.Changed():
	case <-time.After(time.Second):
		t.Fatal("approval not queued")
	}
	pending := service.Approvals.List()
	if len(pending) != 1 {
		t.Fatalf("pending count = %d", len(pending))
	}
	var output bytes.Buffer
	app := App{Service: service, Operator: "alice", Output: &output}
	app.renderPending()
	rendered := output.String()
	for _, required := range []string{"customer-a", public.ID, "codex-1", pending[0].Command.Payload, pending[0].Command.Hash, "ASK", "approve once", "target until detach"} {
		if !strings.Contains(rendered, required) {
			t.Errorf("approval view omitted %q:\n%s", required, rendered)
		}
	}
	if strings.Contains(rendered, "private-id") {
		t.Fatalf("approval view leaked backend ID: %s", rendered)
	}
	if _, err := app.handle(context.Background(), "a "+pending[0].Command.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestOperatorTextEscapesTerminalControlSequences(t *testing.T) {
	rendered := operatorText("before\x1b[2J\nafter")
	if strings.ContainsRune(rendered, '\x1b') || strings.ContainsRune(rendered, '\n') {
		t.Fatalf("operator text retained raw terminal controls: %q", rendered)
	}
	if !strings.Contains(rendered, `\x1b`) || !strings.Contains(rendered, `\n`) {
		t.Fatalf("operator text did not visibly preserve escaped bytes: %q", rendered)
	}
}

func TestApprovalDecisionPrintsOneNewPrompt(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ := policy.New(policy.Config{})
	service, _ := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	public, _ := service.AddTarget(context.Background(), "test", backend.Target{ID: "private-id", DisplayName: "customer-a"})
	_ = service.Attach("codex-1", public.ID)
	session, _ := service.OpenSession(context.Background(), "codex-1", "unix", "")
	defer session.Close(context.Background())
	execDone := make(chan error, 1)
	go func() {
		execDone <- session.Exec(context.Background(), []byte("grep foo /var/log/messages"), discardSink{})
	}()
	select {
	case <-service.Approvals.Changed():
	case <-time.After(time.Second):
		t.Fatal("approval not queued")
	}

	input, commands := io.Pipe()
	defer input.Close()
	defer commands.Close()
	output := &lockedBuffer{}
	appDone := make(chan error, 1)
	go func() {
		appDone <- (&App{Service: service, Operator: "alice", Input: input, Output: output}).Run(context.Background())
	}()
	waitForOutput(t, output, func(value string) bool { return strings.Count(value, "gate> ") == 1 })
	if _, err := io.WriteString(commands, "a\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-execDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("approval was not applied")
	}
	waitForOutput(t, output, func(value string) bool { return strings.Count(value, "gate> ") == 2 })
	if _, err := io.WriteString(commands, "q\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-appDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("operator console did not quit")
	}
	rendered := output.String()
	if strings.Count(rendered, "gate> ") != 2 {
		t.Fatalf("unexpected prompt redraw:\n%s", rendered)
	}
	if !strings.Contains(rendered, "press Enter") {
		t.Fatalf("approval input guidance missing:\n%s", rendered)
	}
}

func TestDecisionWithoutIDUsesNewestPendingCommand(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ := policy.New(policy.Config{})
	service, _ := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	public, _ := service.AddTarget(context.Background(), "test", backend.Target{ID: "private-id", DisplayName: "customer-a"})
	_ = service.Attach("codex-1", public.ID)
	firstSession, _ := service.OpenSession(context.Background(), "codex-1", "unix", "")
	defer firstSession.Close(context.Background())
	secondSession, _ := service.OpenSession(context.Background(), "codex-1", "unix", "")
	defer secondSession.Close(context.Background())

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- firstSession.Exec(context.Background(), []byte("first unknown command"), discardSink{})
	}()
	waitForPendingCount(t, service, 1)
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- secondSession.Exec(context.Background(), []byte("second unknown command"), discardSink{})
	}()
	waitForPendingCount(t, service, 2)

	pending := service.Approvals.List()
	newestID := pending[len(pending)-1].Command.ID
	app := App{Service: service, Operator: "alice", Output: io.Discard}
	if _, err := app.handle(context.Background(), "d"); err != nil {
		t.Fatal(err)
	}
	remaining := service.Approvals.List()
	if len(remaining) != 1 {
		t.Fatalf("pending count after decision = %d, want 1", len(remaining))
	}
	if remaining[0].Command.ID == newestID {
		t.Fatal("decision without an ID selected the oldest command")
	}
	if _, err := app.handle(context.Background(), "d "+remaining[0].Command.ID); err != nil {
		t.Fatal(err)
	}
	for _, done := range []<-chan error{firstDone, secondDone} {
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("denied command did not finish")
		}
	}
}

func TestSingleKeyDecisionDoesNotRequireNewline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	input, commands := io.Pipe()
	defer input.Close()
	defer commands.Close()
	lines := make(chan string, 2)
	readErrors := make(chan error, 1)
	var pendingCount atomic.Int64
	pendingCount.Store(1)
	go readOperatorLines(ctx, input, true, &pendingCount, lines, readErrors)

	if _, err := io.WriteString(commands, "a"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		if line != "a" {
			t.Fatalf("single-key line = %q, want a", line)
		}
	case <-time.After(time.Second):
		t.Fatal("single-key decision waited for a newline")
	}

	// A legacy Enter after the single key is consumed instead of producing an
	// empty command and a duplicate prompt.
	if _, err := io.WriteString(commands, "\nq\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		if line != "q" {
			t.Fatalf("line after legacy Enter = %q, want q", line)
		}
	case <-time.After(time.Second):
		t.Fatal("next operator command was not read")
	}
}

func TestTerminalAttentionAndClearSequences(t *testing.T) {
	var output bytes.Buffer
	app := App{Output: &output, terminalOutput: true}
	app.setTerminalTitle(true)
	app.setTerminalTitle(false)
	if got := output.String(); got != "\x1b]0;[!] Gate\x07\x1b]0;Gate\x07" {
		t.Fatalf("terminal title sequence = %q", got)
	}

	output.Reset()
	app.terminalOutput = false
	app.setTerminalTitle(true)
	if output.Len() != 0 {
		t.Fatalf("terminal title escaped into non-terminal output: %q", output.String())
	}
}

func TestApprovalRedrawClearsScreen(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, _ := policy.New(policy.Config{})
	service, _ := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	var output bytes.Buffer
	app := App{Service: service, Output: &output}
	app.redraw(nil)
	if !strings.HasPrefix(output.String(), "\x1b[2J\x1b[HGate operator console") {
		t.Fatalf("approval redraw did not clear before rendering: %q", output.String())
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitForOutput(t *testing.T, output *lockedBuffer, condition func(string) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if condition(output.String()) {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for output:\n%s", output.String())
}

func waitForPendingCount(t *testing.T, service *gatecore.Service, count int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(service.Approvals.List()) == count {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d pending commands", count)
}

type discardSink struct{}

func (discardSink) Accepted(command.Snapshot, policy.Result) error { return nil }
func (discardSink) State(command.Snapshot) error                   { return nil }
func (discardSink) Output(string, []byte) error                    { return nil }
func (discardSink) Exit(command.Snapshot, int) error               { return nil }
func (discardSink) Error(string) error                             { return nil }
