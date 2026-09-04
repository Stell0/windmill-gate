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

	"github.com/stell0/windmill-gate/internal/approval"
	"github.com/stell0/windmill-gate/internal/backend"
	"github.com/stell0/windmill-gate/internal/command"
	gatecore "github.com/stell0/windmill-gate/internal/gate"
	"github.com/stell0/windmill-gate/internal/policy"
	"github.com/stell0/windmill-gate/internal/storage"
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
	for _, required := range []string{"customer-a", public.ID, "codex-1", pending[0].Command.Payload, pending[0].Command.Hash, "ASK", "Approve? [y] once", "target until detach"} {
		if !strings.Contains(rendered, required) {
			t.Errorf("approval view omitted %q:\n%s", required, rendered)
		}
	}
	if strings.Contains(rendered, "private-id") {
		t.Fatalf("approval view leaked backend ID: %s", rendered)
	}
	if _, err := app.handle(context.Background(), "y "+pending[0].Command.ID); err != nil {
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
	if _, err := io.WriteString(commands, "y\n"); err != nil {
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
	if _, err := app.handle(context.Background(), "n"); err != nil {
		t.Fatal(err)
	}
	remaining := service.Approvals.List()
	if len(remaining) != 1 {
		t.Fatalf("pending count after decision = %d, want 1", len(remaining))
	}
	if remaining[0].Command.ID == newestID {
		t.Fatal("decision without an ID selected the oldest command")
	}
	if _, err := app.handle(context.Background(), "n "+remaining[0].Command.ID); err != nil {
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

func TestSimilarDecisionKeyWorksInLineMode(t *testing.T) {
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
	go func() { done <- session.Exec(context.Background(), []byte("diagnose 123"), discardSink{}) }()
	waitForPendingCount(t, service, 1)
	pending := service.Approvals.List()[0]
	app := App{Service: service, Operator: "alice", Output: io.Discard}
	if _, err := app.handle(context.Background(), "s "+pending.Command.ID); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if rules := service.Policy.TemporaryRules(public.ID); len(rules) != 1 {
		t.Fatalf("similar decision installed %d rules, want 1", len(rules))
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

	if _, err := io.WriteString(commands, "y"); err != nil {
		t.Fatal(err)
	}
	select {
	case line := <-lines:
		if line != "y" {
			t.Fatalf("single-key line = %q, want y", line)
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

func TestAllDecisionKeysWorkInSingleKeyMode(t *testing.T) {
	for _, key := range []string{"y", "s", "n"} {
		t.Run(key, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			input, commands := io.Pipe()
			defer input.Close()
			defer commands.Close()
			lines := make(chan string, 1)
			readErrors := make(chan error, 1)
			var pendingCount atomic.Int64
			pendingCount.Store(1)
			go readOperatorLines(ctx, input, true, &pendingCount, lines, readErrors)
			if _, err := io.WriteString(commands, key); err != nil {
				t.Fatal(err)
			}
			select {
			case line := <-lines:
				if line != key {
					t.Fatalf("single-key line = %q, want %q", line, key)
				}
			case <-time.After(time.Second):
				t.Fatal("single-key decision waited for a newline")
			}
		})
	}
}

func TestLegacyDecisionKeysAreRejected(t *testing.T) {
	app := App{Service: &gatecore.Service{}, Output: io.Discard}
	for _, input := range []string{"a", "d", "a cmd_1", "d cmd_1"} {
		if _, err := app.handle(context.Background(), input); err == nil || !strings.Contains(err.Error(), "unknown operator command") {
			t.Errorf("legacy input %q was not rejected: %v", input, err)
		}
	}
}

func TestAuthorizationLedgerUsesAuditLabelsDeduplicatesAndEscapes(t *testing.T) {
	store, err := storage.Open(filepath.Join(t.TempDir(), "gate.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	engine, err := policy.New(policy.Config{
		Allow: []string{`^(?:uptime|date)$`},
		Deny:  []string{`^reboot$`},
	})
	if err != nil {
		t.Fatal(err)
	}
	service, err := gatecore.NewService(store, engine, approval.NewBroker(), tuiBackend{})
	if err != nil {
		t.Fatal(err)
	}
	public, _ := service.AddTarget(context.Background(), "test", backend.Target{ID: "private-id", DisplayName: "customer-a"})
	_ = service.Attach("codex-1", public.ID)
	session, _ := service.OpenSession(context.Background(), "codex-1", "unix", "")
	defer session.Close(context.Background())

	// Concurrent automatic decisions prove that the coalesced notification is
	// only a wakeup: the ledger is rebuilt from all authoritative rows.
	autoDone := make(chan error, 2)
	go func() { autoDone <- session.Exec(context.Background(), []byte("uptime"), discardSink{}) }()
	go func() { autoDone <- session.Exec(context.Background(), []byte("date"), discardSink{}) }()
	for range 2 {
		if err := <-autoDone; err != nil {
			t.Fatal(err)
		}
	}
	if err := session.Exec(context.Background(), []byte("reboot"), discardSink{}); err != nil {
		t.Fatal(err)
	}

	runDecision := func(payload string, action approval.Action) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- session.Exec(context.Background(), []byte(payload), discardSink{}) }()
		waitForPendingCount(t, service, 1)
		pending := service.Approvals.List()[0]
		if err := service.Approvals.Decide(approval.Decision{
			CommandID: pending.Command.ID, Hash: pending.Command.Hash, Action: action, Actor: "alice",
		}); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	runDecision("manual read", approval.ApproveOnce)
	runDecision("manual block", approval.Deny)
	runDecision("repeat 123", approval.AllowTarget)
	if err := session.Exec(context.Background(), []byte("repeat 456"), discardSink{}); err != nil {
		t.Fatal(err)
	}

	cancelCtx, cancel := context.WithCancel(context.Background())
	cancelled := make(chan error, 1)
	unsafePayload := "inspect\x1b[2J\nnext"
	go func() { cancelled <- session.Exec(cancelCtx, []byte(unsafePayload), discardSink{}) }()
	waitForPendingCount(t, service, 1)
	cancel()
	if err := <-cancelled; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled command returned %v", err)
	}

	var output bytes.Buffer
	app := App{Service: service, Output: &output}
	added, err := app.refreshAuthorizations(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 8 || len(app.ledger) != 8 {
		t.Fatalf("authorization count = %d/%d, want 8", len(added), len(app.ledger))
	}
	if again, err := app.refreshAuthorizations(context.Background()); err != nil || len(again) != 0 || len(app.ledger) != 8 {
		t.Fatalf("ledger was not deduplicated: added=%d total=%d err=%v", len(again), len(app.ledger), err)
	}
	app.renderAuthorizationLedger()
	rendered := output.String()
	for _, required := range []string{
		"[AUTO APPROVE] codex-1> uptime",
		"[AUTO APPROVE] codex-1> date",
		"[AUTO BLOCKED] codex-1> reboot",
		"[USER APPROVE] codex-1> manual read",
		"[USER BLOCKED] codex-1> manual block",
		"[USER APPROVE] codex-1> repeat 123",
		"[AUTO APPROVE] codex-1> repeat 456",
		`[CANCELLED] codex-1> inspect\x1b[2J\nnext`,
	} {
		if !strings.Contains(rendered, required) {
			t.Errorf("ledger omitted %q:\n%s", required, rendered)
		}
	}
	if strings.Contains(rendered, `codex-1> "uptime"`) || strings.ContainsRune(rendered, '\x1b') {
		t.Fatalf("ledger quoted ordinary commands or retained terminal controls: %q", rendered)
	}

	output.Reset()
	app.redraw(nil)
	if !strings.Contains(output.String(), "[USER APPROVE] codex-1> manual read") {
		t.Fatalf("redraw lost the ledger:\n%s", output.String())
	}
	if strings.Contains(output.String(), "private-id") {
		t.Fatalf("ledger/redraw leaked backend ID: %s", output.String())
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
