package tui

import (
	"bytes"
	"context"
	"errors"
	"io"
	"path/filepath"
	"strings"
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

type discardSink struct{}

func (discardSink) Accepted(command.Snapshot, policy.Result) error { return nil }
func (discardSink) State(command.Snapshot) error                   { return nil }
func (discardSink) Output(string, []byte) error                    { return nil }
func (discardSink) Exit(command.Snapshot, int) error               { return nil }
func (discardSink) Error(string) error                             { return nil }
