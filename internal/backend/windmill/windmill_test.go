package windmill

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/nethserver/gate/internal/backend"
)

type fakeRunner struct {
	stdout string
	stderr string
	err    error
	name   string
	args   []string
}

func (r *fakeRunner) Run(_ context.Context, name string, args []string, _ io.Reader, stdout, stderr io.Writer) error {
	r.name, r.args = name, append([]string{}, args...)
	_, _ = io.WriteString(stdout, r.stdout)
	_, _ = io.WriteString(stderr, r.stderr)
	return r.err
}

func (r *fakeRunner) Start(context.Context, string, []string, io.Reader, io.Writer, io.Writer) (process, error) {
	return nil, errors.New("not implemented")
}

func TestListTargetsParsesSessionsForHumanSelection(t *testing.T) {
	runner := &fakeRunner{stdout: `[{"id":4837291,"name":"customer-a"},{"id":"abc","host":"customer-b"}]`}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	targets, err := b.ListTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 || targets[0].ID != "4837291" || targets[1].DisplayName != "customer-b" {
		t.Fatalf("unexpected targets: %#v", targets)
	}
	if strings.Contains(strings.Join(runner.args, " "), "customer-a") {
		t.Fatal("display data unexpectedly sent to Sancho")
	}
}

func TestExecQuotesExactPayloadAndRedactsBackendID(t *testing.T) {
	const backendID = "4837291"
	const payload = "printf '%s\\n' \"a b\""
	runner := &fakeRunner{stdout: "session 4837291", stderr: "session 4837291 failed"}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	result, err := b.Exec(context.Background(), backendID, backend.ExecRequest{
		Payload: []byte(payload), Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("unexpected exit code %d", result.ExitCode)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, backendID) {
		t.Fatalf("backend ID leaked: %q", combined)
	}
	remote := runner.args[len(runner.args)-1]
	if !strings.Contains(remote, shellQuote(payload)) {
		t.Fatalf("exact payload was not transported as one quoted argument: %s", remote)
	}
}

func TestRedactingWriterHandlesSplitSecret(t *testing.T) {
	var out bytes.Buffer
	w := newRedactingWriter(&out, "private-id")
	_, _ = w.Write([]byte("before private"))
	_, _ = w.Write([]byte("-id after"))
	_ = w.Close()
	if got := out.String(); got != "before [backend-id-redacted] after" {
		t.Fatalf("unexpected redaction %q", got)
	}
}

func TestBackendIDIsRedactedFromErrors(t *testing.T) {
	runner := &fakeRunner{err: errors.New("transport failed for 4837291")}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.Exec(context.Background(), "4837291", backend.ExecRequest{Payload: []byte("uptime")})
	if err == nil || strings.Contains(err.Error(), "4837291") {
		t.Fatalf("unsafe error: %v", err)
	}
}
