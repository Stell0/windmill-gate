package windmill

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"testing"

	"github.com/stell0/windmill-gate/internal/backend"
)

type fakeRunner struct {
	stdout    string
	stderr    string
	err       error
	runs      []fakeRun
	runIndex  int
	name      string
	args      []string
	startArgs []string
}

type fakeRun struct {
	stdout string
	stderr string
	err    error
}

func (r *fakeRunner) Run(_ context.Context, name string, args []string, _ io.Reader, stdout, stderr io.Writer) error {
	r.name, r.args = name, append([]string{}, args...)
	result := fakeRun{stdout: r.stdout, stderr: r.stderr, err: r.err}
	if r.runIndex < len(r.runs) {
		result = r.runs[r.runIndex]
		r.runIndex++
	}
	_, _ = io.WriteString(stdout, result.stdout)
	_, _ = io.WriteString(stderr, result.stderr)
	return result.err
}

func (r *fakeRunner) Start(_ context.Context, _ string, args []string, _ io.Reader, _ io.Writer, _ io.Writer) (process, error) {
	r.startArgs = append([]string{}, args...)
	return fakeProcess{}, nil
}

type fakeProcess struct{}

func (fakeProcess) Wait() error { return nil }
func (fakeProcess) Kill() error { return nil }

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

func TestListTargetsParsesSanchoObjectStream(t *testing.T) {
	runner := &fakeRunner{stdout: `
{
  "session": "private-session-a",
  "server": "customer-a",
  "vpn": "172.29.0.1"
}
{
  "session": "private-session-b",
  "server": "customer-b",
  "vpn": "172.29.0.2"
}
`}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	targets, err := b.ListTargets(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 2 {
		t.Fatalf("target count = %d, want 2", len(targets))
	}
	if targets[0].ID != "private-session-a" || targets[0].DisplayName != "customer-a" {
		t.Fatalf("unexpected first target: %#v", targets[0])
	}
	if targets[1].ID != "private-session-b" || targets[1].DisplayName != "customer-b" {
		t.Fatalf("unexpected second target: %#v", targets[1])
	}
}

func TestParseSessionsRejectsMixedArrayAndStream(t *testing.T) {
	_, err := parseSessions([]byte(`[{"id":"private-a"}]{"id":"private-b"}`))
	if err == nil || !strings.Contains(err.Error(), "after session array") {
		t.Fatalf("unexpected error: %v", err)
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

func TestLegacyExecUsesSanchoConnectionMetadataAndPreservesExitCode(t *testing.T) {
	const (
		backendID = "private-session-a"
		vpn       = "172.29.6.206"
		payload   = "printf '%s\\n' \"a b\"; exit 7"
	)
	listing := `{"session":"private-session-a","server":"customer-a","vpn":"172.29.6.206"}`
	runner := &fakeRunner{runs: []fakeRun{
		{stdout: listing},
		{stdout: listing},
		{stdout: "connected to " + vpn + " for " + backendID, stderr: "warning from " + vpn, err: exec.Command("sh", "-c", "exit 7").Run()},
	}}
	b, err := New(Config{Bastion: "bastion.example", TargetSSHPort: 981, runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ListTargets(context.Background()); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	result, err := b.Exec(context.Background(), backendID, backend.ExecRequest{
		Payload: []byte(payload), Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 7 {
		t.Fatalf("exit code = %d, want 7", result.ExitCode)
	}
	remote := runner.args[len(runner.args)-1]
	if strings.Contains(remote, backendID) {
		t.Fatalf("private session ID was sent outside session discovery: %s", remote)
	}
	if !strings.Contains(remote, shellQuote(remoteCommand("sh", "-lc", payload))) {
		t.Fatalf("approved payload was not preserved as the sh -lc argument: %s", remote)
	}
	if !strings.Contains(remote, shellQuote("root@"+vpn)) || !strings.Contains(remote, shellQuote("981")) {
		t.Fatalf("legacy connection metadata missing from remote command: %s", remote)
	}
	if !strings.Contains(remote, shellQuote("LogLevel=ERROR")) || !strings.Contains(remote, shellQuote("UserKnownHostsFile=/dev/null")) {
		t.Fatalf("legacy SSH warning suppression is missing: %s", remote)
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, backendID) || strings.Contains(combined, vpn) {
		t.Fatalf("private connection data leaked: %q", combined)
	}
}

func TestLegacyExecRevalidatesSelectedSession(t *testing.T) {
	runner := &fakeRunner{runs: []fakeRun{
		{stdout: `{"session":"private-session-a","server":"customer-a","vpn":"172.29.6.206"}`},
		{stdout: `{"session":"private-session-b","server":"customer-b","vpn":"172.29.6.207"}`},
	}}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ListTargets(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = b.Exec(context.Background(), "private-session-a", backend.ExecRequest{Payload: []byte("uptime")})
	if err == nil || !strings.Contains(err.Error(), "no longer available") {
		t.Fatalf("unexpected error: %v", err)
	}
	if runner.runIndex != 2 {
		t.Fatalf("runner calls = %d, want discovery plus refresh only", runner.runIndex)
	}
}

func TestLegacyForwardUsesSelectedTargetLoopback(t *testing.T) {
	const backendID = "private-session-a"
	runner := &fakeRunner{stdout: `{"session":"private-session-a","server":"customer-a","vpn":"172.29.6.206"}`}
	b, err := New(Config{Bastion: "bastion.example", TargetSSHPort: 981, runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ListTargets(context.Background()); err != nil {
		t.Fatal(err)
	}
	forward, err := b.OpenForward(context.Background(), backendID, backend.ForwardRequest{
		RemoteHost: "127.0.0.1", RemotePort: 443, LocalPort: 18443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := forward.Close(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.startArgs, " ")
	if strings.Contains(joined, backendID) {
		t.Fatalf("private session ID was sent in legacy forward: %s", joined)
	}
	for _, expected := range []string{
		"127.0.0.1:18443:127.0.0.1:18443",
		"127.0.0.1:18443:127.0.0.1:443",
		"root@172.29.6.206",
		"981",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("legacy forward missing %q: %s", expected, joined)
		}
	}
}

func TestModernForwardBridgesToSanchoListenerPort(t *testing.T) {
	const backendID = "private-session-a"
	runner := &fakeRunner{}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	forward, err := b.OpenForward(context.Background(), backendID, backend.ForwardRequest{
		RemoteHost: "127.0.0.1", RemotePort: 443, LocalPort: 18443,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := forward.Close(); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(runner.startArgs, " ")
	if !strings.Contains(joined, "127.0.0.1:18443:127.0.0.1:18443") {
		t.Fatalf("outer SSH does not connect to the Sancho listener: %s", joined)
	}
	remote := runner.startArgs[len(runner.startArgs)-1]
	for _, expected := range []string{backendID, "--listen-port", "18443", "--remote-port", "443"} {
		if !strings.Contains(remote, shellQuote(expected)) {
			t.Fatalf("Sancho forward missing %q: %s", expected, remote)
		}
	}
}

func TestLegacyConnectionRejectsNonPrivateAddress(t *testing.T) {
	runner := &fakeRunner{stdout: `{"session":"private-session-a","server":"customer-a","vpn":"203.0.113.10"}`}
	b, err := New(Config{Bastion: "bastion.example", runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	_, err = b.ListTargets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "private non-loopback IP") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTargetSSHPortValidation(t *testing.T) {
	if _, err := New(Config{Bastion: "bastion.example", TargetSSHPort: 65536}); err == nil {
		t.Fatal("expected invalid target SSH port to fail")
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
