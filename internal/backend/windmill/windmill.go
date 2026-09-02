// Package windmill implements Gate's private Bastion/Sancho transport.
package windmill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/nethserver/gate/internal/backend"
)

type commandRunner interface {
	Run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error
	Start(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (process, error)
}

type process interface {
	Wait() error
	Kill() error
}

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	return cmd.Run()
}

func (execRunner) Start(ctx context.Context, name string, args []string, stdin io.Reader, stdout, stderr io.Writer) (process, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return commandProcess{cmd}, nil
}

type commandProcess struct{ cmd *exec.Cmd }

func (p commandProcess) Wait() error { return p.cmd.Wait() }
func (p commandProcess) Kill() error { return p.cmd.Process.Kill() }

type Config struct {
	Bastion string
	SSHPath string
	SSHArgs []string
	Sancho  string
	runner  commandRunner
}

type Backend struct {
	config Config
}

func New(config Config) (*Backend, error) {
	if strings.TrimSpace(config.Bastion) == "" {
		return nil, errors.New("Windmill Bastion host is required")
	}
	if config.SSHPath == "" {
		config.SSHPath = "ssh"
	}
	if config.Sancho == "" {
		config.Sancho = "sancho"
	}
	if config.runner == nil {
		config.runner = execRunner{}
	}
	return &Backend{config: config}, nil
}

func (b *Backend) Name() string { return "windmill" }

type sanchoSession struct {
	ID     json.RawMessage `json:"id"`
	Name   string          `json:"name"`
	Host   string          `json:"host"`
	Status string          `json:"status"`
}

func (b *Backend) ListTargets(ctx context.Context) ([]backend.Target, error) {
	var stdout, stderr bytes.Buffer
	args := append(append([]string{}, b.config.SSHArgs...), b.config.Bastion,
		remoteCommand(b.config.Sancho, "session", "list", "--json"))
	if err := b.config.runner.Run(ctx, b.config.SSHPath, args, nil, &stdout, &stderr); err != nil {
		message := strings.TrimSpace(stderr.String())
		if message == "" {
			message = err.Error()
		}
		return nil, fmt.Errorf("list Windmill sessions: %s", message)
	}

	var sessions []sanchoSession
	if err := json.Unmarshal(stdout.Bytes(), &sessions); err != nil {
		return nil, fmt.Errorf("parse Sancho session list: %w", err)
	}
	targets := make([]backend.Target, 0, len(sessions))
	for _, session := range sessions {
		id, err := rawID(session.ID)
		if err != nil {
			return nil, fmt.Errorf("parse Sancho session: %w", err)
		}
		display := session.Name
		if display == "" {
			display = session.Host
		}
		if display == "" {
			display = "Windmill target"
		}
		targets = append(targets, backend.Target{ID: id, DisplayName: display})
	}
	return targets, nil
}

func (b *Backend) Exec(ctx context.Context, backendTargetID string, req backend.ExecRequest) (backend.ExecResult, error) {
	stdout := newRedactingWriter(req.Stdout, backendTargetID)
	stderr := newRedactingWriter(req.Stderr, backendTargetID)
	defer stdout.Close()
	defer stderr.Close()

	args := append(append([]string{}, b.config.SSHArgs...), b.config.Bastion,
		remoteCommand(b.config.Sancho, "session", "exec", backendTargetID, "--", string(req.Payload)))
	err := b.config.runner.Run(ctx, b.config.SSHPath, args, nil, stdout, stderr)
	if err == nil {
		return backend.ExecResult{ExitCode: 0}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return backend.ExecResult{ExitCode: exitErr.ExitCode()}, nil
	}
	return backend.ExecResult{}, fmt.Errorf("execute remote command: %s", redact(err.Error(), backendTargetID))
}

func (b *Backend) OpenForward(ctx context.Context, backendTargetID string, req backend.ForwardRequest) (backend.Forward, error) {
	if req.RemoteHost != "127.0.0.1" && req.RemoteHost != "localhost" {
		return nil, errors.New("Windmill forwards are restricted to the selected target loopback")
	}
	spec := fmt.Sprintf("127.0.0.1:%d:%s:%d", req.LocalPort, req.RemoteHost, req.RemotePort)
	args := append(append([]string{}, b.config.SSHArgs...), "-N", "-L", spec, b.config.Bastion,
		remoteCommand(b.config.Sancho, "session", "forward", backendTargetID))
	proc, err := b.config.runner.Start(ctx, b.config.SSHPath, args, nil, io.Discard, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("open remote forward: %s", redact(err.Error(), backendTargetID))
	}
	return &runningForward{process: proc}, nil
}

type runningForward struct{ process process }

func (f *runningForward) Close() error { return f.process.Kill() }
func (f *runningForward) Wait() error  { return f.process.Wait() }

func rawID(raw json.RawMessage) (string, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		if text == "" {
			return "", errors.New("empty session ID")
		}
		return text, nil
	}
	var number json.Number
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&number); err != nil || number.String() == "" {
		return "", errors.New("invalid session ID")
	}
	return number.String(), nil
}

func remoteCommand(args ...string) string {
	quoted := make([]string, len(args))
	for i, arg := range args {
		quoted[i] = shellQuote(arg)
	}
	return strings.Join(quoted, " ")
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func redact(value, secret string) string {
	if secret == "" {
		return value
	}
	return strings.ReplaceAll(value, secret, "[backend-id-redacted]")
}

// redactingWriter streams while retaining enough overlap to catch a private ID
// split across transport writes.
type redactingWriter struct {
	dst     io.Writer
	secret  string
	pending []byte
}

func newRedactingWriter(dst io.Writer, secret string) *redactingWriter {
	if dst == nil {
		dst = io.Discard
	}
	return &redactingWriter{dst: dst, secret: secret}
}

func (w *redactingWriter) Write(p []byte) (int, error) {
	inputLen := len(p)
	w.pending = append(w.pending, p...)
	keep := len(w.secret) - 1
	if keep < 0 {
		keep = 0
	}
	if len(w.pending) <= keep {
		return inputLen, nil
	}
	flushLen := len(w.pending) - keep
	// If the boundary falls inside a match, retain the whole possible match.
	if w.secret != "" {
		for start := flushLen - len(w.secret) + 1; start < flushLen; start++ {
			if start >= 0 && start+len(w.secret) <= len(w.pending) && string(w.pending[start:start+len(w.secret)]) == w.secret {
				flushLen = start + len(w.secret)
			}
		}
	}
	chunk := redact(string(w.pending[:flushLen]), w.secret)
	if _, err := io.WriteString(w.dst, chunk); err != nil {
		return 0, err
	}
	w.pending = append(w.pending[:0], w.pending[flushLen:]...)
	return inputLen, nil
}

func (w *redactingWriter) Close() error {
	if len(w.pending) == 0 {
		return nil
	}
	_, err := io.WriteString(w.dst, redact(string(w.pending), w.secret))
	w.pending = nil
	return err
}
