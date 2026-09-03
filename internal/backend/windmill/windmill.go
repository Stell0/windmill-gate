// Package windmill implements Gate's private Bastion/Sancho transport.
package windmill

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

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
	Bastion       string
	SSHPath       string
	SSHArgs       []string
	Sancho        string
	TargetSSHPort int
	runner        commandRunner
}

type Backend struct {
	config Config

	mu          sync.RWMutex
	connections map[string]targetConnection
}

type targetConnection struct {
	host string
	port int
}

const DefaultTargetSSHPort = 981

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
	if config.TargetSSHPort == 0 {
		config.TargetSSHPort = DefaultTargetSSHPort
	}
	if config.TargetSSHPort < 1 || config.TargetSSHPort > 65535 {
		return nil, errors.New("Windmill target SSH port must be between 1 and 65535")
	}
	if config.runner == nil {
		config.runner = execRunner{}
	}
	return &Backend{config: config, connections: make(map[string]targetConnection)}, nil
}

func (b *Backend) Name() string { return "windmill" }

type sanchoSession struct {
	ID      json.RawMessage `json:"id"`
	Session json.RawMessage `json:"session"`
	Name    string          `json:"name"`
	Host    string          `json:"host"`
	Server  string          `json:"server"`
	VPN     string          `json:"vpn"`
	Status  string          `json:"status"`
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

	sessions, err := parseSessions(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("parse Sancho session list: %w", err)
	}
	targets := make([]backend.Target, 0, len(sessions))
	connections := make(map[string]targetConnection)
	for _, session := range sessions {
		id, err := rawID(session.backendID())
		if err != nil {
			return nil, fmt.Errorf("parse Sancho session: %w", err)
		}
		if session.VPN != "" {
			connection, err := legacyConnection(session.VPN, b.config.TargetSSHPort)
			if err != nil {
				return nil, fmt.Errorf("parse Sancho session connection: %w", err)
			}
			connections[id] = connection
		}
		display := session.displayName()
		if display == "" {
			display = "Windmill target"
		}
		targets = append(targets, backend.Target{ID: id, DisplayName: display})
	}
	b.mu.Lock()
	b.connections = connections
	b.mu.Unlock()
	return targets, nil
}

func parseSessions(data []byte) ([]sanchoSession, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	values := make([]json.RawMessage, 0, 1)
	for {
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		values = append(values, value)
	}
	if len(values) == 0 {
		return nil, errors.New("empty JSON output")
	}

	first := bytes.TrimSpace(values[0])
	if len(first) > 0 && first[0] == '[' {
		if len(values) != 1 {
			return nil, errors.New("unexpected JSON value after session array")
		}
		var sessions []sanchoSession
		if err := json.Unmarshal(first, &sessions); err != nil {
			return nil, err
		}
		return sessions, nil
	}

	sessions := make([]sanchoSession, 0, len(values))
	for _, value := range values {
		trimmed := bytes.TrimSpace(value)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, errors.New("session stream contains a non-object JSON value")
		}
		var session sanchoSession
		if err := json.Unmarshal(trimmed, &session); err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	return sessions, nil
}

func (s sanchoSession) backendID() json.RawMessage {
	if len(bytes.TrimSpace(s.ID)) > 0 && !bytes.Equal(bytes.TrimSpace(s.ID), []byte("null")) {
		return s.ID
	}
	return s.Session
}

func (s sanchoSession) displayName() string {
	for _, candidate := range []string{s.Name, s.Host, s.Server} {
		if candidate != "" {
			return candidate
		}
	}
	return ""
}

func legacyConnection(host string, port int) (targetConnection, error) {
	address := net.ParseIP(host)
	if address == nil || !address.IsPrivate() || address.IsLoopback() {
		return targetConnection{}, errors.New("legacy target address must be a private non-loopback IP")
	}
	return targetConnection{host: address.String(), port: port}, nil
}

func (b *Backend) connection(backendTargetID string) (targetConnection, bool) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	connection, ok := b.connections[backendTargetID]
	return connection, ok
}

func (b *Backend) refreshConnection(ctx context.Context, backendTargetID string) (targetConnection, error) {
	if _, err := b.ListTargets(ctx); err != nil {
		return targetConnection{}, fmt.Errorf("refresh selected Windmill session: %w", err)
	}
	connection, ok := b.connection(backendTargetID)
	if !ok {
		return targetConnection{}, errors.New("selected Windmill session is no longer available")
	}
	return connection, nil
}

func (b *Backend) Exec(ctx context.Context, backendTargetID string, req backend.ExecRequest) (backend.ExecResult, error) {
	if _, ok := b.connection(backendTargetID); ok {
		connection, err := b.refreshConnection(ctx, backendTargetID)
		if err != nil {
			return backend.ExecResult{}, err
		}
		return b.execLegacy(ctx, backendTargetID, connection, req)
	}
	return b.execSancho(ctx, backendTargetID, req)
}

func (b *Backend) execSancho(ctx context.Context, backendTargetID string, req backend.ExecRequest) (backend.ExecResult, error) {
	stdout, stderr, closeWriters := redactedStreams(req, backendTargetID)
	defer closeWriters()

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

func (b *Backend) execLegacy(ctx context.Context, backendTargetID string, connection targetConnection, req backend.ExecRequest) (backend.ExecResult, error) {
	stdout, stderr, closeWriters := redactedStreams(req, backendTargetID, connection.host)
	defer closeWriters()

	targetCommand := remoteCommand("sh", "-lc", string(req.Payload))
	remote := legacySSHCommand(connection, targetCommand, false, "")
	args := append(append([]string{}, b.config.SSHArgs...), b.config.Bastion, remote)
	err := b.config.runner.Run(ctx, b.config.SSHPath, args, nil, stdout, stderr)
	if err == nil {
		return backend.ExecResult{ExitCode: 0}, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return backend.ExecResult{ExitCode: exitErr.ExitCode()}, nil
	}
	return backend.ExecResult{}, fmt.Errorf("execute remote command: %s", redactMany(err.Error(), backendTargetID, connection.host))
}

func redactedStreams(req backend.ExecRequest, secrets ...string) (io.Writer, io.Writer, func()) {
	stdout, stdoutWriters := redactedStream(req.Stdout, secrets...)
	stderr, stderrWriters := redactedStream(req.Stderr, secrets...)
	return stdout, stderr, func() {
		closeRedactors(stdoutWriters)
		closeRedactors(stderrWriters)
	}
}

func redactedStream(destination io.Writer, secrets ...string) (io.Writer, []*redactingWriter) {
	current := destination
	writers := make([]*redactingWriter, 0, len(secrets))
	for index := len(secrets) - 1; index >= 0; index-- {
		writer := newRedactingWriter(current, secrets[index])
		current = writer
		writers = append(writers, writer)
	}
	return current, writers
}

func closeRedactors(writers []*redactingWriter) {
	for index := len(writers) - 1; index >= 0; index-- {
		_ = writers[index].Close()
	}
}

func redactMany(value string, secrets ...string) string {
	for _, secret := range secrets {
		value = redact(value, secret)
	}
	return value
}

func legacySSHCommand(connection targetConnection, targetCommand string, forwardOnly bool, forwardSpec string) string {
	args := []string{
		"ssh",
		"-o", "BatchMode=yes",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "StrictHostKeyChecking=no",
		"-p", strconv.Itoa(connection.port),
	}
	if forwardOnly {
		args = append(args, "-o", "ExitOnForwardFailure=yes", "-N", "-L", forwardSpec)
	}
	destination := "root@" + connection.host
	if strings.Contains(connection.host, ":") {
		destination = "root@[" + connection.host + "]"
	}
	args = append(args, destination)
	if targetCommand != "" {
		args = append(args, targetCommand)
	}
	return remoteCommand(args...)
}

func (b *Backend) OpenForward(ctx context.Context, backendTargetID string, req backend.ForwardRequest) (backend.Forward, error) {
	if req.RemoteHost != "127.0.0.1" && req.RemoteHost != "localhost" {
		return nil, errors.New("Windmill forwards are restricted to the selected target loopback")
	}
	targetSpec := fmt.Sprintf("127.0.0.1:%d:%s:%d", req.LocalPort, req.RemoteHost, req.RemotePort)
	outerSpec := fmt.Sprintf("127.0.0.1:%d:127.0.0.1:%d", req.LocalPort, req.LocalPort)
	remote := remoteCommand(
		b.config.Sancho, "session", "forward", backendTargetID,
		"--listen-host", "127.0.0.1", "--listen-port", fmt.Sprint(req.LocalPort),
		"--remote-host", req.RemoteHost, "--remote-port", fmt.Sprint(req.RemotePort),
	)
	privateValues := []string{backendTargetID}
	if _, ok := b.connection(backendTargetID); ok {
		connection, err := b.refreshConnection(ctx, backendTargetID)
		if err != nil {
			return nil, err
		}
		remote = legacySSHCommand(connection, "", true, targetSpec)
		privateValues = append(privateValues, connection.host)
	}
	args := append(append([]string{}, b.config.SSHArgs...),
		"-o", "ExitOnForwardFailure=yes", "-L", outerSpec, b.config.Bastion,
		remote)
	proc, err := b.config.runner.Start(ctx, b.config.SSHPath, args, nil, io.Discard, io.Discard)
	if err != nil {
		return nil, fmt.Errorf("open remote forward: %s", redactMany(err.Error(), privateValues...))
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
