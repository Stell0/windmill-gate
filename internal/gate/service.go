// Package gate coordinates policy, approval, execution, and audit boundaries.
package gate

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	"github.com/nethserver/gate/internal/command"
	"github.com/nethserver/gate/internal/forward"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/storage"
	"github.com/nethserver/gate/internal/target"
)

const DefaultOutputLimit int64 = 1024 * 1024

var (
	ErrAgentNotAttached = errors.New("agent is not attached to a Gate target")
	ErrSessionClosed    = errors.New("agent session is closed")
	ErrCommandNotOwned  = errors.New("command does not belong to this agent session")
)

type EventSink interface {
	Accepted(command.Snapshot, policy.Result) error
	State(command.Snapshot) error
	Output(stream string, data []byte) error
	Exit(command.Snapshot, int) error
	Error(string) error
}

type Service struct {
	Targets   *target.Registry
	Policy    *policy.Engine
	Approvals *approval.Broker
	Store     *storage.Store
	Forwards  *forward.Manager
	Aliases   *forward.AliasManager

	backends map[string]backend.Backend
	limit    int64

	mu          sync.RWMutex
	attachments map[string]string
	sessions    map[string]*Session
	running     map[string]runningCommand
}

func (s *Service) EnableForwarding(ctx context.Context, hostsPath string) error {
	manager, err := forward.NewManager(ctx, s, s.Store)
	if err != nil {
		return err
	}
	aliases, err := forward.NewAliasManager(ctx, hostsPath, s.Store, manager)
	if err != nil {
		return err
	}
	s.Forwards, s.Aliases = manager, aliases
	return nil
}

// ResolveBackend is for Gate-owned forwarding code only. The returned private
// identifier must never enter an agent protocol response.
func (s *Service) ResolveBackend(targetID string) (backend.Backend, string, error) {
	binding, err := s.Targets.Resolve(targetID)
	if err != nil {
		return nil, "", err
	}
	implementation := s.backends[binding.Backend]
	if implementation == nil {
		return nil, "", errors.New("target backend is unavailable")
	}
	return implementation, binding.BackendID, nil
}

type runningCommand struct {
	sessionID string
	targetID  string
	cancel    context.CancelFunc
}

type Session struct {
	ID          string
	Identity    string
	TargetID    string
	Transport   string
	Fingerprint string

	service   *Service
	closeOnce sync.Once
	closed    chan struct{}
}

func NewService(store *storage.Store, engine *policy.Engine, broker *approval.Broker, backends ...backend.Backend) (*Service, error) {
	if store == nil || engine == nil || broker == nil {
		return nil, errors.New("store, policy, and approval broker are required")
	}
	byName := make(map[string]backend.Backend, len(backends))
	for _, implementation := range backends {
		if implementation == nil || implementation.Name() == "" {
			return nil, errors.New("backend with a name is required")
		}
		if _, exists := byName[implementation.Name()]; exists {
			return nil, fmt.Errorf("duplicate backend %q", implementation.Name())
		}
		byName[implementation.Name()] = implementation
	}
	return &Service{
		Targets:     target.NewRegistry(),
		Policy:      engine,
		Approvals:   broker,
		Store:       store,
		backends:    byName,
		limit:       DefaultOutputLimit,
		attachments: make(map[string]string),
		sessions:    make(map[string]*Session),
		running:     make(map[string]runningCommand),
	}, nil
}

func (s *Service) SetOutputLimit(limit int64) error {
	if limit <= 0 {
		return errors.New("output limit must be positive")
	}
	s.limit = limit
	return nil
}

// AddTarget is an operator-only operation. The backend target ID never enters
// the returned target or any agent-facing event.
func (s *Service) AddTarget(ctx context.Context, backendName string, backendTarget backend.Target) (target.Target, error) {
	if _, ok := s.backends[backendName]; !ok {
		return target.Target{}, fmt.Errorf("backend %q is not configured", backendName)
	}
	public, err := s.Targets.Add(backendName, backendTarget.ID, backendTarget.DisplayName)
	if err != nil {
		return target.Target{}, err
	}
	binding, err := s.Targets.Resolve(public.ID)
	if err != nil {
		return target.Target{}, err
	}
	if err := s.Store.SaveTarget(ctx, binding); err != nil {
		_, _ = s.Targets.Remove(public.ID)
		return target.Target{}, err
	}
	return public, nil
}

// Attach changes only the target used by future sessions. Existing attached
// sessions cannot be silently switched underneath an agent.
func (s *Service) Attach(agentIdentity, targetID string) error {
	if err := validateIdentity(agentIdentity); err != nil {
		return err
	}
	if _, err := s.Targets.Resolve(targetID); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attachments[agentIdentity] = targetID
	return nil
}

func (s *Service) OpenSession(ctx context.Context, identity, transport, fingerprint string) (*Session, error) {
	if err := validateIdentity(identity); err != nil {
		return nil, err
	}
	if err := validateFingerprint(transport, fingerprint); err != nil {
		return nil, err
	}
	s.mu.RLock()
	targetID := s.attachments[identity]
	s.mu.RUnlock()
	if targetID == "" {
		return nil, ErrAgentNotAttached
	}
	if _, err := s.Targets.Resolve(targetID); err != nil {
		return nil, ErrAgentNotAttached
	}
	id, err := randomID("as_", 10)
	if err != nil {
		return nil, fmt.Errorf("create agent session ID: %w", err)
	}
	session := &Session{
		ID: id, Identity: identity, TargetID: targetID, Transport: transport,
		Fingerprint: fingerprint, service: s, closed: make(chan struct{}),
	}
	if err := s.Store.StartAgentSession(ctx, id, identity, targetID, transport, fingerprint, time.Now().UTC()); err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.sessions[id] = session
	s.mu.Unlock()
	return session, nil
}

func (s *Session) Close(ctx context.Context) error {
	var closeErr error
	s.closeOnce.Do(func() {
		close(s.closed)
		s.service.mu.Lock()
		delete(s.service.sessions, s.ID)
		for _, running := range s.service.running {
			if running.sessionID == s.ID {
				running.cancel()
			}
		}
		s.service.mu.Unlock()
		closeErr = s.service.Store.EndAgentSession(ctx, s.ID, time.Now().UTC())
	})
	return closeErr
}

func (s *Session) Exec(ctx context.Context, payload []byte, sink EventSink) error {
	select {
	case <-s.closed:
		return ErrSessionClosed
	default:
	}
	return s.service.execute(ctx, s, payload, sink)
}

func (s *Service) execute(parent context.Context, session *Session, payload []byte, sink EventSink) error {
	if sink == nil {
		return errors.New("event sink is required")
	}
	cmd, err := command.New(session.ID, session.TargetID, payload)
	if err != nil {
		return err
	}
	binding, err := s.Targets.Resolve(session.TargetID)
	if err != nil {
		return errors.New("attached Gate target is no longer available")
	}
	implementation := s.backends[binding.Backend]
	if implementation == nil {
		return errors.New("attached Gate target backend is unavailable")
	}

	result := s.Policy.Evaluate(session.TargetID, string(payload))
	if err := s.Store.CreateCommand(parent, cmd.Snapshot(), result); err != nil {
		return err
	}
	if err := sink.Accepted(cmd.Snapshot(), result); err != nil {
		return err
	}

	switch result.Decision {
	case policy.Deny:
		return s.finishDenied(parent, cmd, sink, "policy")
	case policy.Allow:
		// No human decision is required, but the same hash check below still
		// binds execution to the submitted bytes.
	case policy.Ask:
		if err := cmd.Transition(command.Waiting, nil); err != nil {
			return err
		}
		if err := s.Store.UpdateCommand(parent, cmd.Snapshot()); err != nil {
			return err
		}
		if err := sink.State(cmd.Snapshot()); err != nil {
			return err
		}
		decision, err := s.Approvals.Wait(parent, cmd, result)
		if err != nil {
			_ = cmd.Transition(command.Cancelled, nil)
			_ = s.Store.UpdateCommand(context.WithoutCancel(parent), cmd.Snapshot())
			return err
		}
		if err := s.Store.RecordApproval(parent, decision); err != nil {
			return err
		}
		if decision.Action == approval.Deny {
			return s.finishDenied(parent, cmd, sink, decision.Actor)
		}
		if decision.Action == approval.AllowTarget {
			if err := s.Policy.AllowForTarget(session.TargetID, decision.Rule); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported policy result %q", result.Decision)
	}

	// Revalidate after all waiting and immediately before transport execution.
	snapshot := cmd.Snapshot()
	if err := cmd.VerifyApproval(snapshot.ID, snapshot.Hash); err != nil {
		return err
	}
	if err := cmd.Transition(command.Running, nil); err != nil {
		return err
	}
	if err := s.Store.UpdateCommand(parent, cmd.Snapshot()); err != nil {
		return err
	}
	if err := sink.State(cmd.Snapshot()); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(parent)
	s.mu.Lock()
	s.running[snapshot.ID] = runningCommand{sessionID: session.ID, targetID: session.TargetID, cancel: cancel}
	s.mu.Unlock()
	defer func() {
		cancel()
		s.mu.Lock()
		delete(s.running, snapshot.ID)
		s.mu.Unlock()
	}()

	stdout := &auditWriter{ctx: ctx, store: s.Store, commandID: snapshot.ID, stream: "stdout", limit: s.limit, sink: sink}
	stderr := &auditWriter{ctx: ctx, store: s.Store, commandID: snapshot.ID, stream: "stderr", limit: s.limit, sink: sink}
	execResult, execErr := implementation.Exec(ctx, binding.BackendID, backend.ExecRequest{
		Payload: cmd.Payload(), Stdout: stdout, Stderr: stderr,
	})
	writerErr := errors.Join(stdout.Err(), stderr.Err())
	if execErr != nil || writerErr != nil {
		exitCode := 1
		if errors.Is(ctx.Err(), context.Canceled) {
			_ = cmd.Transition(command.Cancelled, &exitCode)
		} else {
			_ = cmd.Transition(command.Failed, &exitCode)
		}
		_ = s.Store.UpdateCommand(context.WithoutCancel(parent), cmd.Snapshot())
		message := "remote command failed"
		if execErr != nil {
			message = execErr.Error()
		} else if writerErr != nil {
			message = writerErr.Error()
		}
		_ = sink.Error(message)
		_ = sink.Exit(cmd.Snapshot(), exitCode)
		return errors.Join(execErr, writerErr)
	}

	terminal := command.Failed
	if execResult.ExitCode == 0 {
		terminal = command.Succeeded
	}
	if err := cmd.Transition(terminal, &execResult.ExitCode); err != nil {
		return err
	}
	if err := s.Store.UpdateCommand(parent, cmd.Snapshot()); err != nil {
		return err
	}
	return sink.Exit(cmd.Snapshot(), execResult.ExitCode)
}

func (s *Service) finishDenied(ctx context.Context, cmd *command.Command, sink EventSink, actor string) error {
	exitCode := 126
	if err := cmd.Transition(command.Denied, &exitCode); err != nil {
		return err
	}
	if err := s.Store.UpdateCommand(ctx, cmd.Snapshot()); err != nil {
		return err
	}
	if err := sink.State(cmd.Snapshot()); err != nil {
		return err
	}
	if err := sink.Output("stderr", []byte("gate: command denied by "+actor+"\n")); err != nil {
		return err
	}
	return sink.Exit(cmd.Snapshot(), exitCode)
}

func (s *Service) CancelCommand(commandID string) error {
	s.mu.RLock()
	running, ok := s.running[commandID]
	s.mu.RUnlock()
	if !ok {
		return errors.New("command is not running")
	}
	running.cancel()
	return nil
}

func (s *Service) SessionIdentity(sessionID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if session := s.sessions[sessionID]; session != nil {
		return session.Identity
	}
	return sessionID
}

func (s *Service) Attachments() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make(map[string]string, len(s.attachments))
	for identity, targetID := range s.attachments {
		result[identity] = targetID
	}
	return result
}

// AddForward evaluates a synthetic, exact capability command through the same
// ALLOW/ASK/DENY and immutable approval path as a remote shell command.
func (s *Session) AddForward(ctx context.Context, remotePort uint16, sink EventSink) (forward.Info, command.Snapshot, bool, error) {
	if remotePort == 0 {
		return forward.Info{}, command.Snapshot{}, false, errors.New("remote port must be between 1 and 65535")
	}
	payload := []byte(fmt.Sprintf("gate forward add --remote-port %d", remotePort))
	cmd, authorized, err := s.service.authorizeCapability(ctx, s, payload, sink)
	if err != nil || !authorized {
		return forward.Info{}, snapshotOf(cmd), false, err
	}
	if s.service.Forwards == nil {
		err = errors.New("Gate forwarding is not enabled")
	} else {
		var info forward.Info
		info, err = s.service.Forwards.Add(ctx, s.TargetID, remotePort, s.Identity)
		if err == nil {
			snapshot, finishErr := s.service.completeCapability(ctx, cmd, sink, nil)
			return info, snapshot, true, finishErr
		}
	}
	snapshot, finishErr := s.service.completeCapability(ctx, cmd, sink, err)
	return forward.Info{}, snapshot, true, errors.Join(err, finishErr)
}

func (s *Session) ListForwards() ([]forward.Info, error) {
	if s.service.Forwards == nil {
		return nil, errors.New("Gate forwarding is not enabled")
	}
	return s.service.Forwards.List(s.TargetID), nil
}

func (s *Session) RemoveForward(ctx context.Context, id string) error {
	if s.service.Forwards == nil || s.service.Aliases == nil {
		return errors.New("Gate forwarding is not enabled")
	}
	if err := s.service.Aliases.CloseForward(ctx, s.TargetID, id, s.Identity); err != nil {
		return err
	}
	return s.service.Forwards.Close(ctx, s.TargetID, id, s.Identity)
}

func (s *Session) AddHostAlias(ctx context.Context, hostname string, remotePort uint16, sink EventSink) (forward.AliasInfo, command.Snapshot, bool, error) {
	if remotePort == 0 {
		return forward.AliasInfo{}, command.Snapshot{}, false, errors.New("remote port must be between 1 and 65535")
	}
	var err error
	hostname, err = forward.NormalizeHostname(hostname)
	if err != nil {
		return forward.AliasInfo{}, command.Snapshot{}, false, err
	}
	payload := []byte(fmt.Sprintf("gate host add %s --remote-port %d", hostname, remotePort))
	cmd, authorized, err := s.service.authorizeCapability(ctx, s, payload, sink)
	if err != nil || !authorized {
		return forward.AliasInfo{}, snapshotOf(cmd), false, err
	}
	if s.service.Forwards == nil || s.service.Aliases == nil {
		err = errors.New("Gate forwarding is not enabled")
		snapshot, finishErr := s.service.completeCapability(ctx, cmd, sink, err)
		return forward.AliasInfo{}, snapshot, true, errors.Join(err, finishErr)
	}
	var linked forward.Info
	created := false
	for _, candidate := range s.service.Forwards.List(s.TargetID) {
		if candidate.RemotePort == remotePort {
			linked = candidate
			break
		}
	}
	if linked.ID == "" {
		linked, err = s.service.Forwards.Add(ctx, s.TargetID, remotePort, s.Identity)
		created = err == nil
	}
	if err == nil {
		var alias forward.AliasInfo
		alias, err = s.service.Aliases.Add(ctx, s.TargetID, linked.ID, hostname, s.Identity)
		if err == nil {
			snapshot, finishErr := s.service.completeCapability(ctx, cmd, sink, nil)
			return alias, snapshot, true, finishErr
		}
	}
	if created {
		_ = s.service.Forwards.Close(context.WithoutCancel(ctx), s.TargetID, linked.ID, "alias-rollback")
	}
	snapshot, finishErr := s.service.completeCapability(ctx, cmd, sink, err)
	return forward.AliasInfo{}, snapshot, true, errors.Join(err, finishErr)
}

func (s *Session) ListHostAliases() ([]forward.AliasInfo, error) {
	if s.service.Aliases == nil {
		return nil, errors.New("Gate host aliases are not enabled")
	}
	return s.service.Aliases.List(s.TargetID), nil
}

func (s *Session) RemoveHostAlias(ctx context.Context, hostname string) error {
	if s.service.Aliases == nil {
		return errors.New("Gate host aliases are not enabled")
	}
	return s.service.Aliases.Remove(ctx, s.TargetID, hostname, s.Identity)
}

func (s *Service) authorizeCapability(ctx context.Context, session *Session, payload []byte, sink EventSink) (*command.Command, bool, error) {
	if sink == nil {
		return nil, false, errors.New("event sink is required")
	}
	cmd, err := command.New(session.ID, session.TargetID, payload)
	if err != nil {
		return nil, false, err
	}
	result := s.Policy.Evaluate(session.TargetID, string(payload))
	if err := s.Store.CreateCommand(ctx, cmd.Snapshot(), result); err != nil {
		return cmd, false, err
	}
	if err := sink.Accepted(cmd.Snapshot(), result); err != nil {
		return cmd, false, err
	}
	switch result.Decision {
	case policy.Deny:
		return cmd, false, s.finishDenied(ctx, cmd, sink, "policy")
	case policy.Allow:
	case policy.Ask:
		if err := cmd.Transition(command.Waiting, nil); err != nil {
			return cmd, false, err
		}
		if err := s.Store.UpdateCommand(ctx, cmd.Snapshot()); err != nil {
			return cmd, false, err
		}
		if err := sink.State(cmd.Snapshot()); err != nil {
			return cmd, false, err
		}
		decision, err := s.Approvals.Wait(ctx, cmd, result)
		if err != nil {
			_ = cmd.Transition(command.Cancelled, nil)
			_ = s.Store.UpdateCommand(context.WithoutCancel(ctx), cmd.Snapshot())
			return cmd, false, err
		}
		if err := s.Store.RecordApproval(ctx, decision); err != nil {
			return cmd, false, err
		}
		if decision.Action == approval.Deny {
			return cmd, false, s.finishDenied(ctx, cmd, sink, decision.Actor)
		}
		if decision.Action == approval.AllowTarget {
			if err := s.Policy.AllowForTarget(session.TargetID, decision.Rule); err != nil {
				return cmd, false, err
			}
		}
	default:
		return cmd, false, fmt.Errorf("unsupported policy result %q", result.Decision)
	}
	snapshot := cmd.Snapshot()
	if err := cmd.VerifyApproval(snapshot.ID, snapshot.Hash); err != nil {
		return cmd, false, err
	}
	if err := cmd.Transition(command.Running, nil); err != nil {
		return cmd, false, err
	}
	if err := s.Store.UpdateCommand(ctx, cmd.Snapshot()); err != nil {
		return cmd, false, err
	}
	if err := sink.State(cmd.Snapshot()); err != nil {
		return cmd, false, err
	}
	return cmd, true, nil
}

func (s *Service) completeCapability(ctx context.Context, cmd *command.Command, sink EventSink, operationErr error) (command.Snapshot, error) {
	exitCode := 0
	state := command.Succeeded
	if operationErr != nil {
		exitCode, state = 1, command.Failed
	}
	if err := cmd.Transition(state, &exitCode); err != nil {
		return cmd.Snapshot(), err
	}
	if err := s.Store.UpdateCommand(context.WithoutCancel(ctx), cmd.Snapshot()); err != nil {
		return cmd.Snapshot(), err
	}
	if err := sink.State(cmd.Snapshot()); err != nil {
		return cmd.Snapshot(), err
	}
	if operationErr != nil {
		_ = sink.Error(operationErr.Error())
		_ = sink.Exit(cmd.Snapshot(), exitCode)
	}
	return cmd.Snapshot(), nil
}

func snapshotOf(cmd *command.Command) command.Snapshot {
	if cmd == nil {
		return command.Snapshot{}
	}
	return cmd.Snapshot()
}

func (s *Service) CancelSessionCommand(session *Session, commandID string) error {
	s.mu.RLock()
	running, ok := s.running[commandID]
	s.mu.RUnlock()
	if !ok {
		return errors.New("command is not running")
	}
	if running.sessionID != session.ID {
		return ErrCommandNotOwned
	}
	running.cancel()
	return nil
}

func (s *Service) DetachTarget(ctx context.Context, targetID string) error {
	s.mu.Lock()
	for identity, attached := range s.attachments {
		if attached == targetID {
			delete(s.attachments, identity)
		}
	}
	for _, running := range s.running {
		if running.targetID == targetID {
			running.cancel()
		}
	}
	s.mu.Unlock()
	if s.Aliases != nil {
		if err := s.Aliases.CloseTarget(ctx, targetID, "target-detach"); err != nil {
			return err
		}
	}
	if s.Forwards != nil {
		if err := s.Forwards.CloseTarget(ctx, targetID, "target-detach"); err != nil {
			return err
		}
	}
	if _, err := s.Targets.Remove(targetID); err != nil {
		return err
	}
	s.Policy.DetachTarget(targetID)
	return s.Store.DetachTarget(ctx, targetID, time.Now().UTC())
}

type auditWriter struct {
	ctx       context.Context
	store     *storage.Store
	commandID string
	stream    string
	limit     int64
	sink      EventSink

	mu              sync.Mutex
	err             error
	markerDelivered bool
}

func (w *auditWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	const chunkSize = 32 * 1024
	for offset := 0; offset < len(data); offset += chunkSize {
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		stored, truncated, err := w.store.AppendOutput(w.ctx, w.commandID, w.stream, data[offset:end], w.limit)
		if err != nil {
			w.err = err
			return 0, err
		}
		if len(stored) > 0 {
			if err := w.sink.Output(w.stream, stored); err != nil {
				w.err = err
				return 0, err
			}
		}
		if truncated && !w.markerDelivered {
			w.markerDelivered = true
			if err := w.sink.Output(w.stream, []byte("\n[gate: output truncated]\n")); err != nil {
				w.err = err
				return 0, err
			}
		}
	}
	return len(data), nil
}

func (w *auditWriter) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

func validateIdentity(identity string) error {
	if identity == "" || len(identity) > 128 || !utf8.ValidString(identity) {
		return errors.New("agent identity must be 1-128 UTF-8 bytes")
	}
	for _, r := range identity {
		if unicode.IsControl(r) {
			return errors.New("agent identity contains control characters")
		}
	}
	return nil
}

func validateFingerprint(transport, fingerprint string) error {
	if transport == "ssh" && fingerprint == "" {
		return errors.New("SSH agent fingerprint is required")
	}
	if len(fingerprint) > 256 || !utf8.ValidString(fingerprint) {
		return errors.New("agent fingerprint must be at most 256 UTF-8 bytes")
	}
	for _, r := range fingerprint {
		if unicode.IsControl(r) {
			return errors.New("agent fingerprint contains control characters")
		}
	}
	return nil
}

func randomID(prefix string, size int) (string, error) {
	raw := make([]byte, size)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return prefix + strings.TrimRight(base32.StdEncoding.EncodeToString(raw), "="), nil
}

var _ io.Writer = (*auditWriter)(nil)
