// Package approval coordinates immutable, human command decisions.
package approval

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/stell0/windmill-gate/internal/command"
	"github.com/stell0/windmill-gate/internal/policy"
)

type Action string

const (
	ApproveOnce Action = "approve_once"
	AllowTarget Action = "allow_target"
	Deny        Action = "deny"
)

type Decision struct {
	CommandID string    `json:"command_id"`
	Hash      string    `json:"hash"`
	Action    Action    `json:"action"`
	Actor     string    `json:"actor"`
	DecidedAt time.Time `json:"decided_at"`
	Rule      string    `json:"rule,omitempty"`
}

type Pending struct {
	Command command.Snapshot `json:"command"`
	Policy  policy.Result    `json:"policy"`
}

var (
	ErrNotPending      = errors.New("command is not waiting for approval")
	ErrAlreadyPending  = errors.New("command is already waiting for approval")
	ErrInvalidDecision = errors.New("invalid approval decision")
)

type request struct {
	command  *command.Command
	pending  Pending
	decision chan Decision
}

type Broker struct {
	mu      sync.RWMutex
	pending map[string]*request
	changed chan struct{}
}

func NewBroker() *Broker {
	return &Broker{pending: make(map[string]*request), changed: make(chan struct{}, 1)}
}

func (b *Broker) Wait(ctx context.Context, cmd *command.Command, result policy.Result) (Decision, error) {
	snapshot := cmd.Snapshot()
	req := &request{command: cmd, pending: Pending{Command: snapshot, Policy: result}, decision: make(chan Decision, 1)}
	b.mu.Lock()
	if _, exists := b.pending[snapshot.ID]; exists {
		b.mu.Unlock()
		return Decision{}, ErrAlreadyPending
	}
	b.pending[snapshot.ID] = req
	b.mu.Unlock()
	b.notify()

	select {
	case decision := <-req.decision:
		return decision, nil
	case <-ctx.Done():
		b.mu.Lock()
		delete(b.pending, snapshot.ID)
		b.mu.Unlock()
		b.notify()
		return Decision{}, ctx.Err()
	}
}

func (b *Broker) Decide(decision Decision) error {
	b.mu.Lock()
	req, ok := b.pending[decision.CommandID]
	if !ok {
		b.mu.Unlock()
		return ErrNotPending
	}
	if decision.Action != ApproveOnce && decision.Action != AllowTarget && decision.Action != Deny {
		b.mu.Unlock()
		return ErrInvalidDecision
	}
	if strings.TrimSpace(decision.Actor) == "" {
		b.mu.Unlock()
		return errors.New("approval actor is required")
	}
	if err := req.command.VerifyApproval(decision.CommandID, decision.Hash); err != nil {
		b.mu.Unlock()
		return err
	}
	if decision.DecidedAt.IsZero() {
		decision.DecidedAt = time.Now().UTC()
	}
	if decision.Action == AllowTarget && decision.Rule == "" {
		decision.Rule = SimilarPattern(req.pending.Command.Payload)
	}
	delete(b.pending, decision.CommandID)
	b.mu.Unlock()
	req.decision <- decision
	b.notify()
	return nil
}

func (b *Broker) List() []Pending {
	b.mu.RLock()
	defer b.mu.RUnlock()
	result := make([]Pending, 0, len(b.pending))
	for _, req := range b.pending {
		result = append(result, req.pending)
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Command.CreatedAt.Before(result[j].Command.CreatedAt)
	})
	return result
}

func (b *Broker) Changed() <-chan struct{} { return b.changed }

func (b *Broker) notify() {
	select {
	case b.changed <- struct{}{}:
	default:
	}
}

// SimilarPattern generalizes only standalone decimal arguments for simple
// commands. Anything shell-composed or difficult to tokenize becomes exact.
func SimilarPattern(payload string) string {
	if policy.HasUnsafeComposition(payload) || strings.ContainsAny(payload, "'\"") {
		return "^" + regexp.QuoteMeta(payload) + "$"
	}
	fields := strings.Fields(payload)
	if len(fields) == 0 || strings.Join(fields, " ") != payload {
		return "^" + regexp.QuoteMeta(payload) + "$"
	}
	parts := make([]string, len(fields))
	for i, field := range fields {
		if i > 0 && allDigits(field) {
			parts[i] = `[0-9]+`
		} else {
			parts[i] = regexp.QuoteMeta(field)
		}
	}
	return "^" + strings.Join(parts, " ") + "$"
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func ValidateDecision(decision Decision) error {
	if decision.CommandID == "" || decision.Hash == "" {
		return fmt.Errorf("%w: command ID and hash are required", ErrInvalidDecision)
	}
	return nil
}
