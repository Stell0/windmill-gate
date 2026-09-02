// Package command models immutable commands and their audited lifecycle.
package command

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

type State string

const (
	Queued    State = "queued"
	Waiting   State = "waiting"
	Running   State = "running"
	Succeeded State = "succeeded"
	Failed    State = "failed"
	Denied    State = "denied"
	Cancelled State = "cancelled"
)

var (
	ErrPayloadChanged    = errors.New("command payload changed after submission")
	ErrInvalidTransition = errors.New("invalid command state transition")
)

// Command retains a private copy of the exact bytes received from the agent.
type Command struct {
	mu sync.RWMutex

	id             string
	agentSessionID string
	targetID       string
	payload        []byte
	hash           string
	state          State
	createdAt      time.Time
	startedAt      *time.Time
	finishedAt     *time.Time
	exitCode       *int
}

// Snapshot contains only agent-safe and audit-safe command data.
type Snapshot struct {
	ID             string     `json:"id"`
	AgentSessionID string     `json:"agent_session_id"`
	TargetID       string     `json:"target_id"`
	Payload        string     `json:"command"`
	Hash           string     `json:"hash"`
	State          State      `json:"state"`
	CreatedAt      time.Time  `json:"created_at"`
	StartedAt      *time.Time `json:"started_at,omitempty"`
	FinishedAt     *time.Time `json:"finished_at,omitempty"`
	ExitCode       *int       `json:"exit_code,omitempty"`
}

func New(agentSessionID, targetID string, payload []byte) (*Command, error) {
	if len(payload) == 0 {
		return nil, errors.New("command payload is empty")
	}
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("create command ID: %w", err)
	}
	copyOfPayload := append([]byte(nil), payload...)
	return &Command{
		id:             id,
		agentSessionID: agentSessionID,
		targetID:       targetID,
		payload:        copyOfPayload,
		hash:           Hash(copyOfPayload),
		state:          Queued,
		createdAt:      time.Now().UTC(),
	}, nil
}

func Hash(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}

// Payload returns a copy so callers cannot mutate the approved bytes.
func (c *Command) Payload() []byte {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]byte(nil), c.payload...)
}

func (c *Command) Snapshot() Snapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return Snapshot{
		ID:             c.id,
		AgentSessionID: c.agentSessionID,
		TargetID:       c.targetID,
		Payload:        string(c.payload),
		Hash:           c.hash,
		State:          c.state,
		CreatedAt:      c.createdAt,
		StartedAt:      cloneTime(c.startedAt),
		FinishedAt:     cloneTime(c.finishedAt),
		ExitCode:       cloneInt(c.exitCode),
	}
}

// VerifyApproval binds a decision to both the command ID and exact byte hash.
func (c *Command) VerifyApproval(commandID, approvedHash string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if commandID != c.id || approvedHash != c.hash || Hash(c.payload) != c.hash {
		return ErrPayloadChanged
	}
	return nil
}

func (c *Command) Transition(next State, exitCode *int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !allowedTransition(c.state, next) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, c.state, next)
	}
	now := time.Now().UTC()
	if next == Running {
		c.startedAt = &now
	}
	if next == Succeeded || next == Failed || next == Denied || next == Cancelled {
		c.finishedAt = &now
	}
	if exitCode != nil {
		value := *exitCode
		c.exitCode = &value
	}
	c.state = next
	return nil
}

func allowedTransition(current, next State) bool {
	switch current {
	case Queued:
		return next == Waiting || next == Running || next == Denied || next == Cancelled
	case Waiting:
		return next == Running || next == Denied || next == Cancelled
	case Running:
		return next == Succeeded || next == Failed || next == Cancelled
	default:
		return false
	}
}

func newID() (string, error) {
	var raw [10]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "cmd_" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:]), nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneInt(value *int) *int {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
