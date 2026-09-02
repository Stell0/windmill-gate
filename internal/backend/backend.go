// Package backend defines the private transport boundary used by Gate.
package backend

import (
	"context"
	"io"
)

// Target is a backend-owned target. ID must never be serialized to an agent.
type Target struct {
	ID          string
	DisplayName string
}

// ExecRequest contains the exact, already-approved command payload.
type ExecRequest struct {
	Payload []byte
	Stdout  io.Writer
	Stderr  io.Writer
}

// ExecResult is the result reported by the remote transport.
type ExecResult struct {
	ExitCode int
}

// ForwardRequest describes a target-local TCP endpoint. Host is intentionally
// constrained by callers and implementations; it is not an arbitrary SSH host.
type ForwardRequest struct {
	RemoteHost string
	RemotePort uint16
	LocalPort  uint16
}

// Forward represents a live backend tunnel.
type Forward interface {
	Close() error
	Wait() error
}

// Backend isolates transport-specific identifiers from the agent protocol.
type Backend interface {
	Name() string
	ListTargets(ctx context.Context) ([]Target, error)
	Exec(ctx context.Context, backendTargetID string, req ExecRequest) (ExecResult, error)
	OpenForward(ctx context.Context, backendTargetID string, req ForwardRequest) (Forward, error)
}
