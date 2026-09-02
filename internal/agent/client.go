// Package agent contains the shell-compatible Gate client.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/nethserver/gate/internal/protocol"
)

type Dialer func(ctx context.Context) (io.ReadWriteCloser, error)

type Client struct {
	Dial    Dialer
	AgentID string
	Stdout  io.Writer
	Stderr  io.Writer
}

func UnixDialer(path string) Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		var dialer net.Dialer
		return dialer.DialContext(ctx, "unix", path)
	}
}

// Exec submits one immutable command and waits for its terminal response.
func (c Client) Exec(ctx context.Context, payload string) (int, error) {
	if c.Dial == nil {
		return 1, errors.New("Gate dialer is not configured")
	}
	conn, err := c.Dial(ctx)
	if err != nil {
		return 1, fmt.Errorf("connect to Gate: %w", err)
	}
	defer conn.Close()

	encoder := protocol.NewEncoder(conn)
	decoder := protocol.NewDecoder(conn)
	if err := encoder.Encode(protocol.Request{Type: "hello", Version: protocol.Version, Agent: c.AgentID}); err != nil {
		return 1, fmt.Errorf("send Gate hello: %w", err)
	}
	var hello protocol.Response
	if err := decoder.Decode(&hello); err != nil {
		return 1, fmt.Errorf("receive Gate hello: %w", err)
	}
	if hello.Type == "error" {
		return 1, errors.New(hello.Error)
	}
	if hello.Type != "hello" || hello.Version != protocol.Version {
		return 1, errors.New("invalid Gate hello response")
	}
	if err := encoder.Encode(protocol.Request{Type: "exec", Command: payload}); err != nil {
		return 1, fmt.Errorf("submit command: %w", err)
	}

	stdout, stderr := c.Stdout, c.Stderr
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	for {
		var response protocol.Response
		if err := decoder.Decode(&response); err != nil {
			return 1, fmt.Errorf("read Gate response: %w", err)
		}
		switch response.Type {
		case "accepted", "state":
			continue
		case "stdout":
			if _, err := io.WriteString(stdout, response.Data); err != nil {
				return 1, fmt.Errorf("write stdout: %w", err)
			}
		case "stderr":
			if _, err := io.WriteString(stderr, response.Data); err != nil {
				return 1, fmt.Errorf("write stderr: %w", err)
			}
		case "exit":
			if response.Code == nil {
				return 1, errors.New("Gate exit response omitted status code")
			}
			return *response.Code, nil
		case "error":
			return 1, errors.New(response.Error)
		default:
			return 1, fmt.Errorf("unexpected Gate response type %q", response.Type)
		}
	}
}
