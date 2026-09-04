// Package agent contains the shell-compatible Gate client.
package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"sync"

	"github.com/stell0/windmill-gate/internal/protocol"
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

func SSHDialer(host string, args []string, stderr io.Writer) Dialer {
	return func(ctx context.Context) (io.ReadWriteCloser, error) {
		if host == "" {
			return nil, errors.New("Gate SSH host is required")
		}
		sshArgs := []string{"-T", "-o", "ClearAllForwardings=yes"}
		sshArgs = append(sshArgs, args...)
		sshArgs = append(sshArgs, host)
		cmd := exec.CommandContext(ctx, "ssh", sshArgs...)
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("open SSH stdin: %w", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return nil, fmt.Errorf("open SSH stdout: %w", err)
		}
		if stderr != nil {
			cmd.Stderr = stderr
		}
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("start Gate SSH transport: %w", err)
		}
		return &sshConnection{stdin: stdin, stdout: stdout, cmd: cmd}, nil
	}
}

type sshConnection struct {
	stdin  io.WriteCloser
	stdout io.ReadCloser
	cmd    *exec.Cmd
	once   sync.Once
	err    error
}

func (c *sshConnection) Read(data []byte) (int, error)  { return c.stdout.Read(data) }
func (c *sshConnection) Write(data []byte) (int, error) { return c.stdin.Write(data) }
func (c *sshConnection) Close() error {
	c.once.Do(func() {
		_ = c.stdin.Close()
		c.err = c.cmd.Wait()
		_ = c.stdout.Close()
	})
	return c.err
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
