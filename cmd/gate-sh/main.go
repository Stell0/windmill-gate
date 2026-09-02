package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
)

import "github.com/nethserver/gate/internal/agent"

func main() {
	os.Exit(run())
}

func run() int {
	var command, socket, agentID string
	flag.StringVar(&command, "c", "", "execute one non-interactive command")
	flag.StringVar(&socket, "socket", defaultSocket(), "Gate Unix socket")
	flag.StringVar(&agentID, "agent", defaultAgent(), "agent identity")
	flag.Parse()
	if command == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gate-sh [-socket path] [-agent identity] -c command")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := agent.Client{
		Dial:    agent.UnixDialer(socket),
		AgentID: agentID,
		Stdout:  os.Stdout,
		Stderr:  os.Stderr,
	}
	exitCode, err := client.Exec(ctx, command)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gate-sh: %v\n", err)
		return 1
	}
	return exitCode
}

func defaultSocket() string {
	if value := os.Getenv("GATE_SOCKET"); value != "" {
		return value
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		runtimeDir = filepath.Join(os.TempDir(), fmt.Sprintf("gate-%d", os.Getuid()))
	}
	return filepath.Join(runtimeDir, "gate.sock")
}

func defaultAgent() string {
	if value := os.Getenv("GATE_AGENT_ID"); value != "" {
		return value
	}
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return "local-agent"
}
