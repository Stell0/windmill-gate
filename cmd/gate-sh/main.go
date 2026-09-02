package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
)

import (
	"github.com/nethserver/gate/internal/agent"
	"github.com/nethserver/gate/internal/config"
)

func main() {
	os.Exit(run())
}

func run() int {
	var command, socket, agentID string
	flag.StringVar(&command, "c", "", "execute one non-interactive command")
	flag.StringVar(&socket, "socket", config.SocketPath(), "Gate Unix socket")
	flag.StringVar(&agentID, "agent", config.AgentIdentity(), "agent identity")
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
