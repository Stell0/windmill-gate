package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
)

import (
	"github.com/nethserver/gate/internal/agent"
	"github.com/nethserver/gate/internal/config"
)

func main() {
	os.Exit(run())
}

func run() int {
	var command, socket, agentID, sshHost string
	var sshArgs stringList
	flag.StringVar(&command, "c", "", "execute one non-interactive command")
	flag.StringVar(&socket, "socket", config.SocketPath(), "Gate Unix socket")
	flag.StringVar(&agentID, "agent", config.AgentIdentity(), "agent identity")
	flag.StringVar(&sshHost, "ssh", "", "restricted remote Gate SSH host")
	flag.Var(&sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
	flag.Parse()
	if command == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: gate-sh [-socket path] [-agent identity] -c command")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialer := agent.UnixDialer(socket)
	if sshHost != "" {
		dialer = agent.SSHDialer(sshHost, sshArgs, os.Stderr)
	}
	client := agent.Client{
		Dial:    dialer,
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

type stringList []string

func (l *stringList) String() string { return strings.Join(*l, " ") }
func (l *stringList) Set(value string) error {
	*l = append(*l, value)
	return nil
}
