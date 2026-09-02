package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nethserver/gate/internal/agent"
	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	"github.com/nethserver/gate/internal/backend/windmill"
	"github.com/nethserver/gate/internal/config"
	gatecore "github.com/nethserver/gate/internal/gate"
	"github.com/nethserver/gate/internal/policy"
	"github.com/nethserver/gate/internal/storage"
	"github.com/nethserver/gate/internal/tui"
	defaultpolicy "github.com/nethserver/gate/policy"
)

var version = "dev"

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		return runServer(args, true, stdin, stdout, stderr)
	}
	switch args[0] {
	case "daemon":
		return runServer(args[1:], false, stdin, stdout, stderr)
	case "exec":
		return runExec(args[1:], stdout, stderr)
	case "history":
		return runHistory(args[1:], stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "version", "--version", "-version":
		fmt.Fprintf(stdout, "gate %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "gate: unknown command %q\n", args[0])
		usage(stderr)
		return 2
	}
}

type repeatedFlag []string

func (f *repeatedFlag) String() string { return strings.Join(*f, " ") }
func (f *repeatedFlag) Set(value string) error {
	*f = append(*f, value)
	return nil
}

func runServer(args []string, withUI bool, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var socketPath, databasePath, policyPath, bastion, sancho, selector, agentID, operator string
	var outputLimit int64
	var sshArgs repeatedFlag
	flags.StringVar(&socketPath, "socket", config.SocketPath(), "Unix socket path")
	flags.StringVar(&databasePath, "database", config.DatabasePath(), "SQLite database path")
	flags.StringVar(&policyPath, "policy", config.PolicyPath(), "policy YAML path")
	flags.StringVar(&bastion, "bastion", os.Getenv("GATE_BASTION"), "Bastion SSH host")
	flags.StringVar(&sancho, "sancho", envOr("GATE_SANCHO", "sancho"), "Sancho executable on Bastion")
	flags.StringVar(&selector, "target", "", "target display name or displayed number")
	flags.StringVar(&agentID, "agent", config.AgentIdentity(), "initial attached agent identity")
	flags.StringVar(&operator, "operator", envOr("GATE_OPERATOR", "operator"), "operator audit identity")
	flags.Int64Var(&outputLimit, "output-limit", gatecore.DefaultOutputLimit, "maximum output bytes per command")
	flags.Var(&sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "gate: unexpected positional arguments")
		return 2
	}
	if bastion == "" {
		fmt.Fprintln(stderr, "gate: --bastion or GATE_BASTION is required")
		return 2
	}
	if err := ensurePolicy(policyPath); err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	store, err := storage.Open(databasePath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	defer store.Close()
	implementation, err := windmill.New(windmill.Config{Bastion: bastion, Sancho: sancho, SSHArgs: sshArgs})
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	available, err := implementation.ListTargets(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	selected, err := chooseTarget(available, selector, stdin, stdout)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	service, err := gatecore.NewService(store, engine, approval.NewBroker(), implementation)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	if err := service.SetOutputLimit(outputLimit); err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 2
	}
	public, err := service.AddTarget(ctx, implementation.Name(), selected)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	if err := service.Attach(agentID, public.ID); err != nil {
		fmt.Fprintf(stderr, "gate: attach agent: %v\n", err)
		return 1
	}
	listener, err := agent.ListenUnix(socketPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	defer listener.Close()
	serverErr := make(chan error, 1)
	go func() {
		serverErr <- (&agent.Server{Service: service, Transport: "unix"}).Serve(ctx, listener)
	}()
	fmt.Fprintf(stdout, "Gate target %s (%s) selected\n", public.ID, public.DisplayName)
	fmt.Fprintf(stdout, "Agent %s attached; listening on %s\n", agentID, socketPath)

	if withUI {
		app := tui.App{Service: service, Operator: operator, Input: stdin, Output: stdout}
		if err := app.Run(ctx); err != nil {
			fmt.Fprintf(stderr, "gate: operator console: %v\n", err)
			stop()
			return 1
		}
		stop()
	} else {
		select {
		case <-ctx.Done():
		case err := <-serverErr:
			if err != nil {
				fmt.Fprintf(stderr, "gate: %v\n", err)
				return 1
			}
		}
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if containsTarget(service, public.ID) {
		if err := service.DetachTarget(shutdownCtx, public.ID); err != nil {
			fmt.Fprintf(stderr, "gate: detach target: %v\n", err)
			return 1
		}
	}
	return 0
}

func runExec(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate exec", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var socketPath, agentID string
	flags.StringVar(&socketPath, "socket", config.SocketPath(), "Unix socket path")
	flags.StringVar(&agentID, "agent", config.AgentIdentity(), "agent identity")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: gate exec [options] -- 'exact command'")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := agent.Client{Dial: agent.UnixDialer(socketPath), AgentID: agentID, Stdout: stdout, Stderr: stderr}
	exitCode, err := client.Exec(ctx, flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	return exitCode
}

func runHistory(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate history", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var databasePath, sessionID string
	var limit int
	var asJSON bool
	flags.StringVar(&databasePath, "database", config.DatabasePath(), "SQLite database path")
	flags.StringVar(&sessionID, "session", "", "filter by Gate agent session")
	flags.IntVar(&limit, "limit", 100, "maximum records")
	flags.BoolVar(&asJSON, "json", false, "emit JSON")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	store, err := storage.Open(databasePath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	defer store.Close()
	entries, err := store.History(context.Background(), sessionID, limit)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	if asJSON {
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(entries); err != nil {
			fmt.Fprintf(stderr, "gate: encode history: %v\n", err)
			return 1
		}
		return 0
	}
	for _, entry := range entries {
		exitCode := "-"
		if entry.ExitCode != nil {
			exitCode = strconv.Itoa(*entry.ExitCode)
		}
		fmt.Fprintf(stdout, "%s %-10s target=%s agent=%s exit=%s %s\n",
			entry.CreatedAt.Format(time.RFC3339), entry.State, entry.TargetName, entry.AgentIdentity, exitCode, entry.Command)
	}
	return 0
}

func runPolicy(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "test" {
		fmt.Fprintln(stderr, "usage: gate policy test [--policy path] [--tests path]")
		return 2
	}
	flags := flag.NewFlagSet("gate policy test", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var policyPath, testsPath string
	flags.StringVar(&policyPath, "policy", "policy/default.yaml", "policy YAML path")
	flags.StringVar(&testsPath, "tests", "policy/tests/default.yaml", "policy tests YAML path")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	engine, err := policy.Load(policyPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	suite, err := policy.LoadTestSuite(testsPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	total, failures := suite.Run(engine)
	for _, failure := range failures {
		fmt.Fprintf(stderr, "FAIL %q: got %s, want %s\n", failure.Command, failure.Actual, failure.Expect)
	}
	if len(failures) > 0 {
		fmt.Fprintf(stderr, "%d/%d policy tests failed\n", len(failures), total)
		return 1
	}
	fmt.Fprintf(stdout, "PASS: %d policy tests\n", total)
	return 0
}

func chooseTarget(targets []backend.Target, selector string, input io.Reader, output io.Writer) (backend.Target, error) {
	if len(targets) == 0 {
		return backend.Target{}, errors.New("Sancho reported no available sessions")
	}
	if selector != "" {
		if number, err := strconv.Atoi(selector); err == nil && number >= 1 && number <= len(targets) {
			return targets[number-1], nil
		}
		matches := make([]backend.Target, 0, 1)
		for _, candidate := range targets {
			if candidate.DisplayName == selector {
				matches = append(matches, candidate)
			}
		}
		if len(matches) == 1 {
			return matches[0], nil
		}
		if len(matches) > 1 {
			return backend.Target{}, fmt.Errorf("target display name %q is ambiguous; select by displayed number", selector)
		}
		return backend.Target{}, fmt.Errorf("target %q not found", selector)
	}
	fmt.Fprintln(output, "Available Windmill sessions:")
	for index, candidate := range targets {
		// Deliberately show no backend target identifier.
		fmt.Fprintf(output, "  [%d] %s\n", index+1, candidate.DisplayName)
	}
	fmt.Fprint(output, "Select target number: ")
	line, err := bufio.NewReader(input).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return backend.Target{}, fmt.Errorf("read target selection: %w", err)
	}
	number, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil || number < 1 || number > len(targets) {
		return backend.Target{}, errors.New("invalid target selection")
	}
	return targets[number-1], nil
}

func ensurePolicy(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect policy: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create policy directory: %w", err)
	}
	if err := os.WriteFile(path, defaultpolicy.DefaultYAML, 0o600); err != nil {
		return fmt.Errorf("create default policy: %w", err)
	}
	return nil
}

func containsTarget(service *gatecore.Service, targetID string) bool {
	for _, candidate := range service.Targets.List() {
		if candidate.ID == targetID {
			return true
		}
	}
	return false
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func usage(output io.Writer) {
	fmt.Fprintln(output, "usage: gate [daemon|exec|history|policy test|version]")
}
