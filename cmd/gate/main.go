package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/stell0/windmill-gate/internal/agent"
	"github.com/stell0/windmill-gate/internal/approval"
	"github.com/stell0/windmill-gate/internal/backend"
	"github.com/stell0/windmill-gate/internal/backend/windmill"
	"github.com/stell0/windmill-gate/internal/config"
	"github.com/stell0/windmill-gate/internal/forward"
	gatecore "github.com/stell0/windmill-gate/internal/gate"
	"github.com/stell0/windmill-gate/internal/policy"
	"github.com/stell0/windmill-gate/internal/protocol"
	"github.com/stell0/windmill-gate/internal/remote"
	"github.com/stell0/windmill-gate/internal/review"
	"github.com/stell0/windmill-gate/internal/storage"
	"github.com/stell0/windmill-gate/internal/tui"
	defaultpolicy "github.com/stell0/windmill-gate/policy"
)

var version = "dev"

func main() {
	if filepath.Base(os.Args[0]) == "gate-sh" {
		os.Exit(runShell(os.Args[1:], os.Stdout, os.Stderr))
	}
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return runServer(args, true, stdin, stdout, stderr)
	}
	switch args[0] {
	case "daemon":
		return runServer(args[1:], false, stdin, stdout, stderr)
	case "exec":
		return runExec(args[1:], stdout, stderr)
	case "history":
		return runHistory(args[1:], stdout, stderr)
	case "forward":
		return runForward(args[1:], stdout, stderr)
	case "host":
		return runHost(args[1:], stdout, stderr)
	case "ssh-server":
		return runSSHServer(args[1:], stdin, stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "policy-review":
		return runPolicyReview(args[1:], stdout, stderr)
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
	var socketPath, sshSocketPath, databasePath, policyPath, bastion, sancho, selector, sessionSelector, agentID, operator, hostsPath string
	var outputLimit int64
	var targetSSHPort int
	var sshArgs repeatedFlag
	flags.StringVar(&socketPath, "socket", config.SocketPath(), "Unix socket path")
	flags.StringVar(&sshSocketPath, "ssh-socket", remoteSocketPath(config.SocketPath()), "trusted SSH bridge socket path")
	flags.StringVar(&databasePath, "database", config.DatabasePath(), "SQLite database path")
	flags.StringVar(&policyPath, "policy", config.PolicyPath(), "policy YAML path")
	flags.StringVar(&bastion, "bastion", os.Getenv("GATE_BASTION"), "Bastion SSH host")
	flags.StringVar(&sancho, "sancho", envOr("GATE_SANCHO", "sancho"), "Sancho executable on Bastion")
	flags.StringVar(&selector, "target", "", "target display name or displayed number")
	flags.StringVar(&sessionSelector, "session", "", "private Windmill session ID (operator only)")
	flags.StringVar(&agentID, "agent", config.AgentIdentity(), "initial attached agent identity")
	flags.StringVar(&operator, "operator", envOr("GATE_OPERATOR", "operator"), "operator audit identity")
	flags.StringVar(&hostsPath, "hosts-file", envOr("GATE_HOSTS_FILE", "/etc/hosts"), "Gate-managed hosts file")
	flags.Int64Var(&outputLimit, "output-limit", gatecore.DefaultOutputLimit, "maximum output bytes per command")
	flags.IntVar(&targetSSHPort, "target-ssh-port", windmill.DefaultTargetSSHPort, "legacy Windmill target SSH port")
	flags.Var(&sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "gate: unexpected positional arguments")
		return 2
	}
	if selector != "" && sessionSelector != "" {
		fmt.Fprintln(stderr, "gate: --target and --session are mutually exclusive")
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
	implementation, err := windmill.New(windmill.Config{
		Bastion: bastion, Sancho: sancho, SSHArgs: sshArgs, TargetSSHPort: targetSSHPort,
	})
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
	var selected backend.Target
	if sessionSelector != "" {
		selected, err = chooseSession(available, sessionSelector)
	} else {
		selected, err = chooseTarget(available, selector, stdin, stdout)
	}
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
	if err := service.EnableForwarding(ctx, hostsPath); err != nil {
		fmt.Fprintf(stderr, "gate: enable forwarding: %v\n", err)
		return 1
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
	sshListener, err := agent.ListenUnix(sshSocketPath)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	defer sshListener.Close()
	serverErr := make(chan error, 2)
	go func() {
		serverErr <- (&agent.Server{Service: service, Transport: "unix"}).Serve(ctx, listener)
	}()
	go func() {
		serverErr <- (&agent.Server{Service: service, Transport: "ssh", TrustHelloFingerprint: true}).Serve(ctx, sshListener)
	}()
	fmt.Fprintf(stdout, "Gate target %s (%s) selected\n", public.ID, public.DisplayName)
	fmt.Fprintf(stdout, "Agent %s attached; listening on %s\n", agentID, socketPath)
	fmt.Fprintf(stdout, "Restricted SSH bridge socket: %s\n", sshSocketPath)

	if withUI {
		app := tui.App{Service: service, Backend: implementation, Operator: operator, Input: stdin, Output: stdout}
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
	for _, activeTarget := range service.Targets.List() {
		if err := service.DetachTarget(shutdownCtx, activeTarget.ID); err != nil {
			fmt.Fprintf(stderr, "gate: detach target: %v\n", err)
			return 1
		}
	}
	return 0
}

func runSSHServer(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate ssh-server", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var socketPath, clientsPath string
	flags.StringVar(&socketPath, "socket", remoteSocketPath(config.SocketPath()), "trusted SSH bridge socket")
	flags.StringVar(&clientsPath, "clients", config.SSHClientsPath(), "SSH fingerprint mapping YAML")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	encoder := protocol.NewEncoder(stdout)
	if original := os.Getenv("SSH_ORIGINAL_COMMAND"); original != "" {
		err := errors.New("Gate SSH key is restricted to the protocol bridge; remote commands are not accepted")
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return 1
	}
	fingerprint := os.Getenv("GATE_SSH_KEY_FINGERPRINT")
	if fingerprint == "" {
		err := errors.New("GATE_SSH_KEY_FINGERPRINT is required in the forced command")
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return 1
	}
	clients, err := remote.LoadClients(clientsPath)
	if err != nil {
		_ = encoder.Encode(protocol.Response{Type: "error", Error: err.Error()})
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bridge := remote.Bridge{Dial: agent.UnixDialer(socketPath), Clients: clients, Fingerprint: fingerprint}
	if err := bridge.Run(ctx, stdin, stdout); err != nil {
		fmt.Fprintf(stderr, "gate ssh-server: %v\n", err)
		return 1
	}
	return 0
}

func runExec(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate exec", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var socketPath, agentID, sshHost string
	var sshArgs repeatedFlag
	flags.StringVar(&socketPath, "socket", config.SocketPath(), "Unix socket path")
	flags.StringVar(&agentID, "agent", config.AgentIdentity(), "agent identity")
	flags.StringVar(&sshHost, "ssh", "", "restricted remote Gate SSH host")
	flags.Var(&sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: gate exec [options] -- 'exact command'")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialer := agent.UnixDialer(socketPath)
	if sshHost != "" {
		dialer = agent.SSHDialer(sshHost, sshArgs, stderr)
	}
	client := agent.Client{Dial: dialer, AgentID: agentID, Stdout: stdout, Stderr: stderr}
	exitCode, err := client.Exec(ctx, flags.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	return exitCode
}

func runShell(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("gate-sh", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var command, socketPath, agentID, sshHost string
	var sshArgs repeatedFlag
	flags.StringVar(&command, "c", "", "execute one non-interactive command")
	flags.StringVar(&socketPath, "socket", config.SocketPath(), "Gate Unix socket")
	flags.StringVar(&agentID, "agent", config.AgentIdentity(), "agent identity")
	flags.StringVar(&sshHost, "ssh", "", "restricted remote Gate SSH host")
	flags.Var(&sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if command == "" || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "usage: gate-sh [-socket path] [-agent identity] [-ssh host] -c command")
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	dialer := agent.UnixDialer(socketPath)
	if sshHost != "" {
		dialer = agent.SSHDialer(sshHost, sshArgs, stderr)
	}
	exitCode, err := (agent.Client{
		Dial: dialer, AgentID: agentID, Stdout: stdout, Stderr: stderr,
	}).Exec(ctx, command)
	if err != nil {
		fmt.Fprintf(stderr, "gate-sh: %v\n", err)
		return 1
	}
	return exitCode
}

type connectionOptions struct {
	socketPath string
	agentID    string
	sshHost    string
	sshArgs    repeatedFlag
}

func (o *connectionOptions) bind(flags *flag.FlagSet) {
	flags.StringVar(&o.socketPath, "socket", config.SocketPath(), "Unix socket path")
	flags.StringVar(&o.agentID, "agent", config.AgentIdentity(), "agent identity")
	flags.StringVar(&o.sshHost, "ssh", "", "restricted remote Gate SSH host")
	flags.Var(&o.sshArgs, "ssh-arg", "additional SSH argument (repeatable)")
}

func (o connectionOptions) client(stderr io.Writer) agent.Client {
	dialer := agent.UnixDialer(o.socketPath)
	if o.sshHost != "" {
		dialer = agent.SSHDialer(o.sshHost, o.sshArgs, stderr)
	}
	return agent.Client{Dial: dialer, AgentID: o.agentID, Stderr: stderr}
}

func runForward(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gate forward add|list|remove")
		return 2
	}
	flags := flag.NewFlagSet("gate forward "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var connection connectionOptions
	connection.bind(flags)
	var remotePort int
	if args[0] == "add" {
		flags.IntVar(&remotePort, "remote-port", 0, "selected target loopback port")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return 2
	}
	client := connection.client(stderr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	var request protocol.Request
	switch args[0] {
	case "add":
		if flags.NArg() != 0 || remotePort < 1 || remotePort > 65535 {
			fmt.Fprintln(stderr, "usage: gate forward add --remote-port PORT")
			return 2
		}
		request = protocol.Request{Type: "forward_add", RemotePort: uint16(remotePort)}
	case "list":
		if flags.NArg() != 0 {
			return 2
		}
		request = protocol.Request{Type: "forward_list"}
	case "remove":
		if flags.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: gate forward remove FORWARD_ID")
			return 2
		}
		request = protocol.Request{Type: "forward_remove", CommandID: flags.Arg(0)}
	default:
		fmt.Fprintf(stderr, "gate: unknown forward command %q\n", args[0])
		return 2
	}
	response, err := client.Control(ctx, request)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	switch response.Type {
	case "forward":
		fmt.Fprintf(stdout, "forward: %s\ntarget: %s\nremote endpoint: 127.0.0.1:%d\nlocal endpoint: %s\n",
			response.ResourceID, response.TargetID, response.RemotePort, net.JoinHostPort(response.LocalHost, strconv.Itoa(int(response.LocalPort))))
	case "forward_list":
		var items []forward.Info
		if err := json.Unmarshal(response.Items, &items); err != nil {
			fmt.Fprintf(stderr, "gate: decode forward list: %v\n", err)
			return 1
		}
		for _, item := range items {
			fmt.Fprintf(stdout, "%s target=%s remote=127.0.0.1:%d local=%s\n", item.ID, item.TargetID, item.RemotePort, item.Endpoint())
		}
	case "forward_removed":
		fmt.Fprintf(stdout, "removed forward %s\n", response.ResourceID)
	}
	return 0
}

func runHost(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: gate host add|list|remove")
		return 2
	}
	flags := flag.NewFlagSet("gate host "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	var connection connectionOptions
	connection.bind(flags)
	var remotePort int
	if args[0] == "add" {
		flags.IntVar(&remotePort, "remote-port", 0, "selected target loopback port")
	}
	parseArgs := args[1:]
	leadingHostname := ""
	if args[0] == "add" && len(parseArgs) > 0 && !strings.HasPrefix(parseArgs[0], "-") {
		leadingHostname, parseArgs = parseArgs[0], parseArgs[1:]
	}
	if err := flags.Parse(parseArgs); err != nil {
		return 2
	}
	var request protocol.Request
	switch args[0] {
	case "add":
		hostname := leadingHostname
		if hostname == "" && flags.NArg() == 1 {
			hostname = flags.Arg(0)
		}
		if hostname == "" || (leadingHostname != "" && flags.NArg() != 0) || remotePort < 1 || remotePort > 65535 {
			fmt.Fprintln(stderr, "usage: gate host add HOSTNAME --remote-port PORT")
			return 2
		}
		request = protocol.Request{Type: "host_add", Hostname: hostname, RemotePort: uint16(remotePort)}
	case "list":
		if flags.NArg() != 0 {
			return 2
		}
		request = protocol.Request{Type: "host_list"}
	case "remove":
		if flags.NArg() != 1 {
			fmt.Fprintln(stderr, "usage: gate host remove HOSTNAME")
			return 2
		}
		request = protocol.Request{Type: "host_remove", Hostname: flags.Arg(0)}
	default:
		fmt.Fprintf(stderr, "gate: unknown host command %q\n", args[0])
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	response, err := connection.client(stderr).Control(ctx, request)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	switch response.Type {
	case "host":
		fmt.Fprintf(stdout, "host alias: %s -> %s\nforward: %s\nURL: %s\n", response.Hostname, response.Address, response.ResourceID, response.URL)
	case "host_list":
		var items []forward.AliasInfo
		if err := json.Unmarshal(response.Items, &items); err != nil {
			fmt.Fprintf(stderr, "gate: decode host list: %v\n", err)
			return 1
		}
		for _, item := range items {
			fmt.Fprintf(stdout, "%s target=%s forward=%s URL=%s\n", item.Hostname, item.TargetID, item.ForwardID, item.URL)
		}
	case "host_removed":
		fmt.Fprintf(stdout, "removed host alias %s\n", response.Hostname)
	}
	return 0
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
		fmt.Fprintf(stdout, "%s %-10s target=%s agent=%s exit=%s command=%s\n",
			entry.CreatedAt.Format(time.RFC3339), entry.State, strconv.QuoteToGraphic(entry.TargetName),
			strconv.QuoteToGraphic(entry.AgentIdentity), exitCode, strconv.QuoteToGraphic(entry.Command))
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

func runPolicyReview(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "analyze" && args[0] != "propose") {
		fmt.Fprintln(stderr, "usage: gate policy-review analyze|propose [options]")
		return 2
	}
	mode := args[0]
	flags := flag.NewFlagSet("gate policy-review "+mode, flag.ContinueOnError)
	flags.SetOutput(stderr)
	var databasePath, policyPath, reviewConfigPath, label string
	var minimum int
	var asJSON bool
	flags.StringVar(&databasePath, "database", config.DatabasePath(), "Gate audit database")
	flags.StringVar(&policyPath, "policy", config.PolicyPath(), "currently active Gate policy")
	flags.StringVar(&reviewConfigPath, "config", config.PolicyReviewPath(), "policy-review repository config")
	flags.StringVar(&label, "label", "history", "non-sensitive branch label")
	flags.IntVar(&minimum, "minimum-approvals", 0, "override evidence threshold (minimum 2)")
	flags.BoolVar(&asJSON, "json", false, "emit candidates as JSON")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 {
		return 2
	}
	var reviewConfig review.Config
	var err error
	if mode == "propose" {
		reviewConfig, err = review.LoadConfig(reviewConfigPath)
		if err != nil {
			fmt.Fprintf(stderr, "gate: %v\n", err)
			return 1
		}
		if minimum == 0 {
			minimum = reviewConfig.MinimumApprovals
		}
	}
	if minimum == 0 {
		minimum = 3
	}
	if minimum < 2 {
		fmt.Fprintln(stderr, "gate: minimum approvals must be at least 2")
		return 2
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
	history, err := store.History(context.Background(), "", 10000)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 1
	}
	candidates := review.Analyze(history, engine, minimum)
	if mode == "analyze" {
		if asJSON {
			encoder := json.NewEncoder(stdout)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(candidates); err != nil {
				fmt.Fprintf(stderr, "gate: encode candidates: %v\n", err)
				return 1
			}
			return 0
		}
		if len(candidates) == 0 {
			fmt.Fprintln(stdout, "No policy candidates met the safety and evidence thresholds.")
			return 0
		}
		for _, candidate := range candidates {
			fmt.Fprintf(stdout, "%s\n  approvals=%d sessions=%d targets=%d\n  allows: %s\n",
				candidate.Pattern, candidate.Approvals, candidate.Sessions, candidate.Targets, candidate.AllowedSpace)
			for _, excluded := range candidate.Excluded {
				fmt.Fprintf(stdout, "  excludes: %s\n", excluded)
			}
		}
		return 0
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	proposal, err := (review.Workflow{}).Propose(ctx, reviewConfig, candidates, label)
	if err != nil {
		fmt.Fprintf(stderr, "gate: policy proposal: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "Created branch: %s\nPull request: %s\nNo policy was merged or deployed; human review is required.\n", proposal.Branch, proposal.PullURL)
	return 0
}

func chooseSession(targets []backend.Target, sessionID string) (backend.Target, error) {
	if len(targets) == 0 {
		return backend.Target{}, errors.New("Sancho reported no available sessions")
	}
	for _, candidate := range targets {
		if candidate.ID == sessionID {
			return candidate, nil
		}
	}
	return backend.Target{}, errors.New("Windmill session not found")
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
		fmt.Fprintf(output, "  [%d] %s\n", index+1, strconv.QuoteToGraphic(candidate.DisplayName))
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

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func remoteSocketPath(local string) string {
	if strings.HasSuffix(local, ".sock") {
		return strings.TrimSuffix(local, ".sock") + "-ssh.sock"
	}
	return local + "-ssh"
}

func usage(output io.Writer) {
	fmt.Fprintln(output, "usage: gate [daemon|exec|forward|host|history|policy test|policy-review|ssh-server|version]")
}
