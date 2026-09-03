// Package tui provides Gate's small, accessible operator control surface.
package tui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/nethserver/gate/internal/approval"
	"github.com/nethserver/gate/internal/backend"
	gatecore "github.com/nethserver/gate/internal/gate"
)

type App struct {
	Service  *gatecore.Service
	Backend  backend.Backend
	Operator string
	Input    io.Reader
	Output   io.Writer

	discovered     []backend.Target
	singleKeyInput bool
	terminalOutput bool
}

func (a *App) Run(ctx context.Context) error {
	if a.Service == nil {
		return errors.New("Gate service is required")
	}
	if a.Operator == "" {
		a.Operator = "operator"
	}
	if a.Input == nil {
		a.Input = strings.NewReader("")
	}
	if a.Output == nil {
		a.Output = io.Discard
	}
	restoreInput, singleKeyInput, err := configureCharacterInput(a.Input)
	if err != nil {
		return fmt.Errorf("configure operator terminal: %w", err)
	}
	if restoreInput != nil {
		defer restoreInput()
	}
	a.singleKeyInput = singleKeyInput
	a.terminalOutput = writerIsTerminal(a.Output)
	if a.terminalOutput {
		defer a.setTerminalTitle(false)
	}

	lines := make(chan string)
	scanErrors := make(chan error, 1)
	var pendingCount atomic.Int64
	go readOperatorLines(ctx, a.Input, a.singleKeyInput, &pendingCount, lines, scanErrors)

	a.printBanner()
	a.renderTargets()
	pending := a.Service.Approvals.List()
	pendingCount.Store(int64(len(pending)))
	a.setTerminalTitle(len(pending) > 0)
	a.renderPendingItems(pending)
	displayedPending := pendingSignature(pending)
	promptVisible := false
	for {
		if !promptVisible {
			fmt.Fprint(a.Output, "gate> ")
			promptVisible = true
		}
		select {
		case <-ctx.Done():
			return nil
		case err := <-scanErrors:
			return err
		case <-a.Service.Approvals.Changed():
			pending := a.Service.Approvals.List()
			pendingCount.Store(int64(len(pending)))
			a.setTerminalTitle(len(pending) > 0)
			signature := pendingSignature(pending)
			if signature == displayedPending {
				continue
			}
			displayedPending = signature
			if len(pending) == 0 {
				continue
			}
			a.renderPendingItems(pending)
			promptVisible = false
		case line := <-lines:
			promptVisible = false
			line = strings.TrimSpace(line)
			decisionInput := isDecisionInput(line)
			quit, err := a.handle(ctx, line)
			if err != nil {
				fmt.Fprintf(a.Output, "error: %s\n", operatorText(err.Error()))
			}
			if quit {
				return nil
			}
			pending := a.Service.Approvals.List()
			pendingCount.Store(int64(len(pending)))
			a.setTerminalTitle(len(pending) > 0)
			signature := pendingSignature(pending)
			if err == nil && decisionInput && a.terminalOutput {
				a.redraw(pending)
				displayedPending = signature
				continue
			}
			if signature != displayedPending {
				displayedPending = signature
				a.renderPendingItems(pending)
			}
		}
	}
}

func readOperatorLines(ctx context.Context, input io.Reader, singleKey bool, pendingCount *atomic.Int64, lines chan<- string, readErrors chan<- error) {
	reader := bufio.NewReader(input)
	var current []byte
	swallowLineEnd := false
	send := func(line string) bool {
		select {
		case lines <- line:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for {
		value, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && len(current) > 0 && !send(string(current)) {
				return
			}
			select {
			case readErrors <- func() error {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}():
			case <-ctx.Done():
			}
			return
		}

		if swallowLineEnd {
			if value == '\n' {
				swallowLineEnd = false
				continue
			}
			if value == '\r' {
				continue
			}
			swallowLineEnd = false
		}
		if singleKey && pendingCount.Load() == 1 && len(current) == 0 && (value == 'a' || value == 's' || value == 'd') {
			if !send(string(value)) {
				return
			}
			swallowLineEnd = true
			continue
		}
		switch value {
		case '\r', '\n':
			if !send(string(current)) {
				return
			}
			current = current[:0]
		case '\b', 0x7f:
			if len(current) > 0 {
				current = current[:len(current)-1]
			}
		default:
			current = append(current, value)
		}
	}
}

func (a *App) printBanner() {
	fmt.Fprintln(a.Output, "Gate operator console")
	fmt.Fprintln(a.Output, "Commands: targets, discover, target-add NUMBER, attach AGENT TARGET, agents, approvals, rules, forwards, hosts, a|s|d [COMMAND], history, cancel COMMAND, detach TARGET, quit")
}

func (a *App) renderTargets() {
	fmt.Fprintln(a.Output, "\nTARGETS")
	targets := a.Service.Targets.List()
	if len(targets) == 0 {
		fmt.Fprintln(a.Output, "  (none)")
		return
	}
	for _, target := range targets {
		fmt.Fprintf(a.Output, "  %s  %s  backend=%s\n", target.ID, operatorText(target.DisplayName), operatorText(target.Backend))
		for identity, attached := range a.Service.Attachments() {
			if attached == target.ID {
				fmt.Fprintf(a.Output, "    agent: %s (future sessions)\n", operatorText(identity))
			}
		}
	}
}

func (a *App) renderPending() {
	a.renderPendingItems(a.Service.Approvals.List())
}

func (a *App) renderPendingItems(pending []approval.Pending) {
	if len(pending) == 0 {
		return
	}
	for _, item := range pending {
		targetName := item.Command.TargetID
		for _, candidate := range a.Service.Targets.List() {
			if candidate.ID == item.Command.TargetID {
				targetName = candidate.DisplayName + " (" + candidate.ID + ")"
				break
			}
		}
		fmt.Fprintln(a.Output, "\nWAITING APPROVAL")
		fmt.Fprintf(a.Output, "  target:  %s\n", operatorText(targetName))
		fmt.Fprintf(a.Output, "  agent:   %s\n", operatorText(a.Service.SessionIdentity(item.Command.AgentSessionID)))
		fmt.Fprintf(a.Output, "  command: %s\n", operatorText(item.Command.Payload))
		fmt.Fprintf(a.Output, "  id:      %s\n", item.Command.ID)
		fmt.Fprintf(a.Output, "  hash:    %s\n", item.Command.Hash)
		fmt.Fprintf(a.Output, "  policy:  %s (%s)\n", item.Policy.Decision, item.Policy.Source)
		guidance := "press Enter; without an ID the newest command is selected"
		if len(pending) == 1 && a.singleKeyInput {
			guidance = "single key; no Enter required"
		}
		fmt.Fprintf(a.Output, "  [a] approve once  [s] allow similar for target until detach  [d] deny  (%s)\n", guidance)
	}
}

func (a *App) redraw(pending []approval.Pending) {
	fmt.Fprint(a.Output, "\x1b[2J\x1b[H")
	a.printBanner()
	a.renderTargets()
	a.renderPendingItems(pending)
}

func (a *App) setTerminalTitle(waiting bool) {
	if !a.terminalOutput {
		return
	}
	title := "Gate"
	if waiting {
		title = "[!] Gate"
	}
	fmt.Fprintf(a.Output, "\x1b]0;%s\x07", title)
}

func isDecisionInput(line string) bool {
	fields := strings.Fields(line)
	if len(fields) < 1 || len(fields) > 2 {
		return false
	}
	return fields[0] == "a" || fields[0] == "s" || fields[0] == "d"
}

func pendingSignature(pending []approval.Pending) string {
	ids := make([]string, len(pending))
	for index, item := range pending {
		ids[index] = item.Command.ID
	}
	return strings.Join(ids, "\x00")
}

func (a *App) handle(ctx context.Context, line string) (bool, error) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false, nil
	}
	switch fields[0] {
	case "quit", "q":
		return true, nil
	case "targets":
		a.renderTargets()
	case "discover":
		if a.Backend == nil {
			return false, errors.New("target discovery backend is unavailable")
		}
		available, err := a.Backend.ListTargets(ctx)
		if err != nil {
			return false, err
		}
		a.discovered = available
		fmt.Fprintln(a.Output, "\nAVAILABLE BACKEND TARGETS")
		for index, candidate := range available {
			// Backend IDs deliberately remain private.
			fmt.Fprintf(a.Output, "  [%d] %s\n", index+1, operatorText(candidate.DisplayName))
		}
	case "target-add":
		if a.Backend == nil || len(fields) != 2 {
			return false, errors.New("usage: discover, then target-add NUMBER")
		}
		number, err := strconv.Atoi(fields[1])
		if err != nil || number < 1 || number > len(a.discovered) {
			return false, errors.New("invalid discovered target number")
		}
		public, err := a.Service.AddTarget(ctx, a.Backend.Name(), a.discovered[number-1])
		if err != nil {
			return false, err
		}
		fmt.Fprintf(a.Output, "added Gate target %s (%s)\n", public.ID, operatorText(public.DisplayName))
	case "approvals":
		a.renderPending()
	case "agents":
		sessions, err := a.Service.Store.AgentSessions(ctx, true)
		if err != nil {
			return false, err
		}
		fmt.Fprintln(a.Output, "\nACTIVE AGENTS")
		for _, session := range sessions {
			fmt.Fprintf(a.Output, "  %s  identity=%s target=%s transport=%s", session.ID, operatorText(session.Identity), session.TargetID, operatorText(session.Transport))
			if session.Fingerprint != "" {
				fmt.Fprintf(a.Output, " fingerprint=%s", operatorText(session.Fingerprint))
			}
			fmt.Fprintln(a.Output)
		}
	case "rules":
		a.renderTemporaryRules()
	case "forwards":
		fmt.Fprintln(a.Output, "\nACTIVE FORWARDS")
		if a.Service.Forwards == nil {
			fmt.Fprintln(a.Output, "  (forwarding disabled)")
			break
		}
		for _, item := range a.Service.Forwards.List("") {
			fmt.Fprintf(a.Output, "  %s target=%s remote=127.0.0.1:%d local=%s\n", item.ID, item.TargetID, item.RemotePort, item.Endpoint())
		}
	case "hosts":
		fmt.Fprintln(a.Output, "\nACTIVE HOST ALIASES")
		if a.Service.Aliases == nil {
			fmt.Fprintln(a.Output, "  (host aliases disabled)")
			break
		}
		for _, item := range a.Service.Aliases.List("") {
			fmt.Fprintf(a.Output, "  %s target=%s forward=%s URL=%s\n", item.Hostname, item.TargetID, item.ForwardID, item.URL)
		}
	case "attach":
		if len(fields) != 3 {
			return false, errors.New("usage: attach AGENT TARGET")
		}
		if err := a.Service.Attach(fields[1], fields[2]); err != nil {
			return false, err
		}
		fmt.Fprintf(a.Output, "attached %s to %s for new sessions\n", fields[1], fields[2])
	case "a", "s", "d":
		return false, a.decide(fields[0], optional(fields, 1))
	case "history":
		entries, err := a.Service.Store.History(ctx, "", 50)
		if err != nil {
			return false, err
		}
		fmt.Fprintln(a.Output, "\nHISTORY")
		for _, entry := range entries {
			exit := "-"
			if entry.ExitCode != nil {
				exit = strconv.Itoa(*entry.ExitCode)
			}
			fmt.Fprintf(a.Output, "  %-10s target=%s agent=%s exit=%s command=%s\n", entry.State, operatorText(entry.TargetName), operatorText(entry.AgentIdentity), exit, operatorText(entry.Command))
			stdout, stderr, err := a.Service.Store.OutputPreview(ctx, entry.ID, 1024)
			if err != nil {
				return false, err
			}
			if stdout != "" {
				fmt.Fprintf(a.Output, "    stdout: %s\n", indentPreview(stdout))
			}
			if stderr != "" {
				fmt.Fprintf(a.Output, "    stderr: %s\n", indentPreview(stderr))
			}
		}
	case "cancel":
		if len(fields) != 2 {
			return false, errors.New("usage: cancel COMMAND")
		}
		return false, a.Service.CancelCommand(fields[1])
	case "detach":
		if len(fields) != 2 {
			return false, errors.New("usage: detach TARGET")
		}
		if err := a.Service.DetachTarget(ctx, fields[1]); err != nil {
			return false, err
		}
		fmt.Fprintf(a.Output, "detached %s and cleared target-scoped approvals\n", fields[1])
	default:
		return false, fmt.Errorf("unknown operator command %q", fields[0])
	}
	return false, nil
}

func indentPreview(value string) string {
	return operatorText(value)
}

func operatorText(value string) string {
	return strconv.QuoteToGraphic(value)
}

func (a *App) renderTemporaryRules() {
	fmt.Fprintln(a.Output, "\nTARGET-SCOPED TEMPORARY ALLOWS")
	count := 0
	for _, target := range a.Service.Targets.List() {
		for _, rule := range a.Service.Policy.TemporaryRules(target.ID) {
			fmt.Fprintf(a.Output, "  target=%s (%s)  %s\n", operatorText(target.DisplayName), target.ID, operatorText(rule))
			count++
		}
	}
	if count == 0 {
		fmt.Fprintln(a.Output, "  (none)")
	}
}

func (a *App) decide(action, commandID string) error {
	pending := a.Service.Approvals.List()
	if len(pending) == 0 {
		return errors.New("no commands are waiting")
	}
	// Broker.List returns commands oldest first, so an omitted ID selects the
	// command the operator most recently saw arrive.
	item := pending[len(pending)-1]
	if commandID != "" {
		found := false
		for _, candidate := range pending {
			if candidate.Command.ID == commandID {
				item, found = candidate, true
				break
			}
		}
		if !found {
			return errors.New("waiting command not found")
		}
	}
	decision := approval.Decision{CommandID: item.Command.ID, Hash: item.Command.Hash, Actor: a.Operator}
	switch action {
	case "a":
		decision.Action = approval.ApproveOnce
	case "s":
		decision.Action = approval.AllowTarget
	case "d":
		decision.Action = approval.Deny
	}
	return a.Service.Approvals.Decide(decision)
}

func optional(values []string, index int) string {
	if index >= len(values) {
		return ""
	}
	return values[index]
}
