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
	"unicode"

	"github.com/stell0/windmill-gate/internal/approval"
	"github.com/stell0/windmill-gate/internal/backend"
	gatecore "github.com/stell0/windmill-gate/internal/gate"
	"github.com/stell0/windmill-gate/internal/storage"
)

type App struct {
	Service  *gatecore.Service
	Backend  backend.Backend
	Operator string
	Input    io.Reader
	Output   io.Writer

	discovered      []backend.Target
	singleKeyInput  bool
	terminalOutput  bool
	bellOutput      bool
	audioBell       func()
	ledger          []storage.AuthorizationEntry
	ledgerSeen      map[string]bool
	notifiedPending map[string]bool
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
	a.bellOutput = writerSupportsBell(a.Output)
	if a.bellOutput {
		bellCtx, cancelBell := context.WithCancel(ctx)
		defer cancelBell()
		a.audioBell = startAudioBell(bellCtx, playSystemBell)
	}
	if a.terminalOutput {
		defer a.setTerminalTitle(false)
	}

	lines := make(chan operatorInput)
	scanErrors := make(chan error, 1)
	var pendingCount atomic.Int64
	go readOperatorLines(ctx, a.Input, a.singleKeyInput, &pendingCount, lines, scanErrors)

	if _, err := a.refreshAuthorizations(ctx); err != nil {
		return err
	}
	a.printBanner()
	a.renderTargets()
	a.renderAuthorizationLedger()
	pending := a.Service.Approvals.List()
	pendingCount.Store(int64(len(pending)))
	a.notifyPending(pending)
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
			a.notifyPending(pending)
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
		case <-a.Service.AuthorizationChanged():
			added, err := a.refreshAuthorizations(ctx)
			if err != nil {
				fmt.Fprintf(a.Output, "error: %s\n", operatorText(err.Error()))
				promptVisible = false
				continue
			}
			if len(added) == 0 {
				continue
			}
			pending := a.Service.Approvals.List()
			pendingCount.Store(int64(len(pending)))
			a.notifyPending(pending)
			a.setTerminalTitle(len(pending) > 0)
			if a.terminalOutput {
				a.redraw(pending)
				displayedPending = pendingSignature(pending)
			} else {
				fmt.Fprintln(a.Output)
				a.renderAuthorizationItems(added)
			}
			promptVisible = false
		case input := <-lines:
			// Echo in this loop so keyboard editing and asynchronous approval
			// messages never write to the terminal from different goroutines.
			fmt.Fprint(a.Output, input.echo)
			if !input.submitted {
				continue
			}
			promptVisible = false
			line := strings.TrimSpace(input.line)
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
			a.notifyPending(pending)
			a.setTerminalTitle(len(pending) > 0)
			signature := pendingSignature(pending)
			if err == nil && decisionInput {
				if a.terminalOutput {
					a.redraw(pending)
					displayedPending = signature
				}
				// The service records the decision immediately after the broker
				// wakes, then emits AuthorizationChanged. Wait for that audited
				// event before printing the next prompt.
				promptVisible = true
				continue
			}
			if signature != displayedPending {
				displayedPending = signature
				a.renderPendingItems(pending)
			}
		}
	}
}

type operatorInput struct {
	line      string
	echo      string
	submitted bool
}

func readOperatorLines(ctx context.Context, input io.Reader, singleKey bool, pendingCount *atomic.Int64, lines chan<- operatorInput, readErrors chan<- error) {
	reader := bufio.NewReader(input)
	var current []rune
	var escape rune
	swallowLineEnd := false
	send := func(update operatorInput) bool {
		select {
		case lines <- update:
			return true
		case <-ctx.Done():
			return false
		}
	}
	for {
		value, _, err := reader.ReadRune()
		if err != nil {
			if errors.Is(err, io.EOF) && len(current) > 0 && !send(operatorInput{line: string(current), submitted: true}) {
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

		if value == '\x1b' {
			escape = value
			continue
		}
		// Consume complete CSI/SS3 key sequences, including modifiers. Their
		// final bytes must never become command text or single-key decisions.
		if escape != 0 {
			switch escape {
			case '\x1b':
				if value == '[' || value == 'O' {
					escape = value
				} else {
					escape = 0 // ignore Alt-key combinations too
				}
			default:
				if escape == '[' && value == '[' {
					escape = 'O' // Linux console F1-F5: ESC [ [ A-E
				} else if value >= 0x40 && value <= 0x7e {
					escape = 0
				}
			}
			continue
		}
		if value == '\t' {
			value = ' '
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
		if singleKey && pendingCount.Load() == 1 && len(current) == 0 && (value == 'y' || value == 's' || value == 'n') {
			if !send(operatorInput{line: string(value), echo: string(value) + "\n", submitted: true}) {
				return
			}
			swallowLineEnd = true
			continue
		}
		switch value {
		case '\r', '\n':
			echo := ""
			if singleKey {
				echo = "\n"
			}
			if !send(operatorInput{line: string(current), echo: echo, submitted: true}) {
				return
			}
			current = current[:0]
			if value == '\r' {
				swallowLineEnd = true
			}
		case '\b', 0x7f:
			if len(current) > 0 {
				current = current[:len(current)-1]
				if singleKey && !send(operatorInput{echo: "\b \b"}) {
					return
				}
			}
		default:
			if !unicode.IsPrint(value) {
				continue
			}
			current = append(current, value)
			if singleKey && !send(operatorInput{echo: string(value)}) {
				return
			}
		}
	}
}

func (a *App) printBanner() {
	fmt.Fprintln(a.Output, "Gate operator console")
	fmt.Fprintln(a.Output, "Commands: targets, discover, target-add NUMBER, attach AGENT TARGET, agents, approvals, rules, forwards, hosts, y|s|n [COMMAND], history, cancel COMMAND, detach TARGET, bell, quit")
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
		fmt.Fprintf(a.Output, "  Approve? [y] once  [s] similar for target until detach  [n] deny  (%s)\n", guidance)
	}
}

func (a *App) redraw(pending []approval.Pending) {
	fmt.Fprint(a.Output, "\x1b[2J\x1b[H")
	a.printBanner()
	a.renderTargets()
	a.renderAuthorizationLedger()
	a.renderPendingItems(pending)
}

// notifyPending rings once for each newly waiting request, including requests
// already pending at startup. Rendering or removing requests never rings.
func (a *App) notifyPending(pending []approval.Pending) {
	next := make(map[string]bool, len(pending))
	for _, item := range pending {
		next[item.Command.ID] = true
		if !a.notifiedPending[item.Command.ID] {
			a.ringBell()
		}
	}
	a.notifiedPending = next
}

func (a *App) ringBell() {
	if !a.bellOutput {
		return
	}
	// Keep BEL for terminals reached over SSH and as a fallback when local
	// audio is unavailable. System audio also works when terminal bells are muted.
	fmt.Fprint(a.Output, "\a")
	if a.audioBell != nil {
		a.audioBell()
	}
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
	return fields[0] == "y" || fields[0] == "s" || fields[0] == "n"
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
	case "bell":
		a.ringBell()
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
	case "y", "s", "n":
		if len(fields) > 2 {
			return false, errors.New("usage: y|s|n [COMMAND]")
		}
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

func ledgerText(value string) string {
	quoted := strconv.QuoteToGraphic(value)
	if len(quoted) >= 2 {
		return quoted[1 : len(quoted)-1]
	}
	return quoted
}

func (a *App) refreshAuthorizations(ctx context.Context) ([]storage.AuthorizationEntry, error) {
	entries, err := a.Service.Store.AuthorizationsSince(ctx, a.Service.StartedAt())
	if err != nil {
		return nil, err
	}
	if a.ledgerSeen == nil {
		a.ledgerSeen = make(map[string]bool)
	}
	var added []storage.AuthorizationEntry
	for _, entry := range entries {
		if a.ledgerSeen[entry.CommandID] {
			continue
		}
		a.ledgerSeen[entry.CommandID] = true
		a.ledger = append(a.ledger, entry)
		added = append(added, entry)
	}
	return added, nil
}

func (a *App) renderAuthorizationLedger() {
	fmt.Fprintln(a.Output, "\nAUTHORIZATIONS (CURRENT RUN)")
	if len(a.ledger) == 0 {
		fmt.Fprintln(a.Output, "  (none)")
		return
	}
	a.renderAuthorizationItems(a.ledger)
}

func (a *App) renderAuthorizationItems(entries []storage.AuthorizationEntry) {
	for _, entry := range entries {
		fmt.Fprintf(a.Output, "  [%s] %s> %s\n", entry.Label, ledgerText(entry.AgentIdentity), ledgerText(entry.Command))
	}
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
	case "y":
		decision.Action = approval.ApproveOnce
	case "s":
		decision.Action = approval.AllowTarget
	case "n":
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
