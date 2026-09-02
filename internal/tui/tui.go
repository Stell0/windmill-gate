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

	"github.com/nethserver/gate/internal/approval"
	gatecore "github.com/nethserver/gate/internal/gate"
)

type App struct {
	Service  *gatecore.Service
	Operator string
	Input    io.Reader
	Output   io.Writer
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
	lines := make(chan string)
	scanErrors := make(chan error, 1)
	go func() {
		scanner := bufio.NewScanner(a.Input)
		for scanner.Scan() {
			select {
			case lines <- scanner.Text():
			case <-ctx.Done():
				return
			}
		}
		scanErrors <- scanner.Err()
	}()

	a.printBanner()
	a.renderTargets()
	a.renderPending()
	for {
		fmt.Fprint(a.Output, "gate> ")
		select {
		case <-ctx.Done():
			return nil
		case err := <-scanErrors:
			return err
		case <-a.Service.Approvals.Changed():
			a.renderPending()
		case line := <-lines:
			quit, err := a.handle(ctx, strings.TrimSpace(line))
			if err != nil {
				fmt.Fprintf(a.Output, "error: %v\n", err)
			}
			if quit {
				return nil
			}
		}
	}
}

func (a *App) printBanner() {
	fmt.Fprintln(a.Output, "Gate operator console")
	fmt.Fprintln(a.Output, "Commands: targets, attach AGENT TARGET, approvals, rules, a|s|d [COMMAND], history, cancel COMMAND, detach TARGET, quit")
}

func (a *App) renderTargets() {
	fmt.Fprintln(a.Output, "\nTARGETS")
	targets := a.Service.Targets.List()
	if len(targets) == 0 {
		fmt.Fprintln(a.Output, "  (none)")
		return
	}
	for _, target := range targets {
		fmt.Fprintf(a.Output, "  %s  %s  backend=%s\n", target.ID, target.DisplayName, target.Backend)
		for identity, attached := range a.Service.Attachments() {
			if attached == target.ID {
				fmt.Fprintf(a.Output, "    agent: %s (future sessions)\n", identity)
			}
		}
	}
}

func (a *App) renderPending() {
	pending := a.Service.Approvals.List()
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
		fmt.Fprintf(a.Output, "  target:  %s\n", targetName)
		fmt.Fprintf(a.Output, "  agent:   %s\n", a.Service.SessionIdentity(item.Command.AgentSessionID))
		fmt.Fprintf(a.Output, "  command: %s\n", item.Command.Payload)
		fmt.Fprintf(a.Output, "  id:      %s\n", item.Command.ID)
		fmt.Fprintf(a.Output, "  hash:    %s\n", item.Command.Hash)
		fmt.Fprintf(a.Output, "  policy:  %s (%s)\n", item.Policy.Decision, item.Policy.Source)
		fmt.Fprintln(a.Output, "  [a] approve once  [s] allow similar for target until detach  [d] deny")
	}
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
	case "approvals":
		a.renderPending()
	case "rules":
		a.renderTemporaryRules()
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
			fmt.Fprintf(a.Output, "  %-10s target=%s agent=%s exit=%s  %s\n", entry.State, entry.TargetName, entry.AgentIdentity, exit, entry.Command)
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

func (a *App) renderTemporaryRules() {
	fmt.Fprintln(a.Output, "\nTARGET-SCOPED TEMPORARY ALLOWS")
	count := 0
	for _, target := range a.Service.Targets.List() {
		for _, rule := range a.Service.Policy.TemporaryRules(target.ID) {
			fmt.Fprintf(a.Output, "  target=%s (%s)  %s\n", target.DisplayName, target.ID, rule)
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
	item := pending[0]
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
	} else if len(pending) > 1 {
		return errors.New("multiple commands are waiting; specify a command ID")
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
