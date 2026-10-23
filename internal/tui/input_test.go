package tui

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func nextOperatorLine(t *testing.T, updates <-chan operatorInput) string {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		select {
		case update := <-updates:
			if update.submitted {
				return update.line
			}
		case <-deadline:
			t.Fatal("timed out reading operator command")
			return ""
		}
	}
}

func TestOperatorEditingAndNavigationKeys(t *testing.T) {
	for _, test := range []struct {
		name, input, line, echo string
	}{
		{"DEL backspace", "histx\x7fory\n", "history", "histx\b \bory\n"},
		{"BS backspace", "histx\bory\n", "history", "histx\b \bory\n"},
		{"backspace at prompt", "\x7f\btargets\n", "targets", "targets\n"},
		{"arrows", "\x1b[A\x1b[B\x1b[C\x1b[Dhistory\n", "history", "history\n"},
		{"application arrows", "\x1bOA\x1bOB\x1bOC\x1bODrules\n", "rules", "rules\n"},
		{"modified and function keys", "\x1b[1;5C\x1b[3~\x1bOP\x1b[24~hosts\n", "hosts", "hosts\n"},
		{"Linux console function keys", "\x1b[[A\x1b[[B\x1b[[Crules\n", "rules", "rules\n"},
		{"escape then arrow", "\x1b\x1b[Cagents\n", "agents", "agents\n"},
		{"tabs", "attach\tagent\ttarget\n", "attach agent target", "attach agent target\n"},
		{"UTF-8 backspace", "targeté\x7fs\n", "targets", "targeté\b \bs\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, raw := range []bool{true, false} {
				ctx, cancel := context.WithCancel(context.Background())
				updates := make(chan operatorInput)
				errors := make(chan error, 1)
				var pending atomic.Int64
				go readOperatorLines(ctx, strings.NewReader(test.input), raw, &pending, updates, errors)
				var line, echo string
				reading := true
				for reading {
					select {
					case update := <-updates:
						echo += update.echo
						if update.submitted {
							line = update.line
							reading = false
						}
					case <-time.After(time.Second):
						t.Fatal("input did not submit")
					}
				}
				cancel()
				wantEcho := ""
				if raw {
					wantEcho = test.echo
				}
				if line != test.line || echo != wantEcho {
					t.Fatalf("raw=%v: line=%q echo=%q, want %q / %q", raw, line, echo, test.line, wantEcho)
				}
			}
		})
	}
}

func TestNavigationSequencesCannotApproveCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan operatorInput)
	errors := make(chan error, 1)
	var pending atomic.Int64
	pending.Store(1)
	go readOperatorLines(ctx, strings.NewReader("\x1b[y\x1b[n\x1bOs\x1by\x7fn"), true, &pending, updates, errors)
	if line := nextOperatorLine(t, updates); line != "n" {
		t.Fatalf("escape sequence triggered a decision: %q", line)
	}
}

func TestOperatorCRLFDoesNotSubmitExtraCommands(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	updates := make(chan operatorInput)
	errors := make(chan error, 1)
	var pending atomic.Int64
	go readOperatorLines(ctx, strings.NewReader("history\r\nquit\r\n"), true, &pending, updates, errors)
	for _, want := range []string{"history", "quit"} {
		if got := nextOperatorLine(t, updates); got != want {
			t.Fatalf("line=%q, want %q", got, want)
		}
	}
}
