package approval

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stell0/windmill-gate/internal/command"
	"github.com/stell0/windmill-gate/internal/policy"
)

func TestDecisionMustMatchCommandIDAndHash(t *testing.T) {
	broker := NewBroker()
	cmd, err := command.New("as_1", "gt_1", []byte("uptime"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := broker.Wait(ctx, cmd, policy.Result{Decision: policy.Ask})
		done <- err
	}()
	waitForPending(t, broker)
	snapshot := cmd.Snapshot()
	err = broker.Decide(Decision{CommandID: snapshot.ID, Hash: command.Hash([]byte("uptime; reboot")), Action: ApproveOnce, Actor: "operator"})
	if !errors.Is(err, command.ErrPayloadChanged) {
		t.Fatalf("modified payload approved: %v", err)
	}
	if err := broker.Decide(Decision{CommandID: snapshot.ID, Hash: snapshot.Hash, Action: ApproveOnce, Actor: "operator"}); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSimilarPatternIsConservative(t *testing.T) {
	tests := map[string]string{
		"journalctl -u redis -n 100":  `^journalctl -u redis -n [0-9]+$`,
		"uptime; reboot":              `^uptime; reboot$`,
		"grep 'two words' /var/log/x": `^grep 'two words' /var/log/x$`,
	}
	for input, want := range tests {
		if got := SimilarPattern(input); got != want {
			t.Errorf("SimilarPattern(%q) = %q, want %q", input, got, want)
		}
	}
}

func waitForPending(t *testing.T, broker *Broker) {
	t.Helper()
	deadline := time.After(time.Second)
	for {
		if len(broker.List()) == 1 {
			return
		}
		select {
		case <-broker.Changed():
		case <-deadline:
			t.Fatal("command did not become pending")
		}
	}
}
