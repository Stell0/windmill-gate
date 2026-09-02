package command

import (
	"errors"
	"testing"
)

func TestCommandCopiesAndHashesExactPayload(t *testing.T) {
	payload := []byte("printf 'hello world\\n'")
	cmd, err := New("as_1", "gt_1", payload)
	if err != nil {
		t.Fatal(err)
	}
	snapshot := cmd.Snapshot()
	payload[0] = 'x'
	returned := cmd.Payload()
	returned[0] = 'y'

	if got := string(cmd.Payload()); got != "printf 'hello world\\n'" {
		t.Fatalf("payload mutated: %q", got)
	}
	if snapshot.Hash != Hash([]byte(snapshot.Payload)) {
		t.Fatal("hash does not cover exact command bytes")
	}
	if err := cmd.VerifyApproval(snapshot.ID, snapshot.Hash); err != nil {
		t.Fatalf("valid approval rejected: %v", err)
	}
}

func TestModifiedApprovalIsRejected(t *testing.T) {
	cmd, err := New("as_1", "gt_1", []byte("uptime"))
	if err != nil {
		t.Fatal(err)
	}
	snapshot := cmd.Snapshot()
	if err := cmd.VerifyApproval(snapshot.ID, Hash([]byte("uptime; reboot"))); !errors.Is(err, ErrPayloadChanged) {
		t.Fatalf("modified hash accepted: %v", err)
	}
	if err := cmd.VerifyApproval("cmd_other", snapshot.Hash); !errors.Is(err, ErrPayloadChanged) {
		t.Fatalf("wrong command ID accepted: %v", err)
	}
}

func TestCommandLifecycle(t *testing.T) {
	cmd, err := New("as_1", "gt_1", []byte("uptime"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Transition(Waiting, nil); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Transition(Running, nil); err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	if err := cmd.Transition(Succeeded, &exitCode); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Transition(Running, nil); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("terminal state changed: %v", err)
	}
}
