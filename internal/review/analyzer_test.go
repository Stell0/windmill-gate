package review

import (
	"testing"

	"github.com/stell0/windmill-gate/internal/command"
	"github.com/stell0/windmill-gate/internal/policy"
	"github.com/stell0/windmill-gate/internal/storage"
)

func TestAnalyzeRequiresRepeatedCrossContextManualApprovals(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	history := []storage.HistoryEntry{
		approved("as_1", "gt_1", "journalctl -u redis -n 100"),
		approved("as_2", "gt_1", "journalctl -u redis -n 200"),
		approved("as_3", "gt_2", "journalctl -u agent -n 100"),
		approved("as_4", "gt_2", "rm /tmp/file"),
		approved("as_5", "gt_2", "uptime; reboot"),
		approved("as_6", "gt_2", "grep token=abc /var/log/messages"),
		approved("as_7", "gt_2", "ip route flush table main"),
		approved("as_8", "gt_2", "ls *"),
		approved("as_9", "gt_2", "du /"),
		approved("as_10", "gt_2", "grep value /var/log/windmill-session"),
	}
	candidates := Analyze(history, engine, 3)
	if len(candidates) != 1 {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
	candidate := candidates[0]
	if candidate.Pattern != `^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]+$` || candidate.Approvals != 3 || candidate.Sessions != 3 || candidate.Targets != 2 {
		t.Fatalf("unexpected generalization: %#v", candidate)
	}
}

func TestAnalyzeRejectsSingleContextAndAlreadyAllowedCommands(t *testing.T) {
	engine, _ := policy.New(policy.Config{Allow: []string{`^uptime$`}})
	history := []storage.HistoryEntry{
		approved("as_1", "gt_1", "uptime"),
		approved("as_1", "gt_1", "uptime"),
		approved("as_1", "gt_1", "uptime"),
	}
	if candidates := Analyze(history, engine, 3); len(candidates) != 0 {
		t.Fatalf("already allowed/single-context command proposed: %#v", candidates)
	}
}

func TestExactFallbackStaysAnchoredAndPathSpecific(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	history := []storage.HistoryEntry{
		approved("as_1", "gt_1", "grep timeout /var/log/messages"),
		approved("as_2", "gt_1", "grep timeout /var/log/messages"),
		approved("as_3", "gt_2", "grep timeout /var/log/messages"),
	}
	candidates := Analyze(history, engine, 3)
	if len(candidates) != 1 || candidates[0].Pattern != `^grep timeout /var/log/messages$` {
		t.Fatalf("unsafe exact fallback: %#v", candidates)
	}
}

func approved(sessionID, targetID, value string) storage.HistoryEntry {
	return storage.HistoryEntry{
		AgentSessionID: sessionID, TargetID: targetID, Command: value,
		State: command.Succeeded, PolicyResult: policy.Ask, ApprovalAction: "approve_once",
	}
}
