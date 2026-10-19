package review

import (
	"encoding/json"
	"strings"
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
	if candidate.Pattern != `^journalctl -u `+unitGrammar+` -n `+countGrammar+`$` || candidate.Approvals != 3 || candidate.Sessions != 3 || candidate.Targets != 2 {
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

func TestExactFallbackStaysAnchored(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	history := []storage.HistoryEntry{
		approved("as_1", "gt_1", "free -m"),
		approved("as_2", "gt_1", "free -m"),
		approved("as_3", "gt_2", "free -m"),
	}
	candidates := Analyze(history, engine, 3)
	if len(candidates) != 1 || candidates[0].Pattern != `^free -m$` {
		t.Fatalf("unsafe exact fallback: %#v", candidates)
	}
}

func approved(sessionID, targetID, value string) storage.HistoryEntry {
	zero := 0
	return storage.HistoryEntry{
		ID: sessionID + targetID + value, ExitCode: &zero,
		AgentSessionID: sessionID, TargetID: targetID, TargetName: targetID, Command: value,
		State: command.Succeeded, PolicyResult: policy.Ask, ApprovalAction: "approve_once",
	}
}

func TestConnectionSessionsNeverEstablishIndependence(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	history := []storage.HistoryEntry{approved("as1", "gt1", "journalctl -u redis -n 100"), approved("as2", "gt1", "journalctl -u redis -n 200"), approved("as3", "gt1", "journalctl -u redis -n 1000")}
	report := AnalyzeReport(history, engine, 3)
	if len(report.Candidates) != 0 || len(report.Pending) != 1 || report.Pending[0].Sessions != 3 {
		t.Fatalf("connection IDs counted as support cases: %#v", report)
	}
	history = append(history, history[0], history[1])
	if AnalyzeReport(history, engine, 4).Pending[0].Approvals != 3 {
		t.Fatal("duplicate commands inflated approval counts")
	}
	history[0].ExitCode = nil
	if len(Analyze(history, engine, 3)) != 0 {
		t.Fatal("missing exit evidence accepted")
	}
}

func TestGeneralizationBoundsAndUnsafeCandidates(t *testing.T) {
	for _, value := range []string{"journalctl -u redis -n 1001", "journalctl -u redis -n 0", "journalctl -u --all -n 100", "podman logs --tail all redis", "podman logs --tail 100 --latest", "ls --color=always /etc", "stat --printf=secret /etc/shadow", "grep --include=private x /var/log/messages", "du /var/log", "runagent -m app podman exec db mysql -e SELECT", "asterisk -rx database", "journalctl -u tokenabc -n 100", "journalctl -u ../redis -n 100"} {
		if _, ok := generalize(value); ok {
			t.Errorf("unsafe candidate accepted: %q", value)
		}
	}
	for _, value := range []string{"journalctl -u redis -n 1", "journalctl -u redis -n 1000", "podman logs --tail 1000 redis", "systemctl status redis"} {
		c, ok := generalize(value)
		if !ok {
			t.Fatal(value)
		}
		if _, _, err := ApplyCandidates([]byte("allow: []\ndeny: []\n"), []byte("allow: []\nask: []\ndeny: []\n"), []Candidate{withExample(c, value)}); err != nil {
			t.Fatalf("%s: %v", value, err)
		}
	}
}
func withExample(c Candidate, value string) Candidate { c.Examples = []string{value}; return c }

func FuzzGeneralizedComposition(f *testing.F) {
	for _, seed := range []string{"; reboot", " && reboot", " | sh", " $(id)", "\n", " --unexpected", " > /tmp/x"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, suffix string) {
		c, _ := generalize("journalctl -u redis -n 100")
		engine, _ := policy.New(policy.Config{Allow: []string{c.Pattern}})
		value := "journalctl -u redis -n 100" + suffix
		if engine.Evaluate("gt", value).Decision == policy.Allow {
			derived, ok := generalize(value)
			if !ok || derived.Pattern != c.Pattern {
				t.Fatalf("unsafe extension allowed: %q", value)
			}
		}
	})
}

func TestReattachedTargetDoesNotCreateDiversity(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	a, b, c := approved("as1", "gt1", "free -m"), approved("as2", "gt2", "free -m"), approved("as3", "gt3", "free -m")
	a.TargetName = " Same System "
	b.TargetName = "same system"
	c.TargetName = "SAME SYSTEM"
	report := AnalyzeReport([]storage.HistoryEntry{a, b, c}, engine, 3)
	if len(report.Candidates) != 0 || len(report.Pending) != 1 || report.Pending[0].Targets != 1 {
		t.Fatalf("reattachment counted independently: %#v", report)
	}
}

func TestReportDoesNotSerializeRejectedSecretsOrTargetNames(t *testing.T) {
	engine, _ := policy.New(policy.Config{})
	entry := approved("as1", "gt1", "grep token=customer-secret /var/log/messages")
	entry.TargetName = "private customer display"
	report := AnalyzeReport([]storage.HistoryEntry{entry}, engine, 3)
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{"customer-secret", "private customer display", "as1", "gt1"} {
		if strings.Contains(string(data), private) {
			t.Fatalf("private rejected data exported: %s", data)
		}
	}
	if report.Rejected["outside bounded read-only grammar or sensitive"] != 1 {
		t.Fatal(report)
	}
}
