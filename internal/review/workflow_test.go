package review

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestApplyCandidatesAddsRulesAndBoundaryTests(t *testing.T) {
	policyData := []byte("validated_allow:\n  - regexp: '^pgrep(?: .*)?$'\n    validator: diagnostic_read\nallow: []\ndeny:\n  - '^systemctl restart\\\\b'\n")
	testsData := []byte("allow: []\nask: []\ndeny: []\n")
	candidate := Candidate{
		Pattern:       `^grep timeout /var/log/messages$`,
		Examples:      []string{"grep timeout /var/log/messages"},
		NegativeTests: []string{"grep timeout /var/log/messages --unexpected"},
	}
	updatedPolicy, updatedTests, err := ApplyCandidates(policyData, testsData, []Candidate{candidate})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updatedPolicy), candidate.Pattern) || !strings.Contains(string(updatedTests), "--unexpected") {
		t.Fatalf("proposal omitted rule or tests:\n%s\n%s", updatedPolicy, updatedTests)
	}
	if !strings.Contains(string(updatedPolicy), "validated_allow:") || !strings.Contains(string(updatedPolicy), "validator: diagnostic_read") {
		t.Fatalf("proposal discarded validated rules:\n%s", updatedPolicy)
	}
}

func TestWorkflowCreatesBranchPushAndPRButNeverMerge(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.MkdirAll(filepath.Join(source, "policy", "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "policy", "default.yaml"), []byte("allow: []\ndeny: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "policy", "tests", "default.yaml"), []byte("allow: []\nask: []\ndeny: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"init", "-b", "main"},
		{"config", "user.name", "Test"},
		{"config", "user.email", "test@example.invalid"},
		{"add", "."},
		{"commit", "-m", "initial"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = source
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	runner := &recordingRunner{}
	workflow := Workflow{Runner: runner, Now: func() time.Time { return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC) }}
	candidate := Candidate{
		Pattern: `^grep timeout /var/log/messages$`, Examples: []string{"grep timeout /var/log/messages"},
		Approvals: 3, Sessions: 2, Targets: 2,
		AllowedSpace: "only the exact command", Excluded: []string{"additional arguments"},
		NegativeTests: []string{"grep timeout /var/log/messages --unexpected"},
	}
	proposal, err := workflow.Propose(context.Background(), Config{
		PolicyRepository: source, BaseBranch: "main",
		PolicyPath: "policy/default.yaml", TestsPath: "policy/tests/default.yaml", MinimumApprovals: 3,
	}, []Candidate{candidate}, "session-safe")
	if err != nil {
		t.Fatal(err)
	}
	if proposal.Branch != "gate/policy-suggestions/20260902-120000-session-safe" || proposal.PullURL != "https://example.invalid/pull/1" {
		t.Fatalf("unexpected proposal: %#v", proposal)
	}
	joined := strings.Join(runner.calls, "\n")
	if strings.Contains(joined, "git merge ") || strings.Contains(joined, "gh pr merge") || strings.Contains(joined, " gate deploy ") {
		t.Fatalf("workflow crossed review boundary:\n%s", joined)
	}
	if !strings.Contains(joined, "git push origin "+proposal.Branch) || !strings.Contains(joined, "gh pr create") {
		t.Fatalf("workflow omitted push or PR:\n%s", joined)
	}
	if !strings.Contains(runner.policy, candidate.Pattern) || !strings.Contains(runner.tests, "--unexpected") {
		t.Fatalf("workflow omitted policy/test changes:\n%s\n%s", runner.policy, runner.tests)
	}
	if strings.Contains(runner.body, "Windmill session") && !strings.Contains(runner.body, "No Windmill session") {
		t.Fatalf("unsafe PR body: %s", runner.body)
	}
	if !strings.Contains(runner.body, "human must review and merge") {
		t.Fatalf("PR body omitted human review boundary: %s", runner.body)
	}
}

func TestWorkflowRejectsCandidateNotDerivedFromSafeHistory(t *testing.T) {
	runner := &recordingRunner{}
	_, err := (Workflow{Runner: runner}).Propose(context.Background(), Config{
		PolicyRepository: "unused", BaseBranch: "main", PolicyPath: "policy.yaml",
		TestsPath: "tests.yaml", MinimumApprovals: 3,
	}, []Candidate{{
		Pattern: `^grep.*$`, Examples: []string{"grep password=secret /var/log/messages"},
		Approvals: 3, Sessions: 2, Targets: 2,
	}}, "unsafe")
	if err == nil {
		t.Fatal("unsafe caller-supplied candidate was accepted")
	}
	if len(runner.calls) != 0 {
		t.Fatalf("workflow mutated external state before candidate validation: %#v", runner.calls)
	}
}

type recordingRunner struct {
	calls  []string
	policy string
	tests  string
	body   string
}

func (r *recordingRunner) Run(ctx context.Context, directory, name string, args ...string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "git" && len(args) > 0 && args[0] == "push" {
		return "", nil
	}
	if name == "gh" {
		for index, arg := range args {
			if arg == "--body" && index+1 < len(args) {
				r.body = args[index+1]
			}
		}
		data, _ := os.ReadFile(filepath.Join(directory, "policy", "default.yaml"))
		r.policy = string(data)
		data, _ = os.ReadFile(filepath.Join(directory, "policy", "tests", "default.yaml"))
		r.tests = string(data)
		return "https://example.invalid/pull/1", nil
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = directory
	output, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(output)), err
}
