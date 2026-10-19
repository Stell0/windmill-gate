package review

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stell0/windmill-gate/internal/policy"
)

func TestApplyCandidatesAddsRulesAndBoundaryTests(t *testing.T) {
	policyData := []byte("validated_allow:\n  - regexp: '^pgrep(?: .*)?$'\n    validator: diagnostic_read\nallow: []\ndeny:\n  - '^systemctl restart\\\\b'\n")
	testsData := []byte("allow: []\nask: []\ndeny: []\n")
	candidate := Candidate{
		Pattern:       `^free -m$`,
		Examples:      []string{"free -m"},
		NegativeTests: []string{"free -m --unexpected"},
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
	source := workflowSource(t, false)
	runner := &recordingRunner{}
	workflow := Workflow{Runner: runner}
	candidate := Candidate{
		Pattern: `^free -m$`, Examples: []string{"free -m"},
		Approvals: 3, Sessions: 2, Targets: 2,
		AllowedSpace: "only the exact command", Excluded: []string{"additional arguments"},
		NegativeTests: []string{"free -m --unexpected"},
	}
	proposal, err := workflow.Propose(context.Background(), Config{
		PolicyRepository: source, BaseBranch: "main",
		PolicyPath: "policy/default.yaml", TestsPath: "policy/tests/default.yaml", MinimumApprovals: 3,
	}, []Candidate{candidate}, "session-safe")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(proposal.Branch, "gate/policy-suggestions/") || proposal.PullURL != "https://example.invalid/pull/1" {
		t.Fatalf("unexpected proposal: %#v", proposal)
	}
	cmd := exec.Command("git", "show", "refs/heads/"+proposal.Branch+":policy/default.yaml")
	cmd.Dir = source
	pushed, err := cmd.Output()
	if err != nil || !strings.Contains(string(pushed), candidate.Pattern) {
		t.Fatalf("local upstream did not receive tested branch: %v", err)
	}
	active, err := os.ReadFile(filepath.Join(source, "policy", "default.yaml"))
	if err != nil || string(active) != "allow: []\ndeny: []\n" {
		t.Fatal("upstream active checkout changed")
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
	diffOutput string
	calls      []string
	policy     string
	tests      string
	body       string
	existing   string
	failCheck  string
	checks     []string
	mutate     bool
}

func (r *recordingRunner) Run(ctx context.Context, directory, name string, args ...string) (string, error) {
	call := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, call)
	if name == "git" && len(args) > 1 && args[0] == "diff" && r.diffOutput != "" {
		return r.diffOutput, nil
	}
	if name == "make" || name == "go" {
		r.checks = append(r.checks, call)
		if call == r.failCheck {
			return "", fmt.Errorf("fixture check failure")
		}
		if r.mutate {
			_ = os.WriteFile(filepath.Join(directory, "policy", "default.yaml"), []byte("allow: ['.*']\n"), 0o644)
		}
		return "", nil
	}
	if name == "gh" && len(args) > 1 && args[1] == "list" {
		return r.existing, nil
	}
	if name == "gh" {
		for index, arg := range args {
			if arg == "--body-file" && index+1 < len(args) {
				body, _ := os.ReadFile(args[index+1])
				r.body = string(body)
			}
		}
		data, _ := os.ReadFile(filepath.Join(directory, "policy", "default.yaml"))
		r.policy = string(data)
		data, _ = os.ReadFile(filepath.Join(directory, "policy", "tests", "default.yaml"))
		r.tests = string(data)
		return "https://example.invalid/pull/1", nil
	}
	return (ExecRunner{}).Run(ctx, directory, name, args...)
}

func TestRejectUnboundedRuleEvenWithCuratedTests(t *testing.T) {
	c := Candidate{Pattern: `^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]+$`, Examples: []string{"journalctl -u redis -n 100"}}
	if _, _, err := ApplyCandidates([]byte("allow: []\n"), []byte("allow: []\n"), []Candidate{c}); err == nil {
		t.Fatal("unsafe old regexp accepted")
	}
}
func TestOriginalSuiteCannotRegress(t *testing.T) {
	c, _ := generalize("free -m")
	c.Examples = []string{"free -m"}
	if _, _, err := ApplyCandidates([]byte("allow: []\n"), []byte("ask:\n  - command: free -m\n    expect: ASK\n"), []Candidate{c}); err == nil {
		t.Fatal("original suite regression accepted")
	}
}
func TestOnlyExplicitPositiveDifferentialChanges(t *testing.T) {
	c, _ := generalize("free -m")
	c.Examples = []string{"free -m"}
	before, _ := policy.New(policy.Config{})
	after, _ := policy.New(policy.Config{Allow: []string{`.*`}})
	if err := validateDifferential(before, after, policy.TestSuite{}, []Candidate{c}); err == nil {
		t.Fatal("adversarial broad allowance accepted")
	}
}

func workflowSource(t *testing.T, withGo bool) string {
	t.Helper()
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
	if withGo {
		if err := os.WriteFile(filepath.Join(source, "go.mod"), []byte("module example.invalid/test\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("git", "add", "go.mod")
		cmd.Dir = source
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command("git", "commit", "-m", "source fixture")
		cmd.Dir = source
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func TestSourcePreflightsBeforePublish(t *testing.T) {
	for _, failure := range []string{"", "make policy-test", "go test ./internal/policy ./internal/review", "make test", "make test-race", "mutate"} {
		t.Run(failure, func(t *testing.T) {
			source := workflowSource(t, true)
			runner := &recordingRunner{failCheck: failure, mutate: failure == "mutate"}
			c, _ := generalize("free -m")
			c.Examples = []string{"free -m"}
			c.Approvals = 3
			c.Targets = 2
			_, err := (Workflow{Runner: runner}).Propose(context.Background(), Config{PolicyRepository: source, BaseBranch: "main", PolicyPath: "policy/default.yaml", TestsPath: "policy/tests/default.yaml", MinimumApprovals: 3}, []Candidate{c}, "check")
			calls := strings.Join(runner.calls, "\n")
			if failure != "" {
				if err == nil || strings.Contains(calls, "git push") || strings.Contains(calls, "gh pr create") || strings.Contains(calls, "user.name=Gate") {
					t.Fatalf("published failed/modified preflight: %v %s", err, calls)
				}
			} else if err != nil || len(runner.checks) != 4 {
				t.Fatalf("preflights not run: %v %v", err, runner.checks)
			}
		})
	}
}
func TestEquivalentOpenPRIsReused(t *testing.T) {
	source := workflowSource(t, false)
	runner := &recordingRunner{existing: "https://example.invalid/pull/7"}
	c, _ := generalize("free -m")
	c.Examples = []string{"free -m"}
	c.Approvals = 3
	c.Targets = 2
	proposal, err := (Workflow{Runner: runner}).Propose(context.Background(), Config{PolicyRepository: source, BaseBranch: "main", PolicyPath: "policy/default.yaml", TestsPath: "policy/tests/default.yaml", MinimumApprovals: 3}, []Candidate{c}, "repeat")
	if err != nil || !proposal.Existing || proposal.PullURL != runner.existing {
		t.Fatalf("not reused: %v %#v", err, proposal)
	}
	calls := strings.Join(runner.calls, "\n")
	if strings.Contains(calls, "checkout -b") || strings.Contains(calls, "git push") || strings.Contains(calls, "gh pr create") {
		t.Fatal(calls)
	}
}

func TestPreflightPathNamesUseUnambiguousNULFraming(t *testing.T) {
	source := workflowSource(t, false)
	c, _ := generalize("free -m")
	c.Examples = []string{"free -m"}
	c.Approvals = 3
	c.Targets = 2
	for _, extra := range []string{"unexpected.txt", "policy/default.yaml\nREADME.md"} {
		runner := &recordingRunner{diffOutput: "policy/default.yaml\x00policy/tests/default.yaml\x00" + extra + "\x00"}
		_, err := (Workflow{Runner: runner}).Propose(context.Background(), Config{PolicyRepository: source, BaseBranch: "main", PolicyPath: "policy/default.yaml", TestsPath: "policy/tests/default.yaml", MinimumApprovals: 3}, []Candidate{c}, "")
		if err == nil || strings.Contains(strings.Join(runner.calls, "\n"), "git push") {
			t.Fatalf("unexpected framed path was accepted: %q %v", extra, err)
		}
	}
}

func TestExecRunnerKeepsWarningsOutOfPathData(t *testing.T) {
	if os.Getenv("GATE_REVIEW_RUNNER_CHILD") == "1" {
		fmt.Fprint(os.Stdout, "policy/default.yaml\x00policy/tests/default.yaml\x00")
		fmt.Fprintln(os.Stderr, "fixture git line-ending warning")
		os.Exit(0)
	}
	t.Setenv("GATE_REVIEW_RUNNER_CHILD", "1")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := (ExecRunner{}).Run(context.Background(), "", executable, "-test.run=^TestExecRunnerKeepsWarningsOutOfPathData$")
	if err != nil || output != "policy/default.yaml\x00policy/tests/default.yaml\x00" {
		t.Fatalf("stderr contaminated framed stdout: %q %v", output, err)
	}
}
