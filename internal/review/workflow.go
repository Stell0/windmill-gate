package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/stell0/windmill-gate/internal/policy"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PolicyRepository string `yaml:"policy_repository"`
	BaseBranch       string `yaml:"base_branch"`
	PolicyPath       string `yaml:"policy_path"`
	TestsPath        string `yaml:"tests_path"`
	MinimumApprovals int    `yaml:"minimum_approvals"`
	AutomatedPR      bool   `yaml:"automated_pr"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read policy-review config: %w", err)
	}
	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, fmt.Errorf("parse policy-review config: %w", err)
	}
	if config.BaseBranch == "" {
		config.BaseBranch = "main"
	}
	if config.PolicyPath == "" {
		config.PolicyPath = "policy/default.yaml"
	}
	if config.TestsPath == "" {
		config.TestsPath = "policy/tests/default.yaml"
	}
	if config.MinimumApprovals == 0 {
		config.MinimumApprovals = 3
	}
	if config.PolicyRepository == "" {
		return Config{}, errors.New("policy_repository is required")
	}
	if config.MinimumApprovals < 2 {
		return Config{}, errors.New("minimum_approvals must be at least 2")
	}
	if _, err := cleanRelative(config.PolicyPath); err != nil {
		return Config{}, fmt.Errorf("policy_path: %w", err)
	}
	if _, err := cleanRelative(config.TestsPath); err != nil {
		return Config{}, fmt.Errorf("tests_path: %w", err)
	}
	return config, nil
}

type Runner interface {
	Run(ctx context.Context, directory, name string, args ...string) (string, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, directory, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = directory
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = ioDiscard{}
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w", name, err)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// ioDiscard avoids relaying git/hosting stderr that may contain credentialized
// repository URLs. The underlying exit error remains available to the operator.
type ioDiscard struct{}

func (ioDiscard) Write(data []byte) (int, error) { return len(data), nil }

type Proposal struct {
	Branch   string `json:"branch"`
	PullURL  string `json:"pull_request_url"`
	Existing bool   `json:"existing"`
}

type Workflow struct {
	Runner Runner
}

func (w Workflow) Propose(ctx context.Context, config Config, candidates []Candidate, _ string) (Proposal, error) {
	if len(candidates) == 0 {
		return Proposal{}, errors.New("no policy candidates met the evidence threshold")
	}
	for i, candidate := range candidates {
		canonical, err := canonicalCandidate(candidate)
		if err != nil {
			return Proposal{}, err
		}
		candidates[i] = canonical
		if err := validateEvidenceCandidate(candidate, config.MinimumApprovals); err != nil {
			return Proposal{}, err
		}
	}
	if w.Runner == nil {
		w.Runner = ExecRunner{}
	}
	root, err := os.MkdirTemp("", "gate-policy-review-")
	if err != nil {
		return Proposal{}, fmt.Errorf("create policy-review workspace: %w", err)
	}
	defer os.RemoveAll(root)
	checkout := filepath.Join(root, "policy")
	if _, err := w.Runner.Run(ctx, "", "git", "clone", "--branch", config.BaseBranch, "--single-branch", "--", config.PolicyRepository, checkout); err != nil {
		return Proposal{}, err
	}
	// Content-derived names prevent duplicate proposals across investigations.
	identity := []string{config.PolicyPath, config.TestsPath}
	for _, candidate := range candidates {
		identity = append(identity, candidate.Pattern)
	}
	sort.Strings(identity)
	digest := sha256.Sum256([]byte(strings.Join(identity, "\x00")))
	branch := "gate/policy-suggestions/" + hex.EncodeToString(digest[:8])
	existing, err := w.Runner.Run(ctx, checkout, "gh", "pr", "list", "--state", "open", "--head", branch, "--json", "url", "--jq", ".[0].url // empty")
	if err != nil {
		return Proposal{}, err
	}
	if strings.TrimSpace(existing) != "" {
		return Proposal{Branch: branch, PullURL: existing, Existing: true}, nil
	}
	if _, err := w.Runner.Run(ctx, checkout, "git", "checkout", "-b", branch); err != nil {
		return Proposal{}, err
	}
	policyFile, err := secureFile(checkout, config.PolicyPath)
	if err != nil {
		return Proposal{}, err
	}
	testsFile, err := secureFile(checkout, config.TestsPath)
	if err != nil {
		return Proposal{}, err
	}
	policyData, err := os.ReadFile(policyFile)
	if err != nil {
		return Proposal{}, fmt.Errorf("read upstream policy: %w", err)
	}
	testsData, err := os.ReadFile(testsFile)
	if err != nil {
		return Proposal{}, fmt.Errorf("read upstream policy tests: %w", err)
	}
	updatedPolicy, updatedTests, err := ApplyCandidates(policyData, testsData, candidates)
	if err != nil {
		return Proposal{}, err
	}
	if err := os.WriteFile(policyFile, updatedPolicy, 0o644); err != nil {
		return Proposal{}, fmt.Errorf("write policy proposal: %w", err)
	}
	if err := os.WriteFile(testsFile, updatedTests, 0o644); err != nil {
		return Proposal{}, fmt.Errorf("write policy tests: %w", err)
	}
	// Policy-only repositories are checked in-process above using the complete
	// bundled regression corpus and adversarial differential cases. A Gate
	// source repository must also pass all four mandatory checks on its branch.
	if _, err := os.Stat(filepath.Join(checkout, "go.mod")); err == nil {
		for _, check := range [][]string{{"make", "policy-test"}, {"go", "test", "./internal/policy", "./internal/review"}, {"make", "test"}, {"make", "test-race"}} {
			if _, err := w.Runner.Run(ctx, checkout, check[0], check[1:]...); err != nil {
				return Proposal{}, fmt.Errorf("upstream preflight: %w", err)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return Proposal{}, err
	}
	// Checks must not mutate the exact policy/test bytes already validated.
	finalPolicy, err := os.ReadFile(policyFile)
	if err != nil {
		return Proposal{}, err
	}
	finalTests, err := os.ReadFile(testsFile)
	if err != nil {
		return Proposal{}, err
	}
	if !bytes.Equal(finalPolicy, updatedPolicy) || !bytes.Equal(finalTests, updatedTests) {
		return Proposal{}, errors.New("upstream preflight changed validated proposal bytes")
	}
	// Only these two files may differ. Never commit generated artifacts or secrets.
	changed, err := w.Runner.Run(ctx, checkout, "git", "diff", "--name-only")
	if err != nil {
		return Proposal{}, err
	}
	for _, path := range strings.Split(strings.TrimSpace(changed), "\n") {
		if path != "" && path != config.PolicyPath && path != config.TestsPath {
			return Proposal{}, errors.New("upstream preflight modified an unexpected file")
		}
	}
	if _, err := w.Runner.Run(ctx, checkout, "git", "add", "--", config.PolicyPath, config.TestsPath); err != nil {
		return Proposal{}, err
	}
	if _, err := w.Runner.Run(ctx, checkout, "git", "-c", "user.name=Gate Policy Review", "-c", "user.email=gate-policy-review@localhost", "commit", "-m", "policy: allow repeated read-only diagnostics"); err != nil {
		return Proposal{}, err
	}
	if _, err := w.Runner.Run(ctx, checkout, "git", "push", "origin", branch); err != nil {
		return Proposal{}, err
	}
	body := PullRequestBody(candidates)
	title := "policy: allow repeated read-only diagnostics"
	bodyPath := filepath.Join(root, "pull-request.md")
	if err := os.WriteFile(bodyPath, []byte(body), 0o600); err != nil {
		return Proposal{}, err
	}
	url, err := w.Runner.Run(ctx, checkout, "gh", "pr", "create", "--base", config.BaseBranch, "--head", branch, "--title", title, "--body-file", bodyPath)
	if err != nil {
		return Proposal{}, err
	}
	if strings.TrimSpace(url) == "" {
		return Proposal{}, errors.New("pull request tool returned no URL")
	}
	return Proposal{Branch: branch, PullURL: strings.TrimSpace(url)}, nil
}

func validateEvidenceCandidate(candidate Candidate, minimumApprovals int) error {
	if minimumApprovals < 2 {
		minimumApprovals = 2
	}
	if candidate.Approvals < minimumApprovals || candidate.Targets < 2 {
		return fmt.Errorf("candidate %q does not meet the configured evidence threshold", candidate.Pattern)
	}
	if len(candidate.Examples) == 0 {
		return fmt.Errorf("candidate %q has no observed examples", candidate.Pattern)
	}
	for _, example := range candidate.Examples {
		derived, ok := generalize(example)
		if !ok || derived.Pattern != candidate.Pattern {
			return fmt.Errorf("candidate %q is not safely derived from its examples", candidate.Pattern)
		}
	}
	return nil
}

func ApplyCandidates(policyData, testsData []byte, candidates []Candidate) ([]byte, []byte, error) {
	if len(candidates) == 0 {
		return nil, nil, errors.New("no candidates")
	}
	for i, input := range candidates {
		canonical, err := canonicalCandidate(input)
		if err != nil {
			return nil, nil, err
		}
		candidates[i] = canonical
	}
	before, err := policy.Parse(policyData)
	if err != nil {
		return nil, nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(policyData, &document); err != nil {
		return nil, nil, fmt.Errorf("parse upstream policy: %w", err)
	}
	allow, err := mappingSequence(&document, "allow")
	if err != nil {
		return nil, nil, err
	}
	added := false
	existing := make(map[string]bool)
	for _, node := range allow.Content {
		existing[node.Value] = true
	}
	for _, candidate := range candidates {
		if _, err := regexp.Compile(candidate.Pattern); err != nil {
			return nil, nil, fmt.Errorf("candidate regex %q is invalid: %w", candidate.Pattern, err)
		}
		if !existing[candidate.Pattern] {
			allow.Content = append(allow.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: candidate.Pattern, Style: yaml.SingleQuotedStyle})
			existing[candidate.Pattern] = true
			added = true
		}
	}
	if !added {
		return nil, nil, errors.New("candidate rules already exist upstream")
	}
	updatedPolicy, err := yaml.Marshal(&document)
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy proposal: %w", err)
	}
	engine, err := policy.Parse(updatedPolicy)
	if err != nil {
		return nil, nil, err
	}

	var suite policy.TestSuite
	testDecoder := yaml.NewDecoder(bytes.NewReader(testsData))
	testDecoder.KnownFields(true)
	if err := testDecoder.Decode(&suite); err != nil {
		return nil, nil, fmt.Errorf("parse upstream policy tests: %w", err)
	}
	if _, failures := suite.Run(before); len(failures) > 0 {
		return nil, nil, errors.New("upstream baseline policy tests fail")
	}
	if _, failures := suite.Run(engine); len(failures) > 0 {
		return nil, nil, errors.New("candidate regresses original upstream suite")
	}
	if err := validateDifferential(before, engine, suite, candidates); err != nil {
		return nil, nil, err
	}
	seen := make(map[string]bool)
	for _, group := range [][]policy.TestCase{suite.Allow, suite.Ask, suite.Deny} {
		for _, test := range group {
			seen[string(test.Expect)+"\x00"+test.Command] = true
		}
	}
	for _, candidate := range candidates {
		for _, example := range positiveCases(candidate) {
			if engine.Evaluate("gt_policy_review", example).Decision != policy.Allow {
				return nil, nil, fmt.Errorf("candidate rule does not allow observed example %q", example)
			}
			test := policy.TestCase{Command: example, Expect: policy.Allow}
			if key := string(test.Expect) + "\x00" + test.Command; !seen[key] {
				suite.Allow = append(suite.Allow, test)
				seen[key] = true
			}
		}
		for _, negative := range candidate.NegativeTests {
			decision := engine.Evaluate("gt_policy_review", negative).Decision
			if decision == policy.Allow {
				return nil, nil, fmt.Errorf("candidate rule unexpectedly allows dangerous variant %q", negative)
			}
			test := policy.TestCase{Command: negative, Expect: decision}
			key := string(test.Expect) + "\x00" + test.Command
			if seen[key] {
				continue
			}
			if decision == policy.Deny {
				suite.Deny = append(suite.Deny, test)
			} else {
				suite.Ask = append(suite.Ask, test)
			}
			seen[key] = true
		}
	}
	sortTests := func(tests []policy.TestCase) {
		sort.Slice(tests, func(i, j int) bool { return tests[i].Command < tests[j].Command })
	}
	sortTests(suite.Allow)
	sortTests(suite.Ask)
	sortTests(suite.Deny)
	updatedTests, err := yaml.Marshal(suite)
	if err != nil {
		return nil, nil, fmt.Errorf("encode policy tests: %w", err)
	}
	total, failures := suite.Run(engine)
	if len(failures) > 0 {
		return nil, nil, fmt.Errorf("generated policy failed %d of %d tests", len(failures), total)
	}
	return updatedPolicy, updatedTests, nil
}

func PullRequestBody(candidates []Candidate) string {
	var body strings.Builder
	body.WriteString("## Rationale\n\nGate observed repeated, successful manual approvals for read-only diagnostics. This proposal adds only the narrow rules below.\n\n")
	for _, candidate := range candidates {
		fmt.Fprintf(&body, "### `%s`\n\n", candidate.Pattern)
		fmt.Fprintf(&body, "- Evidence: %d successful manual approvals across %d Gate target contexts; %d connection sessions (not independent support cases).\n", candidate.Approvals, candidate.Targets, candidate.Sessions)
		fmt.Fprintf(&body, "- Allowed input space: %s.\n", candidate.AllowedSpace)
		body.WriteString("- Redacted observed examples:\n")
		for _, example := range candidate.Examples {
			fmt.Fprintf(&body, "  - `%s`\n", redactExample(example))
		}
		body.WriteString("- Important exclusions:\n")
		for _, excluded := range candidate.Excluded {
			fmt.Fprintf(&body, "  - %s\n", excluded)
		}
		fmt.Fprintf(&body, "- Tests: %d positive cases (observed and representative) and %d dangerous/boundary variants.\n\n", len(positiveCases(candidate)), len(candidate.NegativeTests))
	}
	body.WriteString("## Validation\n\nPASS: original upstream suite, complete bundled Gate regression corpus, raw Go regexp positive/negative boundaries and full-engine differential/adversarial checks. Only documented positive cases may change ASK to ALLOW; DENY and existing ALLOW classifications are preserved. Gate source repositories additionally pass make policy-test, targeted Go tests, make test and make test-race before push. Exit success does not establish diagnostic usefulness; investigation context must be reviewed.\n\n")
	body.WriteString("## Review boundary\n\nA human must review and merge this pull request. Gate has not merged, deployed, or changed any active production policy. No Windmill session identifiers are included.\n")
	return body.String()
}

func mappingSequence(document *yaml.Node, key string) (*yaml.Node, error) {
	if document.Kind != yaml.DocumentNode || len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, errors.New("policy must be a YAML mapping")
	}
	mapping := document.Content[0]
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			value := mapping.Content[index+1]
			if value.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("policy %s must be a sequence", key)
			}
			return value, nil
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	valueNode := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	mapping.Content = append(mapping.Content, keyNode, valueNode)
	return valueNode, nil
}

func secureFile(root, relative string) (string, error) {
	clean, err := cleanRelative(relative)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", err
	}
	path := filepath.Join(resolvedRoot, clean)
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve configured policy file: %w", err)
	}
	rel, err := filepath.Rel(resolvedRoot, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", errors.New("configured policy file escapes repository")
	}
	return resolved, nil
}

func cleanRelative(path string) (string, error) {
	clean := filepath.Clean(path)
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) {
		return "", errors.New("path must stay inside the policy repository")
	}
	return clean, nil
}

var credentialAssignment = regexp.MustCompile(`(?i)(password|passwd|token|secret|authorization|cookie)=\S+`)

func redactExample(value string) string {
	return credentialAssignment.ReplaceAllString(value, "$1=[REDACTED]")
}
