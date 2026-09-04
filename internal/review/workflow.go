package review

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/stell0/windmill-gate/internal/policy"
	"gopkg.in/yaml.v3"
)

type Config struct {
	PolicyRepository string `yaml:"policy_repository"`
	BaseBranch       string `yaml:"base_branch"`
	PolicyPath       string `yaml:"policy_path"`
	TestsPath        string `yaml:"tests_path"`
	MinimumApprovals int    `yaml:"minimum_approvals"`
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
	Branch  string `json:"branch"`
	PullURL string `json:"pull_request_url"`
}

type Workflow struct {
	Runner Runner
	Now    func() time.Time
}

func (w Workflow) Propose(ctx context.Context, config Config, candidates []Candidate, label string) (Proposal, error) {
	if len(candidates) == 0 {
		return Proposal{}, errors.New("no policy candidates met the evidence threshold")
	}
	for _, candidate := range candidates {
		if err := validateEvidenceCandidate(candidate, config.MinimumApprovals); err != nil {
			return Proposal{}, err
		}
	}
	if w.Runner == nil {
		w.Runner = ExecRunner{}
	}
	if w.Now == nil {
		w.Now = time.Now
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
	branch := "gate/policy-suggestions/" + w.Now().UTC().Format("20060102-150405")
	if suffix := safeLabel(label); suffix != "" {
		branch += "-" + suffix
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
	url, err := w.Runner.Run(ctx, checkout, "gh", "pr", "create", "--base", config.BaseBranch, "--head", branch, "--title", title, "--body", body)
	if err != nil {
		return Proposal{}, err
	}
	if strings.TrimSpace(url) == "" {
		return Proposal{}, errors.New("pull request tool returned no URL")
	}
	return Proposal{Branch: branch, PullURL: strings.TrimSpace(url)}, nil
}

func validateEvidenceCandidate(candidate Candidate, minimumApprovals int) error {
	if candidate.Approvals < minimumApprovals || (candidate.Sessions < 2 && candidate.Targets < 2) {
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
	var document yaml.Node
	if err := yaml.Unmarshal(policyData, &document); err != nil {
		return nil, nil, fmt.Errorf("parse upstream policy: %w", err)
	}
	allow, err := mappingSequence(&document, "allow")
	if err != nil {
		return nil, nil, err
	}
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
		}
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
	seen := make(map[string]bool)
	for _, group := range [][]policy.TestCase{suite.Allow, suite.Ask, suite.Deny} {
		for _, test := range group {
			seen[string(test.Expect)+"\x00"+test.Command] = true
		}
	}
	for _, candidate := range candidates {
		for _, example := range candidate.Examples {
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
		fmt.Fprintf(&body, "- Evidence: %d manual approvals across %d agent sessions and %d Gate targets.\n", candidate.Approvals, candidate.Sessions, candidate.Targets)
		fmt.Fprintf(&body, "- Allowed input space: %s.\n", candidate.AllowedSpace)
		body.WriteString("- Redacted observed examples:\n")
		for _, example := range candidate.Examples {
			fmt.Fprintf(&body, "  - `%s`\n", redactExample(example))
		}
		body.WriteString("- Important exclusions:\n")
		for _, excluded := range candidate.Excluded {
			fmt.Fprintf(&body, "  - %s\n", excluded)
		}
		fmt.Fprintf(&body, "- Tests: %d positive evidence cases and %d dangerous/boundary variants.\n\n", len(candidate.Examples), len(candidate.NegativeTests))
	}
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

var unsafeLabel = regexp.MustCompile(`[^a-z0-9-]+`)

func safeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.Trim(unsafeLabel.ReplaceAllString(value, "-"), "-")
	if len(value) > 32 {
		value = strings.TrimRight(value[:32], "-")
	}
	return value
}

var credentialAssignment = regexp.MustCompile(`(?i)(password|passwd|token|secret|authorization|cookie)=\S+`)

func redactExample(value string) string {
	return credentialAssignment.ReplaceAllString(value, "$1=[REDACTED]")
}
