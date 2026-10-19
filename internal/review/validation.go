package review

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/stell0/windmill-gate/internal/policy"
	defaultpolicy "github.com/stell0/windmill-gate/policy"
	"gopkg.in/yaml.v3"
)

// canonicalCandidate never trusts caller-supplied tests or explanatory PR text.
// Every example must independently derive exactly the same bounded grammar.
func canonicalCandidate(input Candidate) (Candidate, error) {
	if len(input.Examples) == 0 {
		return Candidate{}, errors.New("candidate has no observed examples")
	}
	var result Candidate
	for _, example := range input.Examples {
		derived, ok := generalize(example)
		if !ok || derived.Pattern != input.Pattern {
			return Candidate{}, errors.New("candidate is not safely derived from its examples")
		}
		result = derived
	}
	result.Examples = []string{}
	for _, example := range input.Examples {
		result.Examples = append(result.Examples, sanitizedExample(example))
	}
	result.Examples = unique(result.Examples)
	result.Approvals = input.Approvals
	result.Sessions = input.Sessions
	result.Targets = input.Targets
	result.PositiveTests = unique(append(result.PositiveTests, result.Examples...))
	result.NegativeTests = unique(result.NegativeTests)
	return result, nil
}

func unique(values []string) []string {
	seen := map[string]bool{}
	result := []string{}
	for _, v := range values {
		if !seen[v] {
			seen[v] = true
			result = append(result, v)
		}
	}
	sort.Strings(result)
	return result
}

// Explicitly document and test inheritance through Gate's existing strict views.
// This does not add or generalize wrapper support in the engine.
func positiveCases(candidate Candidate) []string {
	result := []string{}
	for _, v := range candidate.PositiveTests {
		result = append(result, v, "runagent -m module1 "+v, "runagent -m module1 podman exec container1 "+v)
	}
	// Preserve supported concrete examples from the complete regression corpus as
	// explicit positive tests when this exact bounded family covers them.
	var baseline policy.TestSuite
	if yaml.Unmarshal(defaultpolicy.RegressionYAML, &baseline) == nil {
		for _, group := range [][]policy.TestCase{baseline.Allow, baseline.Ask, baseline.Deny} {
			for _, test := range group {
				inner := test.Command
				if parts := reviewRunagent.FindStringSubmatch(inner); parts != nil {
					inner = parts[1]
					if nested := reviewContainer.FindStringSubmatch(inner); nested != nil {
						inner = nested[1]
					}
				}
				re := regexp.MustCompile(candidate.Pattern)
				if re.MatchString(inner) && !strings.HasPrefix(inner, "runagent ") {
					result = append(result, test.Command)
				}
			}
		}
	}
	return unique(result)
}

func validateDifferential(before, after *policy.Engine, original policy.TestSuite, candidates []Candidate) error {
	allowedChanges := map[string]bool{}
	corpus := []string{"rm /tmp/file", "systemctl restart redis", "mystery command", "journalctl -u redis -n 1001", "podman logs --tail all redis"}
	for _, candidate := range candidates {
		re, err := regexp.Compile(candidate.Pattern)
		if err != nil {
			return err
		}
		for _, v := range candidate.PositiveTests {
			if !re.MatchString(v) {
				return errors.New("regexp does not match a documented positive case")
			}
		}
		for _, v := range positiveCases(candidate) {
			allowedChanges[v] = true
			corpus = append(corpus, v)
		}
		for _, v := range candidate.NegativeTests {
			if re.MatchString(v) {
				return errors.New("regexp admits a negative boundary case")
			}
			corpus = append(corpus, v, "runagent -m module1 "+v, "runagent -m module1 podman exec container1 "+v)
		}
	}
	// The bundled baseline is frozen into this tested Gate binary. A policy-only
	// upstream still receives the complete Gate regression corpus, differentially.
	var baseline policy.TestSuite
	decoder := yaml.NewDecoder(bytes.NewReader(defaultpolicy.RegressionYAML))
	decoder.KnownFields(true)
	if err := decoder.Decode(&baseline); err != nil {
		return err
	}
	for _, suite := range []policy.TestSuite{original, baseline} {
		for _, group := range [][]policy.TestCase{suite.Allow, suite.Ask, suite.Deny} {
			for _, test := range group {
				corpus = append(corpus, test.Command)
			}
		}
	}
	for _, v := range unique(corpus) {
		old, new := before.Evaluate("gt_review", v).Decision, after.Evaluate("gt_review", v).Decision
		if old == new {
			continue
		}
		if old != policy.Ask || new != policy.Allow || !allowedChanges[v] {
			return fmt.Errorf("undocumented policy classification change: %s -> %s", old, new)
		}
	}
	return nil
}

var reviewRunagent = regexp.MustCompile(`^runagent -m [a-zA-Z0-9][a-zA-Z0-9_.-]* (.+)$`)
var reviewContainer = regexp.MustCompile(`^podman exec [a-zA-Z0-9][a-zA-Z0-9_.-]* (.+)$`)
