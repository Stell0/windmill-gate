// Package policy implements Gate's deliberately conservative three-way policy.
package policy

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type Decision string

const (
	Allow Decision = "ALLOW"
	Ask   Decision = "ASK"
	Deny  Decision = "DENY"
)

type Config struct {
	Allow          []string        `yaml:"allow"`
	ValidatedAllow []ValidatedRule `yaml:"validated_allow"`
	Deny           []string        `yaml:"deny"`
}

// ValidatedRule combines a coarse regexp with a named semantic validator. The
// regexp keeps policy files readable; the validator proves argument-level
// safety before the command can be automatically allowed.
type ValidatedRule struct {
	Regexp    string `yaml:"regexp"`
	Validator string `yaml:"validator"`
}

type Result struct {
	Decision Decision
	Rule     string
	Source   string
}

type compiledRule struct {
	pattern string
	regexp  *regexp.Regexp
}

type compiledValidatedRule struct {
	compiledRule
	validator string
}

type Engine struct {
	allow          []compiledRule
	validatedAllow []compiledValidatedRule
	deny           []compiledRule

	mu        sync.RWMutex
	temporary map[string][]compiledRule
}

func Load(path string) (*Engine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	return Parse(data)
}

func Parse(data []byte) (*Engine, error) {
	var config Config
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}
	allow, err := compileRules("allow", config.Allow)
	if err != nil {
		return nil, err
	}
	deny, err := compileRules("deny", config.Deny)
	if err != nil {
		return nil, err
	}
	validatedAllow, err := compileValidatedRules(config.ValidatedAllow)
	if err != nil {
		return nil, err
	}
	return &Engine{allow: allow, validatedAllow: validatedAllow, deny: deny, temporary: make(map[string][]compiledRule)}, nil
}

func New(config Config) (*Engine, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (e *Engine) Evaluate(targetID, command string) Result {
	views, parseErr := commandViews(command)
	for _, view := range views {
		for _, rule := range e.deny {
			if rule.regexp.MatchString(view.text) {
				return Result{Decision: Deny, Rule: rule.pattern, Source: "persistent"}
			}
		}
	}

	// A malformed or shell-composed payload is never automatically allowed.
	// DENY rules were intentionally checked first so dangerous commands retain
	// their stronger classification when their outer text matches a deny rule.
	if parseErr != nil {
		return Result{Decision: Ask, Source: "default"}
	}

	// Target-scoped rules apply only to the submitted outer payload. They are
	// never inherited by runagent or podman wrapper views.
	e.mu.RLock()
	for _, rule := range e.temporary[targetID] {
		if rule.regexp.MatchString(views[0].text) {
			e.mu.RUnlock()
			return Result{Decision: Allow, Rule: rule.pattern, Source: "target"}
		}
	}
	e.mu.RUnlock()

	for _, view := range views {
		for _, rule := range e.allow {
			if rule.regexp.MatchString(view.text) {
				return Result{Decision: Allow, Rule: rule.pattern, Source: "persistent"}
			}
		}
		for _, rule := range e.validatedAllow {
			if rule.regexp.MatchString(view.text) && validators[rule.validator](view.words) {
				return Result{Decision: Allow, Rule: rule.pattern, Source: "persistent"}
			}
		}
	}
	return Result{Decision: Ask, Source: "default"}
}

// AllowForTarget installs a memory-only rule. It is never written to Config.
func (e *Engine) AllowForTarget(targetID, pattern string) error {
	if targetID == "" {
		return errors.New("target ID is required")
	}
	compiled, err := compileRules("temporary allow", []string{pattern})
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.temporary[targetID] = append(e.temporary[targetID], compiled[0])
	return nil
}

func (e *Engine) TemporaryRules(targetID string) []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rules := e.temporary[targetID]
	result := make([]string, len(rules))
	for i, rule := range rules {
		result[i] = rule.pattern
	}
	return result
}

func (e *Engine) DetachTarget(targetID string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.temporary, targetID)
}

func compileRules(kind string, patterns []string) ([]compiledRule, error) {
	rules := make([]compiledRule, 0, len(patterns))
	for index, pattern := range patterns {
		if pattern == "" {
			return nil, fmt.Errorf("%s rule %d is empty", kind, index+1)
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("compile %s rule %d: %w", kind, index+1, err)
		}
		rules = append(rules, compiledRule{pattern: pattern, regexp: compiled})
	}
	return rules, nil
}

func compileValidatedRules(config []ValidatedRule) ([]compiledValidatedRule, error) {
	rules := make([]compiledValidatedRule, 0, len(config))
	for index, item := range config {
		if item.Regexp == "" {
			return nil, fmt.Errorf("validated_allow rule %d regexp is empty", index+1)
		}
		if _, ok := validators[item.Validator]; !ok {
			return nil, fmt.Errorf("validated_allow rule %d has unknown validator %q", index+1, item.Validator)
		}
		compiled, err := regexp.Compile(item.Regexp)
		if err != nil {
			return nil, fmt.Errorf("compile validated_allow rule %d: %w", index+1, err)
		}
		rules = append(rules, compiledValidatedRule{
			compiledRule: compiledRule{pattern: item.Regexp, regexp: compiled},
			validator:    item.Validator,
		})
	}
	return rules, nil
}

func HasUnsafeComposition(command string) bool {
	_, err := tokenizeShell(command)
	return err != nil
}
