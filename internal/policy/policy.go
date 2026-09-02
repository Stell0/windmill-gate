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
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
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

type Engine struct {
	allow []compiledRule
	deny  []compiledRule

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
	return &Engine{allow: allow, deny: deny, temporary: make(map[string][]compiledRule)}, nil
}

func New(config Config) (*Engine, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func (e *Engine) Evaluate(targetID, command string) Result {
	for _, rule := range e.deny {
		if rule.regexp.MatchString(command) {
			return Result{Decision: Deny, Rule: rule.pattern, Source: "persistent"}
		}
	}

	// Shell composition cannot become automatically allowed through the first
	// regex engine. A future parser can make narrower, tested exceptions.
	if HasUnsafeComposition(command) {
		return Result{Decision: Ask, Source: "default"}
	}

	e.mu.RLock()
	for _, rule := range e.temporary[targetID] {
		if rule.regexp.MatchString(command) {
			e.mu.RUnlock()
			return Result{Decision: Allow, Rule: rule.pattern, Source: "target"}
		}
	}
	e.mu.RUnlock()

	for _, rule := range e.allow {
		if rule.regexp.MatchString(command) {
			return Result{Decision: Allow, Rule: rule.pattern, Source: "persistent"}
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

var unsafeComposition = regexp.MustCompile("(?:;|&&|\\||>>|>|<|\\$\\(|`|\\n|\\r)")

func HasUnsafeComposition(command string) bool {
	return unsafeComposition.MatchString(command)
}
