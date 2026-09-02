package policy

import (
	"bytes"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type TestCase struct {
	Command string   `yaml:"command"`
	Expect  Decision `yaml:"expect"`
}

type TestSuite struct {
	Allow []TestCase `yaml:"allow"`
	Ask   []TestCase `yaml:"ask"`
	Deny  []TestCase `yaml:"deny"`
}

type TestFailure struct {
	Command string
	Expect  Decision
	Actual  Decision
}

func LoadTestSuite(path string) (TestSuite, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return TestSuite{}, fmt.Errorf("read policy tests: %w", err)
	}
	var suite TestSuite
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&suite); err != nil {
		return TestSuite{}, fmt.Errorf("parse policy tests: %w", err)
	}
	return suite, nil
}

func (s TestSuite) Run(engine *Engine) (int, []TestFailure) {
	all := make([]TestCase, 0, len(s.Allow)+len(s.Ask)+len(s.Deny))
	all = append(all, s.Allow...)
	all = append(all, s.Ask...)
	all = append(all, s.Deny...)
	failures := make([]TestFailure, 0)
	for _, test := range all {
		actual := engine.Evaluate("gt_policy_test", test.Command).Decision
		if actual != test.Expect {
			failures = append(failures, TestFailure{Command: test.Command, Expect: test.Expect, Actual: actual})
		}
	}
	return len(all), failures
}
