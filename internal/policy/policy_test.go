package policy

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

type policyTests struct {
	Allow []testCase `yaml:"allow"`
	Ask   []testCase `yaml:"ask"`
	Deny  []testCase `yaml:"deny"`
}

type testCase struct {
	Command string   `yaml:"command"`
	Expect  Decision `yaml:"expect"`
}

func TestDefaultPolicyCases(t *testing.T) {
	root := filepath.Join("..", "..")
	engine, err := Load(filepath.Join(root, "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "policy", "tests", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var suite policyTests
	if err := yaml.Unmarshal(data, &suite); err != nil {
		t.Fatal(err)
	}
	for _, group := range [][]testCase{suite.Allow, suite.Ask, suite.Deny} {
		for _, test := range group {
			t.Run(string(test.Expect)+"/"+test.Command, func(t *testing.T) {
				if got := engine.Evaluate("gt_test", test.Command).Decision; got != test.Expect {
					t.Fatalf("got %s, want %s", got, test.Expect)
				}
			})
		}
	}
}

func TestDenyWinsAndUnknownDefaultsToAsk(t *testing.T) {
	engine, err := New(Config{Allow: []string{`^systemctl .+$`}, Deny: []string{`^systemctl restart\b`}})
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Evaluate("gt_1", "systemctl restart redis").Decision; got != Deny {
		t.Fatalf("deny did not win: %s", got)
	}
	if got := engine.Evaluate("gt_1", "mystery command").Decision; got != Ask {
		t.Fatalf("unknown command did not ASK: %s", got)
	}
}

func TestShellCompositionNeverMatchesAllow(t *testing.T) {
	engine, err := New(Config{Allow: []string{`^uptime.*$`}})
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"uptime; reboot", "uptime && reboot", "uptime | sh", "uptime > /tmp/result",
		"uptime $(reboot)", "uptime `reboot`", "uptime\nreboot",
	} {
		if got := engine.Evaluate("gt_1", command).Decision; got != Ask {
			t.Errorf("%q = %s, want ASK", command, got)
		}
	}
}

func TestTemporaryRuleIsTargetScopedAndExpires(t *testing.T) {
	engine, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := engine.AllowForTarget("gt_one", `^journalctl -u redis -n [0-9]+$`); err != nil {
		t.Fatal(err)
	}
	if got := engine.Evaluate("gt_one", "journalctl -u redis -n 200").Decision; got != Allow {
		t.Fatalf("temporary rule not applied: %s", got)
	}
	if got := engine.Evaluate("gt_two", "journalctl -u redis -n 200").Decision; got != Ask {
		t.Fatalf("temporary rule escaped target: %s", got)
	}
	engine.DetachTarget("gt_one")
	if got := engine.Evaluate("gt_one", "journalctl -u redis -n 200").Decision; got != Ask {
		t.Fatalf("temporary rule survived detach: %s", got)
	}
}
