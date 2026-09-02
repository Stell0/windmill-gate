package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nethserver/gate/internal/backend"
)

func TestChooseTargetNeverDisplaysBackendID(t *testing.T) {
	targets := []backend.Target{
		{ID: "windmill-secret-4837291", DisplayName: "customer-a"},
		{ID: "windmill-secret-998", DisplayName: "customer-b"},
	}
	var output bytes.Buffer
	selected, err := chooseTarget(targets, "", strings.NewReader("2\n"), &output)
	if err != nil {
		t.Fatal(err)
	}
	if selected.ID != "windmill-secret-998" {
		t.Fatalf("wrong private selection: %#v", selected)
	}
	if strings.Contains(output.String(), "windmill-secret") || strings.Contains(output.String(), "4837291") {
		t.Fatalf("operator target picker exposed backend ID: %s", output.String())
	}
}

func TestPolicyTestCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"policy", "test", "--policy", filepath.Join("..", "..", "policy", "default.yaml"), "--tests", filepath.Join("..", "..", "policy", "tests", "default.yaml")}, strings.NewReader(""), &stdout, &stderr)
	if exitCode != 0 || !strings.Contains(stdout.String(), "PASS:") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", exitCode, stdout.String(), stderr.String())
	}
}

func TestExecRequiresOneExactArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if exitCode := run([]string{"exec", "uptime", "extra"}, strings.NewReader(""), &stdout, &stderr); exitCode != 2 {
		t.Fatalf("exit=%d, want usage error", exitCode)
	}
}
