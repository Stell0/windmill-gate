package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScopedJournalGrammarBounds(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^journalctl .+$`, Validator: "scoped_journal",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	base := "journalctl _UID=1001 --since=2026-10-22T08:00:00Z --no-pager -n 1000"
	for _, command := range []string{
		base,
		base + ` --grep="error|fail" --case-sensitive=no`,
		"runagent -m module1 " + base,
		"journalctl -t " + strings.Repeat("a", 128) + " --no-pager -n 1",
		"journalctl --user -u web.service --since=2026-10-22T08:00:00Z --until=2026-10-22T09:00:00Z --no-pager -n 1000",
	} {
		if got := engine.Evaluate("gt_test", command).Decision; got != Allow {
			t.Errorf("%q = %s, want ALLOW", command, got)
		}
	}
	for _, command := range []string{
		"journalctl --no-pager -n 1000",
		"journalctl _UID=0 --no-pager -n 1000",
		"journalctl _UID=10000000000 --no-pager -n 1000",
		"journalctl _UID=1001 --no-pager",
		"journalctl -t " + strings.Repeat("a", 129) + " --no-pager -n 1",
		base + " -t tag",
		base + " --user -u web.service",
		"journalctl --user --no-pager -n 100",
		"journalctl -u web.service --no-pager -n 100",
		"journalctl --user -u ../web.service --no-pager -n 100",
		"journalctl --user -u web.service --user --no-pager -n 100",
		"journalctl --user -u web.service -u worker.service --no-pager -n 100",
		base + " --no-pager",
		base + " -o short-iso-precise -o short-iso-precise",
		base + ` --grep="error|fail" --grep="warn|denied"`,
		base + ` --grep="error|fail" --case-sensitive=yes`,
		base + " --grep=" + strings.Repeat("a", 257),
		base + ` --grep="` + strings.Repeat("error|", 16) + `fail"`,
		base + ` --grep="error|Łail"`,
		base + ` --grep="error|\d+"`,
		base + ` --grep="error|[a-z]"`,
		base + ` --grep="error|$(uptime)"`,
		base + " --since=now",
		base + " --no-pager=yes",
		base + "\n",
		"runagent -m module1 runagent -m module2 " + base,
	} {
		if got := engine.Evaluate("gt_test", command).Decision; got != Ask {
			t.Errorf("%q = %s, want ASK", command, got)
		}
	}
}

func TestReviewedJournalFiltersCannotBeExtended(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^journalctl .+$`, Validator: "scoped_journal",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	// These fixtures are independent of the validator's allow set.
	filters := []string{
		"ERROR:|FATAL:|Cannot reload|reload.*fail|Traceback|permission denied|assertion|reconfigur|status is|update-module.d",
		"Starting FreePBX|Started FreePBX|Failed to start FreePBX|freepbx.service:.*(timeout|dependency|timed out)",
		"mariadb.service:.*(timed out|timeout)|Starting mariadb server|Started mariadb server|Failed to start mariadb server",
		"tancredi.service:|Dependency failed for tancredi server|Starting tancredi server|Started tancredi server|Stopped tancredi server",
	}
	for _, filter := range filters {
		base := "journalctl _UID=1001 --no-pager -n 100 --grep="
		if got := engine.Evaluate("gt_test", base+"'"+filter+"'").Decision; got != Allow {
			t.Errorf("reviewed filter %q = %s, want ALLOW", filter, got)
		}
		for _, unsafe := range []string{filter + "|.*", filter + "(a+)+$", "(?i)" + filter, filter + `\d+`} {
			if got := engine.Evaluate("gt_test", base+"'"+unsafe+"'").Decision; got != Ask {
				t.Errorf("modified filter %q = %s, want ASK", unsafe, got)
			}
		}
	}
}

func TestContainerStateProjectionBounds(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	format := " --format '{{.Name}} image={{.ImageName}} status={{.State.Status}} pid={{.State.Pid}} exit={{.State.ExitCode}} started={{.State.StartedAt}} finished={{.State.FinishedAt}}'"
	for _, test := range []struct {
		names string
		want  Decision
	}{
		{"web1", Allow},
		{strings.Repeat("a", 128), Allow},
		{strings.TrimSpace(strings.Repeat("web1 ", 8)), Allow},
		{strings.TrimSpace(strings.Repeat("web1 ", 9)), Ask},
		{strings.Repeat("a", 129), Ask},
		{"", Ask},
		{"--latest", Ask},
		{"web*", Ask},
	} {
		for _, prefix := range []string{"", "runagent -m module1 "} {
			command := prefix + "podman inspect " + test.names + format
			if got := engine.Evaluate("gt_test", command).Decision; got != test.want {
				t.Errorf("%q = %s, want %s", command, got, test.want)
			}
		}
	}
}
