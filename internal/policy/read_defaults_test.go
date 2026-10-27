package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorAuthorizedReads(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	// These reads intentionally include credential files and command arguments.
	// The operator authorized their contents, not arbitrary executing programs.
	allowed := []string{
		"cat /entrypoint", "cat /freepbx_init.sh", "cat /etc/shadow",
		"cat -n /etc/freepbx.conf /run/secrets/database", "cat module.xml",
		"tail -n 200 /etc/asterisk/pjsip.auth.conf", "grep password /app/.env",
		`sed -n "1,25p" /var/www/html/freepbx/admin/modules/core/module.xml`,
		"sed -n 1,1000p /run/secrets/database",
		`grep -nE "profile|audit|log" /var/www/html/freepbx/rest/modules/cti.php`,
		`grep -nE "password" /run/secrets/database /etc/shadow`,
		`sed -n "1,100000p" /etc/shadow`,
		"journalctl", "journalctl --no-pager", "journalctl -b -1 -n all",
		"journalctl --lines=10000 --boot=0 --output=json-pretty",
		`journalctl _UID=1008 --since "2026-10-27 08:21:31" --until "2026-10-27 08:21:34" --no-pager -n 400 -o json`,
		`journalctl --user -u freepbx.service --since "20 minutes ago" --no-pager -n 120 --grep "error|Error|ERROR|fatal|Fatal|failed|Failed|timeout|timed out|Exception"`,
		`journalctl _UID=1008 --since "15 minutes ago" --no-pager -n 80 --grep 'Undefined array key "account"|terminated by SIGSEGV|RCONFFAIL|Failed to start FreePBX'`,
		`journalctl --since=yesterday -o json --output-fields=MESSAGE --grep='error.*(account|mailbox)'`,
		`journalctl -u 'web*.service' -u worker.service --since=-1h --case-sensitive=yes -g 'error|Łail'`,
		"journalctl -k -b0 -pwarning -n100 -ojson",
		"journalctl --disk-usage", "journalctl --list-boots", "journalctl -F MESSAGE",
		"journalctl _UID=0 + _SYSTEMD_UNIT=web.service",
		`journalctl --directory=/var/log/journal --file='/var/log/journal/*.journal' --header`,
		"journalctl --cursor=cursor1 --after-cursor=cursor2 --show-cursor",
		"journalctl --follow", "journalctl -f", "journalctl -nf", "journalctl -bf",
		"journalctl -n 100 -f", "journalctl --rotate", "journalctl --vacuum-size=1M",
		"journalctl --vacuum-time 1h", "journalctl --vacuum-files=1", "journalctl --flush",
		"journalctl --sync", "journalctl --relinquish-var", "journalctl --smart-relinquish-var",
		"journalctl --setup-keys", "journalctl --update-catalog",
		"journalctl --cursor-file=/tmp/cursor", "journalctl --cursor-file /tmp/cursor",
		"journalctl --image=/dev/sda", "journalctl --unexpected", "journalctl --grep",
		`podman ps -a --format "{{.Names}} {{.Image}} {{.Status}}"`,
		`podman ps -a --format '{{json .}}'`,
		`podman ps -a --format '{{printf "%s" .Names}}'`,
		`podman ps -a --format ""`,
		`podman inspect freepbx --format "{{json .Config.Entrypoint}} {{json .Config.Cmd}}"`,
		`podman inspect --format '{{.Config.Entrypoint}} {{.Config.Cmd}}' freepbx web1`,
		`podman container inspect web1 -f '{{json .Args}}'`,
		`podman inspect --format='{{.Path}} {{json .Args}}' web1`,
	}
	for _, command := range allowed {
		for _, prefix := range []string{"", "runagent -m module1 ", "podman exec web1 ", "runagent -m module1 podman exec web1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != Allow {
				t.Errorf("%q = %s, want ALLOW", prefix+command, got)
			}
		}
	}
	blocked := []string{
		"cat", "cat -", "cat --unexpected /etc/passwd", "cat /etc/../shadow",
		"tail -f /etc/passwd", "tail --follow /etc/passwd", "grep password",
		"sed -i -n 1,25p /etc/passwd", "sed -n '1,25e' /etc/passwd",
		"sed -n '1,25w /tmp/out' /etc/passwd",
		`sed -n "18446744073709551616,18446744073709551617p" /etc/passwd`,
		`podman ps -a --format "{{json .}}" --watch`,
		`podman ps -a --format "$(touch /tmp/probe)"`,
		`podman --remote ps -a --format '{{json .}}'`,
		`podman ps -a --format '{{json .}}'suffix`,
		`python3 -c 'print("journalctl")'`,
		"podman inspect web1", `podman inspect web1 --format '{{json .Config.Env}}'`,
		`podman inspect web1 --format '{{json .Config}}'`,
		`podman inspect web1 --format '{{printf "%s" .Config.Cmd}}'`,
		`podman inspect web1 --format '{{.Config.Cmd}}' --format '{{.Args}}'`,
		`podman inspect --latest --format '{{.Config.Cmd}}'`,
	}
	for _, command := range blocked {
		for _, prefix := range []string{"", "runagent -m module1 ", "podman exec web1 ", "runagent -m module1 podman exec web1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got == Allow {
				t.Errorf("%q unexpectedly ALLOW", prefix+command)
			}
		}
	}
	for _, command := range allowed {
		for _, suffix := range []string{"; uptime", " && uptime", " | cat", " > /tmp/out", " $(uptime)", " `uptime`", "\n"} {
			if got := engine.Evaluate("gt_test", command+suffix).Decision; got == Allow {
				t.Errorf("composition unexpectedly ALLOW: %q", command+suffix)
			}
		}
	}
}

func TestBroadAuthorizationPreservesDenyAndUnknownDefaults(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for command, want := range map[string]Decision{
		"journalctl --rotate; rm /tmp/file":                           Deny,
		"journalctlx --rotate":                                        Ask,
		"sed -n '1,20e' /etc/shadow":                                  Ask,
		"runagent -m module1 podman exec --user root web1 journalctl": Ask,
	} {
		if got := engine.Evaluate("gt_test", command).Decision; got != want {
			t.Errorf("%q = %s, want %s", command, got, want)
		}
	}
}

func TestNestedWrapperCannotMatchIntermediateRule(t *testing.T) {
	for _, rule := range []string{
		`^runagent -m module2 podman exec freepbx cat /entrypoint$`,
		`^podman exec freepbx cat /entrypoint$`,
		`^cat /entrypoint$`,
	} {
		engine, err := New(Config{Allow: []string{rule}, Deny: []string{`(^| )rm( |$)`}})
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{
			"runagent -m module1 runagent -m module2 podman exec freepbx cat /entrypoint",
			"podman exec web1 podman exec freepbx cat /entrypoint",
			"runagent -m module1 podman exec web1 podman exec freepbx cat /entrypoint",
			"runagent -m module1 podman exec web1 runagent -m module2 cat /entrypoint",
		} {
			if got := engine.Evaluate("gt_test", command).Decision; got != Ask {
				t.Errorf("nested wrapper = %s, want ASK: %q", got, command)
			}
			if got := engine.Evaluate("gt_test", command+"; rm /tmp/file").Decision; got != Deny {
				t.Errorf("DENY precedence lost: %s", got)
			}
		}
	}
}

func TestStartupProjectionBounds(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		names string
		want  Decision
	}{
		{strings.TrimSpace(strings.Repeat("web1 ", 8)), Allow},
		{strings.TrimSpace(strings.Repeat("web1 ", 9)), Ask},
		{strings.Repeat("a", 128), Allow}, {strings.Repeat("a", 129), Ask},
	} {
		command := "podman inspect " + test.names + " --format '{{json .Config.Cmd}}'"
		if got := engine.Evaluate("gt_test", command).Decision; got != test.want {
			t.Errorf("%q = %s, want %s", command, got, test.want)
		}
	}
}
