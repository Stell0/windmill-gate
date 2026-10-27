package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestApprovedNS7DiagnosticBoundaries(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	observed := []string{
		"cat /etc/nethserver-release",
		"date -Is",
		"httpd -t",
		"systemctl is-active httpd httpd-fpbx rh-php73-php-fpm rh-php56-php-fpm asterisk",
	}
	tests := map[string]Decision{
		"systemctl is-active example.service":                               Allow,
		"systemctl is-active example@instance.service":                      Allow,
		"systemctl is-active " + strings.Repeat("a", 128):                   Allow,
		"systemctl is-active " + strings.TrimSpace(strings.Repeat("a ", 8)): Allow,
		"systemctl is-active " + strings.Repeat("a", 129):                   Ask,
		"systemctl is-active " + strings.TrimSpace(strings.Repeat("a ", 9)): Ask,
		"systemctl is-active":                                               Ask,
		"systemctl is-active --all":                                         Ask,
		"systemctl is-active --wait httpd":                                  Ask,
		"systemctl is-active httpd --quiet":                                 Ask,
		"systemctl is-active -bad.service":                                  Ask,
		"systemctl is-active /etc/httpd":                                    Ask,
		"systemctl is-active ../httpd":                                      Ask,
		"systemctl is-active 'httpd'":                                       Ask,
		"cat /etc/nethserver-release /etc/shadow":                           Allow,
		"cat /etc/nethserver-release/../shadow":                             Ask,
		"date -Is -s 2026-01-01":                                            Ask,
		"httpd -t -f /tmp/config":                                           Ask,
		"httpd -t -D DUMP_CONFIG":                                           Ask,
		"httpd -k start":                                                    Ask,
		"systemctl restart httpd":                                           Deny,
		"unknown-ns7-diagnostic":                                            Ask,
	}
	for _, command := range observed {
		tests[command] = Allow
	}
	prefixes := []string{"", "runagent -m module1 ", "runagent -m module1 podman exec container1 "}
	for command, want := range tests {
		for _, prefix := range prefixes {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != want {
				t.Errorf("%q = %s, want %s", prefix+command, got, want)
			}
		}
	}
	for _, command := range observed {
		for _, prefix := range prefixes {
			for _, suffix := range []string{
				"; uptime", " && uptime", " || uptime", " | cat", " > /tmp/output",
				" >> /tmp/output", " < /tmp/input", " $(uptime)", " `uptime`",
				"\n", "\r", "\t", "\x00", "\x1b", " # comment", " --unexpected",
			} {
				if got := engine.Evaluate("gt_test", prefix+command+suffix).Decision; got == Allow {
					t.Errorf("unsafe diagnostic allowed: %q", prefix+command+suffix)
				}
			}
			if got := engine.Evaluate("gt_test", prefix+command+"; rm /tmp/file").Decision; got != Deny {
				t.Errorf("DENY precedence lost for %q: %s", prefix+command, got)
			}
		}
		for _, prefix := range []string{
			"runagent -m ../module1 ",
			"runagent -m module1 runagent -m module2 ",
			"runagent -m module1 podman exec --privileged container1 ",
			"runagent -m module1 podman exec container1 podman exec container2 ",
		} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got == Allow {
				t.Errorf("unsupported wrapper allowed: %q", prefix+command)
			}
		}
	}
}
