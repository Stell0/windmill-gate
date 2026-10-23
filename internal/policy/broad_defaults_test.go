package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestBroadDefaultPolicyBoundaries(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	// These are classification tests, never production executions. Credential
	// reads and getters with possible side effects are intentionally allowed by
	// the operator-approved broad defaults, rather than assumed to be read-only.
	tests := map[string]Decision{
		"api-cli run module/mail1/get-configuration":                    Allow,
		"api-cli run module/nethvoice1/get-phonebook-credentials":       Allow,
		"api-cli run module/nethvoice1/get-ports-list":                  Allow,
		"api-cli run module/nethvoice1/get-port-migration-status":       Allow,
		"api-cli run module/other1/list-service-providers":              Allow,
		"api-cli run module/other1/get-not-yet-reviewed":                Allow,
		"api-cli run module/" + strings.Repeat("a", 128) + "/get-state": Allow,
		"api-cli run module/m1/get-" + strings.Repeat("a", 64):          Allow,
		"api-cli run module/" + strings.Repeat("a", 129) + "/get-state": Ask,
		"api-cli run module/m1/get-" + strings.Repeat("a", 65):          Ask,
		"api-cli run module/m1/get-":                                    Ask,
		"api-cli run module/m1/list-":                                   Ask,
		"api-cli run module/m1/get-State":                               Ask,
		"api-cli run module/m1/get-state2":                              Ask,
		"api-cli run module/m1/get_state":                               Ask,
		"api-cli run module/../m1/get-state":                            Ask,
		"api-cli run module/-m1/get-state":                              Ask,
		"api-cli run module/m1/set-configuration":                       Ask,
		"api-cli run module/m1/destroy-module":                          Ask,
		"api-cli run module/m1/get-state --data '{}'":                   Ask,
		"api-cli run get-configuration --agent module/m1":               Ask,
		"firewall-cmd --info-service=ssh":                               Allow,
		"firewall-cmd --info-service=nethvoice-proxy1":                  Allow,
		"firewall-cmd --info-service=" + strings.Repeat("a", 128):       Allow,
		"firewall-cmd --info-service=" + strings.Repeat("a", 129):       Ask,
		"firewall-cmd --info-service=":                                  Ask,
		"firewall-cmd --info-service=--reload":                          Ask,
		"firewall-cmd --info-service=../ssh":                            Ask,
		"firewall-cmd --info-service=ssh --permanent":                   Ask,
		"firewall-cmd --reload":                                         Ask,
		"firewall-cmd --add-service=ssh":                                Ask,
		"janus --help":                                                  Allow,
		"janus --version":                                               Allow,
		"/usr/local/bin/janus --help":                                   Allow,
		"/usr/local/bin/janus --version":                                Allow,
		"/tmp/janus --help":                                             Ask,
		"janus":                                                         Ask,
		"janus --debug-level=7":                                         Ask,
		"janus --help --daemon":                                         Ask,
		"janus --version --stun-server=example.invalid":                 Ask,
		"printenv":                   Allow,
		"printenv PATH HOME _CUSTOM": Allow,
		"printenv MARIADB_ROOT_PASSWORD OIDC_CLIENT_SECRET API_TOKEN": Allow,
		"printenv " + strings.Repeat("A", 64):                         Allow,
		"printenv " + strings.Repeat("A", 65):                         Ask,
		"printenv " + strings.TrimSpace(strings.Repeat("PATH ", 15)):  Allow,
		"printenv " + strings.TrimSpace(strings.Repeat("PATH ", 16)):  Ask,
		"printenv --null":      Ask,
		"printenv PATH --null": Ask,
		"printenv 9INVALID":    Ask,
		"printenv BAD-NAME":    Ask,
		"printenv BAD.NAME":    Ask,
		"printenv $HOME":       Ask,
		"unknown-command":      Ask,
	}
	for command, want := range tests {
		for _, prefix := range []string{"", "runagent -m module1 ", "runagent -m module1 podman exec container1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != want {
				t.Errorf("%q = %s, want %s", prefix+command, got, want)
			}
		}
	}
}

func TestBroadDefaultPolicyKeepsShellAndWrapperBoundaries(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{
		"api-cli run module/nethvoice1/get-ports-list",
		"firewall-cmd --info-service=ssh",
		"janus --help",
		"/usr/local/bin/janus --version",
		"printenv",
		"printenv API_TOKEN",
	} {
		for _, prefix := range []string{"", "runagent -m module1 ", "runagent -m module1 podman exec container1 "} {
			for _, suffix := range []string{
				"; uptime", " && uptime", " || uptime", " | sh", " > /tmp/output",
				" >> /tmp/output", " < /tmp/input", " $(uptime)", " `uptime`",
				"\n", "\r", "\t", "\x00", "\x1b", " # comment", " --unexpected",
			} {
				if got := engine.Evaluate("gt_test", prefix+command+suffix).Decision; got == Allow {
					t.Errorf("shell composition unexpectedly allowed: %q", prefix+command+suffix)
				}
			}
			if got := engine.Evaluate("gt_test", prefix+command+"; rm /tmp/file").Decision; got != Deny {
				t.Errorf("DENY precedence lost for %q: %s", prefix+command, got)
			}
		}
		for _, prefix := range []string{
			"runagent -m -bad ", "runagent -m ../module1 ",
			"runagent -m module1 runagent -m module2 ",
			"runagent -m module1 podman exec --privileged container1 ",
			"runagent -m module1 podman exec container1 podman exec container2 ",
		} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got == Allow {
				t.Errorf("unsupported wrapper unexpectedly allowed: %q", prefix+command)
			}
		}
	}
}
