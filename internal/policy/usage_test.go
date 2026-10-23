package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRequestedDiagnosticArgumentBounds(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		"systemctl --user show " + strings.TrimSpace(strings.Repeat("web.service ", 8)) + " --property=Id --no-pager": Allow,
		"systemctl --user show " + strings.TrimSpace(strings.Repeat("web.service ", 9)) + " --property=Id --no-pager": Ask,
		"systemctl --user show " + strings.Repeat("a", 128) + " web.service --property=Id --no-pager":                 Allow,
		"systemctl --user show " + strings.Repeat("a", 129) + " web.service --property=Id --no-pager":                 Ask,
		"systemctl --user show '*.service' --property=Id --no-pager":                                                  Ask,
		"ps -p " + strings.TrimSuffix(strings.Repeat("1,", 16), ",") + " -o pid,lstart,etime,args":                    Allow,
		"ps -p " + strings.TrimSuffix(strings.Repeat("1,", 17), ",") + " -o pid,lstart,etime,args":                    Ask,
		"ps -p 9999999 -o pid,lstart,etime,args":                                                                      Allow,
		"ps -p 10000000 -o pid,lstart,etime,args":                                                                     Ask,
		"ps -p 01 -o pid,lstart,etime,args":                                                                           Ask,
	}
	for _, sampler := range []string{"iostat -xz", "vmstat", "vmstat -d"} {
		for _, args := range []string{"1 1", "10 10"} {
			tests[sampler+" "+args] = Allow
		}
		for _, args := range []string{"0 1", "1 0", "11 1", "1 11", "01 1", "1 01", "999999999999999999 1", "1", ""} {
			tests[sampler+" "+args] = Ask
		}
	}
	for command, want := range tests {
		for _, prefix := range []string{"", "runagent -m module1 ", "runagent -m module1 podman exec web1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != want {
				t.Errorf("%q = %s, want %s", prefix+command, got, want)
			}
		}
	}
}
