package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDiagnosticFileBoundaries(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		"date --iso-8601=seconds":                           Allow,
		"date --set=2026-10-22":                             Ask,
		"findmnt -n -o SOURCE,FSTYPE,TARGET --target /home": Allow,
		"findmnt -n -o SOURCE,FSTYPE,TARGET --target /root": Ask,
		"sha256sum /home/module1/.config/bin/check /home/module2/.config/update-module.d/80restart /home/module3/.config/systemd/user/web.service": Allow,
		"sha256sum /home/module1/.config/environment":                                          Ask,
		"sha256sum /home/module1/.config/bin/../../secret":                                     Ask,
		"sha256sum /home/module1/.config/systemd/user/web.timer":                               Ask,
		"sha256sum --check /home/module1/.config/bin/check":                                    Ask,
		"printenv NETHVOICE_HOST":                                                              Allow,
		"printenv NETHVOICE_TANCREDI_IMAGE NETHVOICE_REPORTS_UI_IMAGE":                         Allow,
		"printenv AGENT_INSTALL_DIR AGENT_STATE_DIR SATELLITE_VOICEMAIL_TRANSCRIPTION_ENABLED": Allow,
		"printenv":                       Allow,
		"printenv MARIADB_ROOT_PASSWORD": Allow,
		"printenv NETHVOICE_HOST MARIADB_ROOT_PASSWORD": Allow,
		"podman top web1":                                                                  Allow,
		"podman top --latest":                                                              Ask,
		"podman top web1 environ":                                                          Ask,
		"sed -n 68,160p /var/lib/asterisk/bin/send_email":                                  Allow,
		"sed -n '1140,1200p' /etc/kamailio/kamailio.cfg":                                   Allow,
		"sed -n \"1,1000p\" /etc/rtpengine/rtpengine.conf":                                 Allow,
		"sed -n 1,20p /app/plugins/example.js":                                             Allow,
		"sed -n 1,20p /var/log/messages":                                                   Allow,
		"sed -n 0,20p /etc/kamailio/kamailio.cfg":                                          Ask,
		"sed -n 20,1p /etc/kamailio/kamailio.cfg":                                          Ask,
		"sed -n 1,1001p /etc/kamailio/kamailio.cfg":                                        Allow,
		"sed -n 999999999999999999999,999999999999999999999p /etc/kamailio/kamailio.cfg":   Ask,
		"sed -n 1,20p /etc/shadow":                                                         Allow,
		"sed -n 1,20p /app/.env":                                                           Allow,
		"sed -n 1,20p /app/../etc/shadow":                                                  Ask,
		"sed -n 1,20p /etc/asterisk/pjsip.auth.conf":                                       Allow,
		"sed -n 1,20p *":                                                                   Ask,
		"sed -i -n 1,20p /etc/kamailio/kamailio.cfg":                                       Ask,
		"sed -n '1,20w /tmp/out' /etc/kamailio/kamailio.cfg":                               Ask,
		"sed -n '1,20e' /etc/kamailio/kamailio.cfg":                                        Ask,
		"grep -nE 'direction|rtpengine' /etc/kamailio/kamailio.cfg":                        Allow,
		"grep -E '^(interface|listen-ng|port-min|port-max)' /etc/rtpengine/rtpengine.conf": Allow,
		"grep -RsnE 'voice|tableName' /app/plugins/dbconn/sequelize_models":                Allow,
		"grep -nE 'Attachment|mailcmd' /var/lib/asterisk/bin/send_email":                   Allow,
		"grep -RniE 'allow|codec' /etc/asterisk /initdb.d/update.php":                      Allow,
		"grep -n error /var/www/html/freepbx/admin/modules/nethcti3/functions.inc.php":     Allow,
		"grep -n password /run/secrets/database":                                           Allow,
		"grep -n password /app/.env":                                                       Allow,
		"grep -R root /etc":                                                                Allow,
		"grep -n error /var/www/html/freepbx/admin/modules/../../config.php":               Ask,
		"asterisk -rx 'dialplan show *201@ext-local'":                                      Allow,
		"asterisk -rx \"dialplan show cti-profile-3\"":                                     Allow,
		"asterisk -rx 'dialplan show cti-profile-3;module load pbx_config.so'":             Ask,
		"stat -c '%n|%W|%w|%Y|%y' /home/module1 /home/module2":                             Allow,
		"stat -c %n|%W|%w|%Y|%y /home/module1":                                             Ask,
		"stat -c '%n|%W|%w|%Y|%y' /etc/shadow":                                             Ask,
	}
	for command, want := range tests {
		for _, prefix := range []string{"", "runagent -m module1 ", "runagent -m module1 podman exec web1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != want {
				t.Errorf("%q = %s, want %s", prefix+command, got, want)
			}
		}
	}
}

func TestCaptureAndTLSBoundaries(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	live := "timeout 120 tcpdump -ni any -s0 -U -c 48 -w /tmp/gate-example.pcap 'udp port 5060 or tcp port 5060 or udp port 20030 or tcp port 20030'"
	boundedTime := "timeout 60 tcpdump -ni any -s0 -U -w /tmp/gate-example.pcap 'udp port 5060'"
	replay := "tcpdump -nn -tttt -A -r /tmp/gate-example.pcap -c 60"
	probe := "timeout 12 openssl s_client -connect example.invalid:5061 -servername example.invalid -verify_hostname example.invalid -verify_return_error < /dev/null 2>&1"
	for _, command := range []string{live, boundedTime, replay, probe} {
		for _, prefix := range []string{"", "runagent -m module1 "} {
			if got := engine.Evaluate("gt_test", prefix+command).Decision; got != Allow {
				t.Errorf("%q = %s, want ALLOW", prefix+command, got)
			}
			for _, suffix := range []string{"; uptime", " && uptime", " || uptime", " | cat", " > /tmp/out", " >> /tmp/out", " $(uptime)", " `uptime`", "\n", " # comment"} {
				if got := engine.Evaluate("gt_test", prefix+command+suffix).Decision; got == Allow {
					t.Errorf("unsafe composition allowed: %q", prefix+command+suffix)
				}
			}
		}
	}
	for _, command := range []string{
		strings.Replace(live, "timeout 120", "timeout 181", 1),
		strings.Replace(live, "timeout 120", "timeout 0", 1),
		strings.TrimPrefix(live, "timeout 120 "),
		strings.Replace(live, "-c 48", "-c 1001", 1),
		strings.Replace(live, "-c 48", "-c 0", 1),
		strings.Replace(live, "/tmp/gate-example.pcap", "/etc/shadow", 1),
		strings.Replace(live, "/tmp/gate-example.pcap", "-", 1),
		strings.Replace(live, "/tmp/gate-example.pcap", "/tmp/gate-../secret.pcap", 1),
		strings.Replace(live, "port 5060", "port 22", 1),
		strings.Replace(live, "-U", "-U -z /tmp/program", 1),
		strings.Replace(live, "-U", "-U -G 1 -W 100", 1),
		strings.Replace(replay, "-c 60", "-c 1001", 1),
		strings.TrimSuffix(replay, " -c 60"),
		strings.Replace(probe, "timeout 12", "timeout 31", 1),
		strings.Replace(probe, ":5061", ":22", 1),
		strings.Replace(probe, "-servername example.invalid", "-servername other.invalid", 1),
		strings.Replace(probe, "-verify_hostname example.invalid", "-verify_hostname other.invalid", 1),
		strings.Replace(probe, "example.invalid", "-bad.invalid", -1),
		strings.Replace(probe, "example.invalid", "bad..invalid", -1),
		strings.Replace(probe, " -verify_return_error", "", 1),
		strings.Replace(probe, " < /dev/null", " < /etc/shadow", 1),
		strings.Replace(probe, "2>&1", "2>/tmp/out", 1),
		strings.Replace(probe, " < /dev/null 2>&1", "", 1),
		"runagent -m module1 runagent -m module2 " + probe,
		"runagent -m module1 podman exec web1 " + probe,
		"uptime < /dev/null 2>&1",
		"sh -c '" + probe + "'",
	} {
		if got := engine.Evaluate("gt_test", command).Decision; got == Allow {
			t.Errorf("unsafe capture/probe allowed: %q", command)
		}
	}
}

func TestTLSRedirectClassificationPreservesOriginalText(t *testing.T) {
	payload := "runagent -m module1 timeout 12 openssl s_client -connect example.invalid:443 -servername example.invalid -verify_hostname example.invalid -verify_return_error < /dev/null 2>&1"
	views, err := commandViews(payload)
	if err != nil || len(views) != 2 || views[0].text != payload {
		t.Fatalf("TLS classification changed or rejected original bytes: views=%v err=%v", views, err)
	}
	engine, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Evaluate("gt_test", payload).Decision; got != Ask {
		t.Fatalf("TLS syntax alone bypassed policy: got %s", got)
	}
}
