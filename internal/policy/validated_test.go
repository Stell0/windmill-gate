package policy

import "testing"

func TestValidatedAsteriskConfigSlice(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp:    `^sed -n (?:"[0-9]+,[0-9]+p"|'[0-9]+,[0-9]+p') /etc/asterisk/pjsip\.endpoint\.conf$`,
		Validator: "asterisk_config_slice",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		`sed -n '11275,11325p' /etc/asterisk/pjsip.endpoint.conf`:    Allow,
		`sed -n "1,1000p" /etc/asterisk/pjsip.endpoint.conf`:         Allow,
		`sed -n '100,99p' /etc/asterisk/pjsip.endpoint.conf`:         Ask,
		`sed -n '1,1001p' /etc/asterisk/pjsip.endpoint.conf`:         Ask,
		`sed -n '1,20p' /etc/asterisk/pjsip.auth.conf`:               Ask,
		`sed -n '1,20p' /etc/asterisk/subdir/pjsip.conf`:             Ask,
		`sed -n '1,20p' /etc/asterisk/../shadow.conf`:                Ask,
		`sed -i '1,20p' /etc/asterisk/pjsip.endpoint.conf`:           Ask,
		`sed -n '1,20w /tmp/copy' /etc/asterisk/pjsip.endpoint.conf`: Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestValidatedDiagnosticReads(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^(?:ls|cat|tail|grep|egrep|pgrep)(?: .*)?$`, Validator: "diagnostic_read",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		"ls -lah /etc/asterisk":                    Allow,
		"ls /var/log/asterisk/..":                  Ask,
		"ls /var/log/*":                            Ask,
		"cat -n /var/log/messages /var/log/secure": Allow,
		"cat":             Ask,
		"cat /etc/shadow": Allow,
		"tail -n 999999999999999999 /var/log/messages": Allow,
		"tail --bytes=4096 /var/log/messages":          Allow,
		"tail -f /var/log/messages":                    Ask,
		"tail --retry /var/log/messages":               Ask,
		"grep -Ein 'error|fatal' /var/log/messages":    Allow,
		"egrep 'error|fatal' /var/log/asterisk/full":   Allow,
		"grep error":                                     Ask,
		"grep error /etc/shadow":                         Allow,
		"grep error /var/log/../lib/private":             Ask,
		"grep error /var/log/messages | cat /etc/shadow": Ask,
		"pgrep asterisk":                                 Allow,
		"pgrep -af 'asterisk main'":                      Allow,
		"pgrep --signal TERM asterisk":                   Ask,
		"pgrep -f $PROCESS":                              Ask,
	}
	for command, expected := range tests {
		t.Run(command, func(t *testing.T) {
			if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
				t.Fatalf("got %s, want %s", actual, expected)
			}
		})
	}
}

func TestPersistentRulesInheritThroughStrictWrappers(t *testing.T) {
	engine, err := New(Config{
		Allow: []string{`^stat -c '%n %s %y' /etc/asterisk/[a-z]+\.conf$`},
		ValidatedAllow: []ValidatedRule{{
			Regexp: `^pgrep(?: .*)?$`, Validator: "diagnostic_read",
		}},
		Deny: []string{`^systemctl restart(?: |$)`},
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		"runagent -m voice1 pgrep -af asterisk":                                              Allow,
		"runagent -m voice1 podman exec freepbx pgrep asterisk":                              Allow,
		"runagent -m voice1 podman exec freepbx stat -c '%n %s %y' /etc/asterisk/pjsip.conf": Allow,
		"runagent -m voice1 systemctl restart asterisk":                                      Deny,
		"runagent -m voice1 podman exec freepbx systemctl restart asterisk":                  Deny,
		"runagent -m voice1 systemctl restart asterisk*":                                     Deny,
		"runagent -m voice1 systemctl restart asterisk && echo changed":                      Deny,
		"runagent --module voice1 pgrep asterisk":                                            Ask,
		"runagent -m ../voice1 pgrep asterisk":                                               Ask,
		"runagent -m voice1 podman --log-level debug exec freepbx pgrep asterisk":            Ask,
		"runagent -m voice1 podman exec --user root freepbx pgrep asterisk":                  Ask,
		"runagent -m voice1 podman exec freepbx":                                             Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}

	if err := engine.AllowForTarget("gt_test", `^pgrep asterisk$`); err != nil {
		t.Fatal(err)
	}
	if got := engine.Evaluate("gt_test", "runagent -m voice1 pgrep asterisk").Decision; got != Allow {
		t.Fatalf("persistent inherited rule stopped matching: %s", got)
	}
	temporaryOnly, _ := New(Config{})
	_ = temporaryOnly.AllowForTarget("gt_test", `^pgrep asterisk$`)
	if got := temporaryOnly.Evaluate("gt_test", "runagent -m voice1 pgrep asterisk").Decision; got != Ask {
		t.Fatalf("temporary rule inherited through wrapper: %s", got)
	}
}

func TestValidatedMySQLRead(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^/usr/bin/mysql(?: .*)?$`, Validator: "mysql_read",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := `/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch asterisk -e `
	tests := map[string]Decision{
		prefix + `"SELECT * FROM users"`:                                         Allow,
		prefix + `'SELECT mailboxuser FROM voicemessages WHERE id=2571 LIMIT 1'`: Allow,
		prefix + `"SHOW TABLES"`:                                                 Allow,
		prefix + `"SHOW TABLES LIKE '%oicemail%'"`:                               Allow,
		prefix + `"SHOW TABLES LIKE %oicemail%"`:                                 Allow,
		prefix + `"SHOW COLUMNS FROM voicemail_users"`:                           Allow,
		prefix + `"SHOW INDEX FROM voicemail_users"`:                             Allow,
		prefix + `"SHOW CREATE TABLE voicemail_users"`:                           Allow,
		prefix + `"DESCRIBE voicemail_users"`:                                    Allow,
		prefix + `"SELECT id,extension,UPPER(name) AS upper_name FROM users WHERE enabled = 1 AND (extension = '100' OR LOWER(name) LIKE '%alice%') ORDER BY extension ASC LIMIT 100 OFFSET 0"`: Allow,
		prefix + `"SELECT REPLACE(name,'old','new') FROM users WHERE users.extension <> '' ORDER BY users.extension DESC LIMIT 0,50"`:                                                           Allow,
		`/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch asteriskcdrdb -e 'SELECT mailboxuser FROM voicemessages WHERE id=2571 LIMIT 1'`:                                                Allow,
		prefix + `"UPDATE users SET name='x'"`:                                                        Ask,
		prefix + `"INSERT INTO users VALUES (1)"`:                                                     Ask,
		prefix + `"DELETE FROM users"`:                                                                Ask,
		prefix + `"TRUNCATE TABLE users"`:                                                             Ask,
		prefix + `"SHOW VARIABLES"`:                                                                   Ask,
		prefix + `"SELECT * FROM users JOIN devices ON users.id = devices.user_id"`:                   Allow,
		prefix + `"SELECT * FROM users UNION SELECT * FROM devices"`:                                  Ask,
		prefix + `"SELECT * FROM users WHERE id = (SELECT id FROM devices)"`:                          Ask,
		prefix + `"SELECT @version FROM users"`:                                                       Ask,
		prefix + `"SELECT * FROM users; DELETE FROM users"`:                                           Ask,
		prefix + `"SELECT * FROM users -- comment"`:                                                   Ask,
		prefix + `"SELECT * FROM users INTO OUTFILE '/tmp/users'"`:                                    Ask,
		prefix + `"SELECT SLEEP(10) FROM users"`:                                                      Ask,
		prefix + `"SELECT * FROM users FOR UPDATE"`:                                                   Ask,
		prefix + `"SELECT * FROM users LIMIT 0"`:                                                      Ask,
		`/usr/bin/mysql --defaults-file=/tmp/client.cnf -N --batch asterisk -e "SELECT * FROM users"`: Ask,
		`/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch mysql -e "SELECT * FROM users"`:      Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestValidatedMySQLShellRead(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^runagent -m [a-zA-Z0-9][a-zA-Z0-9_.-]* podman exec mariadb sh -c .+$`, Validator: "mysql_shell_read",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := `runagent -m nethvoice9 podman exec mariadb sh -c 'mysql -uroot -p${MARIADB_ROOT_PASSWORD} -N -B `
	tests := map[string]Decision{
		prefix + `asterisk -e \"SELECT mailboxuser FROM voicemessages WHERE id=2571 LIMIT 1\"'`:                                      Allow,
		prefix + `asteriskcdrdb -e \"SELECT mailboxuser FROM voicemessages WHERE id=2571 LIMIT 1\"'`:                                 Allow,
		prefix + `asterisk -e \"SHOW TABLES\"'`:                                                                                      Allow,
		prefix + `asterisk -e "DESCRIBE voicemail_users"'`:                                                                           Allow,
		prefix + `asterisk -e \"UPDATE voicemail_users SET attach='yes'\"'`:                                                          Ask,
		prefix + `asterisk -e \"SELECT mailbox FROM voicemail_users; DELETE FROM voicemail_users\"'`:                                 Ask,
		prefix + `mysql -e \"SELECT mailbox FROM voicemail_users\"'`:                                                                 Ask,
		`runagent -m nethvoice9 podman exec other sh -c 'mysql -uroot -p${MARIADB_ROOT_PASSWORD} -N -B asterisk -e \"SHOW TABLES\"'`: Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestLegacyMySQLSelectValidatorRemainsSelectOnly(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^/usr/bin/mysql(?: .*)?$`, Validator: "mysql_select",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := `/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch asterisk -e `
	if actual := engine.Evaluate("gt_test", prefix+`"SELECT * FROM users"`).Decision; actual != Allow {
		t.Fatalf("legacy SELECT = %s, want %s", actual, Allow)
	}
	if actual := engine.Evaluate("gt_test", prefix+`"SHOW TABLES"`).Decision; actual != Ask {
		t.Fatalf("legacy SHOW = %s, want %s", actual, Ask)
	}
}

func TestValidatedContainerGrep(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^runagent -m [a-zA-Z0-9][a-zA-Z0-9_.-]* podman exec [a-zA-Z0-9][a-zA-Z0-9_.-]* grep(?: .*)?$`, Validator: "container_grep",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		`runagent -m nethvoice9 podman exec nethcti-server grep -n getVoicemailNewMsg /app/plugins/dbconn/plugins/dbconn_voicemail.js /app/plugins/dbconn/dbconn_main.js /app/plugins/voicemail/voicemail.js`: Allow,
		`runagent -m nethvoice42 podman exec freepbx grep -nE '^[[:space:]]*(mailcmd|attach)[[:space:]]*=' /etc/asterisk/voicemail.conf`:                                                                      Allow,
		`runagent -m mail1 podman exec postfix grep -i error /var/log/maillog /var/log/messages`:                                                                                                              Allow,
		`runagent -m nethvoice9 podman exec freepbx grep password /run/secrets/database`:                                                                                                                      Ask,
		`runagent -m nethvoice9 podman exec freepbx grep root /etc/shadow`:                                                                                                                                    Ask,
		`runagent -m nethvoice9 podman exec freepbx grep password /app/.env`:                                                                                                                                  Ask,
		`runagent -m nethvoice9 podman exec freepbx grep root /app/../etc/shadow`:                                                                                                                             Ask,
		`runagent -m nethvoice9 podman exec freepbx grep password /app/config | cat`:                                                                                                                          Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestUIDJournalValidatorChecksDatesOrderAndBounds(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^journalctl .+$`, Validator: "uid_journal",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000`:                                                                  Allow,
		`journalctl _UID=1020 --since="2026-09-03 06:45:00 UTC" --until="2026-09-03 08:30:00 UTC" --no-pager -o short-iso-precise -n 500`:                                                         Allow,
		`journalctl _UID=1020 --since="2026-09-03 06:45:00 UTC" --until="2026-09-03 08:30:00 UTC" --no-pager -o short-iso-precise -n 500 -g 00000000-0000-4000-8000-000000000001@example.invalid`: Allow,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000 -g 12345`:                                                         Allow,
		`journalctl _UID=1020 --since=2026-13-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000`:                                                                  Ask,
		`journalctl _UID=1020 --since=2026-09-03T09:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000`:                                                                  Ask,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1001`:                                                                  Ask,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000 -g all`:                                                           Ask,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000 -g call`:                                                          Ask,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000 -g abcdefgh`:                                                      Ask,
		`journalctl _UID=1020 --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000 -g '.*'`:                                                          Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestValidatedRTPengineReadChecksWrapperAndSingleSessionScope(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^runagent -m nethvoice-proxy[0-9]+ podman exec rtpengine rtpengine-ctl(?: .*)?$`, Validator: "rtpengine_read",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]Decision{
		`runagent -m nethvoice-proxy1 podman exec rtpengine rtpengine-ctl --help`:                                             Allow,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions call-00000001@example.invalid`:       Allow,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions 12345`:                               Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions all`:                                 Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions own`:                                 Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions foreign`:                             Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions abcdefgh`:                            Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions '12345'`:                             Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl list sessions call-00000001@example.invalid extra`: Ask,
		`runagent -m nethvoice42 podman exec rtpengine rtpengine-ctl list sessions call-00000001@example.invalid`:             Ask,
		`runagent -m nethvoice-proxy42 podman exec other rtpengine-ctl list sessions call-00000001@example.invalid`:           Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl terminate call-00000001@example.invalid`:           Ask,
		`runagent -m nethvoice-proxy42 podman exec rtpengine rtpengine-ctl set timeout 30`:                                    Ask,
	}
	for command, expected := range tests {
		if actual := engine.Evaluate("gt_test", command).Decision; actual != expected {
			t.Errorf("Evaluate(%q) = %s, want %s", command, actual, expected)
		}
	}
}

func TestValidatedAllowRejectsUnknownValidator(t *testing.T) {
	if _, err := New(Config{ValidatedAllow: []ValidatedRule{{Regexp: `^x$`, Validator: "unknown"}}}); err == nil {
		t.Fatal("unknown validator was accepted")
	}
}
