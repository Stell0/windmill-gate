package policy

import "testing"

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
		"cat /etc/shadow": Ask,
		"tail -n 999999999999999999 /var/log/messages": Allow,
		"tail --bytes=4096 /var/log/messages":          Allow,
		"tail -f /var/log/messages":                    Ask,
		"tail --retry /var/log/messages":               Ask,
		"grep -Ein 'error|fatal' /var/log/messages":    Allow,
		"egrep 'error|fatal' /var/log/asterisk/full":   Allow,
		"grep error":                                     Ask,
		"grep error /etc/shadow":                         Ask,
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

func TestValidatedMySQLSelect(t *testing.T) {
	engine, err := New(Config{ValidatedAllow: []ValidatedRule{{
		Regexp: `^/usr/bin/mysql(?: .*)?$`, Validator: "mysql_select",
	}}})
	if err != nil {
		t.Fatal(err)
	}
	prefix := `/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch asterisk -e `
	tests := map[string]Decision{
		prefix + `"SELECT * FROM users"`: Allow,
		prefix + `"SELECT id,extension,UPPER(name) AS upper_name FROM users WHERE enabled = 1 AND (extension = '100' OR LOWER(name) LIKE '%alice%') ORDER BY extension ASC LIMIT 100 OFFSET 0"`: Allow,
		prefix + `"SELECT REPLACE(name,'old','new') FROM users WHERE users.extension <> '' ORDER BY users.extension DESC LIMIT 0,50"`:                                                           Allow,
		prefix + `"UPDATE users SET name='x'"`:                                                        Ask,
		prefix + `"SELECT * FROM users JOIN devices ON users.id = devices.user_id"`:                   Ask,
		prefix + `"SELECT * FROM users UNION SELECT * FROM devices"`:                                  Ask,
		prefix + `"SELECT * FROM users WHERE id = (SELECT id FROM devices)"`:                          Ask,
		prefix + `"SELECT @version FROM users"`:                                                       Ask,
		prefix + `"SELECT * FROM users; DELETE FROM users"`:                                           Ask,
		prefix + `"SELECT * FROM users -- comment"`:                                                   Ask,
		prefix + `"SELECT * FROM users INTO OUTFILE '/tmp/users'"`:                                    Ask,
		prefix + `"SELECT SLEEP(10) FROM users"`:                                                      Ask,
		prefix + `"SELECT * FROM users FOR UPDATE"`:                                                   Ask,
		prefix + `"SELECT * FROM users LIMIT 0"`:                                                      Ask,
		prefix + `'SELECT * FROM users'`:                                                              Ask,
		`/usr/bin/mysql --defaults-file=/tmp/client.cnf -N --batch asterisk -e "SELECT * FROM users"`: Ask,
		`/usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch mysql -e "SELECT * FROM users"`:      Ask,
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

func TestValidatedAllowRejectsUnknownValidator(t *testing.T) {
	if _, err := New(Config{ValidatedAllow: []ValidatedRule{{Regexp: `^x$`, Validator: "unknown"}}}); err == nil {
		t.Fatal("unknown validator was accepted")
	}
}
