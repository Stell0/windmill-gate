package policy

import (
	"path/filepath"
	"strings"
	"testing"
)

func mysqlShellCommand(query string) string {
	script := `mysql -uroot -p${MARIADB_ROOT_PASSWORD} -N -B asterisk -e "` + query + `"`
	return `runagent -m module1 podman exec mariadb sh -c '` + strings.ReplaceAll(script, `'`, `'\''`) + `'`
}

func TestExpandedMySQLReads(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		"SELECT COUNT(*) AS total,SUM(r.profile_id IS NULL OR r.profile_id=0) AS unassigned,SUM(r.profile_id IS NOT NULL AND r.profile_id<>0 AND p.id IS NULL) AS missing FROM rest_users r LEFT JOIN rest_cti_profiles p ON p.id=r.profile_id",
		"SELECT u.username,r.profile_id FROM rest_users r JOIN userman_users u ON u.id=r.user_id LEFT JOIN rest_cti_profiles p ON p.id=r.profile_id WHERE r.profile_id IS NOT NULL AND r.profile_id<>0 AND p.id IS NULL ORDER BY u.username LIMIT 100",
		"SELECT u.username FROM rest_users r JOIN userman_users u ON u.id=r.user_id WHERE r.profile_id IS NULL OR r.profile_id=0 ORDER BY u.username LIMIT 100",
		"SELECT u.username,u.id,r.profile_id,p.name FROM userman_users u LEFT JOIN rest_users r ON r.user_id=u.id LEFT JOIN rest_cti_profiles p ON p.id=r.profile_id WHERE u.username IN ('alice','bob') ORDER BY u.username",
		"SELECT DISTINCT u.username FROM users AS u INNER JOIN devices AS d ON d.user_id=u.id",
		"SELECT p.*,u.name FROM profiles p RIGHT OUTER JOIN users u ON p.id=u.profile_id",
		"SELECT u.name,d.name FROM users u CROSS JOIN devices d",
		"SELECT u.name,d.name FROM users u,devices d WHERE u.id=d.user_id",
		"SELECT profile_id,COUNT(DISTINCT user_id),AVG(user_id),MIN(user_id),MAX(user_id) FROM rest_users GROUP BY profile_id HAVING COUNT(*)>1 ORDER BY profile_id LIMIT 20",
		"SELECT 1,NULL,TRUE,LOWER('DROP'),REPLACE('INSERT','UPDATE','DELETE')",
		"SELECT username FROM users WHERE username NOT IN ('alice','bob') AND NOT (id=0)",
		"SELECT * FROM users WHERE name='DROP; DELETE FROM users'",
	}
	for _, query := range queries {
		t.Run(query, func(t *testing.T) {
			if got := engine.Evaluate("gt_test", mysqlShellCommand(query)).Decision; got != Allow {
				t.Errorf("read query = %s, want ALLOW", got)
			}
		})
	}
}

func TestExpandedMySQLRejectsWritesAndShellInjection(t *testing.T) {
	engine, err := Load(filepath.Join("..", "..", "policy", "default.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	queries := []string{
		"INSERT INTO users VALUES (1)", "UPDATE users SET id=1", "DELETE FROM users",
		"TRUNCATE TABLE users", "DROP TABLE users", "ALTER TABLE users ADD x INT",
		"CREATE TABLE x (id INT)", "REPLACE INTO users VALUES (1)", "RENAME TABLE users TO x",
		"GRANT ALL ON asterisk.* TO someone", "REVOKE ALL ON asterisk.* FROM someone",
		"SET GLOBAL general_log=1", "CALL change_users()", "LOAD DATA INFILE '/tmp/in' INTO TABLE users",
		"SELECT * FROM users INTO OUTFILE '/tmp/out'", "SELECT * FROM users INTO DUMPFILE '/tmp/out'",
		"SELECT * FROM users FOR UPDATE", "SELECT * FROM users LOCK IN SHARE MODE",
		"SELECT * FROM users; DELETE FROM users", "SELECT * FROM users /* comment */",
		"SELECT * FROM users -- comment", "SELECT * FROM users # comment",
		"SELECT SLEEP(10)", "SELECT GET_LOCK('x',10)", "SELECT RELEASE_LOCK('x')",
		"SELECT LOAD_FILE('/etc/shadow')", "SELECT sys_exec('touch /tmp/probe')",
		"SELECT COUNT (id) FROM users", "SELECT SUM (id) FROM users", "SELECT MAX (id) FROM users",
		"SELECT COUNT(LOAD_FILE('/etc/shadow')) FROM users", "SELECT asterisk.unknown() FROM users",
		"SELECT @x:=1 FROM users", "SELECT COUNT(*) FROM users INTO @x",
		"SELECT * FROM users UNION SELECT * FROM devices",
		"SELECT * FROM users WHERE id IN (SELECT id FROM devices)",
		"SELECT * FROM users LEFT JOIN devices ON users.id=devices.user_id INTO OUTFILE '/tmp/out'",
		"SELECT * FROM users WHERE name='$(touch /tmp/probe)'",
		"SELECT * FROM users WHERE name='`touch /tmp/probe`'",
		"SELECT * FROM users WHERE name='$HOME'",
		`SELECT * FROM users WHERE name='"; touch /tmp/probe; echo "'`,
		`SELECT * FROM users WHERE name='\'; touch /tmp/probe'`,
		"SELECT COUNT(" + strings.Repeat("SUM(", 100) + "id" + strings.Repeat(")", 101) + ") FROM users",
	}
	for _, query := range queries {
		if got := engine.Evaluate("gt_test", mysqlShellCommand(query)).Decision; got == Allow {
			t.Errorf("unsafe query unexpectedly ALLOW: %q", query)
		}
	}
	// Escaped quote delimiters leave the SQL unquoted in sh; reject operators
	// there even when the same bytes would be valid read-only SQL.
	for _, query := range []string{"SELECT id FROM users WHERE id>0", "SELECT COUNT(*) FROM users", "SELECT id FROM users WHERE name='$(touch /tmp/probe)'"} {
		command := `runagent -m module1 podman exec mariadb sh -c 'mysql -uroot -p${MARIADB_ROOT_PASSWORD} -N -B asterisk -e \"` + query + `\"'`
		if got := engine.Evaluate("gt_test", command).Decision; got == Allow {
			t.Errorf("unquoted SQL shell syntax unexpectedly ALLOW: %q", command)
		}
	}
	for _, suffix := range []string{"; touch /tmp/probe", " && uptime", " > /tmp/out", " | cat", "\n"} {
		if got := engine.Evaluate("gt_test", mysqlShellCommand("SELECT COUNT(*) FROM users")+suffix).Decision; got == Allow {
			t.Errorf("composed SQL unexpectedly ALLOW: %q", suffix)
		}
	}
}
