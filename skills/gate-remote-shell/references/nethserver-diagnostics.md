# NethServer diagnostics through Gate

Use this reference for read-only NethServer 8 inspection through `gate-sh`. It
adapts the NethServer administration workflow to Gate's one-command/one-decision
model. Replace placeholders with concrete names learned from earlier output;
never send the angle brackets literally.

Every line in the code blocks below is the value of one `-c` argument. Submit
commands one at a time and parse structured output locally. Do not join them
with `;`, `&&`, a pipe, redirection, or a shell wrapper.

## Diagnostic ladder

Start with identity and capacity:

```bash
hostnamectl --static
id
cat /etc/os-release
uptime
df -h
free -h
cat /proc/sys/fs/file-nr
findmnt -n -o TARGET --target /home
```

When installation order matters, first learn concrete module IDs from inventory,
then compare only their home-directory metadata with the fixed safe format:

```bash
stat -c "%n %W %w %Y %y" /home/<module-id> /home/<another-module-id>
```

Then inspect cluster inventory and host health:

```bash
api-cli --help
api-cli run get-cluster-status
api-cli run list-installed-modules
api-cli run list-actions
systemctl --no-pager --type=service --state=failed
journalctl -p err -b --no-pager -n 100
podman ps -a
```

Use `list-installed-modules` output to choose a concrete `<module-id>`. For each
relevant rootless module, inspect user services and containers:

```bash
api-cli run module/<module-id>/list-actions
api-cli run module/<module-id>/get-status
runagent -m <module-id> systemctl --user --failed --no-legend --no-pager
runagent -m <module-id> podman ps -a
runagent -m <module-id> podman ps -a --format '{{.Names}} [Status:{{.Status}}] [Restarts:{{.Restarts}}]'
```

Do not generate module IDs or use `runagent` on a module assigned to another
node. Gate does not switch nodes or targets; ask the operator to attach the
correct target when necessary.

## Focus a failed service

For a host service:

```bash
systemctl status <unit>.service --no-pager
systemctl show <unit>.service --property=LoadState,ActiveState,SubState,Result,ExecMainStatus,ExecStart,FragmentPath --no-pager
systemctl cat <unit>.service --no-pager
journalctl -u <unit>.service --no-pager -n 200
```

For a rootless module service:

```bash
runagent -m <module-id> systemctl --user status <unit>.service --no-pager
runagent -m <module-id> systemctl --user status {<unit>,<another-unit>}.service --no-pager
runagent -m <module-id> systemctl --user show <unit>.service --property=ActiveState,SubState,Result,NRestarts,ExecMainStatus,ActiveEnterTimestamp --no-pager
runagent -m <module-id> journalctl --user -u <unit>.service --no-pager -n 200
```

If the rootless journal reports insufficient permissions, resolve the numeric
module UID first, wait for it, then issue a root journal query with that number:

```bash
id -u <module-id>
journalctl _UID=<numeric-uid> -p err --no-pager -n 100
```

An old failed unit can coexist with a currently healthy replacement. Compare
failure timestamps, active units from `get-status`, container uptime, and restart
counts before concluding the module is currently down. Do not restart or reset a
failed unit as part of diagnosis.

## Logs

Read bounded logs and never use `--follow` or `-f`:

```bash
api-server-logs logs --entity module --name <module-id> --mode dump --lines 500 --timezone UTC
ls -lah /var/log
tail -n 5000 /var/log/messages
grep -Ein 'error|fatal' /var/log/messages
runagent -m <module-id> podman logs --tail 200 <container>
runagent -m <module-id> podman logs --tail 500 --since 1h --timestamps <container>
```

Gate validates standalone `ls` paths and recognized read-only options. For
`cat`, `tail`, `grep`, and `egrep`, every file operand must be a clean lexical
path under `/var/log`; stdin-only forms, traversal, globs, expansions, unknown
options, and tail follow controls remain subject to operator review. Large
non-following tail counts are safe because Gate still enforces its output cap.

Central log queries must use `--mode dump`, at most 1000 lines, syntactically
safe entity/instance/search values, and optional ISO-8601 `--from`/`--to`
bounds. If centralized logs are empty or fail, use the bounded journal fallback
instead of switching to follow mode.

For an exact module-user journal window, resolve the UID first and use either
UTC timestamp form below. The line limit remains mandatory:

```bash
journalctl _UID=<numeric-uid> --since=2026-09-03T06:45:00Z --until=2026-09-03T08:30:00Z --no-pager -o short-iso-precise -n 1000
journalctl _UID=<numeric-uid> --since="2026-09-03 06:45:00 UTC" --until="2026-09-03 08:30:00 UTC" --no-pager -o short-iso-precise -n 1000
```

When `sqlite3` is installed, the persistent policy permits fixed audit-metadata
queries over recent tasks, optionally narrowed to the four installation actions
and one concrete module queue. They deliberately omit task payload data and
must not end in a semicolon:

```bash
sqlite3 -readonly -json /var/lib/nethserver/api-server/audit.db "SELECT id,user,json_extract(data,'$.action') AS task_action,json_extract(data,'$.queue') AS task_queue,json_extract(data,'$.timestamp') AS requested_at,timestamp AS audited_at FROM audit WHERE action='create-task' ORDER BY id DESC LIMIT 50"
```

Process that JSON locally. Arbitrary SQLite statements, alternate database
paths, audit payload reads, dot commands, and file-reading functions remain
subject to operator review even with `-readonly`.

Many NS8 containers use the journald log driver, so empty `podman logs` output
does not prove that the service emitted no logs. Use the module-user journal
fallback above. Check whether Loki labels are available before depending on
`logcli`:

```bash
logcli labels -q
logcli labels module_id -q
```

Empty label output together with a failed log collector is evidence that the
central log path is unavailable; use bounded journal queries and report the
collector failure separately.

## Cluster metadata and routes

These read-only commands help explain missing or stale module records:

```bash
redis-cli --raw HGETALL cluster/module_node
redis-cli --scan --pattern 'module/<module-id>/*'
api-cli run list-routes --agent module/traefik1
api-cli run module/traefik1/list-actions
api-cli run get-route --agent module/traefik1 --data '{"instance":"<route-instance>"}'
```

Compare Redis membership with installed-module inventory and key scans. A module
listed in `cluster/module_node` but absent from installed modules and without
module keys is likely stale metadata; report it, but do not delete Redis data.

Route results may contain public hostnames and local service endpoints. Summarize
only what is relevant and never confuse a route instance with a Gate target or a
private backend session identifier.

## Networking

Use these host-level reads to understand reachability without probing unrelated
external systems:

```bash
ip route show
ip addr show
firewall-cmd --get-active-zones
firewall-cmd --list-all-zones
```

Separate a local service failure from a remote dependency timeout. Confirm local
provider status with its module `get-status`; if it is healthy, report the remote
address and timeout as an external dependency issue rather than changing the
local provider.

## NethVoice checks

Use exact, read-only commands in the `freepbx` container:

```bash
runagent -m <nethvoice-module-id> podman exec freepbx pgrep -af asterisk
runagent -m <nethvoice-module-id> podman exec freepbx asterisk -rx 'pjsip show transports'
runagent -m <nethvoice-module-id> podman exec freepbx asterisk -rx 'pjsip show contacts'
runagent -m <nethvoice-module-id> podman exec freepbx asterisk -rx 'core show channels concise'
runagent -m <nethvoice-module-id> podman exec freepbx stat -c '%n %s %y' /etc/asterisk/pjsip.conf /etc/asterisk/extensions.conf
runagent -m <nethvoice-module-id> podman exec freepbx /usr/bin/mysql --defaults-file=/root/.my.cnf -N --batch asterisk -e "SELECT extension,name FROM users ORDER BY extension LIMIT 100"
```

The Asterisk CLI policy accepts only quoted commands beginning with `module
show`, `core show`, `database show`, or `pjsip show`, plus the existing exact
`queue show` check. The MySQL form above is parsed as one SELECT over one normal
table. Joins, unions, subqueries, variables, comments, writes, output/locking
clauses, unrecognized functions, alternate credentials/options/databases, and
unsafe shell quoting require an operator decision.

A live Asterisk PID plus configured transports and available contacts establishes
increasingly stronger evidence: process alive, signaling listeners configured,
then peers reachable. Keep those conclusions separate.

Repeated missing upload-file errors often indicate stale scheduled input rather
than a platform-wide outage. A service that crashed on malformed network input
and then shows `NRestarts=1`, `ActiveState=active`, and `Result=success` recovered,
but the malformed-input crash remains worth reporting.

## Stop conditions

Stop and request explicit operator direction before any command that would:

- install, update, remove, configure, restart, stop, enable, disable, or reset a service;
- write Redis state or delete stale metadata;
- edit files, permissions, routes, certificates, firewall rules, or container state;
- display credentials or module configuration likely to contain secrets;
- start an interactive/following command or bypass Gate through direct SSH.

Conclude with the observed evidence, current impact, uncertainty, and the smallest
next diagnostic or remediation step. Distinguish historical failures from active
ones and local faults from remote dependencies.
