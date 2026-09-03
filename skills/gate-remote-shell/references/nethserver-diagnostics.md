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
runagent -m <module-id> podman logs --tail 200 <container>
runagent -m <module-id> podman logs --tail 500 --since 1h --timestamps <container>
```

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
runagent -m <nethvoice-module-id> podman exec freepbx pgrep asterisk
runagent -m <nethvoice-module-id> podman exec freepbx asterisk -rx 'pjsip show transports'
runagent -m <nethvoice-module-id> podman exec freepbx asterisk -rx 'pjsip show contacts'
```

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
