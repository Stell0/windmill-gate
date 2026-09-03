# Gate

> Working name. Gate is a human-controlled command bridge for agent-assisted production support.

Gate lets an agentic harness such as Codex, Claude Code, or Hermes execute diagnostic commands on a remote production server without giving the agent direct access to the underlying Windmill session.

The agent sees a shell-like interface. Gate decides whether each command is automatically allowed, requires human approval, or is denied. Approved commands are executed through the existing Bastion/Windmill/Sancho access path and stdout, stderr, and exit status are returned to the agent.

Gate does **not** replace Windmill. Windmill remains the remote-access transport and customer connectivity layer.

## Implementation status

Gate v0.1-v0.3 is implemented in this repository as one Go module and one binary:

- `gate`: daemon, operator console, shell client, local/remote protocol bridge, forwarding, history, policy tests, and policy review.

`make build` creates `bin/gate-sh` as a symlink to the same binary; invocation through that name selects the shell-compatible one-command client.

The implementation includes opaque targets, immutable SHA-256-bound approvals, `ALLOW`/`ASK`/`DENY` policy, SQLite audit history, multiple attached clients and targets, cancellation, restricted SSH hosting, loopback forwards, owned host aliases, agent skills, and a policy pull-request workflow that never merges or deploys.

### Build and verify

Go 1.25 or newer is required.

```bash
make build
make test
make test-race
make policy-test
```

The binary is written to `bin/gate`, with a `bin/gate-sh` symlink.

### Sancho command contract

Gate keeps Windmill as the transport. Its adapter connects to the configured Bastion with `ssh` and expects these Sancho primitives on that host:

```text
sancho session list --json
sancho session exec <session-id> -- <exact-command-payload>
sancho session forward <session-id> \
  --listen-host 127.0.0.1 --listen-port <port> \
  --remote-host 127.0.0.1 --remote-port <port>
```

`session list --json` may return either an array containing `id` plus `name` or `host`, or a stream of JSON objects containing `session` plus `server`. `session exec` must preserve the final command argument as exact bytes and return the remote exit status. `session forward` must remain attached while the target-scoped forward is active. These are external Sancho capabilities; Gate deliberately does not reproduce Windmill connectivity. Backend IDs used in these calls are redacted from agent-visible output and errors.

Legacy Sancho 0.0.1 installations expose `session`, `server`, and `vpn` but only provide an interactive `session ssh` helper that discards the remote exit status. For this format, Gate revalidates the selected session immediately before use, then uses the Sancho-reported private VPN address to run a constrained nested SSH command through the Bastion. The approved payload remains the exact `sh -lc` argument, and the nested SSH status is returned to the agent. The target SSH port defaults to `981` and can be changed with `--target-ssh-port`. Neither the private session ID nor VPN address is returned to agents. Legacy forwards use the same selected target metadata and still terminate at target loopback.

### Local quick start

Start Gate with the interactive operator console. The target selector prints display names and numbers, never Windmill IDs:

```bash
bin/gate --bastion operator@bastion.example --agent codex-1
```

An operator who already knows the private Windmill session ID can select it without exposing it through the target picker or agent protocol:

```bash
bin/gate --bastion operator@bastion.example --agent codex-1 --session '<session-id>'
```

`--session` is operator-only and mutually exclusive with `--target`. The existing `--target` option continues to accept a display name or displayed number.

In another terminal, submit exactly one command:

```bash
bin/gate-sh --agent codex-1 -c 'uname -a'
```

Unknown commands wait in the operator console. Use `a` to approve once, `s` for a memory-only similar rule scoped to that target until detach, or `d` to deny. `gate daemon` runs without the console and is therefore suitable only when submitted commands are already classified `ALLOW` or `DENY`.

Default local paths are:

```text
$XDG_RUNTIME_DIR/gate.sock
$XDG_DATA_HOME/gate/gate.db
$XDG_CONFIG_HOME/gate/policy.yaml
```

The policy file is bootstrapped from `policy/default.yaml` when absent. The database and socket are mode `0600`.

### Hosted Gate over restricted SSH

Copy `config/ssh-clients.example.yaml` to `~/.config/gate/ssh-clients.yaml` and map each authorized key fingerprint to its audit identity. Start the Gate daemon/operator console on the host, attach that identity to a Gate target, and restrict its public key:

```text
command="GATE_SSH_KEY_FINGERPRINT=SHA256:... /usr/local/bin/gate ssh-server",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty <public-key>
```

The static fingerprint in the forced command must match the mapping file. Gate rejects `SSH_ORIGINAL_COMMAND`; the agent gets neither a host shell nor SSH forwarding. Connect with:

```bash
gate-sh --ssh gate@gate-host -c 'uptime'
```

The forced-command bridge replaces the client-claimed identity with the configured fingerprint mapping and audits the SSH transport and fingerprint privately.

### Forwarding and hostname aliases

Forwards always bind and connect through target loopback. Ports 80 and 443 have narrow default allow rules; other ports become `ASK`:

```bash
gate forward add --remote-port 443
gate forward list
gate forward remove fw_EXAMPLE
```

Hostname-sensitive HTTPS can use a linked Gate-owned resolver entry:

```bash
gate host add foo.example.com --remote-port 443
gate host list
gate host remove foo.example.com
```

Gate reports an effective URL such as `https://foo.example.com:18443/`. It only removes resolver lines bearing the exact ownership marker it created. The daemon must have permission to update the configured hosts file (default `/etc/hosts`); use `--hosts-file` to select an explicitly managed alternative. For remote commands, place `--ssh gate@gate-host` before positional resource IDs.

### Policy review

Copy `config/policy-review.example.yaml` to `~/.config/gate/policy-review.yaml`. Analyze completed, agent-safe audit history without changing external state:

```bash
gate policy-review analyze
```

When explicitly asked to create a proposal:

```bash
gate policy-review propose --config ~/.config/gate/policy-review.yaml
```

The workflow requires repeated successful manual approvals across multiple sessions or targets, rejects unsafe or secret-bearing candidates, adds boundary tests, creates and pushes a `gate/policy-suggestions/...` branch, and opens a pull request. It stops there: a human must review and merge, and deployment remains separate.

## Goals

- Keep the existing Windmill production-access architecture unchanged where possible.
- Give local or remote agentic harnesses a normal shell-like execution interface.
- Keep a human operator in control of production commands.
- Allow safe, narrow commands to be automatically approved by policy.
- Keep Windmill session IDs and backend details private from agents.
- Preserve a complete command, approval, output, and execution history.
- Support local use first, then remote use over SSH.
- Stay small: one binary, one SQLite database, one policy file, no web service required for the first releases.

## Non-goals

- Replacing Windmill, Sancho, or the Bastion host.
- Giving agents an unrestricted interactive root shell.
- Building a generic orchestration platform.
- Requiring MCP, HTTP APIs, Redis, PostgreSQL, or a message broker.
- Automatically learning and applying production allowlist changes without review.

## Current production workflow

```text
operator laptop
    |
    | ssh myself@bastion.host
    v
bastion
    |
    | sancho session ssh <windmill-session-id>
    v
production server
```

Windmill remains responsible for remote support connectivity. Sancho is the operator CLI used to list and connect to Windmill sessions.

## Gate workflow

```text
                        HUMAN CONTROL PLANE

                     select Windmill session
                              |
                              v
                   +-----------------------+
                   | Gate target           |
                   |                       |
                   | id: gt_7FQ2DX         |  <-- agent-visible
                   | backend: windmill     |
                   | backend_id: 4837291   |  <-- private
                   +-----------+-----------+
                               |
                         attach agent
                               |
                               v
+----------------+       +-----+------+       +------------------+
| Codex          |       |            |       | bastion.host     |
| Claude Code    +------>| Gate       +------>| Windmill/Sancho  |
| Hermes         | shell |            | SSH   |                  |
+----------------+       +-----+------+       +--------+---------+
                               ^                       |
                               |                       |
                               | approval              | VPN + SSH
                               |                       v
                        +------+-------+        +--------------+
                        | operator TUI |        | production   |
                        +--------------+        | NS8 server   |
                                                +--------------+
```

## Identity model

Gate intentionally separates three identifiers:

| Identifier | Visibility | Purpose |
| --- | --- | --- |
| Windmill session ID | Gate/operator only | Backend session identifier used by Sancho/Windmill |
| Gate target ID | Agent-visible | Opaque handle for a selected remote target |
| Agent session ID | Gate/operator | Identifies a Codex/Claude/Hermes connection to Gate |

A Gate target ID must be random and unrelated to the Windmill session ID.

Example:

```text
Gate target:       gt_7FQ2DX
Windmill session:  4837291
```

The agent must never be able to derive or retrieve `4837291` through the Gate protocol.

For the simplest workflow, the operator selects a target in Gate and attaches the agent to it. The agent then does not need to specify a target ID at all.

```text
codex-1 -> gt_7FQ2DX -> Windmill session 4837291
```

## Agent interface

The primary interface is a shell-compatible client.

```bash
gate-sh -c 'uname -a'
```

The harness should be able to treat `gate-sh` like a shell. Gate returns:

- stdout
- stderr
- exit code

The first releases intentionally support non-interactive commands only.

Good examples:

```bash
uname -a
uptime
journalctl -u redis -n 100
systemctl status redis
podman ps
grep foo /var/log/messages
```

Not supported initially:

```bash
bash
vim /etc/example.conf
top
less
mysql
ssh another-host
```

The key safety property is:

```text
one command -> one policy decision -> one execution -> one result
```

Approving an interactive shell would destroy that boundary.

## Components

Gate is provided as `gate` plus the shell-compatible `gate-sh` client:

```bash
gate daemon
gate exec
gate forward
gate host
gate history
gate policy test
gate policy-review
gate ssh-server
```

Running plain `gate` starts the local daemon and operator console together.

### Local transport

The daemon listens on a Unix socket, for example:

```text
~/.local/run/gate.sock
```

Local agents use the Unix socket through `gate-sh` or `gate exec`.

### Remote transport

A remotely hosted Gate instance is reached over SSH.

```text
agent laptop
    |
    | SSH public-key authentication
    v
Gate host
    |
    | forced command: gate ssh-server
    v
Gate daemon
```

The SSH key used by an agent should be restricted with a forced command so it cannot open an unrestricted shell on the Gate host.

Example `authorized_keys` concept:

```text
command="GATE_SSH_KEY_FINGERPRINT=SHA256:... /usr/local/bin/gate ssh-server",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty <public-key>
```

The same simple internal protocol can be carried over:

- Unix socket locally
- SSH stdin/stdout remotely

## Internal protocol

Keep the protocol intentionally boring. Newline-delimited JSON is enough for the first implementation.

Example request:

```json
{"type":"exec","command":"uptime"}
```

Example response stream:

```json
{"type":"stdout","data":" 13:00:01 up 32 days\n"}
{"type":"exit","code":0}
```

A request is immutable after submission. Gate should assign an ID and hash the exact command before policy evaluation and approval.

```text
agent submits exact bytes
        |
        v
command ID + hash
        |
        v
operator sees exact command
        |
        v
operator approves command ID/hash
        |
        v
same exact bytes execute
```

## Policy model

Every command results in exactly one policy decision:

```text
ALLOW
ASK
DENY
```

The default is `ASK`.

A deliberately conservative policy file is preferred over a smart parser in the first release.

Example:

```yaml
allow:
  - '^uname\\b'
  - '^uptime$'
  - '^df\\b'
  - '^free\\b'
  - '^systemctl status\\b'
  - '^journalctl\\b'
  - '^podman ps\\b'
  - '^podman logs\\b'
  - '^ip (addr|route|link)\\b'

deny:
  - '\\brm\\b'
  - '\\bmkfs\\b'
  - '\\bdd\\b'
  - '\\breboot\\b'
  - '\\bshutdown\\b'
  - '\\bsystemctl (stop|restart|disable|mask)\\b'
```

Anything that matches neither list becomes `ASK`.

### Approval actions

The operator needs only a few actions initially:

```text
a   approve once
s   approve similar commands for this Gate target until detach/close
d   deny
```

Temporary approvals must not silently modify the persistent policy file.

Persistent policy changes are reviewed separately and, starting in v0.3, may be proposed through a pull request workflow.

## TUI

The TUI is the human control surface.

Suggested states:

```text
gray      queued
yellow    waiting approval
blue      running
green     succeeded
red       failed
purple    denied
```

Example:

```text
 Gate                                              target: gt_7FQ2DX

 TARGET
  customer-a.example.org

 AGENT
  codex-1

 COMMAND
  ? grep foo /var/log/messages

 POLICY
  approval required

 [a] approve once   [s] allow similar for target   [d] deny

 HISTORY

  ✓ 12:31 uname -a
  ✓ 12:31 systemctl status redis
  ✓ 12:32 journalctl -u redis -n 100
  ? 12:32 grep foo /var/log/messages
```

## Storage

Use SQLite.

Default database:

```text
~/.local/share/gate/gate.db
```

Suggested logical tables:

```text
targets
agent_sessions
commands
command_output
approvals
forwards
host_aliases
```

Human-managed persistent policy:

```text
~/.config/gate/policy.yaml
```

No Redis or external database is needed.

## Windmill integration

Gate should initially sit in front of the existing Windmill/Sancho access path.

The first prototype may contain enough Windmill-specific logic to:

1. connect to the Bastion host;
2. list sessions through Sancho;
3. resolve a selected session internally;
4. execute a non-interactive SSH command;
5. stream output back to Gate.

A later small Windmill/Sancho improvement can provide a first-class command such as:

```bash
sancho session exec <session-id> -- <command>
```

Gate would then call that primitive instead of reproducing the session-resolution logic.

The Windmill session ID remains private inside Gate in either case.

## v0.2: local port forwarding and host aliases

v0.2 adds access to remote web interfaces and other TCP services without giving the agent direct network access to the production target.

### Port forwarding

Gate can create forwards for common remote ports such as:

- 80/tcp
- 443/tcp
- application-specific diagnostic ports explicitly requested by the operator

Example conceptual mapping:

```text
remote target gt_7FQ2DX

remote 127.0.0.1:443  -> local 127.0.0.1:18443
remote 127.0.0.1:80   -> local 127.0.0.1:18080
```

The allocated local ports are Gate-owned and recorded in the target/session history.

Example CLI:

```bash
gate forward add --remote-port 443
# -> 127.0.0.1:18443

gate forward list
```

Forward creation is itself policy-controlled and visible in the TUI.

### Remote host aliases

Gate may also expose a remote hostname through a local alias, for example:

```text
foo.example.com -> 127.0.0.1 + Gate local port 18443
```

A hosts file cannot encode a port, so Gate treats hostname resolution and port forwarding as two related pieces:

```text
/etc/hosts (or resolver helper)
127.0.0.1 foo.example.com

Gate registry
foo.example.com:443 -> 127.0.0.1:18443
```

The user-facing endpoint can therefore be reported as:

```text
https://foo.example.com:18443/
```

Gate should support adding and removing these aliases safely and should clean them up when the target is detached or the forward is closed.

Possible CLI:

```bash
gate host add foo.example.com --remote-port 443
gate host list
gate host remove foo.example.com
```

The first implementation should prefer simple, explicit alias management over running a custom DNS server.

## v0.3: agent skills

v0.3 includes optional skills that teach agentic harnesses how to use Gate correctly.

Suggested skills:

### `gate-remote-shell`

Teaches the agent to:

- use `gate-sh` instead of the normal local shell for production commands;
- assume it is attached to the operator-selected target;
- avoid interactive shells;
- keep commands small and observable;
- inspect command output before proposing the next action;
- never ask for or attempt to discover Windmill session IDs.

### `gate-port-forward`

Teaches the agent to:

- request a Gate-managed forward when it needs to inspect a remote HTTP/HTTPS service;
- use the local endpoint returned by Gate;
- avoid opening arbitrary tunnels outside Gate;
- clean up forwards when they are no longer needed.

### `gate-policy-review`

At the end of a support session, reviews the command history and proposes improvements to the shared Gate policy.

The skill must **never directly modify the active production policy**.

Instead it:

1. reads the completed Gate session history;
2. identifies repetitive commands that required approval but appear safe and useful;
3. groups them into generalized policy candidates;
4. rejects candidates that are too broad, contain secrets, use unsafe shell composition, or have side effects;
5. updates the policy repository on a new branch;
6. adds or updates policy tests;
7. opens a pull request to the configured upstream repository;
8. includes evidence from the session and explains why every new rule is safe;
9. leaves final merge and deployment to humans.

Example suggestion:

```text
Observed 9 approved commands:

  journalctl -u redis -n 100
  journalctl -u redis -n 200
  journalctl -u agent -n 100
  ...

Candidate policy:

  ^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]+$
```

The pull request should explain:

- which Gate sessions produced the evidence;
- how many times the pattern was approved;
- whether all executions were read-only and successful;
- what inputs are permitted by the proposed regex/rule;
- what dangerous variants remain excluded;
- which tests prove the boundary.

The skill should prefer several narrow rules over one clever broad rule.

## Security invariants

These are architectural rules, not optional implementation details.

1. Windmill session IDs never cross the Gate/agent boundary.
2. The operator selects or authorizes the remote target.
3. A command is immutable after approval.
4. Default policy result is `ASK`.
5. Interactive shells are not agent-accessible in the initial releases.
6. Persistent policy is never silently changed from an approval action.
7. Port forwarding is explicit, target-scoped, logged, and removable.
8. Agent SSH keys to a hosted Gate use a restricted/forced command.
9. Gate records command, decision, actor, target, stdout/stderr metadata, and exit status.
10. Policy-learning automation proposes pull requests; humans merge and deploy them.

## Implementation stack

Go is the preferred implementation language because:

- Windmill/Sancho are already Go;
- a single executable is convenient for laptop and server deployment;
- SSH support is mature;
- terminal UI libraries are strong;
- SQLite works well without another service.

Dependencies:

```text
Go
SQLite
YAML
the system OpenSSH client
```

Keep dependencies minimal and avoid introducing a service framework unless the design later proves it necessary.

## Repository layout

A possible initial layout:

```text
.
├── cmd/
│   └── gate/
├── internal/
│   ├── agent/
│   ├── approval/
│   ├── backend/
│   │   └── windmill/
│   ├── command/
│   ├── forward/
│   ├── policy/
│   ├── protocol/
│   ├── storage/
│   └── tui/
├── skills/
│   ├── gate-remote-shell/
│   ├── gate-port-forward/
│   └── gate-policy-review/
├── policy/
│   ├── default.yaml
│   └── tests/
├── AGENTS.md
├── PLAN.md
└── README.md
```

## End-to-end milestone

The first end-to-end path remains intentionally small:

1. `gate` connects to the Bastion host.
2. Gate lists Sancho sessions for the human operator.
3. The operator selects one and Gate creates an opaque target ID.
4. `gate-sh -c 'uname -a'` submits a command over the local Unix socket.
5. The TUI shows the exact command and asks for approval.
6. Gate executes it on the selected Windmill target.
7. stdout/stderr/exit code return to `gate-sh`.
8. The full event is recorded in SQLite.

Once this works, the core architecture is validated.
