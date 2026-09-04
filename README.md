# Gate

Gate lets an AI agent inspect a production system while a human stays in
control.

The operator selects the remote target. The agent submits one command at a
time. Gate automatically allows safe diagnostics, asks the operator about
unknown commands, blocks dangerous commands, and records every decision.

## Start in three steps

You do **not** need Go, a compiler, or a developer environment.

You need:

- a Linux or macOS computer with `curl`, `tar`, and `ssh`;
- SSH access to your Bastion;
- Sancho installed on the Bastion;
- [Codex](https://developers.openai.com/codex/cli) if you want to use the
  included agent skills.

### 1. Download Gate

```bash
curl -fsSL https://raw.githubusercontent.com/stell0/windmill-gate/main/install.sh | sh
cd windmill-gate
```

The installer downloads the latest prebuilt binary for Linux or macOS, checks
its SHA-256 checksum, and installs the Gate and NethServer skills. It does not
compile anything.

### 2. Start Gate

In the operator terminal, replace the example Bastion address:

```bash
./gate --bastion operator@bastion.example --agent codex-1
```

Gate shows the available production targets. Choose one by number and leave
this terminal open.

When a command needs a decision, press:

```text
y   approve this command once
s   approve similar commands for this target until it disconnects
n   block this command
```

### 3. Start Codex

Open another terminal in the same directory:

```bash
cd windmill-gate
codex
```

For an NS8 investigation, a good first prompt is:

```text
Use $nethserver-admin for NethServer knowledge and $gate-remote-shell with
agent identity codex-1 for every production command. Inspect the system health.
```

Codex automatically finds the skills in `.agents/skills`. You can also test
Gate without an agent:

```bash
./gate-sh --agent codex-1 -c 'uname -a'
```

## Skills

The release includes three Gate skills:

- `gate-remote-shell` — run small, non-interactive production commands through
  Gate;
- `gate-port-forward` — inspect target HTTP/HTTPS services through controlled
  local forwards;
- `gate-policy-review` — propose narrow policy improvements through a pull
  request, without merging or deploying them.

The installer also retrieves
[`nethserver-admin`](https://github.com/NethServer/agents/tree/main/skills/nethserver-admin),
including all of its reference files. It gives the agent the NS8 administration
knowledge needed for useful diagnostics. Gate still controls how its suggested
commands reach production.

Retrieve the skill again or update it at any time with:

```bash
./update-nethserver-admin
```

If Codex was already running, restart it if the updated skill does not appear.
Use `/skills` inside Codex to see the available skills.

## What Gate does

For every submitted command, Gate:

1. keeps the exact command bytes and calculates their hash;
2. evaluates the command as `ALLOW`, `ASK`, or `DENY`;
3. asks the operator when the result is `ASK`;
4. verifies that the approved bytes did not change;
5. runs the command through the existing Bastion/Windmill/Sancho connection;
6. returns stdout, stderr, and the remote exit code to the agent;
7. stores the command, decision, and result in a local SQLite audit database.

Gate is not an unrestricted remote shell. It does not give agents production
credentials, expose private Windmill session IDs, let agents choose arbitrary
targets, or silently make temporary approvals permanent.

## How Gate decides

Unknown commands always produce `ASK`.

The bundled policy automatically allows only narrow, read-only diagnostics. It
uses regular expressions and semantic validators for commands such as bounded
journal reads, safe log inspection, process inspection, selected Asterisk
commands, and a constrained MySQL `SELECT` form. Dangerous matches produce
`DENY`.

Persistent policy can inspect commands inside these strict NS8 wrappers:

```text
runagent -m MODULE COMMAND
runagent -m MODULE podman exec CONTAINER COMMAND
```

Classification never rewrites the command. Malformed quoting, shell expansion,
shell composition, unsafe options, and unmatched commands remain `ASK` unless a
deny rule matches.

The operator console records authorization as it happens:

```text
[AUTO APPROVE] agent> command
[AUTO BLOCKED] agent> command
[USER APPROVE] agent> command
[USER BLOCKED] agent> command
[CANCELLED] agent> command
```

These labels describe authorization, not whether the remote command succeeded.
Exit status and output remain available in history.

## Architecture

```text
                              human operator
                          selects target / approves
                                    |
                                    v
Codex or agent ---> gate-sh ---> Gate service ---> SSH ---> Bastion
                                    |                        |
                                    |                        v
                                    |                 Sancho/Windmill
                                    |                        |
                                    v                        v
                              SQLite audit            production target
```

The pieces have small, separate responsibilities:

| Piece | Responsibility |
| --- | --- |
| `gate` | Target selection, policy, approval console, execution, audit, and forwarding |
| `gate-sh` | Submits exactly one command and waits for its result |
| Unix socket | Local connection between the agent client and Gate |
| SSH | Connection from Gate to the Bastion |
| Sancho/Windmill | Existing transport from the Bastion to production |
| SQLite | Local audit history |
| YAML policy | Human-managed persistent authorization rules |

Gate deliberately keeps three identities separate:

| Identifier | Who can see it |
| --- | --- |
| Windmill session ID | Gate backend and operator only |
| Random Gate target ID | Gate, operator, and attached agent |
| Agent identity | Gate and operator |

The Gate target ID is random and is never derived from the private Windmill
session ID.

## Useful commands

Run Gate without the interactive console:

```bash
./gate daemon --bastion operator@bastion.example --agent codex-1
```

Daemon mode cannot approve `ASK` commands, so it is useful only when policy
already allows or blocks every expected command.

Inspect command history:

```bash
./gate history --agent codex-1
```

Create and remove controlled web-service forwards:

```bash
./gate forward add --remote-port 443
./gate forward list
./gate forward remove fw_EXAMPLE
```

Create and remove a hostname-sensitive HTTPS alias:

```bash
./gate host add foo.example.com --remote-port 443
./gate host list
./gate host remove foo.example.com
```

Analyze audit history for possible policy improvements:

```bash
./gate policy-review analyze
```

Gate never applies a policy suggestion automatically.

## Local files

| Purpose | Default path |
| --- | --- |
| Unix socket | `$XDG_RUNTIME_DIR/gate.sock` |
| SQLite audit database | `$XDG_DATA_HOME/gate/gate.db` |
| Active policy | `$XDG_CONFIG_HOME/gate/policy.yaml` |
| SSH client identities | `$XDG_CONFIG_HOME/gate/ssh-clients.yaml` |
| Policy-review configuration | `$XDG_CONFIG_HOME/gate/policy-review.yaml` |

On first launch, Gate installs its bundled default policy only when the active
policy file does not exist. A later Gate update never overwrites an existing
policy; the operator must review and deploy policy changes explicitly.

## Build from source

This section is only for contributors. Normal users should use the installer at
the top of this page.

```bash
make build
make policy-test
make test
make test-race
```

Pushing a tag such as `v0.4.0` runs the release workflow. It tests Gate and
publishes prebuilt Linux/macOS archives for AMD64 and ARM64 with a checksum
file. See [PLAN.md](PLAN.md) for design details and [AGENTS.md](AGENTS.md) for
repository rules.
