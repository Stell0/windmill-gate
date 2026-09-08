<img width="220" height="166" alt="computer-drinking2" src="https://github.com/user-attachments/assets/82d235ba-1741-4ffe-9862-8c6de1469123" />

# Windmill Gate

Gate lets an AI agent inspect a production system without giving up human
control.

The operator starts Gate and selects a remote target. The agent then submits
one command at a time. Gate allows known safe diagnostics, asks the operator
about unknown commands, blocks dangerous commands, and records every decision.

Gate uses your existing Bastion, Sancho, and Windmill connection. It does not
give the agent production credentials or an unrestricted remote shell.

## Quick start

You need SSH access to a Bastion where Sancho is installed. Gate itself is a
prebuilt binary, so Go and a compiler are not required. Install
[Codex](https://developers.openai.com/codex/cli) if you want to use the example
agent workflow below.

### Linux or macOS

Install Gate:

```bash
curl -fsSL https://raw.githubusercontent.com/stell0/windmill-gate/main/install.sh | sh
cd windmill-gate
```

Start Gate in the operator terminal, replacing the example Bastion address:

```bash
./gate --bastion operator@bastion.example --agent codex-1
```

Choose a target when prompted and leave this terminal open. Then open a second
terminal, enter the Gate installation directory, and start Codex:

```bash
cd windmill-gate
codex
```

### Windows

Windows requires PowerShell and the OpenSSH client. Install Gate from
PowerShell:

```powershell
irm https://raw.githubusercontent.com/stell0/windmill-gate/main/install.ps1 | iex
Set-Location windmill-gate
```

Start Gate in the operator terminal, replacing the example Bastion address:

```powershell
.\gate.exe --bastion operator@bastion.example --agent codex-1
```

Choose a target when prompted and leave this terminal open. Then open a second
PowerShell window, enter the Gate installation directory, and start Codex:

```powershell
Set-Location windmill-gate
codex
```

### Use Gate with Codex

A good first prompt for an NS8 investigation is:

```text
Use $nethserver-admin for NethServer knowledge and $gate-remote-shell with
agent identity codex-1 for every production command. Inspect the system health.
```

Codex automatically finds the installed skills in `.agents/skills`. If you
want to verify Gate without an agent, submit a harmless command directly:

Linux or macOS:

```bash
./gate-sh --agent codex-1 -c 'uname -a'
```

Windows:

```powershell
.\gate-sh.exe --agent codex-1 -c "uname -a"
```

When a command needs a decision, use the Gate operator terminal:

```text
y   approve this command once
s   approve similar commands for this target until it disconnects
n   block this command
```

Gate is now ready for agent-assisted diagnostics.

## Included skills

The release includes three Gate skills:

- `gate-remote-shell` runs small, non-interactive production commands through
  Gate.
- `gate-port-forward` provides controlled access to target HTTP/HTTPS services.
- `gate-policy-review` proposes narrow policy improvements in a pull request;
  it never merges or deploys them.

The installer also downloads the
[`nethserver-admin`](https://github.com/NethServer/agents/tree/main/skills/nethserver-admin)
skill for NS8 administration knowledge. Gate remains responsible for deciding
whether its suggested commands can run.

Update that skill at any time:

```bash
./update-nethserver-admin
```

On Windows, run `.\update-nethserver-admin.ps1` from PowerShell. Restart Codex
if an updated skill does not appear; `/skills` lists the available skills.

## Common commands

The examples below use Linux/macOS syntax. On Windows, replace `./gate` with
`.\gate.exe`.

Inspect command history:

```bash
./gate history
```

Create, inspect, and remove a controlled web-service forward:

```bash
./gate forward add --agent codex-1 --remote-port 443
./gate forward list --agent codex-1
./gate forward remove --agent codex-1 fw_EXAMPLE
```

Create, inspect, and remove a hostname-sensitive HTTPS alias:

```bash
./gate host add --agent codex-1 --remote-port 443 foo.example.com
./gate host list --agent codex-1
./gate host remove --agent codex-1 foo.example.com
```

On Windows, hostname aliases require an elevated terminal because Gate must
update the system hosts file. Port forwarding itself does not require
elevation.

Run Gate without the interactive operator console:

```bash
./gate daemon --bastion operator@bastion.example --agent codex-1
```

Daemon mode cannot approve `ASK` commands. Use it only when policy already
handles every expected command.

---

## Technical reference

The rest of this document explains Gate's security model and internals. It is
not required for everyday use.

### Security model

Every command follows one auditable path:

```text
receive exact bytes -> hash -> classify -> approve if needed
                    -> verify unchanged -> execute -> record result
```

The decision is `ALLOW`, `ASK`, or `DENY`, with unknown commands defaulting to
`ASK`. Temporary approvals do not modify persistent policy. Gate returns
stdout, stderr, and the remote exit code, and stores the decision and result in
SQLite.

Gate does not expose private Windmill session IDs to agents, let agents choose
arbitrary targets, or silently make temporary approvals permanent.

### Policy

The bundled policy automatically allows only narrow, read-only diagnostics.
Anchored expressions and semantic validators constrain arguments, quoting,
shell composition, and supported NS8 wrappers. Unmatched or malformed commands
remain `ASK` unless a deny rule matches. Classification never rewrites the
approved command.

Analyze audit history for possible persistent policy improvements with:

```bash
./gate policy-review analyze
```

Gate never applies a policy suggestion automatically.

### Architecture

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

| Piece | Responsibility |
| --- | --- |
| `gate` | Target selection, policy, approval, execution, audit, and forwarding |
| `gate-sh` | Submits exactly one command and waits for its result |
| Local IPC | Unix socket on Linux/macOS; access-controlled named pipe on Windows |
| SSH | Connects Gate to the Bastion |
| Sancho/Windmill | Provides the existing transport from Bastion to production |
| SQLite | Stores local audit history |
| YAML policy | Defines human-managed persistent authorization rules |

Gate keeps three identities separate:

| Identifier | Who can see it |
| --- | --- |
| Windmill session ID | Gate backend and operator only |
| Random Gate target ID | Gate, operator, and attached agent |
| Agent identity | Gate and operator |

The Gate target ID is random and is never derived from the private Windmill
session ID.

### Local files

| Purpose | Linux/macOS | Windows |
| --- | --- | --- |
| Local IPC | `$XDG_RUNTIME_DIR/gate.sock` | `\\.\pipe\windmill-gate-<user-hash>` |
| SQLite audit database | `$XDG_DATA_HOME/gate/gate.db` | `%LOCALAPPDATA%\gate\gate.db` |
| Active policy | `$XDG_CONFIG_HOME/gate/policy.yaml` | `%APPDATA%\gate\policy.yaml` |
| SSH client identities | `$XDG_CONFIG_HOME/gate/ssh-clients.yaml` | `%APPDATA%\gate\ssh-clients.yaml` |
| Policy-review configuration | `$XDG_CONFIG_HOME/gate/policy-review.yaml` | `%APPDATA%\gate\policy-review.yaml` |

On first launch, Gate installs its bundled default policy only if the active
policy file does not exist. Updates never overwrite an existing policy; an
operator must explicitly review and deploy persistent policy changes.

### Build from source

Normal users should use the installers above. Contributors can build and test
the project with:

```bash
make build
make build-windows
make policy-test
make test
make test-race
```

Pushing a tag such as `v0.4.0` runs the release workflow. It tests Gate on Linux
and Windows and publishes checksum-protected Linux, macOS, and Windows archives
for AMD64 and ARM64. See [PLAN.md](PLAN.md) for design details and
[AGENTS.md](AGENTS.md) for repository rules.
