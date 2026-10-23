<img width="220" height="166" alt="computer-drinking2" src="https://github.com/user-attachments/assets/82d235ba-1741-4ffe-9862-8c6de1469123" />

# Windmill Gate

Gate lets an AI agent inspect a production system without giving up human
control.

The operator starts Gate and selects a remote target. The agent then submits
one command at a time. Gate applies its configured allow and deny rules, asks
the operator about unmatched commands, and records every decision.

Gate uses your existing Bastion, Sancho, and Windmill connection. It does not
give the agent transport credentials or an unrestricted remote shell. The
bundled policy permits environment and module-action reads that can return
production credentials; see the policy reference below.

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

Start Gate in the operator terminal, replacing the example Bastion address and
session ID:

```bash
./gate --bastion operator@bastion.example --agent codex-1 --session "<SESSION ID>"
```

Leave this terminal open. Then open a second terminal, enter the Gate
installation directory, and start Codex:

```bash
cd windmill-gate
codex
```

### Windows

Windows requires PowerShell and the OpenSSH client. Install Gate from
PowerShell:

```powershell
irm https://raw.githubusercontent.com/stell0/windmill-gate/main/install.ps1 | iex
Set-Location "$env:USERPROFILE\windmill-gate"
```

Start Gate in the operator terminal, replacing the example Bastion address and
session ID:

```powershell
.\gate.exe --bastion operator@bastion.example --agent codex-1 --session "<SESSION ID>"
```

When one approval is pending, the Windows operator console accepts a single-key
decision without Enter. Automatic console echo is disabled while Gate handles
typed input; Gate restores the previous console input settings when it exits.

Leave this terminal open. Then open a second PowerShell window, enter the Gate
installation directory, and start Codex:

```powershell
Set-Location "$env:USERPROFILE\windmill-gate"
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

Gate sounds an alert for each newly waiting approval, including requests already
pending when the console opens. Redraws do not ring again. Type `bell` in the Gate
operator console to test the sound.

For local consoles, Gate plays the Windows system Exclamation sound, the macOS
Ping sound, or the Linux desktop bell using `canberra-gtk-play` (with `paplay`
and the freedesktop bell sound as a fallback). Playback runs in the background
and never blocks approval keys; bursts of requests share a sound instead of
starting overlapping players. Linux needs one of those players installed.
System volume and sound settings still apply.

Gate also sends a terminal bell (BEL), including on Windows consoles without
ANSI support and on macOS. If Gate runs over SSH, only BEL is sent to your
terminal; enable audible bells in that terminal's settings. Redirected output
does not trigger sounds or contain bell characters.

When a command needs a decision, use the Gate operator terminal:

```text
y   approve this command once
s   approve similar commands for this target until it disconnects
n   block this command
```

In character-mode consoles (Linux, macOS and Windows), Backspace edits the
current input and typed characters are echoed by Gate. Arrow and function keys
are ignored; the console does not provide command history or cursor navigation.
Gate restores the previous terminal input settings when it exits.

Gate is now ready for agent-assisted diagnostics.

## Included skills

The release enables three Gate skills:

- `gate-remote-shell` runs small, non-interactive production commands through
  Gate.
- `gate-port-forward` provides controlled access to target HTTP/HTTPS services.
- `gate-policy-review` proposes narrow policy improvements in a pull request;
  it runs before the final support report and never merges or deploys changes.

The canonical optional `gate-c0-memory` skill is included under `skills/` but
is absent from `.agents/skills` by default. Gate needs no C0 service or credentials.
To enable memory discovery in a selected installation, with destination absent:

```bash
cp -R skills/gate-c0-memory .agents/skills/gate-c0-memory
```

On Windows:

```powershell
Copy-Item -Recurse -LiteralPath skills\gate-c0-memory -Destination .agents\skills\gate-c0-memory
```

Disable discovery by removing only that explicitly created directory. Restart
Codex and check `/skills` after either change. Recopy the canonical skill after
an upgrade. Other harnesses should register it only in selected installations.
Authorize C0 through the harness's existing MCP integration and select an
appropriate authorized knowledge space. Read-only access permits retrieval;
missing tools, denied access and outages skip writes while diagnostics and
independent policy review continue. The skill never reads local credentials to
bypass MCP, and memory has no Gate execution hook or command-approval authority.

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
./gate daemon --bastion operator@bastion.example --agent codex-1 --session "<SESSION ID>"
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

The bundled policy combines bounded diagnostics with operator-approved broad
module-action and environment access. It also permits explicitly bounded packet
captures that write to Gate-named files under `/tmp`.
Anchored expressions and semantic validators constrain arguments, quoting,
shell composition, and supported NS8 wrappers. Unmatched or malformed commands
remain `ASK` unless a deny rule matches. Classification never rewrites the
approved command.

Module actions named `get-*` or `list-*` are allowed without additional arguments
for any module identifier of 1–128 characters. The action suffix accepts 1–64
lowercase letters or hyphens. This is an explicit expansion of the earlier narrow,
read-only default: action names do not prove safety. For example, NethVoice
`get-phonebook-credentials` can change a database account and return a password,
and `get-configuration` can return an OIDC client secret.

Bare `printenv` is allowed and returns the complete environment. Alternatively,
it accepts 1–15 variable names, each at most 64 characters, including credential
names. The same rules inherit through the existing strict `runagent` and
container wrapper views. Gate does not redact these environment/action secrets;
agents must still follow applicable sensitive-data handling instructions.
`firewall-cmd --info-service=NAME` accepts one bounded service name, and Janus
accepts only `--help` or `--version`, with an optional `/usr/local/bin/` path.
Other arguments, shell composition and unmatched commands retain approval checks.

Journal reads scoped to one UID, syslog tag or user unit support optional UTC time
bounds, 1–1000 lines and mandatory `--no-pager`. Filters accept bounded IDs, task
selectors, simple diagnostic alternatives and three fixed service-error
expressions; general regular expressions still require approval.
Container inspection additionally permits a fixed runtime-state projection for
up to 8 named containers, including through the existing strict `runagent`
wrapper. Raw inspection and environment projections still require approval.

User-service diagnostics allow `show` for up to eight explicit units, `cat` for
one unit, and `list-jobs`, with `--no-pager`. The fixed Podman container-status
format accepts either single or double quotes. Host checks include `df -h /home`,
`hostname`, `nproc`, the disk/IO pressure accounting files and the exact
`grep PRETTY_NAME /etc/os-release` query. Performance sampling permits `iostat -xz`
and `vmstat` (optionally `-d`) with both an interval and report count of 1–10.
Process inspection uses fixed diagnostic column lists and at most 16 explicit
PIDs. These rules also inherit through the existing strict wrapper views.

Additional rules cover the exact ISO date and mount-source queries, module script
checksums, environment inspection, container process lists and quoted Asterisk
dialplan selectors. `sed -n START,ENDp FILE` accepts at most 1000
lines from known diagnostic source/configuration or log files, with optional
quotes around the range. Grep supports the observed Kamailio, RTPengine, Asterisk
and application source paths. Arbitrary files, shell globs, sed programs and
unsupported command forms still require approval.

Live SIP captures require `timeout` of 1–180 seconds, a fixed `any` interface,
ports 5060/5061/20030, and a `/tmp/gate-NAME.pcap` output path. Capture replay
requires a 1–1000 packet limit. These rules intentionally authorize capture-file
writes; execution deadlines do not impose a file-size limit.

TLS certificate probes require a 1–30 second timeout, port 443 or 5061, matching
connection/SNI/verification hostnames, and the exact `< /dev/null 2>&1` suffix.
That suffix is a specific parser exception; other redirections and pipelines
remain `ASK`. Gate classifies and executes the original command bytes unchanged.
For pipe-separated timestamps, use `stat -c '%n|%W|%w|%Y|%y' /home/MODULE`;
the unquoted form is a shell pipeline and still requires approval.

For NethVoice, bounded database reads run through the `mariadb` container's
fixed credential wrapper. Direct MySQL commands in `freepbx` are not part of
the default allow policy.

Analyze audit history for possible persistent policy improvements with:

```bash
./gate policy-review analyze --report
```

Gate never applies a policy suggestion automatically. Analysis reports rejected
and pending evidence without exporting raw rejected command text. The default
threshold is three distinct successful manual approvals across at least two operator-named Gate
target contexts. Connection sessions never count as independent support cases;
the agent must still verify context independence and diagnostic usefulness.

Configure the operator-selected policy repository using
`config/policy-review.example.yaml`. Set `automated_pr: true` to authorize the
end-of-session skill to publish eligible tested proposals with
`gate policy-review propose --automatic --config <path>`. Explicitly requested
proposals can omit `--automatic`. Without publishing configuration/authority,
analysis and recommendations still work. Generated rules have bounded grammars,
positive/negative tests, original-suite regressions and full-engine differential
checks. Gate source repositories additionally run mandatory Go/distribution/race
checks. Equivalent pending proposals reuse a stable branch/PR. Active policy
changes only through separately authorized human review and deployment.

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

Pushing a tag such as `v0.4.0` runs the release workflow. It tests Gate on Linux, macOS
and Windows and publishes checksum-protected Linux, macOS, and Windows archives
for AMD64 and ARM64. See [PLAN.md](PLAN.md) for design details and
[AGENTS.md](AGENTS.md) for repository rules.
