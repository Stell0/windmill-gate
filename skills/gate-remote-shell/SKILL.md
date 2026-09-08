---
name: gate-remote-shell
description: Diagnose an operator-selected production target through Gate's non-interactive command surface. Use for production shell inspection where Gate mediates policy and human approval; do not use it to obtain a general shell or discover transport identifiers.
---

# Gate Remote Shell

Use Gate for every command that must run on the production target. Assume the
operator has already selected that target and attached this agent identity.

From a downloaded release directory, run:

```bash
./gate-sh --agent <agent-identity> -c '<exact command>'
```

From a Windows release directory, use PowerShell:

```powershell
.\gate-sh.exe --agent <agent-identity> -c '<exact command>'
```

For a source build, use `bin/gate-sh`; when Gate is installed on `PATH`, use
`gate-sh`. For a hosted Gate, add the configured restricted transport before
`-c`:

```bash
gate-sh --ssh <gate-host> --agent <agent-identity> -c '<exact command>'
```

On Windows, the hosted form is `.\gate-sh.exe --ssh <gate-host> --agent
<agent-identity> -c '<exact command>'`.

Use the identity supplied by the harness or operator. Do not guess another
identity if attachment fails.

## Execution contract

Keep the command boundary observable:

- Submit one deterministic, non-interactive command at a time.
- Prefer small read-only diagnostics such as bounded status, journal, process, disk, or network-state queries.
- Prefer a standalone machine-readable command over a remote presentation pipeline. For example, submit `api-cli run list-installed-modules` and process its JSON output locally instead of appending `| jq`.
- Use concrete module, unit, and container names in each command. Shell assignments do not persist between `gate-sh` executions.
- Wait for stdout, stderr, and exit status before choosing a dependent command.
- Treat a command that remains running as potentially waiting for operator approval. Do not submit a duplicate while waiting.
- Treat `ASK` as expected: wait for the operator instead of changing, splitting, encoding, or rerouting the command to evade review.
- Do not invoke interactive programs, shells, pagers, editors, REPLs, or remote-login tools.
- Do not ask for, enumerate, infer, print, or persist Windmill session IDs or backend transport details.
- Do not use direct SSH as a production-target bypass. SSH is permitted only as Gate's configured client transport.

Gate returns remote stdout and stderr on their corresponding local streams and
preserves the remote exit status after execution. Exit status `1` accompanied by
a `gate-sh:` message is a Gate transport/protocol failure; exit status `2` is a
client usage error. Otherwise, interpret a non-zero status as the remote
command's result. Report the visible error and propose the smallest useful
follow-up. Never assume a target change; only the operator can attach a new
target.

For NethServer 8 administration and troubleshooting, read
[NethServer diagnostics](references/nethserver-diagnostics.md) before issuing
commands. It provides a Gate-compatible diagnostic ladder and explains which
results require a dependent follow-up.
