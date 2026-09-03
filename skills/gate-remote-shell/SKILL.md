---
name: gate-remote-shell
description: Diagnose an operator-selected production target through Gate's non-interactive command surface. Use for production shell inspection where Gate mediates policy and human approval; do not use it to obtain a general shell or discover transport identifiers.
---

# Gate Remote Shell

Use `gate-sh -c '<exact command>'` for production execution. For a hosted Gate, add the configured `--ssh <gate-host>` option. Assume the operator has already attached this agent identity to the intended target.

Keep the command boundary observable:

- Submit one deterministic, non-interactive command at a time.
- Prefer small read-only diagnostics such as bounded status, journal, process, disk, or network-state queries.
- Prefer a standalone machine-readable command over a remote presentation pipeline. For example, submit `api-cli run list-installed-modules` and process its JSON output locally instead of appending `| jq`.
- Use concrete module, unit, and container names in each command. Shell assignments do not persist between `gate-sh` executions.
- Wait for stdout, stderr, and exit status before choosing a dependent command.
- Treat `ASK` as expected: wait for the operator instead of changing, splitting, encoding, or rerouting the command to evade review.
- Do not invoke interactive programs, shells, pagers, editors, REPLs, or remote-login tools.
- Do not ask for, enumerate, infer, print, or persist Windmill session IDs or backend transport details.
- Do not use direct SSH as a production-target bypass. SSH is permitted only as Gate's configured client transport.

When a command fails, report the Gate-visible error and propose the smallest useful follow-up. Never assume a target change; only the operator can attach a new target.
