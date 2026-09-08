---
name: gate-port-forward
description: Inspect HTTP or HTTPS services on an operator-selected production target through Gate-managed, target-scoped local forwards and host aliases. Use when diagnostics require a local endpoint; do not create direct SSH or SOCKS tunnels.
---

# Gate Port Forward

Request a selected-target loopback forward through Gate. Use `./gate` from a
downloaded release directory, `bin/gate` from a source build, or `gate` when it
is installed on `PATH`:

```bash
./gate forward add --remote-port 443
```

On Windows, use `.\gate.exe forward add --remote-port 443`.

Use the returned `127.0.0.1:<port>` endpoint. Ports 80 and 443 may be policy-allowed; other ports can wait for operator approval.

If TLS, virtual-host routing, or cookies require the original hostname, request the linked Gate-owned alias:

```bash
./gate host add foo.example.com --remote-port 443
```

Use the exact URL Gate returns, including its local port. Do not edit the
system hosts file directly. On Windows, Gate must be running elevated before a
hostname alias can be added; the forward itself remains loopback-only.

For a hosted Gate, put `--ssh <gate-host>` before resource identifiers or other positional arguments. Do not use direct `ssh -L`, `ssh -R`, dynamic/SOCKS forwarding, proxy commands, agent forwarding, or another tunnel that bypasses Gate.

Review active resources with `./gate forward list` and `./gate host list`.
Remove hostname aliases and forwards when the diagnostic is complete. Expect
Gate to remove its aliases and target-scoped forwards automatically when the
target detaches.
