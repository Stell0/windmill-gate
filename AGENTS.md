# AGENTS.md

Instructions for coding agents working on the Gate repository.

## Project summary

Gate is a human-controlled command bridge for agent-assisted production support.

An agentic harness sends shell commands to Gate. Gate evaluates policy, asks the human operator when necessary, executes approved commands through the existing Bastion/Windmill/Sancho path, and returns stdout, stderr, and exit status.

Gate is deliberately small. Do not turn it into a general remote-management platform.

## Read first

Before changing code, read:

1. `README.md`
2. `PLAN.md`
3. the code around the component being changed
4. policy tests when touching command classification

If repository behavior conflicts with this document, call out the conflict in the change description rather than silently changing an architectural invariant.

## Architectural invariants

These rules are mandatory.

### Backend identity isolation

Agents must never receive a Windmill session ID.

Use separate identities:

```text
Windmill session ID   private backend identifier
Gate target ID        opaque agent-facing identifier
Agent session ID      identifies an attached harness
```

Never derive the Gate target ID from the Windmill session ID.

Never include the Windmill session ID in:

- agent protocol responses;
- stdout/stderr returned to the agent;
- agent-facing errors;
- agent skills;
- policy-review pull requests.

It may appear in operator-only diagnostics and private audit storage where necessary.

### Human target control

The operator chooses or authorizes the remote production target.

Do not add behavior that lets an attached agent enumerate arbitrary Windmill sessions or silently switch production targets.

### One command, one decision

The initial interaction model is:

```text
one command -> one policy decision -> one execution -> one result
```

Do not add an unrestricted interactive shell as a convenience shortcut.

### Immutable approval

The exact command approved by policy/human must be the exact command executed.

Recommended lifecycle:

```text
receive bytes
-> assign command ID
-> hash bytes
-> evaluate policy
-> display exact command
-> approve command ID/hash
-> execute same bytes
```

Do not reconstruct, rewrite, interpolate, or append arguments after approval.

### Policy defaults to ASK

Policy has only three outcomes unless the architecture is explicitly revised:

```text
ALLOW
ASK
DENY
```

Unknown commands are `ASK`.

Do not change unknown-command behavior to automatic allow.

### Persistent policy changes require review

A one-time approval or target-scoped temporary allow must never silently modify the persistent policy file.

Starting in v0.3, policy improvements are proposed through a pull request workflow. Agents may propose, test, commit, push, and open a PR when explicitly using the policy-review workflow, but must not merge or deploy policy changes automatically.

### Windmill remains the transport

Do not reimplement customer connectivity, VPN, NAT traversal, or remote-support enrollment inside Gate.

Gate consumes the existing Bastion/Windmill/Sancho path.

## Simplicity rules

Prefer:

- one Go binary;
- Unix sockets for local IPC;
- SSH for remote Gate access;
- SQLite for local state;
- YAML for human-managed policy;
- newline-delimited JSON for the first protocol;
- explicit small interfaces.

Avoid introducing without a demonstrated need:

- HTTP server frameworks;
- REST APIs;
- gRPC;
- Redis;
- PostgreSQL;
- message queues;
- Kubernetes-specific assumptions;
- MCP as the core protocol;
- plugin systems;
- generic workflow engines.

## Suggested package boundaries

A useful initial layout is:

```text
cmd/gate
internal/agent
internal/approval
internal/backend/windmill
internal/command
internal/forward
internal/policy
internal/protocol
internal/storage
internal/tui
```

Keep Windmill-specific code behind a backend interface so Gate can support another backend later without exposing backend identifiers to agents.

Example conceptual interface:

```go
type Backend interface {
    ListTargets(ctx context.Context) ([]BackendTarget, error)
    Exec(ctx context.Context, backendTargetID string, req ExecRequest) (ExecResult, error)
    OpenForward(ctx context.Context, backendTargetID string, req ForwardRequest) (Forward, error)
}
```

`backendTargetID` is private to the backend implementation. Agent-facing code should work with Gate target IDs.

## Command execution guidelines

- Prefer argv-based execution internally when possible.
- If `sh -lc` is used, treat the complete shell string as the immutable approved payload.
- Stream stdout and stderr separately.
- Preserve remote exit code.
- Add output size limits and truncation markers.
- Support cancellation only when it can be implemented without losing auditability.
- Record start/end timestamps.
- Never log secrets intentionally.

## Policy implementation guidelines

The first policy engine is deliberately conservative.

Do not attempt to build a full shell parser in v0.1.

When adding allow rules:

- keep them narrow;
- prefer read-only commands;
- anchor regexes where possible;
- constrain arguments;
- add positive and negative tests;
- consider shell metacharacters explicitly;
- avoid `.*` in security-sensitive rules unless the allowed space is proven safe.

A rule should demonstrate not only what it allows, but what dangerous variants it still rejects or sends to `ASK`.

## TUI guidelines

The operator TUI is a security surface, not decoration.

Always make the following visible before approval:

- Gate target display name;
- agent identity;
- exact command;
- policy result;
- whether an approval is one-time or target-scoped.

Suggested command states:

```text
queued
waiting
running
succeeded
failed
denied
```

Use consistent colors but do not make color the only state indicator; include symbols/text for accessibility and terminal compatibility.

## v0.2 forwarding rules

Port forwarding is controlled capability, not a raw SSH escape hatch.

When implementing forwards:

- the forward is tied to a Gate target;
- the remote destination is constrained to the selected target/context;
- the local bind defaults to loopback only;
- creation/removal is audited;
- active forwards are visible in the TUI;
- forwards are cleaned up when the target detaches unless explicitly configured otherwise;
- the agent does not receive direct SSH credentials or a generic SOCKS proxy.

Initial common ports are 80 and 443.

Additional ports require explicit request/policy evaluation.

### Host aliases

A hosts file maps names to IPs, not ports.

Represent a requested mapping such as:

```text
foo.example.com -> localhost:[N]
```

as two linked records:

```text
hostname alias: foo.example.com -> 127.0.0.1
port mapping:   foo.example.com:443 -> 127.0.0.1:N
```

Only remove resolver entries that Gate created.

Do not overwrite unrelated `/etc/hosts` content.

The first implementation should avoid a custom DNS daemon.

## v0.3 agent skills

Skills live under `skills/` and should be harness-neutral where practical.

### `gate-remote-shell`

Must teach an agent to:

- use Gate for production execution;
- avoid interactive commands;
- never discover Windmill IDs;
- prefer small diagnostic commands;
- wait for results before issuing dependent actions.

### `gate-port-forward`

Must teach an agent to:

- request Gate-managed forwards;
- use returned local endpoints;
- use Gate-managed host aliases when required;
- avoid bypass tunnels.

### `gate-policy-review`

This skill is security-sensitive.

Its purpose is to propose upstream policy changes from real approval history.

It must:

- read completed Gate session history;
- identify repeated manually approved read-only commands;
- reject unsafe/general candidates;
- produce narrow generalized rules;
- add tests;
- create a branch;
- commit and push changes;
- open a pull request to the configured upstream policy repository;
- redact secrets and backend identifiers;
- stop before merge/deployment.

Never implement “learn policy and apply immediately.”

## Policy-review heuristics

Treat a command as unsuitable for automatic allowlist suggestion when it includes, unless explicitly supported and parsed safely:

```text
;
&&
||
>
>>
<
$()
backticks
shell functions
interactive programs
remote shells
write/delete/restart operations
```

Also reject candidates containing:

- tokens;
- passwords;
- private keys;
- customer-specific secrets;
- unbounded filesystem paths when the rule would become overly broad.

Prefer evidence across multiple approvals and, when possible, multiple targets/sessions before suggesting a persistent global rule.

## Pull request requirements for policy changes

A policy PR should state:

- what commands were observed;
- how many approvals support the change;
- the generalized rule;
- why it is read-only/safe enough for auto-allow;
- which dangerous variants are excluded;
- which tests were added;
- that a human must review and merge it.

Never include Windmill session IDs in the PR.

## Testing expectations

Every feature should have automated tests where practical.

Minimum focus areas:

### Target identity

- Gate target IDs are random/opaque.
- backend IDs never appear in agent protocol serialization.

### Policy

- allow cases;
- ask cases;
- deny cases;
- shell metacharacter boundary cases;
- regression tests for every persistent policy change.

### Approval integrity

- modified command payload after approval is rejected;
- command hash matches executed bytes.

### Protocol

- stdout/stderr framing;
- exit status;
- disconnect handling;
- malformed request handling.

### Forwarding

- loopback bind only by default;
- cleanup on target detach;
- alias ownership/cleanup;
- no arbitrary backend destination escape.

### Storage

- audit records survive restart;
- secret/private backend data is not returned through agent-facing queries.

## Change discipline

When implementing a roadmap item:

1. keep the change scoped to the requested version;
2. add tests with the code;
3. update `README.md` if user-visible behavior changes;
4. update `PLAN.md` if roadmap assumptions change;
5. preserve backwards-compatible protocol behavior when possible;
6. call out security-boundary changes explicitly in the PR description.

## What not to do

Do not:

- expose `sancho session list` directly to agents;
- let agents pass raw Windmill session IDs;
- add `gate shell` as an unrestricted production PTY for agents;
- automatically persist a one-time approval;
- create generic unrestricted SSH port forwarding;
- open Gate TCP listeners by default on laptops;
- hide command mutations from the operator;
- merge automatically generated policy pull requests;
- add unrelated platform integrations while implementing the MVP.

## Definition of done

A Gate change is done when:

- behavior is implemented;
- security invariants still hold;
- tests cover the new boundary;
- operator-visible behavior is understandable;
- agent-facing behavior does not expose backend details;
- relevant documentation is updated.
