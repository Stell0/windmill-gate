# Gate implementation plan

This document defines the staged implementation plan for Gate, the human-controlled shell bridge for agent-assisted production support.

The plan intentionally favors a small, auditable design over feature breadth.

## Implementation status

Versions v0.1 through v0.3 are implemented. The code follows the implementation order below with these completed checkpoints:

- opaque target registry and private Windmill backend mapping;
- bounded local NDJSON protocol over Unix sockets or Windows named pipes and a
  `gate-sh` client;
- immutable command hashing, conservative regex-plus-validator policy evaluation, strict NS8 wrapper views, and hash-bound approvals;
- SQLite audit/history and an accessible operator console with a current-run authorization ledger;
- restricted forced-command SSH bridge with fingerprint-to-identity mapping;
- concurrent targets/clients, cancellation, and target-scoped temporary rules;
- loopback-only forwards and exact-marker-owned hostname aliases;
- harness-neutral Gate skills and a tested policy-analysis/PR workflow that stops before merge or deployment;
- tag-driven GitHub releases with checked prebuilt Linux/macOS/Windows archives,
  no-build installers, repository-scoped Codex skill discovery, and standalone
  updaters for the external `nethserver-admin` skill bundle.

The Windmill adapter prefers the Sancho command primitives documented in `README.md`. It also supports the deployed Sancho 0.0.1 object-stream format with a constrained, target-scoped nested SSH compatibility path through the Bastion. Items under “Later ideas” remain intentionally deferred.

End-user distribution is hosted at `github.com/stell0/windmill-gate`. A `v*`
tag tests the project on Linux and Windows and publishes checksum-protected
archives for Linux, macOS, and Windows on AMD64 and ARM64. Release archives
include Gate's canonical `skills/` content and `.agents/skills` discovery
entries. The installer retrieves the external NethServer admin skill from
`NethServer/agents`; it is not vendored or silently persisted into Gate policy.

## Optional memory and mandatory session review

WG0 prerequisite verified on 19 October 2026: C0 AM6 and final deployment gate
are accepted on main. Deployed app 0.45.0/Core 0.29.0/schema 0016 match accepted
runtime `97a7a1b`. [Exact-source PR validation](https://github.com/Stell0/ns8-czero/actions/runs/39166087566)
and [main validation/publication](https://github.com/Stell0/ns8-czero/actions/runs/39201930016)
are completed/successful. Gate baseline `fca959d` passes 236 policy cases,
targeted policy/review, full Go/distribution and race tests on Linux.

Implementation branch `feat/persistent-memory-policy-review` confines memory to
an optional canonical skill, discovery documentation and packaging checks.
No C0 code enters Gate. Memory and policy review do not invoke each other.
Automatic review is an agent instruction before the final report, not a daemon
hook mistaking a connection disconnect for the end of an investigation.

Policy analysis deduplicates command IDs, requires confirmed execution results
and distinct nonempty operator-named Gate target contexts, and never counts connection sessions
as independent cases. It reports rejected/pending groups, removes broad fallback
argument/path grammars and bounds proposed log counts to 1–1000. Proposals
rederive safe tests, preserve original classifications, compare bundled and
adversarial corpora through the full engine, run mandatory upstream checks and
reuse equivalent open PRs. Existing default-policy allowances remain unchanged;
historical unbounded default log allowances need a separately reviewed security
correction, not an undocumented change during proposal generation.

Acceptance remains pending for cross-session memory through current authorized
harness tools, generated-proposal fixtures, packaging, full suites and
implementation CI. The session's cached C0 connector exposes 63 older operations;
server-side protected-space/ingestion operations cannot be fabricated in that
catalog. Do not claim server/SDK-only evidence proves a refreshed-harness skill pass.

## Design constraints

The following constraints apply to every version:

- Windmill remains the production remote-access transport.
- Agents never receive Windmill session IDs.
- Gate owns an opaque target namespace such as `gt_7FQ2DX`.
- The operator controls target selection.
- Agent commands are non-interactive unless a future design explicitly proves a safe interaction model.
- Every command receives an `ALLOW`, `ASK`, or `DENY` decision.
- `ASK` is the default.
- Approved command bytes cannot change between approval and execution.
- Persistent policy changes require explicit review.
- Local mode should not require a TCP listener; use access-controlled Unix
  sockets or Windows named pipes.
- Remote Gate access uses SSH rather than inventing a new authentication mechanism.
- SQLite is the default state store.

---

# v0.1 — guarded remote command execution

## Objective

Prove the core architecture end-to-end:

```text
agent shell -> Gate -> approval -> Windmill target -> command output
```

## Deliverables

### Gate daemon

- Start a local daemon.
- Listen on a Unix socket.
- Accept one agent client initially.
- Maintain one active human-selected target initially.
- Assign every command a unique ID.
- Hash the exact command payload before approval.

### Windmill backend

- Connect to the configured Bastion host over SSH.
- Run Sancho session listing.
- Parse session information.
- Present Windmill sessions only to the human UI.
- Create random Gate target IDs.
- Store the private mapping:

```text
gate target ID -> Windmill session ID
```

- Execute non-interactive commands through the selected Windmill session.
- Stream stdout/stderr.
- Return the remote exit code.

### Shell client

Provide:

```bash
gate-sh -c '<command>'
```

and optionally:

```bash
gate exec -- '<command>'
```

The client must behave predictably enough for an agentic harness to treat it as a shell execution surface.

### Human TUI

Show:

- available Windmill sessions;
- selected Gate target;
- attached agent;
- queued commands;
- waiting approvals;
- running commands;
- completed command history;
- stdout/stderr preview;
- exit code.

Initial states:

```text
queued
waiting
running
succeeded
failed
denied
```

### Policy engine

Implement only:

```text
ALLOW
ASK
DENY
```

Support narrow regex/pattern rules from a YAML file.

Default result: `ASK`.

### Approvals

Support:

```text
y  approve once
s  allow similar command for this target until detach/close
n  deny
```

Do not persist session approvals into the global policy file.

### Storage

SQLite tables for at least:

- targets
- agent sessions
- commands
- approval decisions
- command output metadata

The first version can store output inline if size limits are enforced; otherwise store output chunks separately.

## Acceptance criteria

A complete test scenario must work:

1. start `gate`;
2. operator sees Sancho sessions;
3. operator selects a production session;
4. Gate creates a random target ID;
5. agent executes `gate-sh -c 'uname -a'`;
6. TUI displays the command;
7. operator approves it;
8. command runs remotely;
9. output is returned to the agent;
10. command and decision appear in history;
11. the agent never sees the Windmill session ID.

## Explicitly deferred

- remote Gate hosting
- multiple simultaneous agents
- arbitrary interactive PTYs
- file transfer
- port forwarding
- host aliases
- persistent policy suggestions
- MCP
- HTTP API

---

# v0.2 — remote Gate and network inspection

## Objective

Make Gate practical as a shared support service and enable agents/operators to inspect remote web services safely.

## Deliverables

### Remote Gate over SSH

Add:

```bash
gate ssh-server
```

An agent can connect to a Gate host using normal SSH public-key authentication.

Recommended SSH restriction:

```text
command="/usr/local/bin/gate ssh-server",no-port-forwarding,no-agent-forwarding <key>
```

Requirements:

- map SSH public key/fingerprint to a Gate client identity;
- do not provide a general shell on the Gate host;
- reuse the same Gate protocol used by the local Unix socket;
- audit remote client identity.

### Multiple targets and clients

- Support multiple Gate targets at once.
- Support multiple attached agent sessions.
- Keep a clear mapping of agent -> target.
- Prevent one agent from switching targets without an explicit Gate/operator action.
- Add command cancellation where feasible.

### Temporary target-scoped policy

- Allow temporary per-target approvals.
- Expire them when the target is detached/closed.
- Show them in the TUI.
- Never persist them automatically.

### SSH forwarding of common ports

Allow Gate to forward selected remote TCP ports through the same remote-support path.

Initial common ports:

```text
80/tcp
443/tcp
```

Additional ports may be requested explicitly.

Example:

```bash
gate forward add --remote-port 443
```

Result:

```text
remote target:   gt_7FQ2DX
remote endpoint: 127.0.0.1:443
local endpoint:  127.0.0.1:18443
```

Requirements:

- Gate chooses or validates the local port;
- forwards are target-scoped;
- creation is policy-controlled;
- the TUI shows active forwards;
- forwards are logged;
- forwards are closed when the target detaches unless explicitly kept by policy;
- agent cannot request an arbitrary destination outside the selected target without explicit approval.

### Remote hostname aliases on localhost

Support operator/agent workflows such as inspecting:

```text
foo.example.com on the remote target
```

through a local Gate forward.

A hosts file cannot encode a TCP port, so model this as two linked resources:

```text
hostname alias:
foo.example.com -> 127.0.0.1

Gate port mapping:
foo.example.com:443 -> 127.0.0.1:18443
```

User-visible endpoint:

```text
https://foo.example.com:18443/
```

Suggested CLI:

```bash
gate host add foo.example.com --remote-port 443
gate host list
gate host remove foo.example.com
```

Requirements:

- update a Gate-managed resolver mechanism or explicitly managed `/etc/hosts` entry;
- track ownership so Gate removes only entries it created;
- avoid clobbering unrelated local resolver configuration;
- clean up aliases when forwards close;
- record aliases in SQLite;
- surface the effective local URL to the agent/operator.

The first implementation should avoid introducing a custom DNS daemon.

## Acceptance criteria

### Hosted Gate

An agent on laptop A can execute a command through Gate on host B using an SSH key restricted to `gate ssh-server`, while the approval UI runs for the operator on host B.

### HTTPS inspection

For a selected target:

1. create a forward from remote port 443;
2. add `foo.example.com` as a Gate host alias;
3. Gate reports a local URL such as `https://foo.example.com:18443/`;
4. the operator/agent can access the forwarded service;
5. closing the target removes the forward and Gate-owned alias.

---

# v0.3 — agent skills and policy improvement workflow

## Objective

Teach agentic harnesses how to use Gate correctly and convert real support-session history into reviewed policy improvements.

## Deliverables

### Skill: `gate-remote-shell`

Create an agent skill that instructs a harness to:

- execute production commands only through `gate-sh`;
- assume Gate has already attached it to a target;
- never discover or request Windmill session IDs;
- prefer small read-only diagnostic commands;
- avoid interactive shells;
- inspect results before issuing the next command;
- ask Gate for approval rather than trying to bypass it;
- keep commands deterministic and easy for a human to understand.

### Skill: `gate-port-forward`

Create an agent skill that instructs a harness to:

- request Gate forwards for HTTP/HTTPS diagnostics;
- use Gate-returned local endpoints;
- use Gate-managed host aliases when hostname-sensitive services require them;
- avoid direct SSH `-L`, SOCKS proxies, or arbitrary tunnels outside Gate;
- close forwards when finished.

### Skill: `gate-policy-review`

Create an end-of-session skill that analyzes Gate history and proposes policy changes through a pull request.

#### Inputs

The skill may consume:

- command text;
- policy result;
- human approval result;
- command exit status;
- whether the command was repeated;
- Gate target/session metadata safe for policy analysis;
- the current upstream policy repository.

It must not include secrets or private Windmill identifiers in the pull request.

#### Candidate selection

A command is a candidate only if it was manually approved and appears to be:

- read-only;
- repeatable;
- useful across multiple support sessions or targets;
- narrow enough to encode safely;
- free of secret values;
- free of unsafe shell composition.

Commands containing constructs such as the following should normally be excluded from automatic policy-rule suggestions unless a dedicated parser proves the exact semantics:

```text
;
&&
||
>
>>
<
$()
backticks
complex pipelines
shell functions
interactive commands
```

Simple pipelines may be supported later with explicit parsing and tests.

#### Generalization

The skill should generalize conservatively.

Bad proposal:

```text
^journalctl.*$
```

Better proposal:

```text
^journalctl -u [a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127} -n (?:[1-9][0-9]{0,2}|1000)$
```

The skill should prefer multiple narrow rules over one broad expression.

#### Policy repository workflow

The upstream repository is configured, for example:

```yaml
policy_repository: git@github.com:example/gate-policy.git
```

At the end of the session the skill may:

1. clone/fetch the policy repository;
2. create a branch such as:

```text
gate/policy-suggestions/<date>-<session>
```

3. modify policy files;
4. add/update tests;
5. run policy test tooling;
6. commit changes;
7. push the branch;
8. open a pull request using GitHub tooling/API available to the harness.

It must **not** merge the pull request or deploy the policy.

#### Pull request content

Every PR should include:

- a short rationale;
- observed command examples, with secrets/redacted data removed;
- number of manual approvals supporting the proposal;
- the proposed rule(s);
- explanation of allowed input space;
- explanation of important excluded/dangerous variants;
- test cases added;
- a statement that the change still requires human review.

Example:

```text
Title: policy: allow bounded journalctl unit reads

Observed during support sessions:
- journalctl -u redis -n 100
- journalctl -u redis -n 200
- journalctl -u agent -n 100

Proposed rule:
^journalctl -u [a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127} -n (?:[1-9][0-9]{0,2}|1000)$

Still excluded:
- --follow
- --output-fields with arbitrary values
- shell pipelines/redirections
- commands with additional arguments
```

### Policy tests

v0.3 should introduce a first-class policy-test format if it does not already exist.

Example:

```yaml
allow:
  - command: "journalctl -u redis -n 100"
    expect: ALLOW

ask:
  - command: "journalctl -u redis --follow"
    expect: ASK

deny:
  - command: "systemctl restart redis"
    expect: DENY
```

The policy-review skill must add tests alongside every proposed rule.

## Acceptance criteria

At the end of a real Gate support session:

1. the agent can invoke the policy-review skill;
2. the skill reads session history;
3. it identifies at least one safe repeated approval candidate;
4. it generates a narrow rule and tests;
5. it opens a pull request against the configured upstream policy repository;
6. the PR contains no Windmill session IDs or secrets;
7. no active Gate policy changes until a human merges and deploys the PR.

---

# Later ideas — not committed to v0.3

Possible future work:

- first-class `sancho session exec` support upstream;
- controlled file upload/download;
- richer command parsing;
- signed central policy bundles;
- policy distribution and rollback;
- per-command risk annotations;
- operator teams and RBAC;
- browser helper for local forwarded host aliases;
- optional MCP facade built on top of the shell interface;
- optional NS8 packaging.

These should not delay the v0.1-v0.3 path.

---

# Implementation order

Recommended sequence:

```text
1. target model + Windmill session listing
2. Unix socket protocol
3. gate-sh client
4. command approval TUI
5. remote command execution
6. SQLite audit/history
7. policy engine
8. remote Gate SSH transport
9. target/client concurrency
10. port forwarding
11. host aliases
12. agent skills
13. policy review + PR workflow
```

At every step, preserve the core security boundary: the agent gets a controlled command surface, not a Windmill session and not a general-purpose production shell.


## WG implementation verification (19 October 2026)

Local candidate passes 241 policy cases, targeted policy/review/CLI tests, full
Go/distribution tests and race tests. The bounded-composition fuzz run passes
23,457 mutations over six seconds with two workers. Both changed skills pass the
skill validator. Linux distribution fixtures include canonical memory references,
keep memory undiscoverable by default and exercise enable/disable; Windows fixtures
exercise equivalent archive/install/discovery behavior in CI.

Disposable local upstream tests clone, create/commit/push a review branch and
verify the upstream active checkout is unchanged. Hosting creation is a recorded
test double, not a real disposable GitHub PR. Source-repository fixtures exercise
all mandatory preflight dispatches and fail each individually; failures and
proposal-byte mutations prevent commit/push. Repeated open-PR fixtures reuse an
existing proposal. Original-suite failures and unsupported/broad rules are rejected.

Independent agent validation reads the full memory skill and references, observes
the old 63-tool C0 catalog and performs one authorized bounded generic text search
(successful, zero hits). Its outage/read-only/injection/resume scenarios are
instruction evaluations, not a live two-session persistence test. Its retention
finding is fixed: local journaling requires an existing verified bounded-expiry
mechanism as well as private permissions, otherwise journaling is omitted.

The extra cross-platform build/fuzz attempt initially hit /tmp disk quota; only
this task's verification cache was moved into ignored `bin/verification` for retry.
Full release-archive verification and implementation CI results remain pending.
Do not mark final acceptance complete: a refreshed authorized harness catalog and
a real two-session evidence/procedure round trip are still required, with native CI results still required. No active policy is changed.


The first implementation CI run [39226319780](https://github.com/Stell0/windmill-gate/actions/runs/39226319780)
passes Linux Go/distribution checks but fails Windows proposal tests: Git's
line-delimited path output leaves carriage returns on intermediate filenames.
The correction uses NUL-delimited Git paths and canonical configured paths;
unexpected filenames containing newlines remain rejected. The complete local
mandatory suites pass after this fix. CI now also exercises native macOS Go and
installer behavior, plus Linux race boundaries.

All six Linux/macOS/Windows AMD64/ARM64 archives build and pass checksum,
canonical-skill/reference and default-discovery checks. The native Linux archive
binary runs. Cross-building initially needed a writable task-local module cache
for Windows dependencies; no system cache/configuration is changed. Temporary
build directories are isolated from Go's package scan, and socket test paths use
a short private verification alias. All verification files remain ignored.

The real private [disposable policy PR](https://github.com/Stell0/gate-policy-review-acceptance-20261019-c8b4b0/pull/1)
is created from three synthetic successful manual approvals across two named
fixture targets. Its proposed branch passes 146 generated policy tests after
fetch, and the complete bundled/adversarial differential checks run before its
actual commit/push. A repeated automatic invocation returns the same branch/URL.
Local active policy and upstream main bytes remain unchanged, and the PR body
contains no private backend fixture value. The repository and PR are explicitly
labelled synthetic acceptance artifacts and remain unmerged; they grant no
production execution authority. No C0 memory is used for policy evidence.

Remaining final acceptance: refreshed connected-harness C0 operations and an
actual two-session evidence/procedure persistence/reuse test. The implementation
PR remains a draft, and CI for the portability correction is pending.


The first portability rerun [39226918375](https://github.com/Stell0/windmill-gate/actions/runs/39226918375)
passes native macOS Go/installer checks and Linux Go/race/installer checks but
retains the Windows fixture failure. The first line-ending diagnosis was incomplete:
the recording test runner used CombinedOutput, mixing Git's line-ending warnings
from stderr into filename data; the production runner already isolates streams.
The fixture now delegates real commands to the production ExecRunner, with a
subprocess regression proving warnings cannot contaminate NUL-framed path data.
The NUL-framing improvement also remains covered for newline-bearing filenames.
The composition fuzz assertion now independently parses canonical decimal counts
and passes another 13,275 mutations rather than rederiving its own grammar.
