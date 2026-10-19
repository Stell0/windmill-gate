---
name: gate-policy-review
description: Review command-policy evidence before every normal support investigation ends, report eligible and rejected improvements, and propose fully tested rules through configured human-reviewed PRs. Never merge, deploy or edit active policy.
---

# Gate Policy Review

Run this independent workflow before the final support report, even when memory
is absent or unavailable. Neither use C0 nor invoke a memory skill. C0 pages are
not evidence of human approval. Best-effort failure must not block the final report.

Use `./gate` in a release, `bin/gate` in a source build, or `gate` on PATH
(`.\gate.exe` on Windows). Read [candidate safety](references/candidate-safety.md).
With authorized local audit access, read bounded `gate history --json` and run:

```bash
./gate policy-review analyze --report
```

The report lists commands considered, successful manual approvals, sanitized
eligible candidates, pending evidence, rejection reasons and test status. It never
contains raw rejected commands. Inspect relevant recent decisions in the available
audit and investigation observations. Distinguish successful execution from useful
diagnosis. Check the actual current persistent policy; exclude already allowed,
currently denied, unsafe, sensitive and unsupported commands. Unknown remains ASK.

Connection `agent_session_id` values are not independent investigations. Gate
requires distinct nonempty operator-named target contexts and repeated distinct successful manual
approvals (default minimum 3, never less than 2). Verify that target contexts are
actually independent needs, not reattachments to the same system used to inflate
evidence. If that cannot be established, report pending evidence and do not publish.
Do not turn one-time or target-scoped approval into a global rule automatically.

For each candidate, check sanitized observed examples, target diversity, usefulness,
bounded grammar and positive/negative tests. Follow
[testing and publishing](references/testing-and-publishing.md). Reject regressions,
unsafe allowances, missing evidence or failing checks. When no candidate qualifies,
report that outcome; do not create an empty PR.

Analysis needs no publishing configuration. When the operator has configured
`policy-review.yaml` with `automated_pr: true`, the configured repository and
publishing credentials, eligible proposals may run without another session prompt:

```bash
./gate policy-review propose --automatic --config <configured-path>
```

Explicit user-requested proposals may use `propose --config <configured-path>`
without automatic mode. If the repository or publishing authority is missing,
perform analysis and recommendations only; do not invent a repository or push.
Preserve configured base branch, policy path and test path. Equivalent pending
proposals reuse a stable branch/PR rather than opening duplicates.

Report considered commands (sanitized), candidates/rejections and reasons,
approval counts/independent contexts, tests run and their actual pass/fail results,
pending evidence and an existing/new PR URL when applicable. Analysis alone does
not mean regexp tests ran. Stop before merge, deployment or loading persistent
policy. Human review/merge and separately authorized deployment remain required.
