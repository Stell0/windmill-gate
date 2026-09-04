---
name: gate-policy-review
description: Review completed Gate audit history and propose narrow persistent allow rules with tests in a human-reviewed pull request. Use at the end of support sessions when repeated manual approvals may justify policy improvement; never merge, deploy, or edit the active policy.
---

# Gate Policy Review

Analyze completed Gate history, not live command input. Use `./gate` from a
downloaded release directory, `bin/gate` from a source build, or `gate` when it
is installed on `PATH`. Start with:

```bash
./gate policy-review analyze
```

Require repeated, successful, manually approved evidence. Reject secrets, backend identifiers, side effects, interactive tools, remote shells, broad paths, and shell composition. Read [candidate safety](references/candidate-safety.md) before accepting or hand-editing any proposal.

Inspect every candidate's observed examples, approval count, session/target diversity, generalized regex, and excluded variants. Prefer several narrow rules to a broad expression. Every new rule needs positive and negative boundary tests.

Only when the user explicitly asks to create the policy proposal, run the configured workflow:

```bash
./gate policy-review propose --config ~/.config/gate/policy-review.yaml
```

That command clones or fetches the configured upstream policy repository, creates a `gate/policy-suggestions/...` branch, edits policy and tests, validates them, commits, pushes, and opens a pull request. Check its generated PR description for redaction and safety rationale.

Stop after reporting the branch and pull-request URL. Do not merge the PR, deploy policy, copy rules into the active Gate policy, or convert a one-time/target-scoped approval into persistent state. A human must review and merge; deployment remains a separate human-controlled action.
