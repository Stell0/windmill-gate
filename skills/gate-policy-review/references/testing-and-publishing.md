# Tests and proposal publishing

Every proposed rule needs actual Go regexp tests and full `policy.Engine.Evaluate`
checks, not a different language's regex engine. Positive cases include sanitized
observed successes, representative variants and permitted wrapper inheritance.
Negative cases cover empty/overlong/option-like selectors, zero/overflow/count
bounds, prefixes/suffixes, unexpected flags, unsafe paths/traversal, quotes,
escapes, controls, newline, substitutions/backticks, composition and wrapper nesting.
Unsafe variants must not ALLOW. Keep current DENY classifications and existing safe
ALLOW classifications. Only documented positive cases can change ASK to ALLOW.

The proposal workflow rederives bounded rules/tests from examples, validates the
original upstream suite before and after, evaluates the complete embedded Gate
regression corpus differentially and tests generated adversarial mutations. It
rejects inconsistent evidence, existing rules, baseline failures, unsafe variants
or undocumented classification changes before committing/pushing.

From the current Gate source checkout, run all mandatory checks:

```bash
make policy-test
go test ./internal/policy ./internal/review
make test
make test-race
```

The same four checks run in an upstream Gate source checkout before publishing.
For a policy-only repository with no Go source, the equivalent is the tested Gate
binary's full-engine original-suite, complete bundled regression and differential
adversarial checks against that branch's modified policy/test files. Report this
as policy-only validation, not as a Go build/race test of code that is absent.
If tests fail, reject the proposal. Do not change expectations to hide regressions.

Before an automatic proposal, ensure the mandatory current-checkout checks passed
for this Gate version, review the diff for sensitive information and confirm
independent context/usefulness. No network/C0 access is needed for analysis. Git
and hosting access are required only for a configured publishing workflow.

Publishing uses a fresh clone, configured file paths and a stable content-derived
`gate/policy-suggestions/...` branch. It checks for an equivalent open PR first,
adds only policy/test files, commits/pushes after checks and creates the PR from a
body file. A failed preflight produces no commit/push/PR. A failed hosting call can
leave a review branch; report it and reconcile before retrying. Do not force-push,
merge, deploy, modify the active policy or copy proposal rules into it.
