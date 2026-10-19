# Candidate safety

Audit evidence must show distinct successful human ASK approvals and genuinely
repeated diagnostic need across independent target contexts. Connection sessions
are informational only. A zero exit is not proof the command helped diagnosis.
The analyzer deduplicates command IDs, rejects missing result evidence and compares
against current policy. Review context before publishing; repeated target
reattachments do not establish independent cases.

Reject composition (`;`, `&&`, `||`, pipes, redirections, `$()`, backticks), controls,
newlines, ambiguous quoting/escapes, interactive tools, remote shells, writes,
deletes, installs, signals, restarts, credential arguments and broad paths. Never
use arbitrary SQL, Asterisk commands or runagent/container wrappers as candidates.
A dedicated parser and separately reviewed implementation are required for a new
family; exact anchoring alone does not make arbitrary flags safe.

The supported journal family is bounded at the regexp level:

```text
^journalctl -u [a-zA-Z0-9][a-zA-Z0-9_.@-]{0,127} -n (?:[1-9][0-9]{0,2}|1000)$
```

It excludes zero, leading zeroes, overflow, 1001+, follow, path selectors,
option-like names and extra flags. Container logs use the same 1–1000 limit and
an alphanumeric-led bounded container name. Other exact fallback candidates use
fixed diagnostic argument grammars, not arbitrary ls/stat/grep paths or options.

Gate's existing strict wrapper views can inherit an inner rule. Proposals must
document and positively test this supported inheritance, and negatively test
nested, malformed and option-bearing wrappers. Do not add broader wrapper support
or rewrite approved command bytes during review.

Sanitize candidate examples before publication. Never export customer data,
credentials or backend identifiers. The PR includes successful approval counts,
independent target context counts (not purported support-case counts), intended
input space, excluded variants, tests and the human-review requirement.
