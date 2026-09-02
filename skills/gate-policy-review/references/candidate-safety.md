# Policy candidate safety

Only propose a command pattern when audit history shows successful manual approvals and the operation is read-only, repeatable, cross-session or cross-target useful, and narrowly representable.

Reject a candidate if it contains or depends on:

- `;`, `&&`, `||`, pipes, redirections, `$()`, backticks, newlines, shell functions, or ambiguous quoting;
- interactive programs, shells, editors, pagers, REPLs, remote login, file transfer, or arbitrary tunnel tools;
- write, delete, install, restart, signal, permission, ownership, mount, or service-state changes;
- tokens, passwords, private keys, cookies, authorization headers, credential-like assignments, or high-entropy secret values;
- customer-specific secrets or a filesystem generalization broader than the observed read-only need.

Use recognized command grammars where possible. For example:

```text
Observed: journalctl -u redis -n 100
Rule:     ^journalctl -u [a-zA-Z0-9_.@-]+ -n [0-9]+$
```

Keep `--follow`, extra arguments, composition, and redirection outside that rule. If safe generalization is uncertain, use an exact anchored rule or reject the candidate.

The pull request must include redacted examples, supporting approval count, context diversity, allowed input space, important excluded variants, tests added, and a statement that human review and merge are still required. Never include Windmill session IDs. Never invoke merge or deployment commands.

