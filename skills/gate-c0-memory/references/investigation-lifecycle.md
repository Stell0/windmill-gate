# Investigation lifecycle

Create a random logical investigation identifier once per support task. Multiple
Gate client connections can belong to that investigation; their `agent_session_id`
values are transport metadata, not case identities. Record product/component,
known versions, symptom, authorized space, start time and current uncertainty.

While tool results remain visible, capture concise diagnostic checkpoints:

- hypothesis being tested and why the next observable diagnostic was chosen;
- exact diagnostic command only when safe to retain, Gate command ID/hash if
  available, current environment and timestamp;
- selected observed stdout/stderr, exit status and truncation/missing-output state;
- whether the observation confirms, contradicts or fails to test the hypothesis;
- failed approaches, lessons, alternative explanations and remaining uncertainty.

These are explicit diagnostic explanations and observations. Do not request,
retain or reconstruct private internal chain-of-thought traces. A zero exit status
means execution succeeded; it does not establish diagnostic usefulness.

Gate audit remains authoritative for execution and approvals. If legitimately
accessible, read `gate history --json` (with an authorized local database and
bounded limit) to reconcile command IDs, approvals and exit statuses. History
contains metadata/output byte counts, not complete historical stdout/stderr.
Never reconstruct missing output from it or silently invent results. Do not
query unrelated audit databases or discover backend target identifiers.

For recoverable local checkpoints, use a task-owned directory under an authorized
local private location with operator-managed expiry cleanup (at most seven days),
POSIX mode 0700 and files 0600, or equivalent user-only Windows ACLs. Verify both
access restrictions and the existing expiry mechanism before writing. If either
cannot be established, omit the local journal. Do not install a cleanup service
as part of this skill. Use only sanitized evidence, at most 256 KiB per
investigation, and record expiry and ownership. Never reuse expired checkpoints. Stop recording at
the cap and mark omissions. On resume, re-read checkpoints, confirm current task,
space authorization and actual system state. Delete only the exact owned journal
files after verified consolidation or their expiry; reject symlinks and avoid
recursive cleanup of shared directories. Secure physical erasure is not promised.
No background service, production command hook or guaranteed exit handler is needed.

Before the final report:

1. Inspect checkpoints and available audit metadata; state the outcome and limits.
2. Search related pages/entities, identify reusable lessons and failed approaches.
3. Create a historical investigation record distinct from the current procedure.
4. Ingest sanitized evidence, wait for readiness and verify immutable citations.
5. Create sourced claims, then create or revision-safely update a reusable procedure;
   preserve history, contradictory results and version constraints. Never replace
   a verified procedure with an unsupported guess.
6. Link the investigation, procedure, product/entities and actual evidence; annotate
   exact content with observation/verification status. Mark stale or superseded
   instructions with links rather than deleting historical observations.
7. Re-read all created/updated records and annotations. Report actual saved IDs,
   incomplete writes, extraction failures, uncertain applicability and follow-ups.

Identical retries use receipts/idempotency; changed content requires reconciliation.
Avoid duplicate procedures by exact slug resolution plus search, not title alone.
If interrupted, recover the journal or persisted checkpoints; unexpected termination
may lose unsaved observations. Consolidation remains best-effort.
