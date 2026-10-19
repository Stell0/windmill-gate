# Knowledge model

Store authored history as Wiki pages (or an existing authorized investigation
object schema). Do not register a new object schema merely to save a case.

An investigation retains its logical ID, symptom, sanitized environment/version,
observed times, outcome, checkpoint evidence, failed approaches and unresolved
questions. It describes what happened, including mistakes and contradictions.
Use a case-specific slug; preserve previous revisions and observations.

A reusable procedure describes scope/applicable product, component and versions,
preconditions, diagnostic commands, expected observations, interpretation,
stop/escalation conditions, failed alternatives and references to validated cases
and immutable evidence. Use a stable procedure slug and resolve it before create.
Version-incompatible procedures need separate applicability, not a silent overwrite.

Use the deployed annotation namespaces for applicability and verification tied to
actual immutable content revisions. The accepted model supplies statuses,
product/component/version tags, confidence, observed_at/verified_at and bounded
extensions. Put knowledge_type (investigation or procedure), supersedes and
source_references in supported metadata/extensions or typed references according
to the actual schema. Never invent unsupported top-level fields. Missing values
remain unknown; confidence records an assessment, not proof.

Claims cite ready immutable evidence chunks. Distinguish observed facts from
hypotheses and authored interpretations. Keep citations and links resolvable;
record missing/deleted references honestly. Relate entities and procedures within
the authorized space. A relation does not grant access across spaces.

After consolidation, search again for duplicates, retain contradictions, link
superseded procedures to the replacement and record why applicability changed.
Re-read the new content/revisions/annotations; a successful write receipt alone
is not a persistence verification. Current best practice and historical case
records remain separate even when a case produced the procedure.
