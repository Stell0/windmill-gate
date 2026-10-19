# Privacy and evidence

Never upload passwords, tokens, cookies, authorization headers, private keys,
Windmill/transport identifiers or unsanitized customer data. Exclude secrets from
queries, titles, slugs, metadata and idempotency keys as well as evidence bodies.
No credentials belong in this skill or its local journal.

Prefer minimal synthetic or redacted excerpts. Replace customer names, addresses,
phone numbers, domains, call IDs and paths consistently where they are unnecessary.
Keep the command grammar and relevant observation intact; document redactions and
any resulting loss of evidence strength. If a command contains an inseparable
secret, omit the command and describe only the sanitized diagnostic purpose.
Never generalize a customer-specific path or credential into a procedure.

Customer-specific evidence may be retained only in an explicitly authorized
protected C0 space with suitable membership. Application-wide Admin access still
applies. Legacy Shared is not private, and a private-sounding space name does not
establish isolation. When adequate authorization/isolation cannot be established,
keep a restricted sanitized local checkpoint or omit the data. Do not change grants
or copy data to another space to make a write succeed.

Record provenance: observation time, logical investigation, product/component,
known version, source tool, selected visible result, exit status, truncation and
redaction state. Claims reference real ready evidence and distinguish direct
observations from interpretation. Missing historical output remains missing.
A historical success does not authorize a production command; Gate decisions and
human approvals remain authoritative.
