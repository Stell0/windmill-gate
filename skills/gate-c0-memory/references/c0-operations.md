# Connected C0 operations

Baseline: accepted C0 app 0.45/Core 0.29, schema 0016. Inspect the actual connected
tool schemas and caller-filtered capabilities; names below omit connector prefixes.
Prefer those schemas over examples here. MCP `c0://capabilities` and the deployed
`/agents` guidance describe current contracts. Do not install credentials or an
OAuth implementation in this skill. Tool availability is not proof of write scope
or permission to place customer data in a particular space.

1. Use `spaces_list`/`spaces_get` to establish the operator-authorized knowledge
   space and access. Supply its `space_id` on every applicable operation. A name
   is not an ACL. Legacy Shared is shared data, not a private customer space.
   Do not create spaces or change grants as an incidental memory action. If no
   adequate isolation exists, keep sanitized checkpoints locally or omit them.
2. `knowledge_search_structured` searches an explicit space with literal product,
   component/version and verification filters. Unknown metadata is not verified.
   Start bounded (for example limit 5), then broaden only within the authorized
   space if exact version tags yield no matches. `knowledge_search` provides
   ordinary source/Wiki search and text fallback. Missing indexing/providers must
   not block text retrieval. Read actual results and immutable revisions using
   `wiki_pages_get`, `entities_get`, `claims_get`, `documents_get`,
   `document_chunks_list` and `citations_get` as appropriate.
3. `sources_ingest_text` accepts selected sanitized text or Markdown, provenance
   metadata and an idempotency key. Use the connected schema's `data` envelope
   and space selector. Accepted baseline limits: body 131072 UTF-8 bytes,
   provenance 16384 bytes, serialized request one MiB. New source: omit source ID
   and expected revision; new version: provide both current source ID/revision.
   Retrying identical bytes uses the same key. Changed bytes or reconciled writes
   use a new key. Do not split secret-bearing payloads to evade limits.
4. The receipt initially may be queued. Poll `source_versions_list` or the returned
   job through authorized operations with bounded attempts (at most 5 over one
   minute). Read the ready document, chunks and stable citations before creating
   a sourced claim. Queued, failed and unavailable extraction are incomplete
   evidence. `source_versions_retry` is appropriate only for retained failed
   evidence and its expected generation; a retry is not proof of readiness.
5. Search before creating a procedure. `wiki_pages_resolve` uses exact slug within
   the same space. `wiki_pages_upsert` is create-only when expected revision is
   absent; update with the freshly read expected revision. Existing create/update
   operations also work under their actual schemas. On conflict, re-read and
   reconcile; do not overwrite another writer or replay changed input with an old
   key. `wiki_revisions_list` retains prior observations.
6. Once evidence is ready, `claims_create` records sourced assertions with actual
   immutable chunk references, not invented IDs. `entities_resolve`/`entities_create`,
   typed entity references and relations link cases, Wiki procedures, product
   versions and evidence. `knowledge_annotations_get`/`update` maintain
   applicability/verification for the exact content revision; changed content
   starts unknown. Use expected annotation revisions and a new retry key after
   reconciliation. Do not label an inference as an observed fact.
7. `knowledge_bundle_apply` can consolidate supported knowledge changes atomically
   in one authorized space, using the deployed bounded step schemas, ready
   evidence and expected revisions. Inspect every receipt and re-read results.
   Sequential operations remain valid; retain a manifest of successes/failures
   and never claim a partial sequence was atomic. Unsupported bundle operations
   must not be simulated as successful.

An older cached connector may advertise only 63 pre-memory operations. If it lacks
space selection, ingestion or current revision schemas, report the limitation.
Do not guess new arguments, write through legacy Shared, or switch to REST with
local credentials. Only retrieve explicitly authorized non-sensitive Shared
knowledge through available read operations; skip unsupported writes. Refreshing
or authorizing the harness connection is an operator action.
