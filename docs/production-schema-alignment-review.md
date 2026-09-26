# Production schema alignment review manifest (#94)

`ProductionSchemaAlignmentManifest.Plan` is a pure, read-only review calculation.
It accepts a fresh exact-23 schema-plan object, an independently observed
production CNPG authority, and one complete table/column inventory **plus
whole-database structural fingerprint** per canonical database. It opens no
connection, signs nothing, emits no SQL, and cannot authorize DDL or row apply.
The caller must separately authenticate the protected source plan, observation,
and target identity; merely constructing these inputs is not evidence.

The reviewed production preimage is deliberately exact. `public.sysdiagrams`
must be absent in the 18 databases listed on #94; the plan retains each
source table as an `add-table` review step marked `PreserveSourceRows`. Earlier
read-only source counts found one row in each, but those counts are not a
current signed row capture. No retirement or row deletion is inferred. Invoice
is missing its two attribution fields; Quotation is missing four provenance
fields plus only the approved `legacy_compatibility.GoogleAnalyticsOutbox`
archive and `public.QuotationAcceptedOutcome` adopter; QuotationRequest is
missing the five reviewed Request fields and `RequestQualificationAudit`.
The old public Quotation source outboxes are **not** permitted in this
production preimage. Material Country/Currency and QuotationRequest
RequestCreateIdempotency remain approved target extensions in the complete
fingerprint and cannot be removed or silently ignored.

The planner derives the expected preimage by removing exactly the reviewed
missing objects and dependent indexes/check from the signed target plan. It
requires the observed name gap and complete structural hash to match that
preimage. Unknown objects, partially applied changes, wrong service field
types/default/nullability, changed retained constraints, wrong/missing target
extensions, source disposition drift, stale source plan, and non-production
authority all fail closed. The output records only object names, preimage and
final hashes, and an ordered review-step digest; it contains no rows or DDL.

This first slice does **not** prove the current production state: #94's latest
observation is names-only, and the source-row counts are historical. Before a
separate production DDL design, obtain a fresh authenticated full catalog and
schema plan, prove the identical additive operation set on an independent
disposable exact-23 PostgreSQL cluster, define distinct signed disposable
proof and short-lived target-specific authorization, validate the production
transport beyond its present plan-only boundary, and obtain explicit owner
approval. Apply per database with pending/uncertain-result handling; do not
run EF `Database.Migrate` over existing databases without migration history.
No deployment, cutover, sysdiagrams retirement, or production row delta is
authorized by this manifest.
