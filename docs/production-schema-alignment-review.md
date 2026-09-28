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

The 2026-09-27 authenticated full-catalog observation found 21/23 whole-schema
hashes different from the reviewed preimage, even where names alone suggested
the reviewed additive gap. ContactRequest and LocationData matched; therefore
the manifest correctly refuses to produce an alignment review. The source-row
counts remain historical. Before a
separate production DDL design, obtain a fresh authenticated full catalog and
schema plan, prove the identical additive operation set on an independent
disposable exact-23 PostgreSQL cluster, define distinct signed disposable
proof and short-lived target-specific authorization, validate the production
transport beyond its present plan-only boundary, and obtain explicit owner
approval. Apply per database with pending/uncertain-result handling; do not
run EF `Database.Migrate` over existing databases without migration history.
No deployment, cutover, sysdiagrams retirement, or production row delta is
authorized by this manifest.

The owner-only `inspect-production-schema-catalog` command is the read-only
full-catalog observation step. It requires a protected, fresh exact-23 source
plan and verified production target authority. For each database it reads table
and column names and the full structural fingerprint from one repeatable-read,
read-only transaction. Its PII-free output binds the source commit, canonical
schema-plan SHA-256, target authority, observation time, and all 23 observed
catalogs. The source-plan freshness and target authority are checked again
before publication. It reads no application rows and signs or applies nothing. The
owner must still review the catalog and run a separate disposable additive proof
before any production DDL request.

`ProductionDefaultDriftReviewPlanner.Plan` is a separate, non-executable
classification for the `present-different` default-expression drift class. It
requires a fresh exact-23 source schema plan, canonical complete catalog order,
and verified production CNPG authority. It records the source-plan digest and
commit, target identity, each observed whole-database fingerprint, and for each
affected table the observed complete-table preimage and expected final-table
fingerprint. The review digest includes every database, table, and listed column
with explicit boundaries. Only schema/table/column names and structural hashes
are emitted; neither actual nor planned default SQL is copied into the review.
The `OtherShapeDriftPresent` flag reports additional drift on the listed table,
not a claim that other databases or tables match. The observer's catalog must
still be independently authenticated; a constructed observation is not proof.
This review does not select a default repair expression, authorize DDL, or
relax `ProductionSchemaAlignmentManifest`'s strict whole-schema preimage gate.
The 304 collation, seven generated-expression, two LockoutEnd type, missing
object, and other shape discrepancies remain separate review work. In
particular, no PostgreSQL type normalization is inferred from the SQL Server
`datetimeoffset` source mapping, whose offset and precision semantics must be
preserved by any later, separately reviewed design.

The catalog now also emits a digest for each table's columns, constraints,
indexes, foreign keys, and complete table shape, all from that same snapshot.
`tableDiagnostics` compares those digests to the *final* source-plan target
shape and labels each table `match`, `shape-drift`, `missing-table`, or
`target-only-table`, with changed structural facets. These labels contain no
row values, SQL expressions, or credentials. An incomplete or duplicate
component catalog fails closed. They do not identify the precise column type,
constraint, or index definition responsible and do not imply additive DDL is
safe. The prior catalog output has no component digests, so a new owner-only,
identity-bound read-only observation is required for this classification.

The subsequent 2026-09-27 observation classified 78 tables with column-shape
drift, seven with index drift, and one with constraint drift; 21 expected tables
were absent and four matched. To narrow the systemic column mismatch without
publishing schema SQL, the observer also emits `columnDiagnostics`: each
observed or expected column name is labeled `match`, `shape-drift`,
`missing-column`, or `target-only-column`. Changed facets are limited to
`type`, `nullability`, `identity`, `default`, `generated`, and `collation`.
Neither the observed type nor default/generated expression or collation value
is serialized. This is a comparison to the expected *final* target shape,
not the reviewed preimage and never DDL authorization. The component and
column diagnostics come from one read-only repeatable-read catalog snapshot;
missing or duplicate column observations fail closed. A fresh owner-only
catalog run after this change is needed to see the column labels.

For owner review, each observed column now also carries fixed-vocabulary
field evidence. `actualTypeCategory` is an approved broad PostgreSQL type
category, never an unconstrained type declaration. `actualCollationMode` is
`inherited` or `explicit`; `actualCollationIdentity` names only a small
allowlist of built-in collations, otherwise `explicit-unreviewed`.
`defaultState` and `generatedState` distinguish absent, unexpected-present,
matching, and present-different expressions without serializing their text.
These fields are diagnostic only: an unreviewed collation or differing default
does not become equivalent by classification, and the exact preimage/shape
gate remains unchanged. A fresh identity-bound, read-only observation is
required to classify the production drifts; previous output cannot be reused
as a new schema authority.

The collation diagnostic now reads `pg_collation` metadata for every explicit
column collation in that same read-only transaction. It requires exactly one
metadata row per explicit column and rejects missing/duplicate metadata,
unknown providers, and an encoding incompatible with the current database.
Output uses fixed labels only: provider (`builtin`, `libc`, `icu`, or
`database-default`), determinism, recorded-vs-current version state, and
`pg-catalog` versus `non-pg-catalog` namespace scope. Raw collation names outside
the existing allowlist, locale, rules, and version values remain unpublished.
These labels help triage the 304 `explicit-unreviewed` observations but cannot
prove equivalence with an inherited PostgreSQL or source SQL Server collation.
The source inventory hashes SQL Server collation metadata but does not map it
to a PostgreSQL collation contract; PostgreSQL behavior also depends on the
provider, locale, rules, determinism, and provider version. The whole-schema
fingerprint and strict alignment gate remain unchanged. No collation change,
normalization, index rebuild, or production DDL is authorized here.
