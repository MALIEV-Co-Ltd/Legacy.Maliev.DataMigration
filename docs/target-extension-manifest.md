# Approved target-only schema profiles

The signed exact-23 source schema plan records a `TargetExtensionProfile` only
for databases with a reviewed PostgreSQL-only service table. The profile is
included in the schema-plan signature; its complete table shape is fixed in
`ApprovedTargetExtensionManifest`. The expected PostgreSQL fingerprint includes
both the SQL Server source-owned tables and these extensions. Unknown target
tables, modified extension columns/defaults/constraints/indexes, or a source
table using an extension name remain schema mismatches.

| Database | Profile | Tables | Owning service |
| --- | --- | --- | --- |
| Material | `material-catalog-v1` | `public.Country`, `public.Currency` | Legacy.Maliev.CatalogService |
| QuotationRequest | `quotation-request-idempotency-v1` | `public.RequestCreateIdempotency` | Legacy.Maliev.QuotationService |

The manifest was checked against the PostgreSQL catalog in the existing
`maliev-legacy/legacy-postgres-main` primary on 2026-09-26: ordered column
types/nullability, UTC timestamp defaults, identity flags, primary keys, and
indexes match the owning service's committed EF migrations. Material's two
tables contained 197 and 168 rows at the earlier PII-free observation;
RequestCreateIdempotency was empty. Those counts are **not** a current row
reconciliation and must never be used as permission to overwrite the tables.
The read-only gap report labels approved-present, approved-missing, and
unapproved target-only tables separately; a names-only report never replaces
the full schema fingerprint.

Disposable schema creation provisions empty extension tables so the same full
shape can be proved without copying target-only production rows. Delta planning,
row operations, and source-owned reconciliation continue to enumerate only
`DatabaseSchemaPlan.Tables`. The transactional executor locks the approved
extension tables and compares their complete ordered row evidence and identity
sequence state before and after source-owned row operations. A change rolls the
database transaction back. This profile does not authorize DDL against a
persistent target, an application deployment, or a data refresh. A fresh signed
plan and disposable proof against the actual target are still required before
issue #97 can close. The remaining source schema gaps and Quotation outbox
transformation are tracked in #94 and #100.

## Guarded local additive repair

`authorize-target-extension-repair` and `apply-target-extension-repair` are a
separate owner-only DDL boundary for an existing **local Aspire** exact-23
cluster. They do not accept a production authority, row-delta authorization, or
canonical bootstrap authorization. The protected config references a current
exact-23 schema plan, local target connection file, exact target authority,
one database (`Material` or `QuotationRequest`), the ordinal-sorted approved
missing set, a distinct DDL authorization public key, and new owner-only output
paths. Authorization signing additionally needs a protected fresh P-256 private
key through `LEGACY_MIGRATION_EXTENSION_REPAIR_AUTHORIZATION_SIGNING_KEY_FILE`,
`allowAuthorizationSigning=true`, and an expiry no more than 15 minutes away.
Execution needs the resulting authorization path and `allowExecution=true`.
Keep `LEGACY_DEPLOY_ENABLED=false` and `LEGACY_MIGRATION_CALLER=owner`.

The only admissible missing sets are `public.Country;public.Currency` for
Material and `public.RequestCreateIdempotency` for QuotationRequest. The
authorization is signed over the source commit, expected complete schema,
target authority/system identifier, database, missing set, and UTC lifetime.
Each command reserves a new owner-only output path atomically before target
work. An apply attempt leaves a durable `pending` marker if execution or final
publication fails; a completed receipt atomically replaces that marker. Do not
infer success or failure from a pending marker: re-observe the target schema
and use a fresh authorization rather than replaying uncertain work.
The pending marker is operational-only, not proof of authorization or DDL
outcome. The completed apply receipt records the signed authorization ID and
envelope digest, source commit, reviewed missing set, target authority, and
target schema hash for audit correlation; it is not a row-reconciliation receipt.
Before creating anything, the executor verifies that no approved extension is
partially present and that the complete source-owned schema already matches the
current signed plan. It creates only the approved tables, primary keys, and
identity sequences in one serializable transaction, then verifies the full
database schema fingerprint before commit. A fresh post-commit read-only
inspection checks target identity, full schema fingerprint, and approved
identity-sequence parameters before publishing success. This narrows, but does
not eliminate, the window for unrelated non-cooperating DDL after inspection.
An exact replay is a no-op; any unexpected table, column, type, constraint, or
identity drift fails closed.

The automated integration fixture has the exact 23 database *names* but only a
synthetic source-owned `Probe` table in Material. It proves inventory gating
and repair behavior, **not** the complete current source-owned schema shape.
This code is not an authorization to change the persistent local target. First
perform a separate fresh full-schema disposable proof from the current signed
exact-23 plan, with fresh identity and signing material, then seek a separately
reviewed local DDL authorization. Production
schema repair remains outside these commands. A successful DDL repair still
requires a new schema plan, fresh disposable row-delta proof, and independent
row-delta authorization; the DDL receipt is not row reconciliation.
