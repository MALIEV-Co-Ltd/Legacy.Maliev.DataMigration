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
