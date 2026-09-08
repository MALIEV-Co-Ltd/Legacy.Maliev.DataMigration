# Exact-23 in-place PostgreSQL delta synchronization

Status: owner approved in chat on 2026-09-08. This design authorizes implementation and validation only. It does not authorize a canonical PostgreSQL write, Legacy application deployment, traffic change, or cutover.

## Outcome

Refresh each of the 23 existing migrated PostgreSQL databases from one immutable, consistent SQL Server backup cutoff without replacing any database. The synchronization computes keyed row differences, applies only inserts, updates, and explicitly reviewed authoritative deletes, reconciles the resulting target, and records signed idempotency evidence. The same engine refreshes the local Aspire PostgreSQL review databases.

Hangfire and Log are retired and remain outside the active inventory.

## Safety boundary

- A full COPY_ONLY SQL Server backup is immutable source input, not a command to perform a full target restore.
- The delta runtime has no database create, drop, rename, promote, swap, truncate, schema-DDL, or shadow-target capability.
- Every participating table requires a non-null primary key from the signed schema plan. Tables without a proven key fail closed.
- Source and target schemas must match the signed plan before comparison and immediately before mutation.
- A plan binds the source receipt and cutoff, schema-plan digest, observed target generation/fence, exact database/table inventory, row fingerprints, and operation counts.
- Execution requires a short-lived signature distinct from planning evidence. A changed plan, target fence, source receipt, schema, or executable is rejected.
- Each database is updated in a bounded serializable transaction with an advisory lock. Inserts and updates run in foreign-key order; deletes run in reverse foreign-key order.
- A failed database transaction rolls back completely. A successful database records its signed checkpoint atomically. A repeated identical cutoff is a no-op; a conflicting replay is rejected.
- Delete operations are derived from the complete authoritative backup and are included in the signed reviewed plan. Deletes are never inferred from a partial source read.
- No row values, credentials, connection strings, or customer PII appear in plans, receipts, logs, or issue evidence.

## Delta model

Rows are identified by the ordered primary-key columns in the signed table plan. Key bytes and row bytes use the existing type-aware canonicalization rules, including exact handling for nulls, binary data, Unicode, invariant decimals, and temporal precision. A planner merge-joins two strictly ordered streams:

- source key absent from target: insert;
- key present in both with different canonical row fingerprint: update;
- key present in both with equal fingerprint: unchanged;
- target key absent from the complete source: authoritative delete.

Duplicate or out-of-order keys, missing key values, mismatched row shapes, streamed values that have not been safely consumed, or a table without a primary key stop planning.

The persisted delta plan contains operation identities and fingerprints, not row payloads. Row payloads are reread at execution under the bound source snapshot and must match their planned fingerprint before mutation.

## Verification

After each database transaction, compare exact schema fingerprints, table counts, deterministic content and aggregate hashes, null counts, foreign-key relationship and orphan counts, and identity/sequence state. Representative read-only service queries are a separate release-gate artifact. The final exact-23 receipt is complete only when every active database has a verified checkpoint at the same source cutoff.

Local Aspire uses the same planner, executor, journal, and reconciliation contracts with a local-resource authority. It may not accept fixtures or synthetic accounts as production-parity evidence.
