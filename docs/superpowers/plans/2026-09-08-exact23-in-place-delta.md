# Exact-23 in-place delta synchronization implementation plan

**Goal:** Incrementally refresh existing production and local Aspire PostgreSQL databases from an immutable SQL Server backup without replacing databases.

**Spec:** `docs/superpowers/specs/2026-09-08-exact23-in-place-delta-design.md`

## Task 1: Pure keyed delta planner

- Add tests first for insert, update, delete, unchanged, composite keys, null/non-null data, Unicode, decimals, timestamps, binary values, missing/null/duplicate/out-of-order keys, row-shape mismatch, and missing primary keys.
- Implement PII-free delta contracts and a streaming merge planner using canonical key and row fingerprints.
- Build, run focused tests, full affected suite, and formatting.

## Task 2: Signed plan and authorization contracts

- Add canonical signed plan payloads binding source receipt/cutoff, schema digest, target fence, runner digest, exact-23 inventory, table evidence, and operation counts/digests.
- Add validation tests for tampering, stale cutoff, wrong inventory, wrong target, conflicting replay, and signature-role separation.
- Build, test, format, and review.

## Task 3: PostgreSQL transactional executor and journal

- Add a canonical-target interface that intentionally exposes no database replacement or DDL operations.
- Add Testcontainers tests for bounded insert/update/delete, FK order, rollback, stale fence, advisory-lock exclusion, replay no-op, conflicting replay rejection, sequence advancement, and permission limits.
- Implement serializable per-database execution and atomic checkpoint journal writes.
- Build, test, format, and review.

## Task 4: SQL Server snapshot reader and exact-23 coordinator

- Stream ordered source rows from the restored immutable backup and ordered target observations.
- Generate and publish a reviewable signed delta plan without row values.
- Execute only with a distinct short-lived owner authorization and revalidate all bindings before each database.
- Prove the active inventory is exactly 23 and excludes Hangfire and Log.

## Task 5: Reconciliation and local Aspire delivery

- Run full post-delta schema, count, checksum, FK, orphan, identity, and sequence reconciliation.
- Route local Aspire refresh through the same delta contracts and produce schema-v2 evidence.
- Add representative service-query validation and encrypted local snapshot evidence.

## Task 6: Protected-main completion

- For each coherent slice: zero-warning Release build, focused tests, full suite, format/static/security review, protected-main PR, green required CI, merge, delete branch, and verify `main` equals `origin/main`.
- Update issue #41 and Project #2 with exact commits and validation evidence.
- Do not perform canonical data writes or deploy Legacy applications without their separate explicit gates.
