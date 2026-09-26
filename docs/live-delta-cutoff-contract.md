# Deterministic live-source cutoff contract (issue #92)

The signed schema-1.2 plan records a bounded *observation window*, not a
durable SQL Server snapshot. Planning closes its 23 snapshot transactions
before a later command opens new ones for apply. A row inserted between those
commands invalidates the signed operation set. The executor must continue to
fail closed and roll back that database; priority ordering and an overnight
schedule only reduce the probability of this failure.

The replacement must capture the source values required for each planned
insert or update while its database's snapshot transaction is open. It must
not re-read mutable SQL Server rows to resolve those operations during apply.
The capture is an owner-only, encrypted, authenticated, bounded-lifetime
artifact, and the signed plan binds its exact digest, source database, table
inventory, schema fingerprint, per-database capture time, and operation hash.
There must be no plaintext spill of customer rows or large values. Unchanged
rows need not be retained; deletions bind the observed target key and row hash.

Apply must independently verify the captured artifact and every staged row's
key and canonical fingerprint against the signed plan. It must verify the
current PostgreSQL target identity, schema, and pre-apply row fingerprints
inside the database transaction. A later SQL Server insert or update is
*deferred to the next run*, not treated as an operation in this run; a later
target mutation is never silently accepted. Source reconciliation for the
checkpoint must derive from the captured snapshot's signed evidence, not a
fresh live scan. PostgreSQL post-apply reconciliation remains checkpoint-bound.
Proof and persistent runs must use the same captured source artifact and
operation set, but different target observations, plans, signing keys, and
short-lived authorizations; production has its own review and authorization.

Implementation gates:

1. Prove encrypted capture round-trips all supported scalar, Unicode,
   decimal, timestamp, binary, and streamed large-value types without
   materializing an unbounded value or writing plaintext files.
2. Prove a SQL Server insert/update/delete after capture does not change the
   operation set applied from the artifact, while target tampering, capture
   tampering, stale capture, wrong database/schema/key, or changed operation
   hash fails before any checkpoint.
3. Prove transaction rollback and idempotent replay after cancellation or
   interruption, including a partially completed exact-23 run.
4. Run disposable exact-23 proof, then distinct persistent-local and
   production-target signed plans and reconciliation. Never replace a
   database, assume an atomic cross-database cutoff, or claim parity with
   later source writes.

The current live-write regression test intentionally asserts safe rollback.
It is not proof that the deterministic capture design has been implemented.
