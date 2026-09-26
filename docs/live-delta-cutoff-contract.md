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

For schema-1.3 planning, each database's encrypted SQL Server capture is closed
before comparing it to PostgreSQL. The target comparison then holds one
read-only repeatable-read PostgreSQL snapshot across all tables in that
database. Its MVCC view is established when the transaction opens, so a target
write between table scans cannot mix target cutoffs in one signed operation set.
The source and target cutoffs are distinct, not a distributed transaction or an
atomic cross-database snapshot. A later target change still fails the guarded
transactional apply/reconciliation; a later source change is deferred.

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

## Capture codec status

`DeltaCapturedRowCodec` provides a bounded encrypted row stream for the
capture/replay path. It preserves SQL scalar types and single-pass large values,
binds the table identity in the authenticated archive context, and rejects
tampering, unsupported types, duplicate keys, and unconsumed large values.
Its raw plaintext codec methods are internal; callers must publish only the
authenticated encrypted form. The exact-23 captured planner, signed plan,
replay executor, and checkpoint reconciliation now use the codec, but a full
live-write disposable proof remains required before persistent execution.
The schema-1.2 live-row mismatch guard remains unchanged.

## Disposable proof identity gate

The exact-23 disposable proof verifier now requires the persistent-local
schema-1.3 plan to bind the *same* encrypted capture, not merely an equivalent
row count, operation hash, or source reconciliation. Its signed manifest must
match the disposable plan's encryption-key fingerprint and every database's
capture window, source reconciliation digest, ordered table name, capture ID,
ciphertext and plaintext digest, selected-row count, and operation hash.
The existing requirements for distinct PostgreSQL identities, target-specific
signed plans, fresh signed reconciliation, and identical per-table operations
remain in force. Separately recapturing SQL Server after disposable proof is
not an acceptable persistent-local plan: daytime writes can change the cutoff.

This is a fail-closed prerequisite, not permission for persistent execution.
The daily helper still creates a fresh run-owned capture and rejects
schema-1.3 persistent `-Execute`; the console independently rejects it as
well. An operator must not copy or re-sign a disposable plan into a persistent
run. Promotion requires a separately validated protected archive handoff and
target-specific planning path, plus disposable live-write, rollback, and
replay integration evidence. Until then, issue #92 remains open and the only
schema-1.3 apply authority is an isolated disposable target.

The signed delta-plan model now reserves schema 1.3 for exact-23 captured
source metadata. Its domain-separated signature binds each database's bounded
snapshot window and PII-free source reconciliation, plus every table's capture
ID, ciphertext/plaintext digests, captured insert/update row count, and
operation hash. The capture encryption key must be distinct from the backup,
plan-signing, and execution-authorization keys. Existing schema 1.1/1.2 plans
are unchanged. The library's authenticated captured-row replay and checkpoint
reconciliation paths now accept reviewed Quotation archive/adoption bindings,
including target-named signed operations. The guarded operator console can
issue a schema-1.3 plan and apply it only to a disposable authority. Persistent
targets remain prohibited pending full exact-23 disposable proof and separate
target-specific authorization. No daily operator should apply a 1.3 plan to a
persistent target yet.

`DeltaCapturedTableArchive` now writes each source table to a create-only,
run-owned encrypted file under an existing protected directory. It records the
ciphertext and plaintext digests, capture ID, row count, and schema-plan hash;
replay verifies ciphertext and authenticated plaintext digest before yielding
rows, checks row count at completed enumeration, and requires the expected
database, table, schema-plan hash, and key. `DeltaCapturedTableRowSource` can
plan from the immutable capture after SQL Server changes, and its signed-plan
factory verifies the plan signature and encryption-key fingerprint. These are
building blocks of the captured path. A second encrypted selection pass retains just the
planned insert/update rows, checks their keys and canonical fingerprints, and
rejects missing rows; the initial full-table encrypted staging file is
temporary and must be removed after a completed run. The guarded exact-23
console creates and uses these artifacts only with captured-source mode and a
disposable apply authority. Its schema-1.2 live-source re-read remains guarded
against drift.
`SignedCapturedSourceReconciliationInspector` can return the source row/FK/
sequence evidence from a fresh trusted plan without another mutable SQL read;
it rejects a different exact-23 schema plan or database schema. The captured
console path selects it for disposable replay.
