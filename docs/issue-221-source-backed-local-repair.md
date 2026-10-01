# Issue 221: source-backed LOCAL repair

## Separate authority

A current target that differs from a historical signed receipt cannot use
historical continuity. Source repair creates a new baseline from a fresh
source capture and reviewed current target preimage. Old receipts, generation
fences, journals, adoption markers and immutable claims remain evidence.
Nothing in this document grants persistent execution or schema DDL.

## Retained claim foundation implemented here

`SourceBackedLocalRepairClaimStore` is internal and cannot issue a write permit.
It reserves a distinct `source-backed-local-repair/v1/preimages/<hash>` and
`source-backed-local-repair/v1/active/<claim-id>` in the existing approved
locked-retention authority. It deliberately shares the exact historical
`claims/v1/target-generations/<generation-hash>` and
`claims/v1/future-plans/<plan-hash>/<generation-hash>` reservation names and
reservation byte schema. Claims in either domain therefore conflict in either
creation order. No old historical receipt is invented or promoted.

All creation uses the existing `IRolloverClaimObjectGateway` create-only
protocol. Bucket policy must have locked retention of at least 31,557,600
seconds, uniform access and disabled versioning. Every returned generation,
retention expiration and exact byte readback is checked. Admission references
are lowercase SHA256 digests, exact Docker generation/volume creation/system
identity, and ordered settled metadata for all 23 required databases. Claims
expire 364 days after creation. A partial publication retains reservations and
fails closed; it is not automatically retried under a new claim.

The existing approved authority is `gs://maliev-legacy-rollover-claims`, with
its dedicated create/get runner. This slice creates no infrastructure, IAM,
live claims, source capture, application rows or public console entry point.
A raw internal reservation is not signature validation. A later trusted issuer
must validate fresh signatures, source/disposable proof and complete target
preimage before it invokes this method; no current CLI invokes it.

## Remaining required execution contract

1. Sign an exact-23 complete target preimage from locked per-database snapshots.
   Include every source-owned row (including rows unchanged by the plan), every
   approved application-owned row and sequence, full approved physical catalog,
   all generation fences and settled journals. Bind the approved extension
   profile and explicit prior metadata; reject unresolved journals.
2. Bind a fresh source capture and same-capture separately signed disposable
   proof, exact zero-delete operation set, physical target identity and distinct
   short-lived authorization. Precision completeness must use the separately
   reviewed exact-value source capture contract, not reconstruct missing digits
   from a normalized public value.
3. Reserve signed, retained repair ordinals in a distinct domain, with global
   authorization replay protection. Re-read immutable authority and physical
   identity around a double exact-23 mixed-state scan. Admit only exact prior
   preimage or matching claim-bound committed adoption; reject third states.
4. Require an explicitly staged and catalog-verified repair adoption marker.
   Row synchronization may not create tables implicitly. In each serializable
   database transaction lock and verify the complete signed preimage, CAS the
   old fence, apply reviewed row operations, reconcile, and atomically write
   checkpoint and repair marker. Rollback must retain old database state while
   immutable reservation/ordinal evidence survives.
5. Publish terminal success only after a new signed checkpoint-bound exact-23
   reconciliation and retained terminal evidence. Publication failure must be
   recoverable from committed markers without replaying operations.

Customer/employee effects, Invoice authority tables, Auth sessions and future
consumer migration-history dispositions require explicit approved contracts.
The source-owned `RequestQualificationAudit` must never be blanket-excluded.
No application deployment, namespace `maliev` write, bulk database replacement
or local session transfer is part of this recovery.

## Validation of retained-store foundation (October 2)

- Whole Release solution build: zero warnings and errors.
- New store and historical store focused tests: 26 passed, zero skipped/failed.
- Core suite: 1,500 passed, 15 owner/environment/platform opt-in skips, zero failures.
- SQL Server suite: 169 passed, nine environment opt-in skips, zero failures.
- Whole solution formatting, staged whitespace, staged and individual-file Gitleaks
  scans passed. Package audit found no vulnerable packages in all six projects.
- Current Workflows current-tree credential scan reports 17 existing fixture
  literals in unrelated baseline files, and no finding in these three files.
  This is recorded as a baseline scanner limitation; it is not called a passing
  whole-repository credential gate and no allowlist or unrelated file was changed.

Feature-contract RED used an explicitly unimplemented internal reservation
method: seven cases compiled with zero warnings/errors and failed with
NotSupportedException before implementation. It is not represented as an
existing runtime regression. Remaining cases cover retained read tampering,
partial publication, insufficient object retention, shape, expiry and
concurrent competing claims. No test or this slice creates a live cloud claim
or grants persistent execution.

## Complete database snapshot reader and overlap correction

The internal preimage reader is read-only when given a repeatable-read/read-only
transaction. It also accepts a caller-owned serializable transaction and never
commits it, provisions metadata, runs DDL, or calls nextval. It records every
application/internal table row multiset, observed supported physical source
schema, table/catalog owner and ACL state, collations and actual versions,
functions/types/extensions/database settings, and every sequence's bigint
physical definition and last_value/is_called. Pending journals and invalid
fence cardinality fail closed. RequireMatches compares complete domain-separated
digests, so unchanged source rows and preserved application effects are covered.
The result is observed evidence, not approved schema or an execution permit.

PostgreSQL sequence state is not MVCC snapshot data. This reader is not a claim
that reading a sequence inside repeatable read freezes concurrent allocators.
Signed issuer/transaction integration still must perform the approved quiescence,
locking, repeated identity and sequence/preimage checks; no live caller invokes
this reader. Profiles, exact source capture, staged marker, retained ordinal,
atomic adoption and terminal publication remain separate incomplete gates.

The claim competition test now uses an asynchronous two-arrival barrier on the
shared generation reservation, with RunContinuationsAsynchronously and a bounded
five-second timeout. It checks both arrivals, one winner/active claim, and both
retained preimage reservations. The raw internal method is named ReserveAsync
to avoid representing shape checks as signature verification.

Validation: whole Release build zero warnings/errors; focused new/historical
claim and actual disposable PostgreSQL preimage checks 35 passed, zero skips;
core suite 1,509 passed, 15 unchanged opt-in/platform skips, zero failures.
Eight churn cases include unchanged source row, preserved effect, old fence,
sequence value/cache, internal schema, function and database configuration;
unsettled journal rejection and serializable caller rollback preserve all rows,
metadata and a sequence above 2^53. Full formatting and scoped/staged scans must
pass before committing this slice. The baseline scanner findings recorded above
remain unchanged and are not waived.
