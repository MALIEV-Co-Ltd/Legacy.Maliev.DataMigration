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

## Catalog coverage correction

Three genuine regression cases initially failed against the implemented reader:
sequence ACL changes, sequence OWNED BY dependency changes, and schema ACL changes
left the preimage digest unchanged. The reader now includes sequence owner/ACL,
persistence/options/dependencies, schema owner/ACL and default privileges,
collation owner, type ACL and standalone composite attributes. The expanded
14-case actual PostgreSQL preimage suite passes with no skips. This is still
observed evidence and does not approve a schema, lock concurrent allocators,
issue a signed repair admission, or grant execution.

The narrow settled-receipt timestamp defect is a separate commit: a valid signed
seven-digit source header and six-digit PostgreSQL checkpoints now bind using
the existing PostgreSQL storage precision rule. Exact signed headers remain
unchanged; a one-microsecond changed actual journal still rejects. This has no
bearing on preserving the exact SQL Server user datetimeoffset values, which
remain governed by the separate exact-capture contract.

Validation after rebasing onto accepted consumer profiles main e2f63f1:
Release build zero warnings/errors; expanded preimage focus 14 passed, no skips;
whole core suite 1,581 passed, 19 unchanged opt-in/platform prerequisites skipped,
zero failures. Whole DataMigration formatting verification passed. Staged diff
and credential checks are required before committing. No persistent runtime
or console admission is created by this correction.

## Signed observed preimage evidence

The new internal preimage attestation signs the entire ordered exact-23
observed database preimages and full Docker/volume/system identity. Its separate
domain binds the paired plan digests, the same-capture disposable receipt and
capture digest, and the fresh authorization ID. The signer must be the trusted
independent proof-evidence role. The lifetime cannot exceed 15 minutes or the
paired authorization. Verification rechecks fresh paired proof/authorization,
identity and each complete observed database digest. Serialize/deserialize
round trips retain verification.

This capsule is observed evidence: it does not approve the physical schema,
attest allocator quiescence or locks, establish cross-database atomic snapshots,
prove future exact-source precision, reserve an immutable claim, create a CLI
or permit persistent execution. A future trusted issuer still must obtain
locked/quiescent live preimages, recheck identity and evidence, and complete the
retained ordinal/marker/atomic-adoption/terminal gates. No persistent target or
live cloud authority is accessed by this slice.

The eight cases reject signature, observed preimage, identity, capture, proof,
authorization, expiry and inventory changes. The binding mutations are re-signed
with the trusted evidence key so signature rejection alone cannot satisfy them.
There is no claimed historical runtime regression or RED phase for this new
non-executing evidence contract. Build and core suite passed: zero warnings/errors,
1,589 core tests passed with 19 unchanged opt-in/platform prerequisite skips.
Final stronger focused checks, formatting and staged scans must pass before
commit. SQL adapter code and CLI execution contracts are unchanged.

## Guarded execution integration

The foundation validation above describes its individual commits. It does not
establish that a later executor build passed, or that the persistent target was
refreshed. Record the exact integrated source commit and its own validation
results before using the execution commands below.

The execution boundary checks the fixed canonical DataMigration repository,
clean synchronized protected main, exact-head required GitHub Actions check,
and the running frozen Release directory against the independently built
canonical Release bytes. A caller configuration flag or historical green check
cannot grant execution. Keep the accepted DataMigration main commit unchanged
through the run; coordinate the single code acceptance lane and data writer.

Prepare a fresh owner-only Windows run root with
`prepare-source-backed-local-repair-authority`. Its protected minimal
`sourceBackedLocalRepairAuthority` configuration contains `artifactRoot` and a
`bindingOutputPath` immediately inside that root. This command creates the
permanent run lock and records its actual filesystem binding. It does not
provision PostgreSQL, read signing keys, or reserve a remote claim. Subsequent
commands must reacquire that same binding; a copied directory is not authority.

Before capture, plans or signed target preimages, provision a fresh run-specific
operator role and reviewed HBA allowlist separately. Bind the role custody
comment to the actual run-root binding. Pin the real Docker image, published
loopback endpoint, persistent volume, PostgreSQL system identifier, observed
client address and role expiration. The maintenance provider rechecks those
facts, sole volume writer, session exclusion and exact HBA file/rules throughout
execution. A physical recovery clone sharing a system identifier is not the
persistent endpoint, and cannot serve as the distinct-system disposable proof.
The provider never provisions a role or opens application access itself.
Install the reviewed HBA allowlist, then perform the separately reviewed restart
of the same container before capture or plans. Publish fresh target identity and
maintenance pins from that restart: `postmasterStartedAtUtc` and
`hbaFileStateSha256` are mandatory. Use the new
`repair-operator-target-identity.json` generation for every downstream plan and
command. HBA reload alone does not exclude previously authenticated sessions;
even a same-byte HBA rewrite after the pinned start fails the maintained gate.
Keep the original application HBA and its authenticated restoration provenance
separate from the currently restricted operator HBA for the post-terminal
lifecycle operation.
The initial operator role is bounded to four hours and cannot be extended by
renewing row authorization. Provision it before observing the signed catalog;
changing it afterward is a preservation-state change, not an automatic renewal.

Generate fresh distinct plan, authorization, proof-evidence and persistent
terminal-evidence signing material in protected files. Project current approved
credentials independently. Capture the approved 23 SQL Server databases through
read-only source access, obtain fresh target-specific paired plans, inspect the
exact operation sets, and execute the same captured operations on a separately
observed disposable PostgreSQL target. Require its independently signed actual
reconciliation, distinct system identity and the normal freshness gates. Test
fixtures and a successful logical copy cannot substitute for that proof.

Use `authorize-source-backed-local-repair` to issue the initial paired row
authorization and each fresh renewal authorization. Its protected
`sourceBackedLocalRepair` configuration adds `authorizationKeyId` and
`authorizationPrivateKeyFile`; `expiresAtUtc` is the fresh authorization expiry
(at most 15 minutes). This signing command does not read `authorizationPath`,
admission, capture AES material or evidence private keys, and creates no claim.
It checks the actual maintained endpoint and all 23 selected physical schemas,
plus the authenticated pair, source schema and disposable proof. Complete
preimage or retained mixed-prefix verification remains mandatory in admission
or renewal before any execution permit. The ordinary
`authorize-paired-local-transition` command retains its original strict row
preflight and cannot authorize this historical-generation repair.

`stage-source-backed-local-repair` explicitly stages an empty
`legacy_migration_internal.delta_source_backed_repair` table in each of the 23
databases before the preimage is signed. Its complete catalog, explicit NOT NULL
constraints, sole primary key and existing journal-owner binding are verified.
An existing empty conforming table is an idempotent retry. A nonempty or altered
table fails closed. Row synchronization never creates the marker table.

`admit-source-backed-local-repair` then obtains the locked exact-23 preimage and
reserves the retained claim. `apply-source-backed-local-repair-next` admits only
the next canonical database from a sealed actual mixed-state observation. Each
database transaction verifies the full preserved preimage, applies the approved
captured row operations, reconciles actual rows, and atomically commits the
checkpoint and marker. Its immutable continuation is published after commit.
If publication is interrupted, recover from the verified committed marker;
do not replay DML or allocate another claim to escape the reservation.

Before reserving the claim, retain the full original signed admission, capsule,
authorization, paired plans, schema and proof with their public signing material.
Bind the distinct persistent terminal signing key ID and fingerprint at that
time too. Private signing keys, capture encryption keys, connections and raw
source rows never belong in that retained authority object.

For a refresh that outlasts its authorization, use
`renew-source-backed-local-repair` with a newly signed paired authorization in
`freshAuthorizationPath` from `authorize-source-backed-local-repair`, the retained database ordinal and
`previousGrantCounter`. Retain a separate signed renewal epoch against the same
original authority, claim, capture, plans, proof, target and actual progress.
Select the verified epoch with `activeGrantCounter` for subsequent apply and
terminal commands. Zero selects the original epoch only while it is fresh and
has not been superseded. Publishing the first grant invalidates an original
permit even if its old authorization has not expired yet.

Renewal requires an actual maintained double scan, immutable chain readback and
a unique fresh authorization. It does not extend a capsule, alter the original
claim, waive source-plan/proof freshness or invent a historical execution clock.
Old signed artifacts are verified at their authenticated issuance instant only
as provenance. Each actual row transaction still requires a current sealed grant
and fresh authorization before commit. A retained all-prior basis zero can
recover interruption before ordinal one publication; it cannot admit an applied
database. A committed prefix remains preserved across renewal.

Create-only authorization-ID reservations cover original source-repair epochs
and their renewals, including nonconsecutive and cross-claim replay attempts.
This protocol does not claim that historical authorizations issued before its
introduction were backfilled into that namespace. Keep fresh source-repair
signing material distinct from historical runs.

`reconcile-source-backed-local-repair` compares all 23 actual targets against
the captured source through the real checkpoint reader and reconciliation
coordinator. Checkpoints remain required; they do not replace the actual source
comparison. A fresh distinct persistent-evidence signer signs terminal evidence,
which is published create-only and independently read back. Repeated publication
must match the retained claim and bytes. Only a verified ordinal-24 observation
and retained terminal receipt establish completion of this target's refresh.

Terminal success on the local target does not establish local-versus-production
parity. Independently compare both targets' required table counts, semantic
checksums, physical types/collations, sequence state, relationships and approved
extensions against the same reviewed capture. Account explicitly for retained
retired tables and environment-owned Auth data. Report capture windows and later
source writes separately. Restore application access and retire the temporary
operator only as a separately recorded post-terminal lifecycle operation;
neither lease disposal nor an expired authorization opens the HBA automatically.

### Reviewed final Quotation schema and daily refresh

Paired capture accepts exactly two derived Quotation physical schemas: the
reviewed retained-outbox transition schema and the complete mapped final schema
from the signed current source schema plan. Both targets must use the same
variant. The console observes the actual catalogs before capture and checks
the selected variant again afterward. No configuration field supplies an
arbitrary accepted schema hash. Final disposable execution requires the full
verified source schema context; the persistent executor requires its sealed
source-repair authority.

For the existing persistent local target, separately review and prove the
preservation-safe move of the two retired public Quotation outboxes into
`legacy_migration_internal.LocalQuotationRetiredGoogleAnalyticsOutbox` and
`legacy_migration_internal.LocalQuotationRetiredQuotationOutcomeOutbox`.
Preserve their rows, object identities, owned sequences, privileges and
dependencies. Do this before signing the new preimage, and bind the archived
tables as immutable private state. This is explicit schema work, not a deletion
inferred from a source delta or a generated Down migration.

The resulting application schema admits the ordinary schema-1.2 daily path.
The repair marker and retained private archives must survive subsequent daily
refreshes. A successful first repair alone does not prove that boundary; verify
a fresh ordinary plan, ordinary authorization, actual row apply and complete
reconciliation with the same preservation constraints.
