# Issue #204: durable rollover claim authority

The global claim authority is a dedicated Cloud Storage bucket in project
`maliev-website`, separate from backup objects and every PostgreSQL database.
The provisioned bucket is `gs://maliev-legacy-rollover-claims`. Its dedicated
runner is `legacy-rollover-claims-runner@maliev-website.iam.gserviceaccount.com`,
bound only to the custom bucket role `legacyRolloverClaimRunner` with
`storage.buckets.get`, `storage.objects.create`, and `storage.objects.get`.
It has uniform bucket-level access, no object versioning, and a locked bucket
retention policy of 31,557,600 seconds (one year). The runner identity receives
only object create and read permissions on this bucket. It receives no object
delete, overwrite, bucket update, or IAM administration permission. Operators
verify inherited project grants as well as bucket grants before using it.

On 2026-09-28 UTC, an impersonated-runner storage probe verified exact object
readback, generation-match replay rejection (HTTP 412), delete denial (HTTP
403), and a retention expiration one year after creation. The probe is retained
under `probes/v1/`; it is not a claim or authorization.

The locked retention policy prevents deletion or replacement during the
retention period. `IfGenerationMatch=0` alone does not: it may succeed after the
live object is removed. Every claim and continuation has a 364-day maximum
validity from the claim object's creation time. After that deadline, admission
fails closed. Recovery after that deadline requires an explicit new migration
design; the retained records are evidence, not reusable authority. Bucket
deletion, retention-policy reduction, and restoring an older bucket snapshot
must not be part of the recovery procedure.

## Object protocol

All object names are under the versioned `claims/v1/` namespace. Their bodies
contain hashes, IDs, target identity, and exact-23 metadata only; no customer
rows or credentials. Writes use `IfGenerationMatch=0` and verify the returned
generation, retention expiration, and exact readback bytes.

1. Reserve `old-receipts/<historical receipt hash>` for one claim ID and
   attestation hash. A second claim for that receipt fails.
2. Reserve `target-generations/<target generation hash>` for the same claim.
   A different receipt and plan cannot claim the same target generation.
3. Reserve `future-plans/<future plan hash>/<target generation hash>` for the
   same claim. A crash between reservations leaves a durable, fail-closed
   incomplete claim.
4. Create `active/<claim ID>` with the hash of the verified signed attestation,
   old plan and receipt hashes, future plan, exact Docker/volume/PostgreSQL identity, and
   ordered 23 initial fence/journal fingerprints. A reader accepts the claim
   only after it re-reads all four objects at their exact generations and
   checks their hashes and retention deadlines.
5. Consume a continuation ordinal by conditionally creating
   `ordinals/<claim ID>/<20-digit ordinal>`. Ordinal one requires the active
   claim; later ordinals require the exact preceding ordinal object and a
   fresh signed continuation/authorization. The ordinal object retains both
   signed documents, the issuance time, and the ordered 23 database states so
   later reads can authenticate an adopted marker's historical authorization.
   A used ordinal cannot be overwritten or replayed. A gap, conflict, missing
   object, reused authorization ID, regressed adopted state, or expired claim
   fails closed. The runner must not issue a subsequent ordinal while a
   previous authorization can still have an in-flight transaction.

The bucket is a one-use claim ledger, not a transaction coordinator for 23
databases. The first claim is published only after independently verifying the
signed historical receipt, current exact-23 rows/schema/sequence evidence,
current Docker/volume/PostgreSQL identity, and the zero-delete paired proof.
The current store implements reservation, exact readback, retention checks,
one-use signed ordinals, and a public read that reauthenticates the original signed
attestation against the signed historical plan and 23-database receipt. It does
not grant execution authority. The following mixed-state reader and transaction
checks are required before any rollover can be enabled.

Before and after a mixed-state scan, the reader re-observes the claim and its
ordinal. Each database is either the exact prior signed state or has an atomic
claim-bound adoption marker, new fence, settled journal, and matching current
row/schema/sequence evidence. No third state is accepted.

The internal read-only mixed-state reader now scans each database under one
repeatable-read snapshot for its metadata and row evidence, performs the full
23-database scan twice, and brackets it with immutable claim/ordinal and
Docker/volume/PostgreSQL identity observations. A prior database must match the
signed historical receipt and initial metadata fingerprint; an adopted database
must match the signed disposable result and a retained ordinal no later than
the highest consecutive ordinal. This reader does not yet issue a write permit.

The per-database adoption transaction must hold the serializable locks,
compare-and-swap the old fence, apply DML and sequences, reconcile, and write
the marker and settled journal together. The existing unconditional metadata
upsert is forbidden on this path. Only a new signed exact-23 terminal
reconciliation completes the claim. A journal hash or global object alone is
never a receipt.

The existing canonical executor now rejects a `SettledPrior` LOCAL fence without
an internal claim-bound adoption permit, and
standalone paired-plan metadata provisioning rejects a different previously
settled Docker generation. This is a fail-closed interim guard; it does not
implement the claim-bound adoption transaction.

An internal adoption transaction path now conditionally changes one verified
prior fence and writes a claim-bound marker only after the settled journal is
present in that same serializable transaction. The marker table's columns and
constraints are checked before use and on readback. A read-only marker reader
joins the settled journal and checks the stored claim, plan, authorization ID,
prior metadata, and adoption time against a retained signed ordinal. Disposable
PostgreSQL tests prove rollback, marker readback, and one-use replay behavior.
The canonical metadata preflight admits a different full Docker generation
only when an internal rollover permit is present, the prior and current
generations share the exact volume creation identity, and the later CAS matches
the signed prior metadata fingerprint. A changed volume is rejected. The
canonical target also re-observes the exact Docker, volume, and PostgreSQL
identity before and after opening each database transaction; a restart on the
same volume is rejected before DML.
One disposable 23-database PostgreSQL test walks the claim through 0, 1, 22,
and 23 committed adoptions, checks every fence and marker at each boundary,
rolls back an interrupted transaction, and rejects duplicate adoption.
The path has no public permit producer yet; an
authenticated exact-23 mixed-state reader that checks the retained ordinal against
every adopted marker is still needed
before it can be used for a real rollover.

Fresh continuation signing after a 15-minute authorization expires requires a
new independently verified mixed-state scan and new authorization ID. The
same captured plan and disposable proof may be reused only while their own
freshness policy accepts them. If either expires, this claim stops; no plan is
silently renewed or substituted. Persistent Quotation content drift remains a
separate live-data stop. No application deployment or traffic cutover is part
of this contract.

The internal continuation issuer now performs the fresh double scan, signs a
new bounded authorization and exact-23 continuation, reserves the next
immutable ordinal, performs another double scan, and only then constructs the
separate paired-plan and rollover transaction permits. An all-adopted
continuation can supply a fresh paired permit for a read-only terminal
reconciliation; terminal completion still requires a new signed exact-23
receipt. No console command invokes this issuer or enables a live rollover.
An internal terminal reviewer requires all 23 observed adopted states and a
fresh signed exact-23 receipt with the same plan, operation hashes, and
disposable-proof row evidence. It never declares generic success.
