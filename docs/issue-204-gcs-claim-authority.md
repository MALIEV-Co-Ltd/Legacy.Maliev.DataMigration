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
   fresh signed continuation/authorization. A used ordinal cannot be
   overwritten or replayed. A gap, conflict, missing object, or expired
   claim fails closed. The runner must not issue a subsequent ordinal while a
   previous authorization can still have an in-flight transaction.

The bucket is a one-use claim ledger, not a transaction coordinator for 23
databases. The first claim is published only after independently verifying the
signed historical receipt, current exact-23 rows/schema/sequence evidence,
current Docker/volume/PostgreSQL identity, and the zero-delete paired proof.
The current store implements reservation, exact readback, retention checks,
and one-use ordinals. Its internal read verifies storage object integrity but
does not authenticate the original signed attestation again. It does not grant
execution authority. The following reader and transaction checks are required
before any rollover can be enabled.

Before and after a mixed-state scan, the reader re-observes the claim and its
ordinal. Each database is either the exact prior signed state or has an atomic
claim-bound adoption marker, new fence, settled journal, and matching current
row/schema/sequence evidence. No third state is accepted.

The per-database adoption transaction must hold the serializable locks,
compare-and-swap the old fence, apply DML and sequences, reconcile, and write
the marker and settled journal together. The existing unconditional metadata
upsert is forbidden on this path. Only a new signed exact-23 terminal
reconciliation completes the claim. A journal hash or global object alone is
never a receipt.

Fresh continuation signing after a 15-minute authorization expires requires a
new independently verified mixed-state scan and new authorization ID. The
same captured plan and disposable proof may be reused only while their own
freshness policy accepts them. If either expires, this claim stops; no plan is
silently renewed or substituted. Persistent Quotation content drift remains a
separate live-data stop. No application deployment or traffic cutover is part
of this contract.
