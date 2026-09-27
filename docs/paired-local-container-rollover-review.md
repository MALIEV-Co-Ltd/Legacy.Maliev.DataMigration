# Paired LOCAL container rollover: fail-closed review contract

Issue #193 concerns a persistent PostgreSQL named volume mounted by a replacement Docker container. A matching volume name and PostgreSQL system identifier do **not** prove that the previous reconciled row set is still present. The existing `delta_paired_local_metadata_preimage_invalid` rejection is correct until an independently signed continuity proof is available. This document is a prospective contract, not execution authority or an instruction to alter a persistent database.

## Required evidence before fence adoption

The owner-only rollover command must verify the *previous* signed paired LOCAL plan and exact-23 terminal reconciliation using their trusted public keys. It must bind each database's prior fence and complete settled journal to that plan's target observation and signed checkpoint; a journal hash alone is not a signed receipt. If the prior receipt, plan, or trust key is unavailable, stop.

Independently observe the former full container ID as absent or stopped. Observe the replacement full container ID, creation/start times, loopback-only port, mounted read-write `PGDATA`, named-volume driver, Docker volume creation time and mountpoint, and PostgreSQL system identifier before and after a read-only reconciliation. Require the old and new volume *physical identity*, mount location, and system identifier to agree; a matching volume name alone is insufficient. Recheck capacity and exact current physical schema in all 23 active databases.

Read and compare the current target's exact-23 table/row/semantic checksum, sequence, extension, and schema evidence against the verified prior signed terminal receipt. The comparison must use the prior plan's schema and cutoff, not a new live-source plan. Any unverified table, changed digest, unresolved journal, missing database, active former container, or identity drift rejects the rollover. This proves continuity at the prior cutoff; it does not claim present-time SQL Server parity or an atomic cross-database snapshot.

The resulting PII-free continuity attestation should be short-lived, separately signed, and bind the old plan and receipt hashes, all 23 prior metadata fingerprints and current target digests, old/new full Docker generations, physical volume identity, PostgreSQL system identifier, current new plan hash/authorization ID, and observation interval. It must be one-use and must not contain connection strings, row values, credentials, or signing material. Never re-sign the prior receipt as though it described the new container.

## Admission and atomicity

`PairedLocalTransitionMetadataInspector` should continue rejecting different container IDs without this exact verified attestation. `PairedLocalTransitionPreflight` must verify it and require stable metadata and Docker/volume/PG observations on both sides of its read-only row checks. `PairedLocalTransitionExecutionPermit` must carry only the validated attestation identity, not an untrusted boolean. `PostgreSqlDeltaCanonicalTarget.BeginAsync` must reverify the attestation, prior fence/journal fingerprint, physical schema, PostgreSQL system identifier, and current signed generation **inside** the serializable per-database transaction before adopting the new fence. The fence update and row operation must commit or roll back together. Existing `LocalDockerGenerationGuard.VerifyAsync` remains exact and runs before each database transaction. A newly signed ordinary exact-23 terminal reconciliation is required after apply.

The paired CLI needs protected paths for the prior signed plan/receipt and continuity attestation, a distinct trusted continuity-signing role, and an issuance command that performs the read-only proof. Current paired requests contain only the new plan/disposable proof; therefore accepting a new container by changing `SameDockerGeneration` alone would bypass the security boundary.

## Required disposable tests before enabling rollover

- Different container ID with otherwise settled metadata rejects in read-only preflight and locked transaction without changing the fence (covered by `PairedLocalTransitionMetadataInspectorTests`).
- Bad/expired signature, missing prior plan or receipt, partial 23, changed old fence or journal, unsettled journal, attestation replay, and changed new plan or authorization all reject.
- Old container still running, volume name reused with different creation time or mountpoint, different PostgreSQL system identifier, different physical schema, or a changed row/sequence digest all reject.
- A valid disposable 23/23 continuity attestation permits exactly one atomic adoption; a forced operation failure rolls back the generation update, and retry requires a fresh authorization and observation.
- Re-observe Docker generation and PostgreSQL identity before every subsequent transaction, and verify a newly signed exact-23 terminal receipt after success.

No persistent LOCAL or production database is modified by this review contract. Issue #193 remains open until the attestation producer, verifier, CLI wiring, disposable proof, and guarded reconciliation are implemented and validated.

## Historical artifact review slice

`HistoricalPairedLocalEvidenceReviewer.Verify` checks an old signed persistent-LOCAL schema-1.4 plan against its signed terminal exact-23 reconciliation. It uses the plan's own creation time to validate the original bounded capture window; it does **not** extend the plan's execution lifetime. It requires trusted, distinct plan/evidence public keys, matching plan/receipt hashes, all 23 signed checkpoint operation and target-observation hashes, and matching source and physical schema fingerprints. An authentic old receipt remains reviewable after normal execution freshness expires. The returned `HistoricalPairedLocalEvidenceReview` is expressly non-authorizing and contains only PII-free hashes/timestamps/counts.

This verifier does not read Docker, PostgreSQL, the named volume, or present target rows. It is only the first input to a future fresh continuity attestation; it must never be wired directly into `PairedLocalTransitionExecutionPermit` or used to bypass the container-generation fence.
