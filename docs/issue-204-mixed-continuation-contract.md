# Issue #204: mixed-state continuation review, not rollover authority

`HistoricalLocalMixedContinuationVerifier` is a pure, PII-free comparison of a
signed continuation, a purported known-claim snapshot, current signed transition
authorization, and ordered 23-database metadata observations. It accepts exact
0/1/22/23 adopted subsets and rejects unknown claims, stale continuation
ordinals, changed generation/plan/authorization identities, expired material,
signature changes, and incomplete or changed database evidence. Its result has
`AuthorizesExecution=false`. No CLI, execution permit, metadata provisioner, or
canonical target consumes it. In particular, the caller-supplied claim and
observations are **not** authenticated by this pure method; it is unsafe to use
the review as a write gate.

## Required durable claim design before implementation

1. Choose one owner-controlled, non-rollbackable claim authority and define its
   restore/failover policy. A table in one of the 23 independently restored
   target databases is not sufficient. Its unique claim key must bind the
   original signed continuity attestation hash/ID, historical plan/receipt,
   future exact-23 plan hash, full target generation and PostgreSQL/volume
   identity. Claim creation is create-only and serializable. A competing claim
   for the same old receipt or new plan/generation must fail. A missing or
   restored-back claim must fail closed, never be recreated from per-DB fences.
2. Record an immutable initial 23/23 old-state fingerprint and a monotone next
   continuation ordinal. The first signed attestation is consumed by exactly
   one claim, not by each database. Later signed continuations bind that claim,
   its ordinal, fresh target identity and every database's observed phase. The
   claim authority must CAS the ordinal (or an equivalent nonce) before a
   continuation can be used; merely calling the pure verifier twice does not
   prevent replay. Expired authorization and continuity signatures are never
   extended. Define separately how a fresh authorization is issued if the
   captured plan/source freshness has expired; an expired plan must not be
   silently grandfathered.
3. Each target database needs an adoption marker bound to claim ID, original
   attestation hash, **current** authorization/continuation ID, old fence and
   complete journal fingerprint, new plan/target generation, operation hash,
   and reconciliation hash. Under one serializable transaction, lock/recheck
   physical schema and PostgreSQL identity, CAS the old fence, apply DML,
   reconcile, insert the marker and checkpoint, then commit together. A forced
   failure must leave the old fence and no marker or row change. Never call the
   existing metadata provisioner's unconditional fence upsert for rollover.
4. There is no cross-database transaction. After crash, independently scan all
   23 databases: an old database must match the original signed preimage; an
   adopted database must have the exact claim-bound marker and settled journal
   plus freshly verified post-update rows/sequences/schema. Any third state,
   missing journal, changed target identity, or conflicting claim stops. Do not
   infer 23/23 success from global bookkeeping; only a new ordinary signed
   exact-23 terminal reconciliation can complete the claim.
5. Authorization admission must still invoke the full signed paired-plan and
   disposable-proof policy, captured-source and Docker guards, and in-transaction
   row checks. This pure review checks signatures and bounded expiry only; it
   intentionally does not replace those policies. Persistent LOCAL execution
   and production cutover remain disabled.

The remaining proof suite must use a disposable PostgreSQL cluster, including
0/1/22/23 mixed states, process interruption after each commit boundary,
transaction rollback, concurrent/replayed claims, expired authorization,
changed identity, unknown plan, and exact post-update reconciliation. The
known persistent Quotation content drift remains an independent hard stop.
