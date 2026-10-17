#
> Current source status (October 16, 2026): historical preparation observations below
> are not current execution authority. See [current validation and remaining gates](current-customer-sequence-definition.md#october-16-continuation).
> The current production inventory contract is exactly 49 non-template databases
> and all 51 catalog entries; local remains 26. Fixed production Customer operand
> ownership is `legacy_customer_owner`, independently verified against the bound
> native baseline; `postgres` is not an interchangeable table/sequence owner.
 Guarded Customer sequence START definition component

## Scope and preservation

This source component permits only the reviewed fixed statement:

```sql
ALTER SEQUENCE public."Customer_ID_seq" START WITH 1000;
```

It does not reset allocation. The fully observed `last_value`, `is_called`, and `log_cnt` remain exact. The sequence OID, Customer table OID, column ordinal, integer type, identity/dependency ownership, owner, increment, range, cache, cycle, and every other native definition field remain exact. The frozen definition comparator permits only `pg_sequence.seqstart` and the positively observed replacement `pg_class.relfilenode`; neither arbitrary catalog omission nor object recreation is permitted. Whole Customer public/private row bytes, multiplicity, journals, immutable receipts, relations, and all physical sequence state remain exact. There is no row deletion, `setval`, `RESTART`, backfill, allocation call, history copy, security role provisioning, or financial execution path.

The native reader uses the exact field extraction established by `CurrentCustomerSequenceNativeFeasibilityTests`, alongside the shared whole-database raw catalog/row/sequence capture. It requires an existing Customer connection and one repeatable-read or serializable transaction. The owner approved extending the prior definition and tests after fresh production metadata showed the ID at ordinal9. The ID ordinal must be positive and is derived only by the trusted reader's exact `public.Customer`/`ID` name and sequence internal ownership dependency join. It is not fixed to1 or9 and no production OID is hardcoded. The full native state digest binds actual table/sequence OIDs, attribute ordinal, owner, type, allocation fields, and full native tuple hashes into both signed scope and operation. Review issuance, admission and reservation independently obtain the actual native observation; provider expected input, real preflight and locked native observation must match that same signed digest and Customer raw snapshot. A caller re-signing an invented ordinal cannot replace independent native observation. The pure comparator checks shape and preservation, not semantic decoding of opaque catalog hashes; it is insufficient execution authority without these trusted-reader and signed-state checks. Native fixtures now cover actual ordinal1 and ordinal9 with allocated/nonallocated rollback/commit/readback and exact log_cnt preservation.

## Independent admission evidence

The distinct review, authorization, and receipt domains use three separately pinned P-256 public keys. Review signing validates semantic scope and a genuine signature before environment callbacks. Authorization lasts at most fifteen minutes, is target specific, binds the exact review, and cannot extend the maintenance lease. Scope binds the accepted migration source commit, approved current V3 source23/100-table schema plan, independently accepted fresh SQL catalog report digest, exact owner head and two source file pins, fixed definition digest, operation digest, native/definition proof, recovery review, role transition review, target identity/generation/custody, and every complete fleet preimage.

Independent observations are required again during admission, reservation, and execution. The SQL report must match the independently held approved report hash and confirm identity seed1000/increment1 and valid current allocation. The clean Customer owner checkout must match its two frozen source pins. A signed claim supplied by a caller is not independent source evidence. A future closed environment must read the actual approved evidence and current clean owner checkout; serialized callbacks cannot supply execution authority.

Local fleet is exactly the approved23 databases plus `Auth`, `postgres`, and `legacy_local`. Production must bind the complete freshly observed53-name inventory and all53 preimages, including historical shadows. The fixed owner derives from authenticated target kind: `legacy_local` locally, `postgres` in maliev-legacy. No caller-selected owner is accepted.

## Physical phase and execution

The source23 physical baseline has a precise before/after phase obligation. A future closed environment must derive only this fixed Customer sequence definition exception from the approved operation and genuine prepared/terminal evidence: before is START1; after is START1000. Every other approved source23 physical field must match its accepted phase. It must not broadly waive Customer schema validation or accept a caller-provided phase flag. The provider passes scope into this obligation; this source slice does not implement that closed reader.

Before any provider access, the permit requires a fresh operation across all immutable storage slots. It atomically reserves the operation and refuses reuse or an unknown reservation acknowledgment. Execution has a finite deadline, requires resource admission and custody, verifies actual installed maintenance role/HBA semantics and absence of other client backends/prepared transactions/event triggers, and obtains serializable whole-database locks before inspecting the exact preimage. The fixed DDL is followed by native preservation comparison. A genuine prepared receipt must be retained before COMMIT. The writer transaction and backend close before independent committed readback; the complete fleet is then independently compared against the one Customer advancement. Only acknowledged terminal publication advances the predecessor chain. A later fleet failure produces uncertainty linked to that latest authentic terminal, never success. Any uncertain COMMIT or publication stops the permit permanently.

Immutable receipts validate signature, operation, authorization, independently held predecessor, UTC freshness, maintenance window, and prepared/terminal after-hash continuity. Unknown or failed evidence slots must be rejected by the future closed reader. The provider never retries after sticky stop or erases evidence.

## Integration and validation status

Integrated against protected-main source base `0479c52477bed58811964bae91386e4927a119f7`. The Customer maintenance validator pin binds canonical-LF SHA `5fc4d018d7ecfec6517db497d1bc8e06dc204be91d1ae2a421f5d41f34d72324` of approved helper Git blob `d921fa5a7cee24b9769437d53f8b7e39c01bd2c5`. Only CRLF-to-LF normalization was used to verify that source pin; no BOM stripping or trimming was performed. Fresh native proof remains required. No shared helper duplicates or dependency edits belong to this slice.

All build, focused tests, relevant suite, formatting/analyzers, native PostgreSQL provider proof, and runtime checks are **UNRUN** because the parent holds the serialized heavy validation lane. The pure test source covers genuine distinct claims, re-signed semantic attacks rejected before callbacks, foreign domains, fresh catalog/owner drift, single-use reservation, unknown retained slots, lost reservation acknowledgment, fleet drift, authentic predecessor chaining, terminal publication uncertainty, and receipt freshness/after-hash attacks. No keys were generated while preparing source.

Required before execution authority: integrated zero-warning Release build, focused and relevant suites, static gates, genuine bounded native provider rollback/commit/dropped-ACK/publication/fleet/preservation proof, validation of the new closed Console/configuration/evidence reader source and genuine native proof, current helper/source acceptance, exact protected-head required checks/reviews, fresh target-specific operational evidence and signatures, and parent writer admission. This component alone grants no persistent-target authority and proves no data parity.

No workers, containers, database sessions, port forwards, network access, target writes, commits, or publication were created for this source-only slice. Foreground file inspection/edit commands completed. No disposable runtime resources remain.
