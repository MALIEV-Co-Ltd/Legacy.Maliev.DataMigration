# Historical LOCAL checkpoint timestamp precision

Bounded fix for issue #226; parent #221 and source precision issue #186 remain open.

## Contract

The signed plan and reconciliation header retain the original seven-digit UTC
cutoff. PostgreSQL stores checkpoint timestamps at microsecond precision. The
historical metadata binder now uses its existing exact PostgreSQL normalization
when comparing a signed database checkpoint with that plan cutoff. This is not
a tolerance: the checkpoint must equal the cutoff floored to microseconds.

The regression uses `2026-10-01T17:05:39.1654853Z` in the plan and receipt header,
and `.165485Z` in all 23 signed checkpoints. Binding succeeds for those exact
values; changing one journal timestamp by one microsecond still fails with
`delta_historical_local_metadata_invalid`. All other signature, plan hash,
schema, inventory, generation, fence and settled-journal checks are unchanged.

This read-only binder still has `AuthorizesExecution = false`. The change does
not authorize adoption, rollover, schema repair, persistent database writes or
changes to application-row timestamps. It does not resolve the source precision
contract in #186 or the runtime/CLI readiness in #221.

## Provenance and validation

The isolated two-file change was reviewed from owner-lane commit
`f876b7aed14051bfe1c0e36f9b8df210e3f82f7f` and independently reproduced on
accepted protected main `e2f63f1f15fa93c0eb811e0542751f157f292e5a`. No adjacent
claim-store or preimage-reader implementation was imported.

Sequential root validation:

- Release solution build with warnings as errors: zero warnings/errors.
- Original binder baseline: 53 focused tests passed.
- New regression with the original comparison: one genuine failure at the
  historical binder; retained as RED evidence.
- Repaired binder: 54 focused tests passed, zero skips.
- Native PostgreSQL snapshot-enabled core suite: 1,566 passed, zero failures,
  three unchanged prerequisite/platform skips (1,569 total).

Commands: `dotnet build Legacy.Maliev.DataMigration.slnx -c Release -warnaserror`;
`dotnet test tests/Legacy.Maliev.DataMigration.Tests -c Release --no-build`
with focused `DisposableDeltaProofVerifierTests` filter, then the unfiltered
suite with `MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1` and the installed PostgreSQL
18 dump/restore tools. `LEGACY_DEPLOY_ENABLED=false` throughout. No production
SQL Server scan or persistent PostgreSQL mutation was performed by this slice.
