# Daily read-only SQL Server comparison

`scripts/invoke-daily-readonly-delta.ps1` is a backup-free row comparison path for
already populated exact-23 PostgreSQL targets. It reads every source and target
table in primary-key order, signs insert/update/reviewed-delete operations,
then uses the transactional executor, idempotency journal, and post-apply
reconciliation. It does not use SQL Server Change Tracking or CDC and does not
make daily SQL Server backups. Read volume is still a full table scan.

The template's baseline `backupManifestSha256` remains provenance of the
original migrated dataset, not a fresh daily backup. Live plans use schema
`1.2`, bind a freshly observed SQL Server identity/inventory hash, and sign
the source capture start and completion times. Each database uses a separate
SQL Server snapshot transaction; there is no atomic cross-database cutoff.
Source or target drift from the signed plan fails closed.
Unattended local execution stops if the plan contains a deletion; deletion
sets require separate review. Production execution always requires separate
review, including plans containing only inserts or updates.

## Operator setup

1. Use clean synchronized protected `main` with green exact-head CI. Keep
   `LEGACY_DEPLOY_ENABLED=false`. Project only owner-protected connection/key
   file paths into an owner-only template JSON; never put credentials or
   connection strings in the template.
2. Keep the template and output root on a local owner-only Windows filesystem,
   outside the repository. Use the existing `DeltaCommandConfiguration` fields
   with `"sourceMode": "live-readonly-comparison"`, the original baseline
   backup-manifest hash and backup signer fingerprint, fresh target observation,
   and distinct trusted keys. Set `allowPlanSigning=true`; local automatic
   execution also needs `allowAuthorizationSigning=true` and
   `allowExecution=true`.
3. The operator host supplies the existing signing-key file environment
   variables through protected credential projection. The SQL Server login
   needs read-only access and complete metadata visibility; all 23 databases
   must be online with SNAPSHOT isolation enabled.
4. Use distinct templates, target observations, plans, and authorizations for
   local and production. The script refuses `-Execute` for production. Its
   production invocation produces a plan for separate review and signing.

```powershell
$env:LEGACY_DEPLOY_ENABLED = 'false'
$env:LEGACY_MIGRATION_CALLER = 'owner'
& .\scripts\invoke-daily-readonly-delta.ps1 `
  -TemplatePath '<owner-protected-local-template.json>' `
  -OutputRoot '<owner-only-local-output-root>' -Execute
```

Omit `-Execute` for plan-only. The script creates a unique owner-only run
directory, validates protected main and exact-head CI, builds in Release with
warnings as errors, and generates a signed live plan. For local execution it
signs a short-lived authorization immediately before apply and publishes new
owner-only plan, authorization, execution, and reconciliation artifacts. On
failure it stops without retrying or deleting artifacts. Never reuse a run
directory or an earlier authorization.

The daily automation may execute local sync only after the protected template,
source health, target identity, and credential projection are independently
reviewed. Production should plan daily and request owner review for the
separate execution action. No application deployment, traffic change,
database replacement, or SQL Server configuration change is included.
