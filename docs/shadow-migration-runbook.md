# Exact-25 shadow migration operator runbook

This runbook does not authorize a production operation. It defines a preparation
phase, a mandatory owner-review stop, an approved execution phase, and a separate
finalization phase. Every `--config` path must be an owner-only, non-link file.
Never put a connection string, password, token, private key, or secret value on
the command line.

## External runtime references

Set `LEGACY_DEPLOY_ENABLED=false` for every phase. Supply sensitive values only
through these environment references:

- backup: `LEGACY_MIGRATION_BACKUP_SQL_USERNAME`,
  `LEGACY_MIGRATION_BACKUP_SQL_PASSWORD`, and
  `LEGACY_MIGRATION_RECEIPT_SIGNING_KEY_FILE`;
- disposable restore/source: `LEGACY_SQLSERVER_ADMIN_CONNECTION` and
  `LEGACY_MIGRATION_SQLSERVER_CONNECTION`;
- authorization: `LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE`;
- shadow execution: `LEGACY_MIGRATION_POSTGRES_ADMIN_CONNECTION`,
  `LEGACY_MIGRATION_POSTGRES_CONTROL_CONNECTION`,
  `LEGACY_MIGRATION_CNPG_API_SERVER`, `LEGACY_MIGRATION_CNPG_TOKEN_FILE`,
  `LEGACY_MIGRATION_CNPG_CA_FILE`, and
  `LEGACY_MIGRATION_EXECUTION_SIGNING_KEY_FILE`;
- snapshot: `LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE`, containing an
  owner-only base64 encoding of exactly 32 random bytes; and
- restore/provenance and final evidence:
  `LEGACY_MIGRATION_PROVENANCE_SIGNING_KEY_FILE` and
  `LEGACY_MIGRATION_FINAL_EVIDENCE_SIGNING_KEY_FILE`.

Backup, authorization, execution, provenance, and final-evidence keys must be
five distinct ECDSA P-256 keys. Final evidence compares public-key fingerprints
and fails closed on role reuse.

## Protected configuration

The protected JSON contains these sections. It uses camel-case property names
and rejects unknown properties.

- `fullBackup`: exact namespace, pod name, pod UID, container, approved UTC run
  time, unique run ID, matching `gs://.../database/full/YYYY-MM-DD/<runId>/`
  prefix, new local work/publication directories, backup key ID, transport limit
  from one through three, and `allowSourceBackup: true`.
- `restoreBackups`: signed receipt and trust paths, new recovery/container/volume
  bindings, digest-pinned SQL Server 2022 and staging images, pending/final
  restore-receipt paths, freshness limit, and provenance key/trust.
- `plan`: a create-new output path and the exact reviewed 40-character source
  commit SHA.
- `authorizeShadow`: receipt/plan/create-new output paths, expected source commit,
  independently reviewed schema-plan SHA-256, runner SHA-256, target generation,
  UTC issue/expiry times no more than one hour apart, authorization key ID,
  backup trust, receipt freshness limit, and `allowShadowAuthorization: true`.
- `executeShadow`: receipt, plan, authorization, create-new result, trust stores,
  runner digest, execution key ID, expected control/shadow roles, namespace
  `maliev-legacy`, and cluster `legacy-postgres-main`.
- `exportLocalSnapshot`: completed result path, a new output directory, and the
  pinned `pg_dump` path.
- `signProvenance`: evidence-bound create-new output path, independently reviewed
  plan digest, current UTC issue time, provenance key ID, and
  `allowProvenanceSigning: true`.
- `evidence`: execution, provenance, receipt, plan, authorization, and final
  verified-restore paths; all upstream trust stores; create-new publication
  directory; snapshot/backup generation/restore/evidence/lease identities and
  times; and the distinct final-evidence key ID.

`authorize-shadow` re-hashes the exact fresh plan, verifies the signed exact-25
backup, validates plan freshness and source commit, rejects stale approval
windows and backup/authorization key reuse, and publishes create-only. It cannot
mint an authorization without the reviewed digest and explicit allow flag.

`sign-provenance` verifies the exact-25 signed execution, authorization, backup,
and final restore receipt. Cleanup must be `Removed`; a pending cleanup receipt
cannot produce provenance.

## Commands and mandatory stop

```powershell
$Repository = 'B:\maliev-legacy\Legacy.Maliev.DataMigration'
$Config = '<owner-only-absolute-path>\run-config.json'
$env:LEGACY_DEPLOY_ENABLED = 'false'

dotnet build "$Repository\Legacy.Maliev.DataMigration.slnx" --configuration Release
dotnet test "$Repository\Legacy.Maliev.DataMigration.slnx" --configuration Release --no-build

& "$Repository\scripts\prepare-shadow-migration.ps1" `
  -ProtectedConfigPath $Config -Configuration Release
```

Preparation performs the explicitly allowed source backup and immutable GCS
upload, restores only into disposable local SQL Server 2022, and generates the
fresh plan.

**STOP.** Record the plan file byte hash and canonical schema-plan SHA-256,
inspect all 25 database plans, and place that exact canonical digest into
`authorizeShadow.reviewedSchemaPlanSha256`. Do not continue until the owner has
reviewed the plan and set `allowShadowAuthorization: true`.

```powershell
& "$Repository\scripts\execute-approved-shadow-migration.ps1" `
  -ProtectedConfigPath $Config -Configuration Release
```

The approved phase signs the reviewed authorization and writes only run-owned
`legacy_shadow_*` databases plus `legacy_migration_control`. Inspect the signed
result: it must cover exactly 25 databases and prove table row, content,
aggregate, null, relationship, orphan, and sequence parity. After that review,
set `signProvenance.allowProvenanceSigning: true`.

```powershell
& "$Repository\scripts\finalize-shadow-migration.ps1" `
  -ProtectedConfigPath $Config -Configuration Release
```

Finalization writes a new MLVSNP02 directory containing exactly 25 encrypted
dumps and `manifest.json`, removes disposable SQL Server resources, signs
provenance only from the completed cleanup receipt, and atomically publishes
final evidence and its review baseline.

## Live-write gates

Preparation writes backup files in the live SQL Server pod and creates immutable
GCS objects. Approved execution creates or patches run-owned CloudNativePG
`Database` resources and writes shadow databases and the migration-control
journal. Applying RBAC/admission policies, PostgreSQL ACLs, secrets, or workload
identity also mutates live state. Every such action needs explicit authorization.

Canonical promotion, traffic cutover, application deployment, and canonical
production writes are absent and remain unauthorized.
