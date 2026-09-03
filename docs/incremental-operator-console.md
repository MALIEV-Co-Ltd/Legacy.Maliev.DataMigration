# Protected incremental operator console

This is a software repair, not authorization for another migration. The repaired
workflow copies the current exact `DatabaseInventory.ActiveDatabases` sequentially,
persists each signed checkpoint, and immediately encrypts, downloads and locally
restores/verifies it before continuing. Literal Log exclusion and exact-23 AppHost
consumers are still Task 5; do not run against changed inventory using old approvals.

The failed historical exact-24 run had no signed local snapshot. Its automatic
cleanup deleted the PostgreSQL shadows. New checkpoints cannot recover those
deleted shadows. Original backups and restore sources remain untouched; any future
reuse requires independent identity verification and fresh explicit authorization.
There is no automatic cross-run, changed-plan, changed-runner or changed-backup adoption.

## Commands and authority

Every invocation accepts only `<command> --config <owner-protected JSON path>`.
Never put passwords, connection strings, token contents or private keys on the CLI.
All modes require `LEGACY_DEPLOY_ENABLED=false`. No command retries in the background.

| Command | Behavior |
| --- | --- |
| `authorize-shadow` | The original, explicitly approved signed execution receipt. With `incremental.runtime`, target observation uses the explicit protected host Kubernetes boundary; other authorization modes remain unchanged. |
| `plan-incremental` | Checks exact fresh original inputs, real source/Docker, running publication, target endpoints and read-only local preflight. Writes a review document. No signer, permanent root/lock, local probe DB, journal schema repair or lease acquisition. It does not authenticate the restricted restore password. |
| `execute-shadow` | Requires `incremental.allowExecution=true`. Reads protected keys and prerequisites, acquires one fresh Windows authority, signs admission against that held binding, then transfers it to the admitted coordinator. Legacy `executeShadow` configuration alone is refused. |
| `plan-resume` | Authenticates the original admission and reads the real consistent journal snapshot without schema repair/lease acquisition. Exports exact admission/checkpoint/terminal texts in a snapshot document for review or completed-local use. No continuity is invented. |
| `authorize-resume` | Requires `allowSigning=true`, external signed `continuityPath`, current read-only observations, exact journal baseline and existing Windows binding. Signs a fresh bounded authorization to `outputPath`. It never signs source continuity. |
| `resume-shadow` | Requires `allowExecution=true`, original admission, external continuity and the reviewed fresh resume authorization. Reacquires only the original root/lock, revalidates independently and resumes through the coordinator. |
| `finalize-local` | Requires an exported authenticated completed snapshot, original local root/lock, external root key and full local checkpoint inventory. No execution factory, remote connection, Docker, native dump/restore or execution signer is constructed or requested. Matching lost-response publication replays unchanged. |

Publication file parents must already exist with owner-only access (the current
Windows owner has effective FullControl with no deny rules, or owner-only Unix0700); the console does not
create or repair these parents for incremental commands. Files are created with
an explicit owner-only Windows ACL or Unix0600 before any bytes are written.
`outputPath` must be outside both staging and the final snapshot directory, and
the two directories must not contain one another. Windows short-name/stream
notation is refused; normalized casing and dot segments cannot bypass collisions.

Initial `admissionPath` must be a new protected output path outside staging and
final artifacts, distinct from `outputPath` after canonical comparison. Its
local copy is not proof that the journal committed. If setup leaves a bare lock/root
or admission file but the journal has no admitted run, stop for explicit setup
recovery or an approved new root. Do not delete or adopt that state automatically.
Resume never recreates missing/replaced roots or locks.

## Protected configuration references

The top-level `signingRoles` contains `backup`, `authorization`, `execution`,
`provenance`, and `finalEvidence`; each is `{ "keyId": "reviewed-id",
"subjectPublicKeyInfoPath": "absolute-protected-file" }`. Public key files contain
base64 SubjectPublicKeyInfo. All five IDs and key fingerprints must be distinct.

The top-level `incremental` object contains:

- `artifactRoot`: permanent owner-only local Windows fixed-NTFS staging root.
- `outputDirectory`: separate final snapshot directory outside staging.
- `snapshotId`: immutable original snapshot identity, reused exactly on recovery.
- `outputPath`: new planning/signing or compatible execution-result output file.
- `expectedSourceCommitSha`, `expectedRunnerDigestSha256`: independently reviewed
  policy values, unchanged throughout this admitted run.
- `maximumObservationAgeMinutes`: positive, at most 60; exactly the admitted policy.
- Initial inputs: `receiptPath`, `planPath`, `authorizationPath`,
  `verifiedRestoreReceiptPath`; original exact text is retained in admission.
- `admissionPath`: initial output or exact existing admission input on recovery.
- Resume: `continuityPath`, `resumeAuthorizationPath`, `resumeExpiresAtUtc` (for
  authorization only; UTC, at most one hour and no later than continuity expiry).
- Completed-local: `completedSnapshotPath`, exported by `plan-resume`.
- `allowExecution` and `allowSigning`: false unless that action is explicitly approved.

`incremental.runtime` is required except for `finalize-local`:

- Owner-protected absolute connection file references: `sourceConnectionFile`,
  `controlConnectionFile`, `shadowAdministrativeConnectionFile`,
  `localAdministrativeConnectionFile`, `localRestoreConnectionFile`.
- Exact role expectations: `expectedControlRole`, `expectedShadowAdminRole`.
- Absolute existing PostgreSQL 18 `pgDumpPath`, `pgRestorePath`.
- Independently verified local PostgreSQL Docker `localContainerId`, `localImageId`,
  `localSystemIdentifier` expectations. These are not accepted as observations.
- Explicit HTTPS `kubernetesApiServer`, owner-protected `kubernetesTokenFile`,
  and `kubernetesCaFile`; the namespace/cluster comes from verified original approval.

Runtime measurement always uses the **actual running `AppContext.BaseDirectory`**,
with `RunnerArtifactManifestMeasurer` file-handle manifest semantics. There is no
configurable alternate publication directory or metadata-only image digest.

Private-key environment variables reference owner-protected PEM files:
`LEGACY_MIGRATION_EXECUTION_SIGNING_KEY_FILE` and
`LEGACY_MIGRATION_AUTHORIZATION_SIGNING_KEY_FILE` for their respective actions.
`LEGACY_MIGRATION_SNAPSHOT_ENCRYPTION_KEY_FILE` references a base64 32-byte key file
strictly outside staging and final artifacts. Do not store a plaintext database dump.

## Future runtime prerequisites

Configuration/measurement and execution require fresh owner authorization. This
software slice changes no credentials, forwarding, certificates, ACLs or live roles.
The host's authenticated PostgreSQL TLS endpoint must independently report the same
`pg_control_system().system_identifier` as signed CloudNativePG observation. Runtime
roles need the existing narrow identity-observation permission; the tool never
auto-grants it or weakens strict role/TLS validation.

Local verification requires a separate administrative connection and an **existing
restricted restore login**. Read-only preflight cannot authenticate a password for a
login with no connectable DB. Explicit execution therefore runs a uniquely owned
local temporary-DB credential/readiness probe before any remote journal mutation.
Actual archive verification repeats fresh checks and runs `pg_restore` as that
restricted login, never as admin. No roles or global ACLs are auto-provisioned.

The verifier accepts authenticated trusted-pipeline archives, not arbitrary hostile
SQL. PostgreSQL logins can change their own password/default settings; this is not
a general malicious-SQL sandbox.

## Progress, result compatibility and preservation

Progress reports distinct `remoteCommitted`, `downloaded`, and `localVerified`
counts from confirmed outcomes in this invocation. A confirmed commit can precede
a later checkpoint/local failure. Matching local reuse increments local verification
without a new download. Completed-local replay reports zero downloads.

`outputPath` for execution remains `MigrationExecutionResult` (`status`, `receipt`),
not the newer coordinator wrapper. Terminal signed receipt semantics and full-inventory
guards remain unchanged. Snapshot manifest stays in the final snapshot directory.
Final evidence still separately requires signed cleanup, provenance and verified
restore artifacts: successful incremental execution does not manufacture them.

Failures preserve completed local bytes and all remote candidates. Only an active
transaction is rolled back; there is **no automatic remote shadow deletion**, including
empty, partial, pending or ambiguously provisioned candidates. Local verification
cleans only its exact-owned invocation-local temporary database. Separate explicit
remote cleanup remains outside recovery and requires its own approved workflow.

Validation uses disposable SQL Server/PostgreSQL/native tooling and controlled
observer seams; no live-stack or production-factory acceptance is implied.
