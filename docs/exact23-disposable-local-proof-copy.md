# Exact-23 disposable LOCAL proof copy

`scripts/new-exact23-disposable-copy.ps1` prepares a separate, run-owned PostgreSQL 18
copy of the existing persistent LOCAL Aspire PostgreSQL cluster. It is a read-only
source operation. It does not change the persistent source, authorize a production
schema change, or prove production parity. Run it only after the owner has reviewed
the source identity, disk capacity, and protected-main gate.

## Preconditions

- Run on Windows as the owner with `LEGACY_DEPLOY_ENABLED=false` and
  `LEGACY_MIGRATION_CALLER=owner`. Docker, PostgreSQL 18 client tools, `dotnet`,
  `git`, and `gh` must be available. The repository must be clean, protected
  `main` at the exact remote head, with a successful exact-head main CI run.
- The persistent source must be the running container mounted on the fixed
  `legacy-maliev-exact23-postgres-data` volume. Supply its full 64-character
  Docker container ID, its observed SHA-256 PostgreSQL system identifier, and
  an owner-only connection file for the loopback `postgres` superuser endpoint.
  The helper never prints the password. Independently verify these inputs before
  invoking it; do not infer them from a container name alone.
- Use a new, owner-only, non-linked local directory outside the repository and
  a unique `legacy-delta-proof-<12-32 lowercase alphanumeric>` name. Supply a
  pinned `postgres:18@sha256:<64 hex>` image reference. The target name, volume,
  and output files must not exist already.
- Reserve at least three times the observed source database size plus 10 GiB
  on the run-directory drive, and source-size plus 10 GiB on the Docker volume
  filesystem. The helper checks both before restoration.

Example shape (placeholders are deliberately not usable credentials or IDs):

```powershell
$env:LEGACY_DEPLOY_ENABLED = 'false'
$env:LEGACY_MIGRATION_CALLER = 'owner'
& .\scripts\new-exact23-disposable-copy.ps1 -Action Create `
  -RunDirectory 'C:\owner-only\unique-run' `
  -Name 'legacy-delta-proof-uniqueownerid' `
  -SourceContainerId '<verified full Docker container ID>' `
  -ExpectedSourceSystemIdentifierSha256 '<verified SHA-256 system ID>' `
  -SourceConnectionFile 'C:\owner-only\source.connection' `
  -ImageReference 'postgres:18@sha256:<verified 64-character digest>'
```

The source connection file must be an owner-only plain-text Npgsql connection
string with `Host=127.0.0.1`, `Database=postgres`, the verified published port,
and the source container's exact `POSTGRES_USER` role and password. The helper
rejects a connection role that differs from that container identity; the
canonical persistent LOCAL role need not be named `postgres`. Do not put the connection string on
the command line, in logs, or in the receipt. Treat the run directory and its
SQL dumps as protected data: they can contain every LOCAL row, including PII.

## What the helper proves

The helper requires the exact canonical set of 23 databases. On the persistent
source, only the observed PostgreSQL role's default database and the separate
`Auth` runtime database may coexist; arbitrary extra databases still fail.
The disposable target must contain exactly 23 and no extras. For
each database it records a physical-schema fingerprint, makes a read-only
serializable-deferrable plain dump, restores it to a new independent PG18 volume,
and compares the before, source-after, and copy logical schema-and-data dump
SHA-256 hashes, physical-schema fingerprints, and `COPY` row counts. It checks
the PostgreSQL 18 dump-version banner as metadata and normalizes only that
banner for the logical hash (for example, an 18.4 source and 18.6 disposable
image). It hashes each `COPY` row and sorts those hashes within its own table,
so a restore-induced heap-order change does not look like a changed row. Row
values, duplicate multiplicity, table boundaries, and non-`COPY` SQL remain
strictly compared; incomplete sections fail closed. The original protected
SQL dumps are not rewritten. The helper also checks source and
target system identifiers, identities, inventory, and loopback port
again before publishing a PII-free `exact23-copy-receipt.json` and protected
`target-disposable.connection` file. The receipt includes only names, hashes,
counts, container identity, and completion time. It never includes row contents
or a connection secret.

Each database is captured in its own repeatable read-only snapshot. The 23
database dumps are sequential, **not** one cross-database atomic snapshot.
Source mutation during the run causes a digest/fingerprint mismatch and fails
closed in ordinary cases, but a transient change that disappears between
observations cannot be excluded. Do not treat this copy alone as an operator
approval, parity attestation, or production target-schema migration.

## Cleanup and failure handling

After a complete receipt, run the same helper with `-Action Cleanup`, the same
`-RunDirectory`, and the same `-Name`. It rechecks the receipt, exact labels,
nonce, image, container ID, exclusive volume use, connection, and target system
identifier. Only then does it remove that target container and volume. It keeps
the source, receipt, dumps, and target connection file; protect or retire those
artifacts under the separate data-retention procedure. On any incomplete or
uncertain run, it publishes no complete receipt and does **not** automatically
remove containers or volumes. Inspect identities and resolve the failure before
any manual cleanup; never aim cleanup at the persistent source.

The `LEGACY_MIGRATION_SYNTHETIC_TEST_ONLY=true` gate and
`-SyntheticSourceVolumeName` option are exclusively for the repository's
integration test. They accept only a separately labeled
`legacy-delta-synthetic-source-*` volume, not the persistent LOCAL volume.
