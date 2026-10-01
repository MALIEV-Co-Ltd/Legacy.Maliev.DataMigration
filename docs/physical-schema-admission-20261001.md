# Reject unsupported physical schema behavior before admission

Issue: MALIEV-Co-Ltd/Legacy.Maliev.DataMigration#222.
Base: `fa7c8f3b4940748d1690b74d9e162eabaf0a2ef2`.

## Boundary

The existing column/constraint/index fingerprint must not admit an apparently
ordinary table whose physical behavior differs from the reviewed contract.
`InspectSchemaAsync` now checks the same PostgreSQL connection and transaction
before computing that existing fingerprint. It rejects partitioned relations,
unvalidated CHECK constraints, table rewrite rules, and nondefault index
operator classes. Failures contain fixed codes and a redacted message, not
table names, rows, credentials, or query parameters. Cancellation is propagated.

This is an admission guard, not a new fingerprint format, approved extension
profile, repair executor, migration authorization, or schema DDL. Supported
historical schemas retain their existing hashes. No source adapter, signed
manifest, row operation, journal, authorization, or target fence is changed.
Internal migration bookkeeping remains excluded under the existing boundary.

## Actual regression evidence

Six new tests use fresh run-owned shadow databases inside the existing disposable
PostgreSQL fixture. Four mutate exactly one physical facet and assert its
specific rejection code; two ordinary-schema controls preserve the signed
fingerprint and round-trip a named Thai/English row. Test-only DDL never touches
a persistent target.

The first attempt failed during fixture commit because table reconciliation had
not been recorded; that setup diagnostic is not product RED. After fixing only
the new fixture, `physical-genuine-red` was four failures and two passes against
unchanged runtime. After the narrow guard, `physical-green` was six passes,
zero failures/skips.

## Validation

- Release solution build with warnings as errors: zero warnings/errors.
- Focused new tests: 6/6 passed, no skips.
- Ordinary full main suite: 1,482 passed, 15 skipped, zero failures.
- Native-enabled full main suite: 1,494 passed, three skipped, zero failures,
  4m59s. TRX `TestResults/physical-native-full/physical-native-full.trx`, SHA-256
  `000440FDE4BA5CB4E0740634567FD709BBA89031CC7CE076FCC92B0C822D919D`.
- Native-enabled isolated SQL adapter suite: 177 passed, one skipped,
  zero failures, 2m23s, separate TRX
  `TestResults/physical-sql-native/sql-native.trx`.
- Scoped formatting, transitive package vulnerability audits and whitespace
  checks passed. Final whole-solution formatting and staged secret checks are
  required before committing.

The native run enables SQL integration and PostgreSQL18 dump/restore tooling
only on synthetic disposable fixtures. The remaining operator-proof checks
need protected owner inputs or their supported execution platform; they are
not waived and no live exact-23 or persistent reconciliation is claimed.
The earlier ordinary SQL suite had 169 passes/nine skips, but its shared TRX
name was overwritten by the other project; the native rerun above retains
separate evidence rather than claiming that overwritten file still exists.

## Reproduce

```powershell
dotnet build Legacy.Maliev.DataMigration.slnx -c Release --nologo -warnaserror
dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj -c Release --no-build --no-restore --filter FullyQualifiedName~PostgreSqlPhysicalAdmissionTests
$env:MALIEV_RUN_SQLSERVER_INTEGRATION='1'
$env:MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION='1'
$env:PG_DUMP_PATH='C:\Program Files\PostgreSQL\18\bin\pg_dump.exe'
$env:PG_RESTORE_PATH='C:\Program Files\PostgreSQL\18\bin\pg_restore.exe'
Remove-Item Env:LEGACY_SNAPSHOT_INTEGRATION_CONNECTION -ErrorAction SilentlyContinue
dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj -c Release --no-build --no-restore --logger 'trx;LogFileName=physical-native-full.trx' --results-directory TestResults/physical-native-full
dotnet test tests/Legacy.Maliev.DataMigration.SqlServer.Tests/Legacy.Maliev.DataMigration.SqlServer.Tests.csproj -c Release --no-build --no-restore --logger 'trx;LogFileName=sql-native.trx' --results-directory TestResults/physical-sql-native
```

No application deployment, production SQL configuration, persistent PostgreSQL
write, infrastructure creation, or claim-store operation occurred. Consumer
extension profiles (#97), physical production alignment (#94), and a distinct
source-backed recovery caller (#221) remain separate work.

## Independent review and final seven-case guard

Independent review found that index-level collation was also absent from the
existing fingerprint. A seventh disposable test recreates the same unique
named index using a nondeterministic ICU collation and ordinary default
operator class. Against the initial guard it genuinely failed to throw while
all six earlier controls passed (`physical-index-red`). The narrow fix compares
each key's `indcollation` with its actual indexed column's `attcollation`, using
matching ordinals; INCLUDE slots are excluded and constraint-backed indexes
are included. Reviewed column collations and ordinary noncollatable columns
remain supported. No fingerprint format changes.

Final fresh Release build: zero warnings/errors. Focused seven cases all pass,
zero skips (`physical-index-green`). Final native main suite: 1,495 passed,
three skipped, zero failures, 4m58s; TRX
`TestResults/physical-final-native/physical-final.trx`, SHA256
`083DCC0082EF1DBEA828AE7AB5212C62397090E9D786A8B46851165BA86CEEA8`.
Final native SQL adapter suite: 177 passed, one skipped, zero failures, 1m51s;
`TestResults/physical-final-sql/sql-final.trx`, SHA256
`78881EA634CCBFDD3D4008859BE17D1D25291DA1B5887CF7080D6F7FCE0672ED`.
Whole-solution formatting passed. Existing execution-tunnel admission tests
passed9, durability tests6 and missing-config rejection1.

The guard covers the explicitly tested physical facets, not every PostgreSQL
catalog feature. Index access-method equivalence remains an untested follow-up;
no claim is made that this bounded change resolves every physical-schema issue.
Protected exact-head and post-main CI remain required before acceptance.
