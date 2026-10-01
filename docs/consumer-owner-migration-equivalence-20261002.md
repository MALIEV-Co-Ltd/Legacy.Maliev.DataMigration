# #225 actual owner-EF equivalence proof — implemented local candidate

Initial base: DataMigration candidate `21d0624f6d26de4e77b5584d1d0d33a466eebf24` (#224). Reparented without loss onto protected merge `e2f63f1f15fa93c0eb811e0542751f157f292e5a`, with identical tree `5d3a79dfb36da1ff007f671929e5dc0dc4aa2b21`; exact-head/security and post-main 36914838141 passed. Parent #97 remains open. No production schema/setup/repair authority follows from this fixture.

## Immutable producers

Accounting `1913979fa67e1d5864d1469ac1e9e768548af4ba`: actual `InvoiceDbContext`, Data/Application/Domain graph; six Invoice migrations ending `20261001133820_RetainInvoiceNotificationReceipt`. Auth `51afbbd6e2829382a3431338abedccf339de33b1`: actual Customer/EmployeeIdentityDbContext, Infrastructure/Application/Domain graph; respectively three/two migrations ending `202609260001_AddCustomerIdentityCreateOperations` and `202609300001_AddEmployeeRecoveryEffects`.

Both graphs use EF10.0.12/NpgsqlEF10.0.3. They do not require API, IAM, provider calls or Defaults/Contracts. Full owner API graphs retain their own different Defaults pins, but are not built here. DataMigration production/test project references remain unchanged; only the separate test utility references pinned owner projects.

## Independent boundary

Helper executes actual `Database.MigrateAsync`, returning applied migration IDs only. The tests independently assert the complete six/three/three owner table inventories, then compare ONLY the four approved receipt table catalog components with the approved immutable manifest. They do not derive a source plan from the owner schema or authorize migration history, marketing/source columns, Customer PasswordSetupRequired, or source-owned tables as new target extensions. Existing component rules retain physical defaults/nullability/keys/constraints/indexes and unsupported physical behavior rejection. Column physical ordinal placement is intentionally not a fingerprint input; key and constraint column ordering remains strict.

Unique PG18 Testcontainer-owned database names bind an explicit random run ID, loopback connection and exact database comment. Helper validates name/context/deployment-off before connecting, then verifies PG18 plus ownership comment before any EF DDL. Child environment is cleared except required process search/system variables, explicitly deployment false. Synthetic connection is private stdin, never arguments or output. Input/process lifetime/drain are bounded. Rejections expose fixed diagnostics only. No ambient persistent connection or operator CLI is consumed.

Fresh subprocess restarts preserve nonempty synthetic receipts, exact digests and an advanced Customer bigint identity. Existing #224 source-only delta/rollback/replay tests remain independent and unchanged. Owner migrations are applied Up only: this proof does not establish destructive Down safety or change retention policy.

## Chronology / diagnostics

- Unchanged base test-project Release build: 0 warnings/errors.
- New three-case equivalence test build: 0 warnings/errors.
- Initial actual focused run: 0 PASS / 3 assertion FAIL / 0 SKIP: mandatory helper absent. This is test portability RED, not a product-schema defect. Retained TRX: `tests/Legacy.Maliev.DataMigration.Tests/TestResults/natth_MALIEV-31USFIV_2026-10-02_02_22_24_net10.0.trx`.
- Private exact clones created with no hardlinks. Windows long-path checkout required local Git longpaths support; absent files were materialized without force/reset, originals untouched.
- First actual helper graph build failed with 29 inherited CA diagnostics. Neither owner supplies `.editorconfig`; the nested clone inherits DataMigration's all-analyzers-warning policy, unlike standalone owner CI. Root approved an ignored private boundary `root = true` ONLY; no severity suppression or owner source/config edit. This is a build/fixture diagnostic, not migration equivalence RED.
- Subsequent helper exposed MSB3277: transitive EF Relational10.0.4 versus owner10.0.12. Helper explicitly references the same reviewed Relational10.0.12 and uses MSBuild `-warnaserror`; fresh helper and all six owner project builds completed 0 warnings/errors. Owners remain exact clean pins.
- Actual initial twelve-case focus executed all real owner migrations: 12 PASS / 0 FAIL / 0 SKIP. `TestResults/owner-ef-actual-focus/owner-ef-actual-focus.trx`. Includes six unowned/no-DDL rejections and three nonempty restart/digest controls. This establishes a passing compatibility proof, not a repaired product regression.

## Mandatory CI wiring (implemented after genuine RED)

Root expanded ownership to the reusable build workflow and one new CI contract test. The contract built 0 warnings/errors, then failed at the actual missing setup/preparation step (one genuine assertion RED, `TestResults/owner-ef-ci-red/owner-ef-ci-red.trx`). The workflow now adds ONLY setup-dotnet `26b0ec14cb23fa6904739307f278c14f94c95bf1` with 10.0.x and the mandatory pwsh preparation script, AFTER existing exec-tunnel admission and BEFORE unchanged normal validation. The action pin is identical to frozen Workflows6017816's setup action. No new secret, permission, cache, optional/fail-open step, publication or deployment change. Both pinned owner repositories were independently observed public (`isPrivate=false`), so no cross-repository token is required. Exact clean SHA/origin checks and the required DLL path fail closed. Original checkout, normal validation and native/SQL steps remain unchanged.

## Final local validation

Commands were executed inside this isolated worktree only:

- `dotnet build Legacy.Maliev.DataMigration.slnx -c Release --nologo -warnaserror -p:TreatWarningsAsErrors=true -p:UseSharedCompilation=false`: 0 warnings/errors.
- `./scripts/prepare-consumer-owner-migration-proof.ps1`: actual helper plus six pinned owner projects, 0 warnings/errors. The helper has a direct EF Relational10.0.12 reference to match owner compilation; no owner package/source changes.
- Focused `dotnet test ... -c Release --no-build --no-restore --filter 'FullyQualifiedName~ConsumerOwnerMigrationEquivalenceTests|FullyQualifiedName~ConsumerOwnerMigrationProofCiContractTests'`: 13 PASS, zero errors/skips. Final TRX `TestResults/owner-ef-final13-focus/owner-ef-final13-focus.trx`, SHA256 `d51e8fab9afcf74fe3c2f2abc85bdd7c0db186745dbc793971042bf3ffebd261`.
- Unfiltered native suite with `MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1`, installed PG18 pg_dump/pg_restore paths and NO ambient `LEGACY_SNAPSHOT_INTEGRATION_CONNECTION`: 1578 PASS / 3 existing gated SKIP / 0 errors, 1581 total, 6m28s. TRX `TestResults/owner-ef-final-native-full/owner-ef-final-native-full.trx`, SHA256 `ffb5f21cc12d8972c3bd0936ec4b1b4a4b13842604e77c23f32d67aa4cee95d4`.
- SQL-adapter suite, run serially after native with both existing integration flags and actual PG18 tools: 178 PASS / 0 SKIP / 0 errors, 7m30s. All SQL Server/PostgreSQL writes were to owned disposable test containers, never original or persistent databases. TRX `TestResults/owner-ef-final-sql-full/owner-ef-final-sql-full.trx`, SHA256 `24132f52110b20889cb7d879753264097d78fe4376e85b037e64f6c999c7696f`.

Raw unexcluded native coverage: DataMigration85.84%, Console58.26%, SqlServer0%. SQL suite coverage: SqlServer77.81%, DataMigration37.68%, Console7.47%, linked native Tests1.99%. These are separate collector scopes, not combined coverage or an 80% waiver. Helper/owner subprocess behavior was directly tested; those subprocess assemblies are not asserted covered by the native collector.

The original default-profile full (1561 PASS / 19 gated SKIP) omitted native enablement and is retained diagnostic evidence, not final acceptance. Pre-CI native-enabled full1577 PASS / 3 SKIP is historical proof before the new mandatory CI assertion. Initial new CI compilation diagnostics were fixed only in the new test before asserting its genuine RED.

An erroneous verify-only format invocation40199 overlapped SQL60808: SQL had started first and remained live when formatting was observed terminal EXIT0. That formatting result is excluded; source status showed no drift. After SQL terminated, sequential whole-solution and separate helper verify-only formatting27935 completed EXIT0. Actionlint, preparation-script PowerShell AST, solution's six package vulnerability audits and separate helper vulnerability audit passed. No validation skip/exclusion, old assertion or threshold was changed. Final scoped secret scans/readbacks are recorded at handoff; the initial scoped scan already reported no leaks.

## Residual data-readiness gates — not closed by this proof

The disposable owner `__EFMigrationsHistory` records prove that actual pinned Up migrations executed. They do NOT approve source `public.__EFMigrationsHistory` row disposition or a canonical baseline contract. Source-history rows require an independently approved preservation/disposition and baseline procedure: no blanket history exclusion, replacing source history with this disposable owner inventory, or silently stamping an owner baseline is authorized. This remains a #97 data-readiness gate.

CustomerIdentity `PasswordSetupRequired` and Quotation `DecisionOrderVersion` are source-owned overlay/readiness questions outside these three receipt profiles and four tables. Their presence in owner code or other proofs does not approve defaults, historical backfill, copy semantics, schema repair, row admission or activation. Each requires its own reviewed source/target contract and evidence. These residuals prevent declaring whole #97 data readiness from physical receipt equivalence alone.

No whole owner/canonical fingerprint parity, original complete Identity-table parity, API/IAM positive authority, live provider behavior, production-derived exact23 restore, destructive Down safety, timeout-fault injection or persistent bootstrap/repair is claimed. The three unchanged native skips retain owner-protected production-derived #94/full-schema gates and unsupported-platform control; they are not waived. #221/#186/operator authority and parent #97 remain separate.

## Seven-file ownership / handoff

Root independently read all seven files and the complete workflow delta, rebuilt
the Release solution and preparation helper/owner graph with zero warnings/errors,
and executed all 13 focused tests with zero failures/skips. Original final native
and SQL TRX counters, individual skipped outcomes and SHA-256 hashes above were
independently parsed and matched. Root whole-solution format, actionlint,
PowerShell syntax, diff and seven-file secret scan passed. These remain candidate
checks until exact-head and post-merge protected CI pass; no deployment follows.

Six NEW files: `tools/ConsumerOwnerMigrationProof/ConsumerOwnerMigrationProof.csproj`, `tools/ConsumerOwnerMigrationProof/Program.cs`, `scripts/prepare-consumer-owner-migration-proof.ps1`, `tests/Legacy.Maliev.DataMigration.Tests/ConsumerOwnerMigrationEquivalenceTests.cs`, `tests/Legacy.Maliev.DataMigration.Tests/ConsumerOwnerMigrationProofCiContractTests.cs`, this document. Sole existing file changed: `.github/workflows/_build-and-test.yml` (approved two steps only). Production runtime/profiles/StateInspector/repair/public CLI/signed hashes and all old tests remain unchanged. No commits, pushes, GitHub mutations, provider calls or persistent operations performed. Local results remain candidate evidence pending root independent validation and protected CI.
