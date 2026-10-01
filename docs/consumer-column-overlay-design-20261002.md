# Consumer column overlays — #229 / parent #97

## Current phase and authority

Latest phase: approved inactive explicit-profile foundation on protected main
`27c1798a56d803151c7d2a1d1e967d4a482557bf` (exact-main CI 36923700395 SUCCESS).
Root reviewed all eleven existing callsite diffs, both new helpers, the complete 40-case new
test file and this design before approving broad validation. No default/operator activation,
schema application, repair, old test, source projection, CLI, workflow or historical signature
semantics have changed. The historical TEST/DESIGN-only baseline at
`5aee7ee0d23c6bc11d75b130f2eae07057c6435c` and genuine RED chronology are retained below;
those historical phase statements are superseded by the latest chronology sections.

All database specimens are synthetic run-owned PostgreSQL 18 Testcontainers databases.
Creation and mutations in these tests are disposable fixture setup, not persistent DDL authority.
No SQL Server source, current customer rows, provider, Kubernetes, secret store or production
database is accessed. No commits, pushes or GitHub writes. Existing ignored proof artifacts remain.

## Exact source/owner evidence

Original committed mirror checkpoint is
`bed10c7d15e0698e0b75f1329d0f312937f5d77f`. Neither overlay name occurs anywhere
in that committed tree. Source identity fields are in `Maliev.Identities/ApplicationUser.cs`;
source quotation fields are in
`Maliev.QuotationService.Data/Database/QuotationContext/Quotation.cs`.

| Contract | Immutable owner/source provenance | Physical and lifecycle contract |
|---|---|---|
| CustomerIdentity `public.AspNetUsers.PasswordSetupRequired` | Auth owner `51afbbd6e2829382a3431338abedccf339de33b1`; Infrastructure migration `Migrations/CustomerIdentityPostgres/202609070001_AddCustomerPasswordSetupLifecycle.cs`. Introduction `d5836e925c24f84b719c1ac10d2553dcd760e75a`, parent `756767a015b3798673cce86475b784dc33da8c08`. Source identity initial migration file last changed at `72eb9f1949176392141951d35e6e06f7c30af4c2`, parent `023aa2f143fa5a8f557d72c1302b9add64792d6a`. | boolean, NOT NULL, DEFAULT false. Customer-only; Employee mapping ignores it. Existing true/false is explicit lifecycle state, never inferred from PasswordHash. Initial setup/reset completion clears false; identity creation may explicitly request true. |
| Quotation `public.Quotation.DecisionOrderVersion` | Quotation owner `5ac9a8c202b1189b910d5c4870d64bb5f820743c`; Data migration `Migrations/Quotation/20260930070000_PreserveDecisionOrderVersion.cs`. Introduction `3b27b4babd2a742aad29a29c6b7ff8beca1846bb`, parent `9788378d7628917c8fef9bc7df70bfbf41afd7fa`. Source model last changed at `3b8bfe3658a1205b4811d063d44bec8cfa88d895`, parent `aa54f8074c2edcd5cc3a508a18120f9508e5ce18`. | nullable timestamp without time zone, no default. Existing NULL/non-NULL binding preserved exactly at PostgreSQL microsecond precision. Application decision workflow uses it for accepted linked-Order retry keys. Current owner captures historical fallback only during specific accepted edits/invoice attachment, and clears binding for new decisions. No migration backfill to now/ModifiedDate/AcceptedUtc. |

Existing consumer evidence inspected in the previous read-only audit: Auth `LegacyIdentityReader`,
`CustomerIdentityAdminService`, `CustomerSelfService`; Quotation `QuotationRepositories` and
`Application/Services/QuotationDecisionWorkflow.cs`. Owner tests include Auth
`IdentityPostgresMigrationTests`, `LegacyIdentityReaderTests`, `CustomerIdentityAdminTests`,
`CustomerSelfServiceTests`; Quotation `QuotationInvoiceConsumerContractHttpTests`,
`QuotationInvoiceDecisionHttpPostgresTests`, `QuotationDecisionHighWaterHttpTests`,
`QuotationFirstDecisionPrecisionHttpTests`. These were inspected, not executed in this slice.

## Proposed immutable profile contract (not implemented)

Use the existing signed `DatabaseSchemaPlan.TargetExtensionProfile` field; do not add an unsigned
ambient option or silently change historical profile meanings.

* `CustomerIdentity` / `auth-customer-create-authority-v2`: retain the complete existing v1
  `CustomerIdentityCreateOperations` table and sequence contract, plus exactly the lifecycle column
  overlay on source-owned `public.AspNetUsers`.
* `Quotation` / `quotation-decision-order-version-v1`: exactly the retry-version column overlay
  on source-owned `public.Quotation`. Compose with separately validated existing source-outbox
  disposition; never exempt its source rows or transition guard.
* Existing `auth-customer-create-authority-v1`, no-profile Quotation and all other historical
  profile/hash formats retain their previous meaning. An old signed plan does not acquire overlays.
* Exact database/schema/table/column/type/nullability/default/generated/identity/collation facets;
  no pattern matching, broad extra-column tolerance, default inference or SQL normalization.
* Reject source overlap before classifying a column as target-only. Inspect both projected source
  columns and captured source inventory; wrong schema/table/column, unsupported or ambiguous profile
  and unknown extra physical objects remain fail-closed.
* Overlay physical columns belong to target fingerprint inventory but not source row codec,
  source comparison, mutable UPDATE assignments or INSERT source payload. Existing rows retain
  their target values; source inserts omit the column, yielding literal owner defaults false/NULL.
* No PasswordHash heuristic, silent bootstrap classification, NULL replacement, bulk backfill,
  timestamp conversion, decision-version recomputation or runtime field initialization.
* Capture keyed pre-existing overlay state under the existing owning transaction/table locks and
  verify preservation after source-only mutations. The new state proof must compose with existing
  receipt table/sequence proof, not replace it. Root-row delete behavior needs an explicit policy
  before implementation: preservation evidence must not accidentally prohibit a reviewed source
  delete or silently authorize loss of a live owner binding. Phase-one tests cover update/insert only.

Proposed minimal runtime ownership for later review: NEW exact column-overlay manifest/state helper;
narrow `ApprovedTargetExtensionManifest` dispatch and fingerprint target-table composition;
`TargetSchemaGapAnalyzer` target column inventory; existing state-inspection/reconciliation callsites
only where needed to bind and compare overlay state. Do not mutate `schema.Tables` into a source
projection containing owner-only columns, widen repair/bootstrap, or change public operator CLI.
Actual required callsites and state evidence format must be reviewed before code; no acceptance
from a fixture-provided hash alone. Admission must continue through real canonical/preflight APIs.

## Executed tests and precise reach

Baseline build: `dotnet build Legacy.Maliev.DataMigration.slnx -c Release --nologo -warnaserror
-p:UseSharedCompilation=false`: 0 warnings / 0 errors. Standalone solution graph contains no
Defaults/Contracts references; no private dependency pin changes were needed or made.

Existing baseline focus filter:
`FullyQualifiedName~ConsumerTargetExtensionProfileTests|FullyQualifiedName~ConsumerTargetExtensionPreservationTests|FullyQualifiedName~ApprovedTargetExtensionManifestTests`.

* Initial `TestResults/column-overlay-baseline-focus/column-overlay-baseline-focus.trx`:
  73 total, 69 PASS, 4 native-tool prerequisite SKIP. Not affected-native acceptance.
* Repeated unchanged binaries with `MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1`,
  `PG_DUMP_PATH=C:/Program Files/PostgreSQL/18/bin/pg_dump.exe`, corresponding `pg_restore.exe`,
  `LEGACY_DEPLOY_ENABLED=false`, ambient snapshot connection/database unset:
  `TestResults/column-overlay-baseline-native-focus/column-overlay-baseline-native-focus.trx`:
  73 PASS, 0 failure/error/skip. No native full suite or browser run.

Fresh solution Release after NEW tests: 0 warnings / 0 errors. New focus:
`dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj
-c Release --no-build --no-restore --filter FullyQualifiedName~ConsumerColumnOverlayContractTests
--logger trx;LogFileName=column-overlay-initial-red.trx
--results-directory TestResults/column-overlay-initial-red`.

Initial result: 23 total, 17 PASS / 6 assertion FAIL / 0 errors or skips.

| Cases | Actual evidence / disposition |
|---|---|
| Two new profile fingerprint cases | Genuine feature RED: existing `ComputeExpected` refuses the unimplemented exact profile with `target_extension_profile_invalid`. Not a regression or unsafe acceptance. |
| Two real PG canonical entry cases | Genuine feature RED: independently created physical owner-overlay shape matches the literal expected hash before normal `PostgreSqlDeltaCanonicalTarget.BeginAsync`; entry then refuses new profile at actual lock-inventory selection. No copy effect occurs. |
| Two source-column collision cases | BLOCKED negative controls: actual profile-invalid refusal happens before expected source-overlap classification. They do not prove current unsafe source acceptance. |
| Four unknown/wrong-database profiles | PASS, exact unsupported-profile refusal. |
| Two historical profiles | PASS: old fingerprints do not silently gain columns; source projection remains unchanged. |
| Nine PG physical mutations | PASS: independently valid owner shape matches; changed type, nullability, missing/changed default or generated expression changes actual catalog fingerprint. These are physical detector controls, not new-profile admission proof (new profile still unsupported). |
| Two PG concrete source statement cases | PASS: actual existing canonical SQL unit rollback, commit/reconcile and journal replay preserve true/false and exact non-NULL/NULL; inserted source rows use false/NULL; one journal/no duplicate insert. Explicit synthetic unit profile=NULL with independently supplied physical hash. This is NOT signed preflight/profile admission or overlay state-guard proof. |

The root tables in these tests are minimal two-column source projection specimens (identity Id/Email,
quotation ID/Comment), not complete owner EF schemas or fresh authenticated source plans. Customer
receipt schema is the already reviewed immutable shape, not new owner-EF proof. No claim of joined
Auth/Quotation HTTP behavior or whole owner fingerprints follows from these probes.

## Explicit remaining gates

After reviewed runtime, new-profile negative physical/source collision tests must reach their
specific guards rather than generic unsupported-profile refusal. Add keyed preservation-guard
tampering and source inventory collision controls when a reviewed state API exists; do not invent
a missing public API or compile-failing test. Actual rollback/replay tests must then use the admitted
new profiles and compose with nonempty customer receipts/advanced bigint sequence.

Migration-history row disposition/baseline remains independently unresolved: source
`public.__EFMigrationsHistory` is source-owned and cannot be excluded, replaced with owner IDs or
silently stamped by this overlay work. #225 physical owner EF proof does not certify canonical
history or a production baseline. No source qualification exemption, old hash reinterpretation,
schema creation/repair, source history exclusion or owner-baseline stamping is authorized here.
Parent #97 readiness, #221/#186 persistent scope, hosted/operator approval and production-derived
exact-23 proof remain separate. Final runtime/full native/SQL validation is not authorized or claimed
in this TEST/DESIGN phase; no raw coverage threshold waiver is implied.

## Final frozen diagnostic checkpoint

Scoped formatter initially found whitespace/braces/block-body diagnostics only in the NEW test.
Mechanical formatting was restricted to that file; no tracked file changed. After adding
no-effects assertions before the expected admission assertion, a fresh solution Release again
completed with 0 warnings / 0 errors. No assertions were weakened.

Final combined filter adds `FullyQualifiedName~ConsumerColumnOverlayContractTests` to the existing
three baseline classes, using the same explicit PG18 flags/tool paths and deployment=false.
`TestResults/column-overlay-final-diagnostic/column-overlay-final-diagnostic.trx` is terminal:
**96 total / 90 PASS / 6 assertion FAIL / 0 errors, skips, timeouts or aborted**.
Independent XML readback splits NEW 23 into 17 PASS / 6 FAIL and existing 73 into 73 PASS.
Failure categories remain four genuine feature-admission RED and two blocked collision controls.
Both canonical entry cases reached exact physical-hash equality and zero root rows/journal entries
(and zero Customer create receipts) before failing the expected admission assertion.

Final TRX SHA256:
`82a945ebd8893463f903226080b252697ab4df91ce26174418327969c679c2a7`.
Flagged unchanged baseline TRX SHA256:
`37d4718def4198923a0e0809a7a4ae2e36fc3dece0cd2b6a7ac0c3726706bbfe`.
Retained initial NEW 23-case diagnostic SHA256:
`1e621bcf148b10d50f4c5dd1f7f2dc39c35754b8c1f3911618b2fbfc1fb8a09d`.

Final scoped `dotnet format ... --include <NEW test> --verify-no-changes` passed sequentially
after tests. Scoped redacted gitleaks stdin scans for both new files found no leaks;
`git diff --check` passed and tracked diff remained empty. No full native/SQL/browser suite,
coverage report, persistent schema operation or runtime implementation was performed. These
diagnostics are deliberately RED design evidence, not a passing release or #97 readiness claim.
Both files and ignored evidence are released to root for review; all owned command handles are terminal.

## Approved inactive foundation: latest chronology

The historical TEST/DESIGN-only checkpoint above is retained evidence, not the current
implementation status. Root approved the bounded inactive foundation after independently
reproducing 96 tests (90 PASS / 6 assertion FAIL). The workspace was safely fast-forwarded
to accepted main `27c1798a56d803151c7d2a1d1e967d4a482557bf`, whose exact-main CI
`36923700395` succeeded. The two new test/design files and ignored diagnostics were preserved.

The explicit profiles are `auth-customer-create-authority-v2` and
`quotation-decision-order-version-v1`. Physical composition adds only the exact owner column
for inspection/fingerprinting; it never changes `schema.Tables`, source projections/codecs,
`TablesFor` extra-table semantics, `ApplySchema`, bootstrap or repair creation branches.
Default `ProfileForDatabase`, source generation and exact23/operator activation gates remain
unchanged and do not admit these new profiles as a persistent execution policy.

New overlay state is streamed under the existing transaction locks. Its independent domain
`consumer-column-overlay-state-v1` binds database, explicit profile, source and target schema
hashes, the historical receipt/sequence digest when applicable, and the complete keyed overlay
evidence. Reconciliation compares the pre-existing keyed subset after excluding only the signed
INSERT key hashes, requires every such inserted row to have exactly false/NULL, rejects missing
or unknown keys, and stores the final full-state digest in the checkpoint. Root DELETE is now
explicitly forbidden at entry and defensively at Apply, before mutations: the earlier deletion
policy question is superseded by this conservative phase-one policy. New-profile nonlocal replay
freshly checks checkpoint/root/overlay state before returning AlreadyCommitted.

Historical v1 state framing is unchanged; a new independent literal digest regression uses
`c6ff812513379a12b6cbfebe71e57e11554d55c09708ec6ab635b3a6cb2a293c` for a synthetic
Customer receipt state with sequence next value 3000000001. This is not reinterpretation of
an existing signed plan/hash. No root-row map is retained: only streaming evidence and signed
INSERT key hashes are held in memory, and no row values are logged.

New executable coverage now includes admitted rollback/commit/replay and replay tamper;
source-inventory-only collisions; entry/defensive root-delete rejection; changed existing keys,
unknown keys and nondefault inserted overlays; actual Begin rejection for all nine physical
column drift cases; and nonempty Customer receipts with advanced bigint sequence preserved.
Primitive no-profile controls remain separately named and are not approved-overlay admission.

The first expanded 39-case run retained six fixture-reference failures: separately constructed
TableCopyPlan objects were rejected by the existing schema-membership precondition before
Apply. Only new fixtures were corrected to use the actual schema table reference. The existing/
unknown state controls also now insert the valid signed default row first, so their exact
ordered-content/row-count assertions reach the intended comparison rather than a missing-INSERT
precondition. The corrected 39-case run passed; after adding the literal historical digest and
actual drift-entry assertions, fresh Release completed with 0 warnings / 0 errors and
`TestResults/column-overlay-early-runtime-focus/column-overlay-early-runtime-focus.trx`
passed **40 / 40, zero skips**.

This remains an EARLY runtime-review candidate, not full native/SQL acceptance or #97 readiness.
Migration history disposition, owner baseline stamping, persistent/schema-apply authority,
source codec changes, historical hash upgrades, root deletion, CLI/default activation and repair
widening are deliberately excluded. No commit, push, GitHub mutation or persistent operation
has been performed. Root reviews the complete runtime diff before broad suites.

## Final candidate validation and freeze

Root read the complete early runtime/test/design diff and approved broad validation. Runtime
has not widened since that review. Whole-format verification initially reported IDE0046 on the
new conditional state-hash branch; only equivalent conditional-return syntax was corrected.
Fresh solution Release then passed with **0 warnings / 0 errors**, and final combined focus
passed **113 / 113, zero skips** (the 40 new cases plus all 73 original affected controls).

Exact commands, executed serially in this workspace:

```text
dotnet build Legacy.Maliev.DataMigration.slnx -c Release -p:TreatWarningsAsErrors=true -p:UseSharedCompilation=false
dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj -c Release --no-build --no-restore --filter "FullyQualifiedName~ConsumerColumnOverlayContractTests|FullyQualifiedName~ConsumerTargetExtensionProfileTests|FullyQualifiedName~ConsumerTargetExtensionPreservationTests|FullyQualifiedName~ApprovedTargetExtensionManifestTests"
./scripts/prepare-consumer-owner-migration-proof.ps1
dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj -c Release --no-build --no-restore --collect "XPlat Code Coverage"
dotnet test tests/Legacy.Maliev.DataMigration.SqlServer.Tests/Legacy.Maliev.DataMigration.SqlServer.Tests.csproj -c Release --no-build --no-restore --collect "XPlat Code Coverage"
dotnet format Legacy.Maliev.DataMigration.slnx --no-restore --verify-no-changes
dotnet list Legacy.Maliev.DataMigration.slnx package --vulnerable --include-transitive
```

All test commands used explicit unique result directories/TRX names below. Native full used
the unchanged accepted owner-EF preparation helper in the SAME PowerShell process, preserving
its exported `MALIEV_CONSUMER_OWNER_EF_PROOF_DLL`. Private exact owner pins were Accounting
`1913979fa67e1d5864d1469ac1e9e768548af4ba` and Auth
`51afbbd6e2829382a3431338abedccf339de33b1`; helper Release also passed 0 warnings/errors.
This standalone DataMigration solution does not use Defaults/Contracts project references.
`LEGACY_DEPLOY_ENABLED=false`, ambient snapshot connection/shadow variables removed,
`MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1`, and explicit PG18 tools were set:
`C:/Program Files/PostgreSQL/18/bin/pg_dump.exe` and `pg_restore.exe`.
The final SQL full additionally used `MALIEV_RUN_SQLSERVER_INTEGRATION=1`.

| Artifact | Executed result | SHA256 |
| --- | --- | --- |
| `TestResults/column-overlay-final-focus/column-overlay-final-focus.trx` | 113 PASS, 0 FAIL/SKIP | `0e04a5114cd70b7ec9ee5fc5c5846c5dc49c8fa11bba2e8daaca759281029fe0` |
| `TestResults/column-overlay-native-full/column-overlay-native-full.trx` | 1619 PASS, 3 existing SKIP, 0 FAIL | `305a4652a6133d82686c5b43a4081472d4437565b1d100c3ce2c58f091125a1f` |
| `TestResults/column-overlay-sql-enabled-full/column-overlay-sql-enabled-full.trx` | 178 PASS, 0 FAIL/SKIP | `30217bc57642ed60861c0bbf5c49efb941c67acdfc07792a803e4ca4129df6af` |

The first SQL attempt omitted its SQL opt-in and retained 169 PASS / 9 prerequisite SKIP in
`TestResults/column-overlay-sql-full`; it is diagnostic only, NOT SQL integration acceptance.
The subsequent enabled unfiltered full includes the actual SQL→PG/native recovery pipeline.
The three native skips remain explicitly excluded acceptance:

- `FullSchemaTargetExtensionRepairProofTests.FreshLiveExact23Schema_RepairsBothExtensionsOnDisposablePostgreSql`
- `WindowsLocalRunAuthorityTests.Acquire_UnsupportedPlatform_FailsExplicitlyWithoutCreatingRoot`
- `Issue94SchemaRepairProofTests.RepairedDisposableIdentityAndQuotation_ReplayWithoutSchemaMutation`

Unexcluded raw coverage is retained separately, not silently merged or threshold-waived:

| Package | Native line / branch | SQL line / branch |
| --- | --- | --- |
| DataMigration | 85.91% / 69.57% | 37.55% / 23.95% |
| Console | 58.26% / 50.89% | 7.47% / 5.70% |
| SqlServer | 0% / 0% | 77.81% / 63.66% |
| Tests (reported by SQL collector) | not reported | 1.96% / 1.79% |

Native raw report: `TestResults/column-overlay-native-full/ea56c53d-5cd4-491c-a013-13be0192d19b/coverage.cobertura.xml`.
SQL raw report: `TestResults/column-overlay-sql-enabled-full/7f340641-a14d-4029-b207-5129d3c65188/coverage.cobertura.xml`.
Whole format verification, `git diff --check`, scoped redacted gitleaks of every owned complete
file, and transitive vulnerability audit of all six solution projects passed. No analyzer,
coverage, old assertion, prerequisite or security allowlist was weakened.

Complete owned file list (no old test/script/workflow or runtime file outside this list changed):

- `src/Legacy.Maliev.DataMigration/ApprovedConsumerColumnOverlayManifest.cs` (NEW)
- `src/Legacy.Maliev.DataMigration/ConsumerColumnOverlayStateInspector.cs` (NEW)
- `src/Legacy.Maliev.DataMigration/ApprovedTargetExtensionManifest.cs`
- `src/Legacy.Maliev.DataMigration/ApprovedTargetExtensionStateInspector.cs`
- `src/Legacy.Maliev.DataMigration/CanonicalPostgreSqlDeltaTarget.cs`
- `src/Legacy.Maliev.DataMigration/ConsumerTargetExtensionSequenceValidator.cs`
- `src/Legacy.Maliev.DataMigration/DeltaReconciliationInspectors.cs`
- `src/Legacy.Maliev.DataMigration/HistoricalPairedLocalCurrentTargetReview.cs`
- `src/Legacy.Maliev.DataMigration/PostgreSqlRolloverDatabaseReader.cs`
- `src/Legacy.Maliev.DataMigration/PostgreSqlShadowTarget.cs` (fingerprint callsite ONLY)
- `src/Legacy.Maliev.DataMigration/ProductionDefaultDriftReview.cs`
- `src/Legacy.Maliev.DataMigration/ProductionSchemaCatalogInspector.cs`
- `src/Legacy.Maliev.DataMigration/TargetSchemaGapAnalyzer.cs`
- `tests/Legacy.Maliev.DataMigration.Tests/ConsumerColumnOverlayContractTests.cs` (NEW)
- `docs/consumer-column-overlay-design-20261002.md` (NEW)

Final candidate is frozen for independent root execution. No owned build/test/format handle
remains live. Parent #97 remains open: source migration-history disposition and any owner
baseline contract, persistent applicability, default/operator activation and production-derived
data readiness are NOT established by this inactive foundation or disposable proof. Root-delete
is blocked; no persistent DDL, source access, stamping, repair, deployment, commit/push or
GitHub mutation occurred. The accepted four-table owner-EF tests do not establish a whole
canonical source-plan overlay/history baseline.

## Independent root review and validation

Root reviewed all thirteen runtime files, the complete new forty-case test contract,
and this design against clean accepted `27c1798a56d803151c7d2a1d1e967d4a482557bf`.
Fresh Release build with warnings as errors passed zero warnings/errors. With
`MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1`, `PG_DUMP_PATH` and `PG_RESTORE_PATH`
pointing to installed PostgreSQL18 tools, the exact combined four-class focus
passed 113/113, zero failures/skips, in
`TestResults/root-column-overlay-native-focus/focus.trx`.
Two earlier root prerequisite diagnostics are retained, not acceptance: an initial
broader filter omitted the archive opt-in (four skips), and the next used incorrect
tool environment names (four tool-prerequisite failures). No assertion or guard
was weakened; the corrected environment rerun executed all four archive cases.
Agent unfiltered native/SQL evidence above was independently inspected; the three
explicit native exclusions remain exclusions, not passing tests. This is an
inactive opt-in code foundation, not owner history disposition, persistent
applicability, source-plan activation or completed production migration.
