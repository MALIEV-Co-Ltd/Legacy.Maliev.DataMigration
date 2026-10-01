# Consumer target-only authority profiles: implementation and diagnostic chronology

## Current implementation checkpoint: repaired focus GREEN, full gates pending

The historical sections below retain their original evidence and are not current implementation
status. Root-approved sequence admission is now implemented in the new
`ConsumerTargetExtensionSequenceValidator`, with one await before state/next-value inspection;
native recovery inventory now includes validated approved extension tables. Fresh Release build
completed with zero warnings/errors; `consumer-sequence-final-focus` executed 64 tests, all passed.
No old tests, signed hashes, repair scope, DDL authority or last-value semantics changed.

The first required real SQL/native pipeline rerun failed at Invoice restored schema
reconciliation rather than Customer sequence object admission. Retained TRX:
`consumer-real-pipeline-repaired-focus/consumer-real-pipeline-repaired-focus.trx`.
This is NOT final acceptance and neither full suite has been rerun as final proof.

A new native `pg_dump`/`pg_restore` Invoice regression independently reproduced the mismatch:
all column/index/foreign-key components agree; only InvoiceNotificationCorrelation constraints
disagree. Exact PG18 restore reparse changes three array-wide varchar-to-text casts into
per-element casts (Receipt, ReceiptPhase and State). Admission and Identity checks are unchanged.
Root subsequently approved and the candidate now contains only three additional exact restored
catalog literals, still bound to exact schema/table/check name/ordered columns. No SQL general
normalization was added. Fresh Release remains zero warnings/errors; the final combined
profile/preservation/approved-extension/recovery focus executed 117 tests, all passed, zero skips.
This includes actual native archive positive and changed-value/group/operator negative controls.
The real SQL pipeline and serial full suites remain required before frozen final acceptance.

The next real pipeline reached the existing reviewed Material collation and was rejected by
the global namespace-dependency prohibition (`consumer-real-pipeline-final`, SHA256
80579bb59e4fdea1b45ac388c972d3e9f6295c65746da6d9f052b6dfd364b4c2).
NEW independently owned Material recovery fixture confirmed `pg_collation/public/legacy_ci_as`
as its unsupported dependency (`material-reviewed-collation-red`, SHA256
19cfea79678217de4bda0ffc9ce6cc2fce08bc6353adf1c942682db29a3c3bcb).
This is an existing reviewed Material profile/recovery-guard conflict, not new schema repair
or a generic collation exception. Root approved exact requested-OID admission in RecoveryObjects:
validated source+extension inventory must reference this collation; exactly one public/name OID,
ICU provider, locale `und-u-ks-level2`, nondeterministic, encoding -1, NULL ICU rules, and nonnull
recorded/current provider-version agreement. Only that OID with object-subid zero is excepted
from the namespace dependency clause. Every other global object prohibition remains unchanged.
No ApplySchema changes or new collation creation capability are provided by recognition.

Meaningful actual changed-locale/determinism/provider/extra/unrequested negative controls ran
alongside supported-profile RED (5 PASS/1 genuine FAIL). Custom ICU rules at the same locale
then independently produced 6 PASS/1 genuine FAIL before the NULL-rules guard. These raw
diagnostics remain retained. Initial CREATE COLLATION FROM syntax and Npgsql untyped uint OID
parameter errors are distinct implementation/fixture diagnostics, not claimed semantic RED.
The latter was corrected with an explicit Oid parameter type before the rules regression.
Fresh Release 0W/0E and final combined 124 PASS/0 FAIL/0 SKIP focus are now executed;
real SQL/native pipeline and full suites are still pending at this checkpoint.

The subsequent real pipeline identified a candidate empty-shadow regression: collation lookup
was required before any schema application, rejecting the legitimate empty Material shadow.
NEW `material-empty-shadow-red` reproduced one genuine failure with seven rejection controls;
`material-empty-contract-red` further established two genuine failures / seven controls before
repair (empty shadow rejected, collation-only shadow incorrectly admitted). Parent approved
optional exact lookup OID zero and deferred required-OID check after complete relation inspection.
OID zero grants no namespace exception; populated targets requiring the collation must have a
valid OID, and collation-only shadows fail closed rather than being classified verified empty.
Existing global object/schema checks and verified-empty contract are preserved. No populated
missing-collation or malformed/extra/unrequested-collation admission is introduced.

Actual genuine diagnostic: `consumer-native-invoice-diagnostic-corrected/consumer-native-invoice-diagnostic.trx`,
1 assertion failure / 0 fixture errors / 0 skips, SHA256
`130b4fcd81e5bcc4455c008b4d094379cfe181a569cd7fc23c326092d838ab19`.
Earlier new diagnostic build failures (wrong existing fact attribute name and named `_` lambda
parameter assignment) and the CREATE DATABASE privilege fixture error are not product failures;
they remain retained separately. The corrected fixture uses the existing disposable container
administrator only for creating/deleting its independent restored database; native dump/restore,
actual catalog readback and production fingerprint inspection are real.

## Latest frozen sequence-admission RED, 2026-10-02

Earlier 49-case focus was green but NOT complete physical admission. Actual serial native full:
1536 passed / 0 failed / 3 pre-existing skips / 1539 total, TRX consumer-profiles-full-native,
SHA256 e5c781822680bf2c82baa62eada3e72d61d8ac96babcb9aff93f549578efcd5e.
Skips: owner-only Issue94 repair proof, owner-only fresh-live full-schema repair proof and
the unsupported-platform Windows authority control. Native dump/restore 18.1 executed with
MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1 and no ambient persistent snapshot connection.
Raw native coverage: DataMigration 85.77%, Console 58.26%, SqlServer 0% in this run (separate
adapter run follows); no coverage waiver or hosted/persistent proof is inferred.

Actual serial SQL adapter full with both integration flags: 177 passed / 1 failed / 0 skipped,
TRX consumer-profiles-full-sql-adapter, SHA256
6128b4fa55d191d84d9ba27abc530b995939a03cb58928280d7453b7a15e89de.
Existing RealSqlPgNative_LaterFailureAndNewCoordinator_RevalidatesAndPreservesWithoutRecopyOrRedump
genuinely fails native restored archive admission: PostgreSqlShadowRecoveryObjects inventories
identity ownership only from source plan.Tables, excluding approved Customer receipt identity.
Root reviewed and authorized only adding approved extension tables to that inventory; no
unknown-object/sequence allowance, old test weakening or runtime repair has yet been applied.

New executable sequence tests built 0W/0E and ran actual disposable PG18 mutations:
15 executed / 3 preservation controls passed / 12 failed / 0 errors/skips,
consumer-sequence-admission-red.trx SHA256
72f382ab918ad125e5e284ecc47dd1662ef92d5c69baf01524efda6575fa9737.
Eight definition/mode mutations are accepted incorrectly by current StateInspector; the ninth
ownership mutation reaches a production InvalidCastException on DBNull sequence lookup rather
than a fixed redacted admission error. Every DDL mutation executed, and its actual catalog
definition differs from the independently captured baseline. These are not fixture syntax failures.
Native supported-extension test is genuine rejection RED; two subsequent arbitrary/drift
rejection controls are blocked at the same healthy baseline until inventory repair, not yet
independent evidence of their negative branch. Advanced bigint 3000000001 and nonempty
four-table rollback/commit/replay controls remain green.

Definition frame: [type,start,increment,min,max,cache,cycle,attidentity,internal-owner-count].
Baseline: [bigint,1,1,1,9223372036854775807,1,false,d,1].
Actual mutations: increment=2; start=2; cache=2; cycle=true; type=integer with max2147483647;
min=0; max=9223372036854775806; identity mode=a; detached replacement sequence mode empty
and internal-owner-count=0. Exact SQL and synthetic catalog frames are retained in the NEW test/TRX.
Signed IdentityCopyPlan is (Id,SeedValue1,IncrementValue1,CurrentValue1,IsCalled false);
CurrentValue/IsCalled are not definition invariants and must NOT force live runtime state back to seed.

Proposed bounded guard: NEW profile-bound sequence validator, only CustomerIdentity /
auth-customer-create-authority-v1, awaited inside the existing transaction before StateInspector
row/next-value reads. Require actual public CustomerIdentityCreateOperations.Id bigint BY DEFAULT
identity and its unique internal owning pg_depend relation, actual pg_get_serial_sequence identity,
pg_sequence bigint/start1/increment1/min1/maxlong/cache1/no-cycle. Missing/different ownership or
definition throws fixed target_extension_sequence_definition_invalid without values/credentials;
cancellation/query failure is not swallowed. No nextval/setval/DDL/repair/schema/hash change.
Old unprofiled/Material/QuotationRequest plans remain unchanged. Separate narrow recovery fix:
plan.Tables.Concat(ApprovedTargetExtensionManifest.TablesFor(plan)) for identity inventory only.
This latest candidate is intentionally RED and frozen for root review, not commit-ready.
After scoped formatting, fresh Release again passed 0W/0E and the frozen focused repeat
consumer-sequence-admission-frozen-red.trx retained the same 3PASS/12FAIL/0errors/0skips.
All full/build/test handles are terminal. No sequence validator or recovery inventory repair
has been implemented yet; existing runtime remains exactly the initial approved profile slice.
Raw SQL-adapter-run coverage: SqlServer77.81%, DataMigration36.17%, Console0%, test assembly2.03%.
These are per-run unexcluded reports, not a merged total or an 80% coverage waiver.

## Current bounded runtime candidate, 2026-10-02 — supersedes historical ownership below

Base is accepted protected main dd225cd8d1cc76f908257fbc41098822ea705e91. Root authorized
three immutable profiles, four complete consumer table shapes, exact six source/catalog check
pairs with ordered columns, and one fingerprint dispatch. Existing Quotation compatibility
is delegated unchanged. Root accepted PR223 physical guards; new four drift tests now assert
their exact errors rather than accepting a generic fingerprint difference. No guard is duplicated.
No old tests, StateInspector, repair, CLI, fences, schema/workflows or consumer code changed.
Profile recognition does not authorize repair, setup, bootstrap, migration or persistent DDL.

New strict tests reject changed predicates/NULL logic, name/schema, default and collation;
ordered check-column mutations do not receive compatibility. Historical null-profile plans
retain their hash/inventory; selecting a new profile changes signed plan payload. Existing
Quotation profile is checked against an independently transcribed old table inventory.

Actual disposable PG target-unit preservation tests seed nonempty receipts in all four tables,
then invoke PostgreSqlDeltaCanonicalTarget Begin/Apply/Reconcile/Commit plus rollback on
disposal and AlreadyCommitted replay. Row counts/ordered digests match preimages, one source
Probe insertion and one journal row persist, and Customer bigint next-value 3000000001 remains
unchanged. The advance happens only during synthetic fixture setup, never during delta.
These target-unit plans are not operator-signed admission/CLI or real exact-23 execution proof.
No source qualification or privileged persistent data boundary is bypassed or modified.

Fresh Release builds passed zero warnings/errors. First focus 33 passed; next focus 45 passed
at TestResults/consumer-profiles-second-green/consumer-profiles-second-green.trx.
Retained setup diagnostics: consumer-profiles-preservation-focus incorrectly used the existing
NOCREATEDB fixture role for CREATE DATABASE; consumer-preservation-corrected-fixture incorrectly
called Commit on an AlreadyCommitted replay. Only NEW fixture usage was corrected to existing
disposable admin and actual replay protocol; neither is a product defect or product RED.
The original 23 RED evidence and all seven literal capture strings below remain retained.
Full native suites have not started: early runtime review requested before that gate.

## Approved diagnostic capture, 2026-10-02

Only the new test and this document changed. Runtime profiles, canonicalizer, StateInspector,
repair, fences, old tests and physical guards remain unchanged at fa7c8f3. PR223 is still a
required acceptance dependency, not proof conferred by these schema-only diagnostics.

Release build passed with zero warnings/errors before actual disposable PG18 capture.
Two capture cases passed, verifying all seven conkey column arrays against independently
transcribed owner expectations. Exact catalog strings are now frozen as assertions in the new
fixture; initial capture TRX is retained at TestResults/consumer-check-catalog-capture/consumer-check-catalog-capture.trx.
Final fresh Release build passed 0 warnings/0 errors after correcting new-field CA1859
(the intermediate build diagnostic is retained; no analyzer suppression).
All new fixture cases: 25 executed, 13 passed, the same 12 expected failures, zero errors/skips,
TestResults/consumer-check-literals-final/consumer-check-literals-final.trx. Both exact catalog
literal/column cases passed. No full-suite or physical-guard acceptance is claimed.
After target-typed-new formatting correction (IDE0090), another fresh Release passed 0W/0E,
the exact two literal cases passed in consumer-check-literals-format-final.trx, and scoped
verify-only format exited zero. All command handles are terminal. Only these two new files
remain untracked; no tracked runtime or existing test changed. This is frozen diagnostic
evidence for root review, not a commit-ready or full-green implementation.
The original 23-case RED artifacts remain unchanged. These specimens do not execute owner EF
migrations and do not establish deployed readiness or preserved nonempty effect rows.

Compatibility proposal: exact public schema/table/check-name and reviewed source/catalog pair
only, using the separately pinned owner migrations above. Admission already normalizes with
the existing outer-parenthesis rule; the four correlation and two employee checks require
literal pairs. Preserve column arrays exactly. Reject unknown predicates, loosened constants,
changed NULL/AND/OR logic and altered array members. No generic cast/grouping/IN equivalence.
StateInspector already compares ordered rows and long sequence values; preservation tests
are required before any claim that nonempty effects or bigint sequence state survive delta.
Repair remains restricted to its existing databases and integer sequence policy.

- `InvoiceCreationAdmission.CK_InvoiceCreationAdmission_Quotation`: columns `QuotationID`; catalog:
  ```sql
  ("QuotationID" > 0)
  ```

- `InvoiceNotificationCorrelation.CK_InvoiceNotificationCorrelation_Identity`: columns `InvoiceID, QuotationID, Purpose, SenderServiceSubject, IntentID, WorkflowOperationID, PayloadBinding, OriginIssuer, OriginEmployeeSubject, OriginServiceSubject, SenderIssuer, BindingKeyID, PayloadFrameVersion, BindingVersion`; catalog:
  ```sql
  (("InvoiceID" > 0) AND ("QuotationID" > 0) AND (("Purpose")::text = 'invoice-issued'::text) AND (("SenderServiceSubject")::text = 'service:legacy-accounting'::text) AND ("IntentID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("WorkflowOperationID" <> '00000000-0000-0000-0000-000000000000'::uuid) AND ("IntentID" <> "WorkflowOperationID") AND (octet_length("PayloadBinding") = 32) AND (length(("OriginIssuer")::text) > 0) AND (length(("OriginEmployeeSubject")::text) > 0) AND (length(("OriginServiceSubject")::text) > 0) AND (length(("SenderIssuer")::text) > 0) AND (length(("BindingKeyID")::text) > 0) AND (("PayloadFrameVersion")::text = 'notification-payload-v1'::text) AND (("BindingVersion")::text = 'accounting-invoice-notification-hmac-v1'::text))
  ```

- `InvoiceNotificationCorrelation.CK_InvoiceNotificationCorrelation_Receipt`: columns `RemoteVersion, RemoteState, RemoteAdmittedAt, RemoteUpdatedAt, RemoteReceiptBinding`; catalog:
  ```sql
  ((("RemoteVersion" IS NULL) AND ("RemoteState" IS NULL) AND ("RemoteAdmittedAt" IS NULL) AND ("RemoteUpdatedAt" IS NULL) AND ("RemoteReceiptBinding" IS NULL)) OR (("RemoteVersion" IS NOT NULL) AND ("RemoteVersion" > 0) AND ("RemoteState" IS NOT NULL) AND ("RemoteAdmittedAt" IS NOT NULL) AND ("RemoteUpdatedAt" IS NOT NULL) AND ("RemoteReceiptBinding" IS NOT NULL) AND (octet_length("RemoteReceiptBinding") = 32) AND ("RemoteUpdatedAt" >= "RemoteAdmittedAt") AND (((("RemoteState")::text = 'admitted'::text) AND ("RemoteVersion" = 1)) OR ((("RemoteState")::text = 'submitting'::text) AND ("RemoteVersion" = 2)) OR ((("RemoteState")::text = ANY ((ARRAY['outcomeUnknown'::character varying, 'providerAccepted'::character varying])::text[])) AND ("RemoteVersion" = 3)))))
  ```

- `InvoiceNotificationCorrelation.CK_InvoiceNotificationCorrelation_ReceiptPhase`: columns `Phase, RemoteVersion, RemoteState`; catalog:
  ```sql
  (((("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NULL)) OR ((("Phase")::text = ANY ((ARRAY['Admitted'::character varying, 'ExecutionIssued'::character varying])::text[])) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'admitted'::text)) OR ((("Phase")::text = 'OutcomeUnknown'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = ANY ((ARRAY['submitting'::character varying, 'outcomeUnknown'::character varying])::text[]))) OR ((("Phase")::text = 'ProviderAccepted'::text) AND ("RemoteVersion" IS NOT NULL) AND (("RemoteState")::text = 'providerAccepted'::text)))
  ```

- `InvoiceNotificationCorrelation.CK_InvoiceNotificationCorrelation_State`: columns `Version, RemoteVersion, UpdatedAt, CreatedAt, Phase, AdmissionIssuedAt, ExecutionIssuedAt`; catalog:
  ```sql
  (("Version" > 0) AND (("RemoteVersion" IS NULL) OR ("RemoteVersion" > 0)) AND ("UpdatedAt" >= "CreatedAt") AND (("Phase")::text = ANY ((ARRAY['Prepared'::character varying, 'AdmissionIssued'::character varying, 'Admitted'::character varying, 'ExecutionIssued'::character varying, 'OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) AND (("AdmissionIssuedAt" IS NULL) OR ("AdmissionIssuedAt" >= "CreatedAt")) AND (("ExecutionIssuedAt" IS NULL) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" >= "AdmissionIssuedAt"))) AND ((("Phase")::text = 'Prepared'::text) OR ("AdmissionIssuedAt" IS NOT NULL)) AND ((("Phase")::text <> 'Prepared'::text) OR (("AdmissionIssuedAt" IS NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NULL))) AND ((("Phase")::text <> 'AdmissionIssued'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL))) AND ((("Phase")::text <> 'Admitted'::text) OR (("AdmissionIssuedAt" IS NOT NULL) AND ("ExecutionIssuedAt" IS NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> 'ExecutionIssued'::text) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['OutcomeUnknown'::character varying, 'ProviderAccepted'::character varying])::text[])) OR (("ExecutionIssuedAt" IS NOT NULL) AND ("RemoteVersion" IS NOT NULL))) AND ((("Phase")::text <> ALL ((ARRAY['ProviderAccepted'::character varying, 'RejectedBeforeSubmission'::character varying])::text[])) OR ("RemoteVersion" IS NOT NULL)))
  ```

- `EmployeeRecoveryEffects.CK_EmployeeRecoveryEffects_Binding`: columns `TokenSha256, OwnerSubject, BeforeSecurityStamp, AfterSecurityStamp`; catalog:
  ```sql
  ((length(("TokenSha256")::text) = 64) AND (length(("OwnerSubject")::text) > 0) AND (length("BeforeSecurityStamp") > 0) AND (length("AfterSecurityStamp") > 0))
  ```

- `EmployeeRecoveryEffects.CK_EmployeeRecoveryEffects_PurposePayload`: columns `Purpose, PasswordPayloadHash`; catalog:
  ```sql
  (((("Purpose")::text = 'employee-password-reset'::text) AND ("PasswordPayloadHash" IS NOT NULL)) OR ((("Purpose")::text = 'employee-email-confirmation'::text) AND ("PasswordPayloadHash" IS NULL)))
  ```

## Current scope, 2026-10-01

Base: clean protected DataMigration `fa7c8f3b4940748d1690b74d9e162eabaf0a2ef2`.
Owned workspace: `B:/maliev-legacy/.worktrees/datamigration-consumer-extensions-20261001`,
branch `codex/consumer-target-extension-profiles-20261001`.
Only this document and NEW `ConsumerTargetExtensionProfileTests.cs` may change.
Runtime/manifest/repair/schema/CLI/workflow and all old tests are unchanged.
No commit, keys, live database access, provider, Kubernetes, persistent DDL or refresh.
The sole persistent data owner remains task `01a0e5d4`; these tests grant no operator authority.

## Independently pinned consumer shapes

| Owner commit | Database | Proposed immutable profile | Exact tables |
|---|---|---|---|
| Accounting `1913979fa67e1d5864d1469ac1e9e768548af4ba` | Invoice | `accounting-invoice-authority-v1` | `public.InvoiceCreationAdmission` (9 columns), `public.InvoiceNotificationCorrelation` (25 columns) |
| Auth `51afbbd6e2829382a3431338abedccf339de33b1` | CustomerIdentity | `auth-customer-create-authority-v1` | `public.CustomerIdentityCreateOperations` (7 columns, bigint identity) |
| Same Auth commit | EmployeeIdentity | `auth-employee-recovery-authority-v1` | `public.EmployeeRecoveryEffects` (12 columns, UUID PK) |

Accounting source paths under `Legacy.Maliev.AccountingService.Data/`:
`Migrations/Invoice/20260928094829_AddInvoiceCreationAdmission.cs`,
`20261001105037_AddInvoiceNotificationCorrelation.cs`,
`20261001133820_RetainInvoiceNotificationReceipt.cs`,
`InvoiceDbContextModelSnapshot.cs` and `AccountingDbContexts.cs`.
Admission has UUID OperationID PK and the positive QuotationID check; ResultJson alone is nullable.
Correlation retains all immutable identity/HMAC fields and seven nullable lineage/receipt fields,
UUID IntentID PK, unique InvoiceID+Purpose, and Identity/State/Receipt/ReceiptPhase checks.
No identity sequence, FK, invented effect or default is added to either table.

Auth paths under `Legacy.Maliev.AuthService.Infrastructure/`:
`Migrations/CustomerIdentityPostgres/202609260001_AddCustomerIdentityCreateOperations.cs`,
`Migrations/EmployeeIdentityPostgres/202609300001_AddEmployeeRecoveryEffects.cs`,
and `LegacyIdentityContexts.cs`.
Customer operation preserves bigint Id identity, two unique indexes (ServiceSubject+OperationKey,
DatabaseId), exact bytea fields without inventing SQL length checks from EF annotations.
Employee effect preserves UUID ActionId PK, two checks, unique TokenSha256+Purpose and both
nonunique indexes; PasswordPayloadHash and FinalizedAcknowledgedAt are nullable.
These identity contexts have hand-authored migrations, not separate identity-context snapshots.

Test literals are independently transcribed from those committed migrations. Disposable specimens
are created through the actual DataMigration PostgreSQL adapter; this is NOT execution of owner EF
migrations and is NOT deployed physical readiness or data parity. No fixture records historical
effects, schema history or source data. Owner migration equivalence needs separate subsequent proof.

## Excluded boundaries

Quotation `e0a24ea08b3681fb30e2de9608cd825dd708c0ca` is inspected, not changed.
`RequestQualificationAudit` and Request qualification/version/transaction fields exist in committed
source `bed10c7d15e0698e0b75f1329d0f312937f5d77f`: they remain ordinary source-owned delta rows.
`QuotationAcceptedOutcome` is already canonical adoption of the source outcome outbox under the
existing signed disposition. Do not classify it twice or resurrect analytics delivery.
`RequestCreateIdempotency` remains the unchanged existing target-only profile.
Accounting Receipt contains its three source-owned tables, not a new receipt journal.
Auth RefreshSessions/action tokens/nonces and extra runtime database stay outside exact-23.
Do not import local Auth session rows, seed migration history, or fabricate notifications/recovery.

`Quotation.DecisionOrderVersion` and `CustomerIdentity.AspNetUsers.PasswordSetupRequired` require
separate source-absence-verified preserve-only column-overlay contracts. This slice admits neither.
Historical AcceptedUtc compatibility columns also cannot be ignored by a table extension profile.

## Behavioral tests and honest RED classification

Recognition: three new profile expectations fail because ProfileForDatabase returns null.
Collision: three future-profile cases currently return profile-invalid, safely refusing everything;
they are BLOCKED collision controls, not existing unsafe acceptance. After recognition they must
reach source-overlap rejection. Three wrong database/profile controls pass today.
Existing Material/QuotationRequest semantics and collision controls must remain unchanged.

Physical drift probes start from a newly created literal consumer specimen and compare its actual
before/after catalog fingerprint. SQL mutations happen only in run-owned disposable PG18 shadows:
unvalidated Admission check; partitioned Admission relation; Employee effect INSERT rewrite rule;
Customer operation varchar_pattern_ops unique index. Extra stored generated columns are controls.
The four drift mutations currently succeed and leave the observed hash identical: genuine missing
physical-facet evidence, separately from profile recognition.

Literal expected-versus-actual fingerprints do not match for Invoice/EmployeeIdentity checks.
Those two compatibility failures are retained but NOT attributed to a production canonicalization
defect until independently reviewing check column ordering and PostgreSQL deparsed expression
forms. CustomerIdentity expected shape matches. No silent broad SQL normalizer is proposed.

Initial TRX `TestResults/consumer-profile-initial-red/consumer-profile-initial-red.trx`: 16 total,
12 failed/4 passed/0 skipped. Five physical/control cases were masked by baseline equality,
so that run is NOT proof of their drift failure. The updated test separates baseline shape
compatibility from actual before/after drift observation, preserving the initial diagnostic.
Categorized TRX `TestResults/consumer-profile-categorized-red/consumer-profile-categorized-red.trx`:
19 total, 12 failed/7 passed/0 skipped. Split: 3 genuine recognition RED; 3 blocked collision
expectations; 4 reached physical drift RED; 2 unresolved check-shape compatibility failures.
Final expanded checkpoint `TestResults/consumer-profile-final-red/consumer-profile-final-red.trx`:
23 total, 12 failed/11 passed/0 errors/0 skips. Failure categories remain exactly the same;
four added existing-profile recognition/collision controls passed. All build/test handles are terminal.

## Narrow runtime proposal for root review, NOT authorization

1. NEW consumer profile shape definitions plus manifest dispatch/selection only; immutable names,
exact database binding and source collision guard. Preserve existing profile meanings and signed
historical plans; never silently upgrade an old plan to current profiles.
2. Exact physical guard additions for reached validation/relation/rule/opclass gaps, with explicit
baseline metadata, fail-closed policy and versioning review. Changing the global schema hash or
inspection refusal can affect old signed artifacts: do not reinterpret historical checkpoints.
3. Independently resolve literal check-shape compatibility before writing new expected fingerprint
definitions. Do not accept unknown checks, weaken NULL handling or broaden equivalent-expression rules.
4. Add preservation proof: actual synthetic nonempty authority rows before/after source-only delta,
rollback/replay, exact ordered row digests and bigint sequence state. Existing locks include extension
tables before apply; no row copy, source comparison, reseed or deletion of these authority tables.

Recognition is not DDL capability. Existing repair explicitly permits only Material/QuotationRequest,
all-missing/all-present sets, and integer sequence validation. Do NOT simply widen it: partial
Invoice upgrades and bigint identity require separately reviewed, freshly signed exact missing-set
contracts and disposable pre/post evidence. No provider or authority activation follows schema creation.

Protected PR CI is required before operator execution. New schema fingerprints still require fresh
target review/signatures and proof; this does not grant rollover or new-baseline permission. Old
receipt/profile history remains immutable. No whole source owner or data parity completion is claimed.

## Historical test/design-only executed commands (superseded by checkpoints above)

From this owned worktree:
`dotnet build Legacy.Maliev.DataMigration.slnx -c Release --nologo -warnaserror`:
baseline and all subsequent builds succeeded with zero warnings/errors.
Existing focused manifest/repair suite: 8 passed, 0 failures/skips,
`TestResults/extension-baseline/extension-baseline.trx`.
New focus uses `dotnet test tests/Legacy.Maliev.DataMigration.Tests/Legacy.Maliev.DataMigration.Tests.csproj
-c Release --no-build --no-restore --filter FullyQualifiedName~ConsumerTargetExtensionProfileTests`
with uniquely owned absolute results paths and named TRXs above.
Full suite deliberately deferred until runtime authorization per root instruction; no full-green claim.

Scoped `dotnet format ... --include tests/Legacy.Maliev.DataMigration.Tests/ConsumerTargetExtensionProfileTests.cs`
completed successfully before the final zero-warning Release rebuild and final 23-case execution.
Verify-only scoped format exited zero. Git whitespace checks included both new untracked files
via `git diff --no-index --check -- NUL <file>`; zero whitespace defects (normal LF/CRLF notices only).
Unmodified Gitleaks stdin scanned both owned files with `--no-banner --redact`: no leaks/suppressions.
No existing tracked file changed. Full suite and broader final runtime static gates await root's
runtime decision; this intentionally failing test/design tree is not commit-ready.

## Final runtime candidate and executed acceptance (supersedes historical pending sections)

Base: protected main `dd225cd8d1cc76f908257fbc41098822ea705e91`; no commits or external writes.
All three consumer profiles/four tables, exact check aliases, strict Customer identity definition,
validated native recovery identity inventory and reviewed requested collation admission are now
implemented. No old test, repair/CLI/DDL authority, signed hash representation, source disposition,
operator fence or workflow changed. Empty shadows retain the prior verified-empty contract;
collation-only shadows fail closed. All raw genuine RED and fixture/implementation diagnostics
remain preserved, including the later native Invoice and Material/empty-shadow discoveries.

Executed from this worktree with Release and owned disposable fixtures:

| Gate | Actual result | Artifact SHA256 |
| --- | --- | --- |
| Fresh solution Release (`-warnaserror -p:UseSharedCompilation=false`) | 0 warnings, 0 errors | Terminal command evidence |
| Combined consumer profile/preservation/approved extension/recovery focus after EOF-only normalization | 127 passed, 0 failed/skipped | `186373bcf01d4747285b9bc03c4d58d42907cb036352c3a59ef1e6ad66e8f7a1` |
| Previously failing actual all-23 SQL/PG/native resume/final-console pipeline | 1 passed, 0 failed/skipped, 4m56s | `f12d4fb6b73a786f29a9f7c687ffe93b53434a82dc3e38d6c1cd8f8d40cadc32` |
| Unfiltered native suite with coverage | 1565 passed, 0 failed, 3 pre-existing skips, 1568 total, 4m29s | `4fd3c05c341eaf1aef6169c956661811c7ed96d06cd4ada117bdfe09b7eab18e` |
| Unfiltered SQL adapter suite with coverage | 178 passed, 0 failed/skipped, 6m48s | `ad7060e777dd4f5a412ff015037602c388ec99d155aea068e1803dc1d59401e1` |

TRX directories under owned `TestResults` respectively: `consumer-frozen-post-whitespace-focus`,
`consumer-real-pipeline-frozen`, `consumer-frozen-native-full`, `consumer-frozen-sql-full`.
The native tools are PostgreSQL 18.1 `C:/Program Files/PostgreSQL/18/bin/pg_dump.exe` and
`pg_restore.exe`; `MALIEV_RUN_PG18_SNAPSHOT_INTEGRATION=1` enabled both runs,
`MALIEV_RUN_SQLSERVER_INTEGRATION=1` enabled the real SQL run. Process-local persistent snapshot
connection/shadow and owner-only Issue94/full-schema live-proof flags were removed, not fabricated.

Native three unchanged skips: Issue94 owner-input repair proof; fresh-live exact-23 target-extension
repair proof; opposite-platform Windows authority control. These remain omitted acceptance gates.
No production-derived snapshot, hosted pipeline, operator authorization, persistent migration,
provider, cloud or deployment acceptance is established by disposable fixtures.

Unexcluded raw per-run coverage is deliberately not merged or waived:
native `88aa0d41-9e30-4064-b597-22a06dd192b5/coverage.cobertura.xml` reports DataMigration 85.80%,
Console 58.26%, SqlServer 0%. SQL `6072ab70-0efc-45ae-b747-c4b004fdb278/coverage.cobertura.xml`
reports SqlServer 77.81%, DataMigration 37.68%, Console 7.47% (shared test assembly 2.01%).
There is no blanket 80% quality waiver or whole-owner completion claim.

Whole solution verify-only formatting passed. Current NuGet.org vulnerability audit reported no
vulnerable direct/transitive packages in all six projects. Scoped Gitleaks stdin readback of all
ten owned files reported no leaks. Git tracked whitespace checks passed; independent untracked
file checks caught and removed only one trailing blank EOF line in each of Shapes, Compatibility
and PreservationTests after full-suite completion. No semantic/assertion change occurred; a fresh
Release rebuild and combined focus were rerun after that mechanical normalization. `--no-index`
file-vs-NUL exit 1 means differing files, not a whitespace error; final output was independently
checked for whitespace diagnostics rather than misclassifying that exit code.

Candidate is for independent root review and protected head/main CI, not persistent execution.
