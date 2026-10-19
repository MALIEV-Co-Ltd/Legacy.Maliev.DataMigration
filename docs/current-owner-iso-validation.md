# ISO repair validation checkpoint — October 19, 2026 (Bangkok)

This is source preparation. Persistent schema changes, row refresh, production readiness and local/production data parity remain unverified. Historical preparation documents describe their original slices; this checkpoint records the current combined worktree.

## Changes

- Bind ISO admission to the reviewed exact local 26 / production 49 non-template database keys. Independently bracket full fleet captures with system-bound complete catalog observations, including all 51 production catalog entries and template flags.
- Preserve the four distinct Auth, Customer, Country and Material operand-owner purposes. No change to historical signed source profiles, row authority, immutable receipts or persistent data.
- Add signed negative inventory cases for missing, extra, substituted, case-changed and historical 53-entry inventories, rejecting before source callbacks or reservations.
- Correct an analyzer code fix that inserted `NotImplementedException` arms into the review and authorization switches. Explicit persistent and native-bootstrap arms retain the original claim strings. Existing scope validation still rejects undefined admission values. No analyzer suppression or threshold change.

## Completed checks

- Release build after formatting and the switch correction: zero warnings, zero errors (`0b8a6325b8524cf99cbca94887043e0c`).
- Focused ISO/console/admission/consumer/custody tests: 188 passed, zero failed, zero skipped (`fc8340dce86b456ab9b159218d3d3316`).
- Full Core info-severity formatter verification: passed (`a95b18c7fd93472280be5aef89af61a5`).
- Test-project formatter application completed with its scope guard; only original task-owned changed/new source files were eligible (`f7a0f7c2a5cc4f4dbec55ecf459767d8`). This is not a separate successful verification pass.
- Local complete candidate source scan: 640 files, zero findings (`e38514ca1d014678ae65b2b605f68868`). The diagnostic uses the actual finding count; its configured zero process exit is not a passing security gate. The source copy was removed. Required hosted scanning remains mandatory.
- `git diff --check`: passed.

## Incomplete checks and actual resource failures

- The pre-correction focused test attempt was refused before process startup below the unchanged 3 GiB admission threshold. No failing-test reproduction is claimed for the formatter regression; the defect was found by source review.
- The broader consumer/extension/reconciliation regression run was interrupted at the unchanged 1 GiB host free-memory floor (`cba2f0253251464e823215c15fe4d04f`). There is no complete suite result.
- Full Console formatter verification was interrupted at the same runtime floor (`894e56c736eb4ef78adebd975e92f6c0`). Full Tests verification remains not run after application. Neither is marked passing.
- The interrupted regression left no current-run Testcontainers or .NET workers at independent observation. An unrelated Redis container created October 1 was preserved.

## Integration with protected main `caf6ad3414ca860518674e919510a778efd236a7`

The original candidate is commit `945356d53ed977785d3099300c6042e249850106`. A normal merge of current main preserves both command families, all four operand-owner purposes and the patched PKCS package. Auth custody tests remain in `WindowsFocusedCustodyImportTests`; the independent ISO cases now use `WindowsIsoFocusedCustodyImportTests` to preserve both sets.

The first integrated test compilation hit `System.OutOfMemoryException` under the unchanged 512 MiB child heap cap. The process observer also failed; every known worker and both initially unobserved PIDs were independently absent afterward. A retry with `DOTNET_PROCESSOR_COUNT=1` only in the owned helper environment passed the complete Release build with zero warnings/errors (`0b88468399794734876394aa063be6a0`) and 656 combined focused tests, zero failures/skips (`2a75a1f26b55481b81aa55afc268cc51`). The heap cap, host admission/floor and owned RSS guard were unchanged. Full-suite, formatting, native and hosted results must still be recorded separately; the original 640-file scan does not certify the merged tree.

## Remaining gates

### October 20 hosted failure correction

Protected main `caf6ad3414ca860518674e919510a778efd236a7` passed required CI `39157184621`. PR head `ef77894c7fded0bb8e8ddb530462d4ed1dd13f63` failed required CI `39161504435`: SQL tests 196 passed / 1 failed / 1 skipped; Core tests 2705 passed / 2 failed / 178 skipped. Both Release builds had zero warnings/errors and the secret scan was clean.

Two negative tests still classified enum value 4 as unknown after ISO selection 4 was added. They now exercise undefined value 5 and assert it is undefined. SQL constructor acceptance and the exact Country/Material profile mappings explicitly cover ISO selection 4. The pure storage test now records definition artifacts only when its ledger is configured, retaining every storage assertion. A configured invalid ledger still throws; the genuine precursor reader still requires all 17 authenticated cases, their held entry/exit artifacts and stdout markers. Ordinary unit execution without a ledger emits no definition-proof marker and grants no proof authority.

The corrected local Release build was NOT RUN: admission refused process startup below the unchanged 3 GiB minimum (`ba2f5ef2d1b34255a3ba369491405091`). Consequently local focused tests, full suites and formatter checks are NOT RUN for this correction. The owner-approved draft-before-validation exception applies; require the replacement exact-head hosted build, full SQL/Core suites, formatter/static/security/coverage and compatibility checks before accepting the fix or merging. No production or persistent-local database action is authorized by this test correction.

Fresh owner observation found clean Country head `ea5930bd13cdb0dd5d8ab9c60a85fb90c8dfe0f7` and Catalog head `f78e5b2b2d3c72ce8dbc13ab40dbcfaa58215339`. Git comparisons confirm both complete Data directories are identical to the previous heads, and all six actual file hashes still match. Update only the current overlay head pins; retain the original signed row-profile identifiers and every file pin. Two added negative cases explicitly reject the old heads. The attempted red build was interrupted by the unchanged 1 GiB memory floor before tests; no observed red result or post-repin test pass is claimed. The 656-pass result above predates this repin.

Integrated full Core formatting verification passed (`8c7547b8b91b4c74806ffef38b2c0b2d`). Console verification was interrupted at the 1 GiB floor (`72757bd2d94d43afbdda3f645decc753`) after reporting one whitespace defect in `CurrentOwnerIsoIntendedRuntimeReadback.Read`. That block has been expanded; a fresh successful Console check is still required. Tests formatting and the complete regression suite remain incomplete. Do not claim the final repinned tree has passed the earlier build/tests/scan.

Complete Console and Tests formatter verification, relevant regression suites, current-main integration, review and exact-head hosted Release/tests/static/security/coverage gates with unchanged policies. Before protected merge, require every repository protection and check, then verify the exact merged-main SHA.

Genuine current PostgreSQL 18.1 components, target-shaped closed proof, recovery/decrypt-and-restore proof, remaining Auth/Customer/ContactRequest prerequisites, fresh source capture and separate signed target-specific plans/authorizations remain required before persistent effects. An earlier PostgreSQL 18.4 feasibility result is not a current production proof. Do not use this checkpoint or a source merge as database execution authority.
