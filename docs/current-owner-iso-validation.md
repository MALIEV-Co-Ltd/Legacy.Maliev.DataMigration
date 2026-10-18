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

## Required continuation

Complete Console and Tests formatter verification, relevant regression suites, current-main integration, review and exact-head hosted Release/tests/static/security/coverage gates with unchanged policies. Before protected merge, require every repository protection and check, then verify the exact merged-main SHA.

Genuine current PostgreSQL 18.1 components, target-shaped closed proof, recovery/decrypt-and-restore proof, remaining Auth/Customer/ContactRequest prerequisites, fresh source capture and separate signed target-specific plans/authorizations remain required before persistent effects. An earlier PostgreSQL 18.4 feasibility result is not a current production proof. Do not use this checkpoint or a source merge as database execution authority.
