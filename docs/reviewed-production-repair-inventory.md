# Reviewed production repair inventory

Source-only inventory correction; no production execution authority.

## Immutable discovery

Protected-main base: `2311152110776ad2407ba5cb7da729972164b001`.
Genuine report: `outputs/production-customer-independent-inventory-b546b5e4a57149b19d54e1888e551725/report.json`.
Report SHA256: `fbfb1ceb37a4da27dd396b0978032320c62ebde313e69938ab91d55c94d8b703`.
Observed UTC: `2026-10-13T04:45:03.9553980+00:00`.

The complete catalog contains 51 names: 49 connectable non-template databases and exactly template0 (template=true, connections=false) / template1 (template=true, connections=true). The 49 include all 23 active databases, Auth, postgres, legacy_migration_control and all 23 exact historical shadow names. The earlier narrative count 53 was incorrect. The original PostgreSQL JSONB inventory digest is a different encoding from the existing C# baseline digests; none is substituted or rewritten.

`ReviewedProductionRepairInventory` fixes the complete ordinal name/flag profile and exports defensive read-only copies. Missing, renamed, substituted, extra, case-aliased, duplicate or connection-disabled non-template databases reject. Templates never enter the preservation baseline map. A future catalog change requires a new reviewed profile, not automatic adoption. Local authority remains the separate exact 26-name profile (23 active + Auth + postgres + legacy_local), with standard template flags.

## Guarded integration

Retained31 and V3 admissions replace their erroneous production count check with exact profile-key validation. Existing source plans, global hash encodings, per-database hashes, target observation hash, signed reviews/authorizations, run binding, fresh operation reservation and receipt semantics remain unchanged.

Their Console collectors observe ALL pg_database names and flags before and after each complete fleet capture, through separate fresh read-only repeatable-read postgres connections. Each observation first rechecks the existing actual custody/run/target topology and ordinary-access rejection, then the actual installed maintenance policy and pinned pg_control_system identity. The observer itself additionally requires the actual transaction read-only setting and exact signed system pin. No public callback or marker substitutes for the native observation. Every baseline database is still captured via its existing fresh connection and intern pool; no giant byte-array cloning or capacity waiver is introduced.

The existing scope's TargetObservationSha256, Target.SystemIdentifierSha256, target generation and RunBindingSha256 already bind this composition under signed review; no new authority contract or historical hash mutation is needed. Catalog queries use explicit complete flags rather than filtering away non-connectable databases. Initial and final complete inventories must both equal the immutable reviewed profile.

## Ownership and other production prerequisites

This slice deliberately leaves owner fences unchanged. V3 `PostgreSqlCurrentAppOwnedV3Repair.cs` selects production owner postgres (line107), uses it for native before/candidate/readback and ALTER TABLE OWNER (line141). The Console collector supplies the same owner; `CurrentAppOwnedV3AdditivePreservation.cs` line23 rejects any owner outside legacy_local/postgres and verifies actual relation/sequence owners. Genuine production owners for Invoice/PurchaseOrder/Quotation and the precise new-relation owner grants must be independently observed and reviewed before a separate narrowly pinned owner contract can be implemented. Globally replacing postgres or accepting an arbitrary supplied owner is unsafe.

Retained31 provider/preservation/Console contain no postgres/legacy_local relation-owner coercion or owner-changing DDL; their complete catalog preservation remains exact. Production role/HBA/exclusivity, fresh source/owner plans, actual PostgreSQL18.1 compatibility, backup/restore, closed Console proof, immutable receipt/recovery gates and current capacity remain separate prerequisites; this inventory correction alone cannot admit production execution.

Customer/Auth/ISO/archive candidates retain their separate wrong53 gates and require subsequent reviewed use of this inventory profile. Customer production owner is genuinely legacy_customer_owner, not postgres, and must be independently pinned with all required table/sequence ownership closure. Disposable fixture postgres ownership is not evidence of production ownership.

## Validation plan and truthful status

Root ran Release build with zero warnings and zero errors (run d84d0d9618574554ae094b8881cc398a) and 108 focused tests passed with zero failures/skips (run b78d35264b5a44beb068a67f6c906695). The first build disclosed four native-fixture compiler errors, which were corrected; the current build includes that corrected fixture. Full suite and hosted validation remain not run. Native execution did not start: unchanged 3GiB memory admission refused run aa46e06d88704a2bb5c78f806059c5ef. Automatic solution formatting began but was aborted by the unchanged 1GiB host-memory floor in run 5bd366487bb242c4a997fa89721515c0; formatting is not passed. All known owned workers exited with no reported cleanup failure. No persistent database effects, signing material, commit or publication occurred for this slice.

1. Release build (zero warnings/errors) under unchanged resource admission.
2. Focused ReviewedProductionRepairInventoryTests, CurrentAppOwnedRetained31AdmissionTests and CurrentAppOwnedV3RepairAdmissionTests; verify genuine51/49 profile, local26, immutable exports, signed malformed fleet and actual-system/read-only binding negatives.
3. Existing retained31 provider native regression: its preserved26th disposable database is now correctly named legacy_local instead of an arbitrary extra; no effect/owner/HBA semantics changed.
4. Native/closed Console inventory boundary tests: unexpected disabled database; absent/renamed control or shadow; template flag drift; complete-catalog mutation during fleet capture; wrong system/topology/run; confirm initial/final connections are independent and failure precedes effects. The new native fixture supplies 10 local26 and 7 genuine49 observer cases on bounded, separately owned disposable storage; execution is not yet claimed. Those observer cases do not prove closed Console custody, cloud, installed-HBA or full-fleet collector composition.
5. Relevant suites, full formatting/static/security/hosted checks on the exact head and exact protected-main follow-up.

No resources were created, so no resource remains to clean up.