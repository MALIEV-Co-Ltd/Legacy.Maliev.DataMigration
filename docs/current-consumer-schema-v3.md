# October 2026 consumer schema candidate

`CurrentConsumerSchemaV3` is an explicit opt-in target profile. Historical defaults,
V1 and V2 keep their profile labels and physical fingerprints. The exact 23 SQL
Server databases and 100 source table projections remain unchanged. Mixed V2/V3
inventories are rejected rather than treated as a coherent approved profile.

## Contracts

The companion `current-consumer-schema-v3-source-contracts.json` records clean
consumer repository commits and SHA-256 digests of the actual migration sources
inspected on October 12. The new target-only objects are:

- PurchaseOrder: immutable `OrderItemCreateReceipt` and
  `PurchaseOrderFileCreateReceipt`, with their four-column digest/operation keys,
  operations 3/4, version 1 bindings, complete response and five digest checks.
- Quotation: `QuotationInvoiceCompletionOperation`, including its unique quotation
  index and nullable claim/lease fields. Its text decision version is separate from
  the source Quotation table's timestamp overlay.
- Invoice: nullable `OriginIssuer`, `FinancialResultJson`, `FinancialOwnershipJson` and `EmployeeCompletionJson` appended
  to `InvoiceCreationAdmission`. No defaults, historical authority or backfill.

New text fields use explicit `C` under the existing V2 policy. Source row comparison
does not include these application-owned fields or tables; complete extension
content, null counts, relationships and sequence evidence remain mandatory.
The approved quotation outbox archive/adoption mapping and decision-version overlay
continue under V3, including the explicit adopted outcome text collations.

PostgreSQL adds grouping parentheses when deparsing the receipt checks. Only exact
table/name/column tuples and the pinned source/native predicate pairs are normalized;
different versions, columns or check names remain distinct.

## Admission limits and validation

This profile alone supplies no repair, delete, archive, maintenance-role or row-write
authority. No persistent database was changed while preparing it. Existing fixed
eight-table repair remains a separately admitted V1-to-V2 operation. V3 additionally
requires reviewed preservation-safe repair, genuine pinned owner EF comparison,
disposable execution proof and fresh target-specific admission before use on either
persistent target. Full schemas and application-owned state must be reconciled after
the subsequent dual-target row refresh.

The first local Release build passed with zero warnings/errors. Eight focused tests
initially produced five passes and three failures: fixture equality, missing overlay
evidence and native receipt predicate representation. The corrections are under
validation; those initial failures are not passing evidence. Local resource guards
remain unchanged, and a later build was refused below the 3 GiB admission threshold.
Exact-head hosted full suites, formatting, static/secret and PostgreSQL compatibility
checks remain mandatory before protected merge. This is a draft candidate rather
than migration completion.

After correction, Release builds with zero warnings/errors and all 10 focused
tests pass with zero skips, including the three native PostgreSQL schemas.
Whitespace validation found one indentation diagnostic, now corrected. Its rerun
was blocked by the unchanged 3 GiB memory admission floor, so formatting is not
yet a passing local check. Full suite remains not run locally under the recorded
memory constraint; this publication uses the owner's October 10 draft exception.

## Independent review regression follow-up

The review found two coverage gaps: coexistence of both approved outbox
archive/adoption mappings with the quotation overlay/completion extension, and
nonempty retained application-owned state. The follow-up tests pin the physical
archive/adoption/overlay contracts, compare nonempty extension evidence and reject
changed retained content. The test project formatter completed on the resulting
source. Its new Release build was not run: the unchanged 3 GiB host-free admission
guard refused the child before startup. The prior ten-test result does not validate
this new test source. Exact-head hosted build, focused/full suites, formatting and
PostgreSQL compatibility follow-up remain mandatory under the owner's October 10
draft publication exception. No persistent writes or additional helpers occurred.
The follow-up source subsequently rebuilt with zero warnings/errors. Full Core
project formatting corrected the new manifest's style rules without modifying
unrelated files. New focused tests still did not run: two admission checks refused
startup below the unchanged 3 GiB host-free threshold. Hosted validation of this
exact formatted head remains required; the earlier ten tests remain prior evidence.


## October 12 selection regression correction

Hosted validation on b892104 found two old negative cases treating enum value 3
as unknown; value 3 is now the explicit V3 opt-in. Negative coverage uses 4, while
SQL constructor coverage explicitly accepts V3 without opening the source.
Historical wire tests and defaults are unchanged. The corrected solution builds
in Release with zero warnings/errors, and all 26 local V3/profile-selection tests
pass without skips. Separate SQL constructor tests were not run: unchanged 3 GiB
host-free admission rejected launch with no owned processes. Required follow-up is
that exact-head hosted SQL test lane, all Core tests and formatting, before merge.
This publication uses the owner-approved migration draft validation-order exception;
it is not schema execution or source/target reconciliation acceptance.

## October 12 actual owner migration correction and proof

Actual full InvoiceDbContext Up exposed two previously omitted October 5 fields,
OriginIssuer (nullable character varying(512)) and FinancialResultJson (nullable
text). V3 now appends those before FinancialOwnershipJson and
EmployeeCompletionJson, for 13 InvoiceCreationAdmission columns. All four fields
have explicit C collation and no default or historical backfill. V1/V2 contracts
remain unchanged.

The corrected solution rebuilt in Release with zero warnings/errors. All 26 Core
V3/selection tests and all six SQL constructor tests passed without skips; complete
Core and test-project formatting ran. Hosted validation of the earlier 1b2e5a9 head
passed Release, 1859 Core tests and 197 SQL tests, but failed manifest formatting;
that earlier head was not accepted. Required exact-head full validation remains a
merge gate for this correction.

A fresh off-repository helper referenced the actual clean pinned application Data
projects, ran every owner Up migration on three isolated PostgreSQL 18.4 databases,
and compared the selected extension components. PurchaseOrder child receipt tables
matched without normalization. Invoice's two extensions and Quotation's completion
extension matched only after explicit C normalization of their inherited text
collations; exact noncollation shapes were verified first and all normalized tables
were empty. Invoice normalized 20 columns and Quotation six. The original owner
schema is therefore not claimed to match unmodified. The completed run was
`d36fa4c64acd43f08dba5ae57a20bce1`; its container was removed, ephemeral credentials
deleted and owned processes exited before acceptance. This proves selected extension
components only, not whole owner schemas, populated preservation, closed Console
execution, persistent repairs or data parity.
