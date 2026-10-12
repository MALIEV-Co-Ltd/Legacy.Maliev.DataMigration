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
- Invoice: nullable `FinancialOwnershipJson` and `EmployeeCompletionJson` appended
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