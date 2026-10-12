# Guarded eight-table repair candidate

This draft adds a fixed create-only path for the eight application-owned tables
in Customer, Order and Upload represented by `CurrentConsumerSchemaV2`.
It does not refresh rows or establish local-versus-Kubernetes parity.

The Console requires a clean, synchronized, exact-green protected main, protected
Windows run custody, distinct signed review/authorization/receipt roles,
target-specific identity and maintenance pins, and retained hashes of independent
native, recovery and role-transition reviews. The path rechecks installed policy,
locks existing relations and catalogs, preserves existing rows and full sequence
tuples, publishes prepared evidence before commit, and requires committed readback.
Uncertain commit or readback results never issue a success receipt.

Catalog tuple identities are hashed before retention: statistics and descriptions
may contain application data. A native disposable regression fixture deliberately
puts a synthetic private value into PostgreSQL statistics and verifies it is absent
from serialized preservation evidence while repeat captures remain identical.
Identical non-OID catalog tuples retain distinct digest/occurrence keys. The same
fixture verifies that removing or adding an existing dependency occurrence fails
preservation; duplicate tuples are not discarded.

## Execution gates still required

This source candidate has no persistent execution acceptance. Admission unit tests
and the catalog privacy fixture do not supply a genuine eight-table runtime proof.
Genuine installed-role/HBA/endpoint, create-and-readback, preservation, rollback,
lost-acknowledgment and recovery cases remain required before persistent DDL.
The retained 31-column collation operation is explicitly rejected by this issuer.
Auth archive commands and native PostgreSQL nullable-unique fingerprint changes
are separate prepared work and are absent from this slice.

The October 12 consumer audit also found newer contracts outside this fixed set:
purchase-order child receipt tables, quotation invoice-completion operations and
invoice ownership columns. Current source planning and reconciliation must account
for those separately. The disabled customer-document registry is separate from
ordinary Upload migration, and consolidated Catalog ISO changes cannot be applied
to retained Country rows by assuming an empty-table precondition.

## Validation status at draft publication

The parent integration rebuilt with zero warnings and errors before the catalog
privacy correction. Its full local Core suite was not completed: the unchanged
1 GiB host-memory floor aborted two attempts, including one admitted above 4.6 GiB.
All recorded owned processes exited and no test containers remained.

This extracted slice and its new native regression have not been built or tested
locally. Publication uses the owner's October 10 draft-PR validation-order exception.
Required follow-up is exact-head hosted Release build with zero warnings/errors,
focused tests, full relevant suites, formatting, secret/static checks and PostgreSQL
18 compatibility checks under unchanged policies. A green draft alone does not
replace the genuine execution proofs above or accept migration completion.

## Catalog multiplicity correction validation

The extracted correction builds in Release with zero warnings and errors. All 13
focused repair and native catalog privacy tests pass with no skips. The local full
suite remains not run to completion because of the recorded memory admission
failures. The local formatting check reported three whitespace diagnostics (fixed)
then exhausted its process memory budget; formatting is not a local pass.
Exact-head hosted full-suite, formatting and PostgreSQL compatibility validation
are required before review acceptance. No persistent database writes occurred.

## Native fixed DDL fixtures

The new three-database fixture covers literal eight-table DDL, native schema
fingerprints, exact object closure, complete catalog/retained rows/sequence evidence,
commit readback, successful rollback and rejected retained-row mutation rollback.
It does not exercise the closed Console issuer, installed maintenance-role/HBA
checks, custody, prepared receipt publication or commit acknowledgment loss; those
execution gates remain required. Local validation of this addition is not run:
the unchanged 3 GiB host-free admission guard refused the build before starting
a child. Exact-head hosted validation is required under the draft exception.
