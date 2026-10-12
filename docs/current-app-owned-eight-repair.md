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

## Execution connection and host observation corrections

The executor closes its per-database backend after same-session committed
readback and before global preservation opens an independent backend. The
zero-other-client policy remains enforced. A native Core-executor regression
uses actual PostgreSQL policy/catalog observations through a separate connection;
it also verifies two retained receipt payloads. The sink and source/custody
callbacks in that component fixture do not establish closed-Console acceptance.

The production observer now uses its existing host factory. A Windows fixture
constructs the actual Console environment with owner-protected token/CA files
inside held run custody. It verifies constructor compatibility, not a production
API request or persistent admission. TLS and endpoint guards remain unchanged.

Both corrections built with zero warnings/errors and passed 18 focused local
tests, including the Windows constructor fixture, before formatting. The prior
published head passed hosted Core (1,829 passed, 90 skipped) and SQL Server
(196 passed, one skipped) suites but failed formatting. Formatting was applied
in separate bounded Core, Console and test project passes; fresh build/tests and
exact-head hosted validation are required for the resulting source.

## Retained receipt recovery remains an execution blocker

The current Console apply loop starts its receipt chain from zero. It does not
validate and resume a retained committed database receipt, and the executor
checks the original preimage before classifying an already-created table set.
After partial commit or lost acknowledgment, replay can therefore fail its
preimage check or collide with immutable create-new receipt filenames. Do not
remove, replace or ignore those receipts, or treat a fresh manual baseline as a
recovery attestation. A signed reconciliation path must verify the retained
chain, actual current preservation and schema, and commit classification before
any continuation. Uncertain outcomes remain unresolved until that path is
implemented and genuinely exercised. Persistent execution is not accepted.
After formatting, the complete Release solution build again passed with zero
warnings/errors and all 18 focused local tests passed without skips. A subsequent
format-verify attempt did not start because the unchanged 3 GiB host-free admission
guard failed. Full local suites remain not run to completion; exact-head hosted
validation remains required. All test helpers exited and disposable containers
were absent after the run.

## Exclusive HBA component fixture

The native executor/policy regression now runs with both ordinary fixture HBA and
an actually installed exclusive HBA file in its own bounded disposable PostgreSQL
container. The exclusive variant verifies ordinary login rejection (SQLSTATE 28000)
after reload, permits the bound maintenance role, detects a second operator client,
and completes the real Core create/readback/global-preservation path. Release build
passes with zero warnings/errors; all 19 focused tests pass with zero skips. The
whole test project formatter completed and the formatted solution rebuilt with zero
warnings/errors. This does not supply closed Console/source/custody acceptance or
retained-receipt recovery. Hosted full-suite/format compatibility checks still apply.

Independent recovery review selected a separate signed read-only reconciliation
followed by a fresh operation UUID and fresh authorization. Historical claims and
receipt chains must be authenticated at their recorded times without renewing
permission. Actual states must match original-before or an authentic prepared-after
snapshot, preserve the complete original catalog/rows/sequences, retain the exact
final schema/object closure and empty new tables, and form an applied prefix.
A create-only predecessor-to-successor reservation must prevent replay or competing
successors. Fresh admission binds the reconciliation and observed baseline; applied
databases produce signed read-only skip observations. Changed/expired maintenance
installation requires an independently reviewed exact role/catalog transition,
since pg_authid is part of complete preservation. These are implementation and
native/closed-Console proof prerequisites, not permission granted by this document.
## Repair-specific IPv4 transport

The approved GKE API is an IPv4 endpoint. Only the internal current-app-owned
repair composition accepts that endpoint form; general host factories remain
DNS-only. Protected trust files, TLS name validation, custom roots, server-auth
EKU, disabled proxies and redirects remain required. The repair handler additionally
requires an exact iPAddress SAN: Windows platform verification alone accepted a
numeric DNS SAN in the first regression run (43 passed, one failed). Invalid IP
SAN lengths, illegal GeneralName tags and trailing DER reject. Signed claim
validation and the signed target-pin hash precede observation/token transmission.

The corrected Release build has zero warnings/errors; all 49 focused native,
policy, construction and real TLS tests pass without skips. This proves transport
and component behavior, not closed Console persistent execution, retained-receipt
recovery, source refresh or target parity. A formatter attempt hit the unchanged
host memory floor and all owned processes exited; subsequent Core and test-project formatting completed, Core verify-no-changes
passed, and the formatted Release build again passed with zero warnings/errors.
Hosted exact-head full-suite/format compatibility checks remain required.
