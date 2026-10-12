# Historical eight-table receipt authentication

This internal component authenticates supplied exact historical review,
authorization and receipt bytes. It grants no execution permission and has no
Console dispatch, live observer, database connection, signer or successor issuer.
Expired claims are checked at their recorded authorization issuance instant only;
that instant must never be passed to a runtime permit.

Strict canonical JSON rejects ignored, duplicate and missing required fields.
Receipt file names, original operation, authorization hash, before hashes, signing
role, chronology and the complete supplied chain are authenticated. Input byte
arrays are copied before decoding and hashing. A PII-free manifest digest retains
every supplied receipt independently of input ordering.

The exact executor's publication failures are retained conservatively:

- A durable prepared file whose publication acknowledgment failed may have a
  precommit failure sibling linked to the previous database receipt. That precise
  form is flagged; normal acknowledged publication links its terminal to prepared.
- A committed file may coexist with an Uncertain publication-failure receipt.
  Both must match prepared, hashes and chronology. The transcript remains
  Uncertain, preserves both files, and prohibits any later database attempt.
- Authentic late receipt timestamps are recorded outside the authorization
  window. Authentication does not assert that execution was timely or authorized.

Storage completeness is not proved by a caller-supplied collection. Closed custody
must independently enumerate and retain all original artifacts before reconciliation.
Actual native before/after state, complete preservation, final schema/object closure,
empty new tables, current role/HBA/custody/source acceptance and fresh independent
signed reconciliation remain required. A fresh successor must reserve the original
operation once, use a new UUID and authorization, and bind the reviewed reconciliation.
No old executor may be replayed or claim expiration extended.

## Validation at draft publication

Independent static review found three executor compatibility gaps, all addressed
above with regression cases. Intermediate revisions compiled in Release with zero
warnings/errors. The final revised build and tests were not run: two attempts were
rejected before launch by unchanged host-free admission below 3 GiB. No owned
process started in either rejected attempt. The owner-approved migration draft
validation-order exception permits reviewed publication for hosted follow-up.
Exact-head Release build, focused history regressions, full affected suites and
format checks remain required before protected merge. Component tests are not
native publication-interruption, closed Console, storage-completeness, live-state
or successor execution proof. Persistent database execution remains unaccepted.

## Subsequent local validation

After capacity recovered, the revised solution built in Release with zero
warnings and zero errors. All 70 focused history, repair, native policy, catalog
and TLS tests passed without skips. Complete Core and test-project formatting
finished, Core verify-no-changes passed, and the formatted solution rebuilt with
zero warnings and errors. Every recorded task-owned child exited. Exact-head
hosted full-suite and PostgreSQL compatibility checks remain required. These
results do not establish storage completeness, live-state reconciliation or a
fresh successor permit.
