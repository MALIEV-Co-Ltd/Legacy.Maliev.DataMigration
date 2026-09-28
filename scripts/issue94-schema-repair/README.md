# Issue #94 exact-23 schema repair

These 20 SQL files encode the reviewed additive target repair: 18 preserved
`sysdiagrams` tables, Quotation's archive and adopter, the Request qualification
audit, 11 missing service columns with their indexes and check, and 12 timestamp
defaults. The `manifest.json` hashes the exact SQL bytes. The files contain no
application rows or credentials.

Run them only through `tools/Issue94SchemaRepair`. The runner binds the fresh
exact-23 source plan to an authenticated full production catalog, verifies the
CloudNativePG system identifier and exact per-database preimage inside a
serializable transaction, checks the manifest bytes, and requires the expected
final structural fingerprint before commit. It checks the final fingerprint
again on a new connection. A database already at the exact final fingerprint
is an idempotent replay. An unknown or partially applied shape stops.

The two Identity databases also require a fresh owner-only
`source-lockoutend-exact.json` companion capture. The runner checks every
captured row against the runtime timestamp's UTC microsecond projection and
stores the seven-place source value in
`legacy_migration_internal."AspNetUserLockoutEndExact"`. That schema is excluded
from the canonical fingerprint; its rows must be verified separately.

The reviewed production preimage was captured from cluster
`maliev-legacy/legacy-postgres-main` (UID
`6e0426c3-3426-4d6d-aa9b-64228f0af20f`) on 2026-09-28. The source plan
digest is `bbacf159a026d958cc604489ffd4272697d18035953db91c4f0b9bc592412fc7`.
The runner accepts only the `maliev-legacy` production authority and never
addresses the `maliev` namespace. A fresh catalog and an independent restore
proof are required when either the authority or source plan changes.

The additive DDL creates empty missing tables. The separately signed source
row delta copies their historical rows and reconciles the full 23-database
data set. Never replace, truncate, or recreate a production database to use
these scripts.
