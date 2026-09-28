# Reviewed production collation contract (#184, #94)

The authenticated read-only catalog from 2026-09-28 09:28:53–09:31:48 UTC
observed 304 explicit `public.legacy_ci_as` column collations in the canonical
23-database PostgreSQL target. Its owner-only file SHA-256 is
`7e6bf5a6efe0ada97c46b262c2f50fbe18790a94ab1e5f52e8af224788c7a316`.
The exact sorted `database|schema|table|column` inventory has SHA-256
`f93642d9fb2a2516b1032e1b4d35ac0c36defdd21709d73d5a8b442beff7fbc5`.
The manifest lists 297 SQL Server sourced columns and seven approved Material
target-only columns. No other column receives this collation implicitly.

The target collation is PostgreSQL ICU `und-u-ks-level2`, nondeterministic,
with its recorded provider version matching the installed version. The source
uses SQL Server `SQL_Latin1_General_CP1_CI_AS` and `Latin1_General_CI_AS`.
Read-only synthetic comparisons found an important difference: both SQL Server
collations equate `ß`/`ss`, `œ`/`oe`, `æ`/`ae`, and `a ` / `a`; the target does
not. The approved target contract preserves the existing production collation
and makes it explicit in the generated schema plan. It does not claim
cross-engine semantic equivalence. Future writes involving these values can
behave differently; a guarded row delta must still prove key and row parity.

The bootstrap creates the named collation only when a reviewed column requires
it, and verifies ICU provider, locale, nondeterminism, and current provider
version before creating tables. The schema fingerprint still checks every
column's exact collation identity and the existing whole-database gate remains
strict. The manifest changes no production data or column definition.
