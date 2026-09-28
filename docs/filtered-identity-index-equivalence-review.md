# Filtered Identity index equivalence (#185)

The 2026-09-28 read-only production catalog showed four index facets on
`CustomerIdentity` and `EmployeeIdentity`: `AspNetRoles.RoleNameIndex` and
`AspNetUsers.UserNameIndex` in each database. The source plan asks for a unique
index on one nullable normalized name with an exact `IS NOT NULL` filter.
PostgreSQL has the same unique index and filter with `indnullsnotdistinct = false`.
The plan fingerprint previously expected `true` for every unique nullable key.

The filter removes all NULL keys from this one-column index. The PostgreSQL
NULLS setting therefore cannot affect which rows collide. A disposable
PostgreSQL 18 test confirms that two NULL values coexist, duplicate non-NULL
values fail, and the expected index fingerprint matches the observed catalog.
For unfiltered indexes, composite keys, and filters on other columns, the
existing NULLS NOT DISTINCT requirement remains.

The source and target collations on these name columns remain under separate
review. This change neither proves their equality nor relaxes the column,
table, or whole-database schema gates. It performs no production DDL or row
copy.
