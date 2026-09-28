# Disposable collation semantic proof (#187)

This proof uses only synthetic strings and a temporary schema in the existing
PostgreSQL 18 Testcontainers fixture. It compares an inherited deterministic
column collation with an explicitly assigned, case- and accent-insensitive ICU
collation with numeric ordering. Both tables contain the same six invented
values. No source or production database is contacted.

The focused test demonstrates that equality with `E` matches one inherited
value but three explicit-collation values; distinct counts are six and four.
It also observes lexical `item10, item2` ordering under the fixture's inherited
collation versus numeric `item2, item10` ordering under the explicit collation.
For an `ORDER BY` using the explicit collation, `EXPLAIN` contains a sort when
only an inherited-collation index exists, then uses a compatible index without
that sort after an explicit-collation index is created. The test checks the
index collation identities in PostgreSQL's catalog as well as the plans.

Finally, two synthetic values can coexist under an inherited-collation UNIQUE
constraint, while an attempted column-collation change fails with a unique
violation during index rebuild. The original two rows remain. The test's
temporary schema and collation are dropped afterward.

These examples prove that collation metadata affects query and constraint
behavior. They **do not** identify or classify any of the 304 production
`explicit-unreviewed` columns, compare SQL Server source semantics, prove a
particular PostgreSQL collation equivalent, or authorize DDL. The production
preimage/whole-schema guard is unchanged. Each real column still needs fresh
authenticated source and target catalogs, owner-approved equality/order/case/
accent/uniqueness disposition, affected-index and collision review, an
independent exact-23 disposable proof, and separately authorized target-specific
production DDL with rollback or forward-fix planning.
