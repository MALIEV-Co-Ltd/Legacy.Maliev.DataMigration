# Identity LockoutEnd target contract

`CustomerIdentity` and `EmployeeIdentity` retain `public."AspNetUsers"."LockoutEnd"`
as `timestamp with time zone`, matching the active ASP.NET Identity runtime mapping.
Only those two source columns may map from SQL Server `datetimeoffset(7)` to this
target type. The migration projects the UTC instant to PostgreSQL's six decimal
places by truncating the seventh decimal place. Other `datetimeoffset(7)`
columns continue to map to lossless text.

The exact seven-place source value, including its original offset, must also be
captured in `legacy_migration_internal."AspNetUserLockoutEndExact"`, keyed by
user ID. That internal table is excluded from the ordinary structural
fingerprint. A target timestamp is valid only when it equals the UTC
microsecond projection of the companion value. A missing or changed companion
value is a row-integrity failure, even when the 23 structural fingerprints
match. The companion capture must be refreshed and verified before any row
synchronization that can change `LockoutEnd`.

The production alignment on 2026-09-28 observed 11 non-null customer values
and one non-null employee value; eight customer values had a nonzero seventh
decimal place. The production repair uses a separate owner-only exact-value
capture and a disposable PostgreSQL 18 proof before writing the companion
table on the authorized target.
