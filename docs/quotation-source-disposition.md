# Quotation source outbox disposition

The SQL Server `Quotation` schema plan must identify both `dbo.GoogleAnalyticsOutbox`
and `dbo.QuotationOutcomeOutbox` as the reviewed `quotation-outboxes-v1` source
disposition. The marker is part of the signed schema-plan digest. Its validation
pins the source names, ordered columns and types, nullability, identity column,
primary keys, and unique event-key constraints to the committed source contract.
Missing, partial, or drifted outboxes fail closed.

This marker is **not** authorization to copy either table into an ordinary
PostgreSQL runtime table. Both live-row schema-1.2 and captured-source schema-1.3
planning use the reviewed target disposition: `QuotationOutcomeOutbox` maps to
`public.QuotationAcceptedOutcome` and `GoogleAnalyticsOutbox` maps to
`legacy_compatibility.GoogleAnalyticsOutbox`. Captured planning encrypts the
original source rows inside the SQL Server snapshot, then maps from that immutable
capture into separately encrypted, target-shaped replay rows. Signed operations,
capture bindings, and reconciliation use target names and fingerprints. The
temporary source-shaped capture is discarded after selected replay rows are
sealed. The operator console permits schema-1.3 apply only for its guarded
disposable authority; persistent PostgreSQL writes require a later, separately
reviewed authorization and full exact-23 proof.
Existing signed plans without the marker cannot be reused against a source
containing these outboxes; generate a fresh plan with the exact protected-main
runner.
