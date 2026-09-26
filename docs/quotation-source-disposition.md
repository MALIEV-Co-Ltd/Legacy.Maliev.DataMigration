# Quotation source outbox disposition

The SQL Server `Quotation` schema plan must identify both `dbo.GoogleAnalyticsOutbox`
and `dbo.QuotationOutcomeOutbox` as the reviewed `quotation-outboxes-v1` source
disposition. The marker is part of the signed schema-plan digest. Its validation
pins the source names, ordered columns and types, nullability, identity column,
primary keys, and unique event-key constraints to the committed source contract.
Missing, partial, or drifted outboxes fail closed.

This marker is **not** authorization to copy either table into an ordinary
PostgreSQL runtime table. The exact-23 delta planner continues to reject these
source tables until the canonical `QuotationAcceptedOutcome` transformation,
read-only analytics archive, replay/identity handling, and signed reconciliation
are integrated and proven on disposable data. Existing signed plans without the
marker cannot be reused against a source containing these outboxes; generate a
fresh plan with the exact protected-main runner.
