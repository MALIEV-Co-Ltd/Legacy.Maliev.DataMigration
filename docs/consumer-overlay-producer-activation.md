# Explicit consumer overlay production

The source-schema `plan` command accepts optional `plan.consumerOverlays`:

```json
{
  "plan": {
    "outputPath": "OWNER_PROTECTED_NEW_SCHEMA_PATH",
    "sourceCommitSha": "ACCEPTED_SOURCE_COMMIT",
    "consumerOverlays": "CurrentConsumerColumnsV1",
    "contactRequestCollationProfile": "ExplicitC"
  }
}
```

Omitting this member selects `HistoricalDefaults`. Historical profiles, fingerprints, receipt signature framing and parameterless receipt verification remain unchanged. Unknown selections fail. Current selection activates both reviewed profiles together: CustomerIdentity `auth-customer-create-authority-v2` and Quotation `quotation-decision-order-version-v1`. Consumer overlay selection does not change other database profiles. The independently selected collation profile below changes only ContactRequest target column metadata. The producer selects profiles inside its genuine SQL Server schema snapshots, before computing physical target hashes. Source column projections, source hashes and table dispositions remain unchanged. Do not edit a produced or signed schema to activate columns.

The columns are target-only: `public.AspNetUsers.PasswordSetupRequired boolean NOT NULL DEFAULT false` and `public.Quotation.DecisionOrderVersion timestamp without time zone NULL` without a default. The existing overlay contract preserves lifecycle/decision values during updates and replay, initializes only approved inserted keys, and rejects source collisions and root deletions. CustomerV2 retains the CustomerV1 operation receipt tables and sequence contract.

Fresh schema writers include the physical columns while retaining historical raw source bootstrap tables and the separate reviewed Quotation archive/adoption mapping. Existing databases require a separately reviewed, preservation-proven additive transition. This patch does not issue additive DDL authority or broaden the historical production alignment manifest. Complete the existing accepted-run operation before producing or adopting a new accepted schema. Keep old journals, immutable effects/receipts, private archives and source-repair markers.

The schema-bound reconciliation verifier authenticates unchanged receipt signature framing and binds exact plan/schema hashes, all table inventories, source/physical hashes, extension-state presence and atomic checkpoints. The caller separately authenticates the supplied plan. The historical parameterless verifier still rejects the new Quotation overlay receipt. Active-profile proof, terminal, representative-query, AppHost evidence, snapshot and local-finalization paths use schema-bound verification. Historical-only review paths retain historical behavior.

Supported ordinary delta execution still requires a fresh genuine signed plan, disposable proof, authorization, observed target and full physical/maintenance/source gates. Metadata provisioning is per database and is not atomic across23 or with subsequent row application; this change does not claim otherwise. Consumer release acceptance remains separately bound to actual owner migrations and compiled/deployed model versions.

## Independent ContactRequest collation selection

The source-schema `plan.contactRequestCollationProfile` member accepts `LegacyInherited` (the default when omitted) or `ExplicitC`. It is independent of `plan.consumerOverlays`: either selection can be used alone or both can be selected together. Unknown values and an unexpected ContactRequest source shape fail closed.

`ExplicitC` records `COLLATE "C"` only for the seven reviewed target fields in `ContactRequest.public.Message`: `FirstName`, `LastName`, `Email`, `Company`, `Telephone`, `MessageContent` and `Country`. It preserves source projections, source types and hashes, identities, defaults, nullability and every other target column. Current database locale and inherited collation metadata must be observed separately; this profile does not relabel inherited defaults or recreate a database. Fresh target schema writers emit the selected column collations. Selecting the profile does not issue authority to change an existing target: existing column changes require a separately reviewed, preservation-proven transition and actual post-change catalog verification.

## Optional ordinary comparison read windows

For ordinary live-read-only 1.2 delta planning, `delta.recordSourceReadWindows` defaults to `false`. Selecting `true` signs `sourceReadWindow.startedAtUtc` and `sourceReadWindow.completedAtUtc` on each of the exact 23 ordered database entries. All windows must be present, UTC, nondecreasing and inside the signed source cutoff/completion interval. They bound each database's actual table-comparison read loop, which includes target comparison work; they are not SQL Server transaction commit times and do not establish an atomic cross-database snapshot. Captured/Quotation physical-transition planning rejects this option. Omitting it preserves historical plan framing and behavior.

Validation must finish before publication: build first with zero warnings/errors; producer/Console, receipt and physical writer tests; existing overlay preservation tests; affected SQLServer/Core/Console suites with required owner-proof environment; formatting/static checks and genuine supported pipeline proofs. Source-only preparation is not a successful validation or operational activation.
