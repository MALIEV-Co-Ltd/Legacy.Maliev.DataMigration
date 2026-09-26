# Reviewed Quotation target bootstrap (#132)

The captured Quotation schema plan maps `dbo.GoogleAnalyticsOutbox` to
`legacy_compatibility.GoogleAnalyticsOutbox` and `dbo.QuotationOutcomeOutbox` to
`public.QuotationAcceptedOutcome`. An existing local Aspire Quotation database may
still contain source-shaped `public.GoogleAnalyticsOutbox` and
`public.QuotationOutcomeOutbox`. This bootstrap **retains** both old tables and
creates only the two reviewed disposition targets. It never moves rows, drops,
renames, replaces, or alters the old tables.

The normal signed `TargetSchemaSha256` excludes the old public outboxes. While
they remain, the whole-database fingerprint cannot equal that final target hash.
The bootstrap therefore derives a temporary exact transition fingerprint from
the signed source plan: all reviewed mapped targets **plus exactly both** original
source-shaped public outboxes. Before creation it requires the complete source
shape to match the signed plan. Unknown tables or structural drift, one missing
old table, and a partially present target pair all fail closed. The resulting
transition fingerprint is rechecked after creation and in a fresh read-only
transaction; target identity sequences are checked separately. This is not an
exact-23 delta proof or final target parity claim.

The console exposes distinct `authorize-quotation-target-bootstrap` and
`apply-quotation-target-bootstrap` commands. Both require an owner-only protected
configuration, `LEGACY_MIGRATION_CALLER=owner`,
`LEGACY_DEPLOY_ENABLED=false`, an exact-23 protected schema plan, and
the exact local Aspire target authority. The authorization command additionally
requires `allowAuthorizationSigning=true`, a UTC expiry no more than 15 minutes
away, and a protected key named by
`LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_AUTHORIZATION_SIGNING_KEY_FILE`.
The apply command requires `allowExecution=true` and a protected authorization
file. The separate DDL signature binds the source commit, source and reviewed
target schema hashes, transition fingerprint, exact target authority, and fixed
two-table missing set. A new protected
output path is reserved before any DDL; an attempted apply keeps a pending marker
on failure. No production target or row-delta authorization is accepted.

For a disposable authority (`aspire://legacy-postgres-main-local/disposable-*`),
the apply command requires a distinct protected `evidenceKey` and
`LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_EVIDENCE_SIGNING_KEY_FILE` before DDL.
After post-commit schema and sequence verification it publishes a signed,
PII-free disposable transition proof. The proof binds the source commit,
source/final/transition schema hashes, exact disposable target identity,
fixed missing set, authorization envelope digest, result, and completion time.
The same command may return `already-current` on exact replay. A failed or
uncertain run leaves its pending marker; do not infer success from it.

Persistent local Aspire (`aspire://legacy-postgres-main-local/persistent-*`)
requires that protected proof and its independent public `disposableProofKey`
on both authorization and apply. The proof must be no older than 12 hours,
validly signed, and from a **different PostgreSQL system identifier**. The
persistent authorization has a separate signature domain and binds the exact
signed proof envelope hash; it expires within 15 minutes. Proof trust and
persistent authorization trust cannot reuse the same key. The runner rechecks
the exact live target authority before either command and the PostgreSQL
system identifier within the serializable DDL transaction. No disposable
authorization or proof can be replayed as a persistent authorization.

Example configuration section (paths and authority are placeholders; do not put
credentials in this JSON):

```json
{
  "quotationTargetBootstrap": {
    "schemaPlanPath": "<owner-only exact-23 schema plan>",
    "targetConnectionFile": "<owner-only local Aspire connection file>",
    "targetAuthority": "<exact observed local Aspire authority object>",
    "authorizationKey": "<trusted key reference object>",
    "outputPath": "<new owner-only receipt path>",
    "authorizationPath": "<protected authorization file for apply>",
    "authorizationExpiresAtUtc": "<UTC instant within 15 minutes for authorize>",
    "evidenceKey": "<distinct trusted disposable evidence key; disposable apply only>",
    "disposableProofPath": "<signed disposable transition proof; persistent only>",
    "disposableProofKey": "<trusted disposable proof key; persistent only>",
    "allowAuthorizationSigning": false,
    "allowExecution": false
  }
}
```

This guarded path authorizes only the reviewed additive local DDL after a fresh
disposable proof and explicit owner review. Any mismatch between the observed
existing EF-created public outboxes and the signed source shape needs separate
review; do not weaken the fingerprint or retire the old tables under this
command. The resulting transition fingerprint is **not** the final signed
`TargetSchemaSha256`: ordinary row-delta planning still rejects the retained
outboxes. No row apply, production DDL, or production bootstrap is authorized.
Retirement or any transition-aware row path requires a separate reviewed
change and full exact-23 disposable row proof under #92.
