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
    "allowAuthorizationSigning": false,
    "allowExecution": false
  }
}
```

Only disposable PostgreSQL proof is authorized by this change. Any mismatch
between the observed existing EF-created public outboxes and the signed source
shape needs separate review; do not weaken the fingerprint or retire the old
tables under this command. A fresh local/production delta plan and full exact-23
disposable proof remain prerequisites for later admission. Production bootstrap
requires independent observation, authorization, and implementation review.
