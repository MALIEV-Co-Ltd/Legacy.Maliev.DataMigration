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

Before issuing that signature, authorization opens `Quotation` in a read-only
repeatable-read transaction. It checks the complete signed physical source
preimage (or exact already-current transition shape on replay), both retained
outboxes, the target pair, the system identifier, and target sequences where
present. Drift or a partially bootstrapped target cannot receive a new DDL
authorization. Apply still independently rechecks inside its serializable
transaction before any additive DDL; authorization does not lock future state.

For a disposable authority (`aspire://legacy-postgres-main-local/disposable-*`),
the apply command requires a distinct protected `evidenceKey` and
`LEGACY_MIGRATION_QUOTATION_BOOTSTRAP_EVIDENCE_SIGNING_KEY_FILE` before DDL.
After post-commit schema and sequence verification it publishes a signed,
PII-free disposable transition proof. The proof binds the source commit,
source/final/transition schema hashes, exact disposable target identity,
fixed missing set, authorization envelope digest, result, and completion time.
The same command may return `already-current` on exact replay. A failed or
uncertain run leaves its pending marker; do not infer success from it.

## Isolated disposable Quotation copy

`scripts/new-quotation-disposable-copy.ps1` creates a **new independent**
PostgreSQL 18 cluster for a disposable transition proof; it never creates a
shadow database inside persistent Aspire. It is an owner-operated, local-only
tool, not a production backup or a migration authorization. Do not run it until
the protected-main exact-head checks are green and the owner has reviewed the
current persistent container, volume, system identifier, and Quotation state.

Create a fresh owner-only, non-link run directory on a protected local disk.
Keep the existing persistent connection in a separate owner-only connection
file pointing to its loopback-published `postgres` database; do not place a
password on a command line. Supply the full inspected persistent container ID,
the independently observed SHA-256 of its `pg_control_system()` identifier, a
digest-pinned `postgres:18@sha256:...` image, and a never-used
`legacy-quotation-proof-<12-32 lowercase alphanumeric>` name. The helper
requires the persistent `legacy-maliev-exact23-postgres-data` volume and exact
loopback binding, performs a read-only serializable-deferrable logical dump of
only `Quotation` into the protected run directory, then restores into its own
labelled volume/container bound to `127.0.0.1` on a Docker-assigned port. It
rejects equal source/copy PostgreSQL system identifiers. It writes a protected
target connection file and PII-free identity/dump-hash receipt; the dump and
connection file are sensitive and must remain owner-only. Errors are coded,
without dumping SQL, connection strings, or PostgreSQL stderr to logs.
The one-time `quotation-copy-container.env` credential projection is removed
immediately after the new container ID, run labels, volume mount, and pinned
image are verified. If creation fails before that verification, the protected
file is retained for owner review; never assume an uncertain container state
is safe to erase. Verified cleanup also removes a residual exact run-owned env
file from an older successful copy.

```powershell
& ./scripts/new-quotation-disposable-copy.ps1 -Action Create `
  -RunDirectory <owner-only-new-run-directory> `
  -Name legacy-quotation-proof-<unique-lowercase-id> `
  -SourceContainerId <full-observed-persistent-container-id> `
  -ExpectedSourceSystemIdentifierSha256 <independently-observed-sha256> `
  -SourceConnectionFile <owner-only-persistent-loopback-connection-file> `
  -ImageReference postgres:18@sha256:<reviewed-image-digest>
```

The helper does not create or sign a schema plan, authorization, or transition
proof. Verify the copy's receipt and observed authority separately. Use the
fresh exact-23 source schema plan and the protected `Quotation` bootstrap config
below with `targetConnectionFile` set to this copy's generated connection file
and `targetAuthority` set to the independently verified
`aspire://legacy-postgres-main-local/disposable-*` authority and receipt system
hash. Then run `authorize-quotation-target-bootstrap` with a distinct protected
authorization signer, review its output, and run `apply-quotation-target-bootstrap`
with a distinct protected evidence signer. Each step needs a new output path.
The disposable command itself validates the complete pre-DDL source shape and
will reject a copied EF-created outbox if it differs structurally from the signed
source plan. A names-only inventory is not a fingerprint or DDL permission.

After recording and reviewing the signed disposable proof, remove **only** the
copy resources using the receipt-bound cleanup. Cleanup verifies the exact
container ID, fresh nonce labels, volume mount, and exclusive volume use before Docker
removal. It leaves the protected dump, receipt, and connection file for explicit
owner retention/disposal policy; never point cleanup at persistent Aspire. A
failed/incomplete create has no `copy-complete` receipt and must stop for manual
ownership review, not automatic deletion or reuse.

```powershell
& ./scripts/new-quotation-disposable-copy.ps1 -Action Cleanup `
  -RunDirectory <same-owner-only-run-directory> `
  -Name legacy-quotation-proof-<same-id>
```

Persistent local Aspire (`aspire://legacy-postgres-main-local/persistent-*`)
requires that protected proof and its independent public `disposableProofKey`
on both authorization and apply. The proof must be no older than 12 hours,
validly signed, and from a **different PostgreSQL system identifier**. The
persistent command additionally requires the exact-23 source schema plan to
have a UTC capture no more than two hours old, with the disposable proof
completed after that capture; a stale or future-dated plan fails closed. The
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
`TargetSchemaSha256`. The separately reviewed schema-1.4 delta row path binds
that physical transition hash in its signed plan, target fence, atomic apply,
and reconciliation, with disposable exact-23 row proof. This bootstrap does not
issue that row authorization or apply rows. Neither path retires, drops, or
rewrites the two old public outboxes. No persistent-local or production DDL,
row apply, or cutover is implied by a code merge or disposable proof; each
requires its own current plan, independent authorization, and reconciliation.
