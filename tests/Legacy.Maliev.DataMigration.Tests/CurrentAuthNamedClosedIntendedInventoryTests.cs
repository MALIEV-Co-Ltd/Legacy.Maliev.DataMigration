using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Pure predicate/signature tests; these values grant no native or execution authority.
public sealed class CurrentAuthNamedClosedIntendedInventoryTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Reviewed_inventory_is_accepted_by_candidate_and_signed_observation(bool production)
    {
        using var fixture = new Fixture(production);
        Assert.Equal(production ? 49 : 26, fixture.Facts.BeforeDatabaseSha256.Count);
        fixture.Require(fixture.Facts);
    }

    [Theory]
    [InlineData("substitution")]
    [InlineData("extra")]
    [InlineData("missing")]
    [InlineData("old53")]
    public void Production_inventory_drift_is_rejected_by_both_predicates(string mutation)
    {
        using var fixture = new Fixture(true);
        var hashes = fixture.Facts.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        string shadow = hashes.Keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        if (mutation is "substitution" or "missing") { _ = hashes.Remove(shadow); }
        if (mutation is "substitution" or "extra") { hashes.Add("unreviewed_database", new string('a', 64)); }
        if (mutation == "old53")
        {
            for (int i = 0; i < 4; i++) { hashes.Add("unreviewed_database_" + i, new string('a', 64)); }
        }
        var facts = fixture.Facts with { BeforeDatabaseSha256 = hashes, GlobalPreservationSha256 = CurrentAuthRepairPermit.FleetSha256(hashes) };
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireCandidate(facts));
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireSigned(facts));
    }

    [Theory]
    [InlineData("substitution")]
    [InlineData("extra")]
    [InlineData("missing")]
    [InlineData("case")]
    public void Local_inventory_drift_is_rejected_by_both_predicates(string mutation)
    {
        using var fixture = new Fixture(false);
        var hashes = fixture.Facts.BeforeDatabaseSha256.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        if (mutation != "extra") { _ = hashes.Remove("legacy_local"); }
        if (mutation != "missing") { hashes.Add(mutation == "case" ? "Legacy_Local" : "unreviewed_database", new string('a', 64)); }
        var facts = fixture.Facts with { BeforeDatabaseSha256 = hashes, GlobalPreservationSha256 = CurrentAuthRepairPermit.FleetSha256(hashes) };
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireCandidate(facts));
        _ = Assert.Throws<MigrationExecutionException>(() => fixture.RequireSigned(facts));
    }

    private sealed class Fixture : IDisposable
    {
        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly DateTimeOffset _now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        private readonly LocalExecutionBinding _binding = new(1, "pure-host", "pure-volume", @"D:\pure-unit", "root", "lock", "lock-id", 1);
        private readonly FreshSchemaPlan _source;
        private readonly ReceiptAttestationTrustStore _trust;
        private readonly CurrentAuthRepairSigningPins _pins;
        internal CurrentAuthNamedClosedIntendedFacts Facts { get; }

        internal Fixture(bool production)
        {
            FreshSchemaPlan source = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
            _source = source with { Databases = [.. source.Databases.Select(database => database.Database == "Quotation" ? Quotation(database) : database)] };
            _trust = new([new("pure-review", _key.ExportSubjectPublicKeyInfo())]);
            _ = _trust.TryGetPublicKeyFingerprintSha256("pure-review", out string fingerprint);
            _pins = new("pure-review", fingerprint, "unused-authorization", new string('b', 64), "unused-receipt", new string('c', 64));
            IEnumerable<string> names = production ? ReviewedProductionRepairInventory.ExportProductionNames()
                : DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]);
            var hashes = names.ToDictionary(x => x, _ => new string('a', 64), StringComparer.Ordinal);
            Facts = new(Guid.NewGuid(), _source.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(_source),
                new(production ? DeltaTargetAuthorityKind.ProductionCloudNativePg : DeltaTargetAuthorityKind.LocalAspire,
                    production ? "gke://maliev-website/pure-unit" : "aspire://legacy-postgres-main-local/pure-unit", new string('d', 64)),
                production ? "maliev-legacy" : "local-aspire", production ? "legacy-postgres-main" : "legacy-postgres-main-local",
                "pure-generation", new string('e', 64), _binding.ComputeSha256(), hashes, CurrentAuthRepairPermit.FleetSha256(hashes),
                new("pure-role", "pure-comment", _now.AddMinutes(-1), _now.AddHours(3), _now.AddMinutes(-2), _now.AddMinutes(-2),
                    new string('b', 64), new string('c', 64), "/pure-unit/pg_hba.conf"), new string('f', 64));
        }

        internal void Require(CurrentAuthNamedClosedIntendedFacts facts) { RequireCandidate(facts); RequireSigned(facts); }
        internal void RequireCandidate(CurrentAuthNamedClosedIntendedFacts facts)
        {
            CurrentAuthNamedClosedIntent.RequireCandidate(facts, _source, _binding, _now);
        }
        internal void RequireSigned(CurrentAuthNamedClosedIntendedFacts facts)
        {
            var artifact = new CurrentAuthProofArtifact(@"D:\pure-unit\held.json", new string('a', 64));
            var observation = new CurrentAuthNamedClosedIntendedObservation("current-auth-observed-closed-intended-subject-v1", facts,
                ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256, ApprovedCurrentAuthSchema.ClosureSha256,
                ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true),
                CurrentAuthRepairPermit.OperationSha256(_source, facts.DefinitionPrecursorSha256), new string('a', 64), new string('b', 64), new string('c', 64),
                @"D:\pure-unit\binding.json", @"D:\pure-unit\source.json", @"D:\pure-unit\pins.json", artifact, artifact,
                _now, _now.AddHours(1), 180001, "pure-review", null);
            observation = observation with
            {
                Signature = Convert.ToBase64String(_key.SignData(CurrentAuthNamedClosedIntent.Payload(observation),
                HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
            };
            CurrentAuthNamedClosedIntent.Require(observation, _source, _trust, _pins, _now);
        }

        private static DatabaseSchemaPlan Quotation(DatabaseSchemaPlan database)
        {
            TableCopyPlan[] tables = [database.Tables[0],
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox, "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", true),
                ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox, "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", false), .. database.Tables.Skip(3)];
            database = database with
            {
                Tables = tables,
                SourceDispositionProfile = ApprovedSourceDispositionManifest.QuotationOutboxesV1,
                SourceTableDispositions = ApprovedSourceDispositionManifest.DispositionsForDatabase("Quotation", tables)
            };
            return database with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database) };
        }

        public void Dispose()
        {
            _key.Dispose();
        }
    }
}
