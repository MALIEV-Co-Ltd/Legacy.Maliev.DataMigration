using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DatabaseMigrationCheckpointTests
{
    [Fact]
    public void Checkpoint_CanonicalSignatureSurvivesSerializationAndDictionaryOrdering()
    {
        using var data = new CheckpointTestData();
        DatabaseMigrationCheckpoint signed = data.Sign(data.Checkpoint);
        DatabaseMigrationCheckpoint restored = JsonSerializer.Deserialize<DatabaseMigrationCheckpoint>(JsonSerializer.Serialize(signed))!;
        TableReconciliationEvidence table = restored.Reconciliation.Tables[0];
        restored = restored with
        {
            Reconciliation = restored.Reconciliation with
            {
                Tables = [table with { NullCounts = new Dictionary<string, long> { ["Value"] = 0, ["ID"] = 0 } }],
            },
        };

        Assert.StartsWith("legacy-maliev-database-checkpoint-v1\0", Encoding.UTF8.GetString(MigrationEvidenceAttestation.CreatePayload(restored)));
        data.Verifier.Validate(restored, data.Checkpoint.Shadow);
        Assert.Equal(MigrationEvidenceAttestation.CreatePayload(signed), MigrationEvidenceAttestation.CreatePayload(restored));
    }

    [Theory]
    [InlineData("run")]
    [InlineData("source")]
    [InlineData("plan")]
    [InlineData("backup")]
    [InlineData("runner")]
    [InlineData("generation")]
    [InlineData("owner")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("name")]
    [InlineData("schema")]
    [InlineData("hash")]
    [InlineData("sequence-value")]
    [InlineData("time")]
    public void Checkpoint_ChangedSignedFieldsAreRejected(string field)
    {
        using var data = new CheckpointTestData();
        DatabaseMigrationCheckpoint changed = Change(data.Sign(data.Checkpoint), field);
        Assert.Equal("checkpoint_invalid", Assert.Throws<MigrationExecutionException>(() => data.Verifier.Validate(changed, data.Checkpoint.Shadow)).Code);
    }

    [Theory]
    [InlineData("run")]
    [InlineData("source")]
    [InlineData("plan")]
    [InlineData("backup")]
    [InlineData("runner")]
    [InlineData("generation")]
    [InlineData("owner")]
    [InlineData("attempt")]
    [InlineData("fence")]
    [InlineData("name")]
    [InlineData("database")]
    [InlineData("schema")]
    [InlineData("source-schema")]
    [InlineData("rows")]
    [InlineData("hash")]
    [InlineData("missing-table")]
    [InlineData("duplicate-table")]
    [InlineData("extra-table")]
    [InlineData("missing-column")]
    [InlineData("extra-column")]
    [InlineData("negative-count")]
    [InlineData("excess-count")]
    [InlineData("missing-orphan")]
    [InlineData("extra-orphan")]
    [InlineData("missing-relationship")]
    [InlineData("extra-relationship")]
    [InlineData("missing-sequence")]
    [InlineData("extra-sequence")]
    [InlineData("database-attempt")]
    [InlineData("database-fence")]
    [InlineData("nonzero-orphan")]
    [InlineData("null-shadow-database")]
    [InlineData("null-tables")]
    [InlineData("null-counts")]
    [InlineData("null-evidence")]
    [InlineData("bad-table-hash")]
    [InlineData("negative-row")]
    public void Checkpoint_TrustedSignatureDoesNotBypassIdentityOwnershipOrEvidenceValidation(string field)
    {
        using var data = new CheckpointTestData();
        DatabaseMigrationCheckpoint changed = data.Sign(Change(data.Checkpoint, field));
        Assert.Equal("checkpoint_invalid", Assert.Throws<MigrationExecutionException>(() => data.Verifier.Validate(changed, data.Checkpoint.Shadow)).Code);
    }

    [Fact]
    public void Checkpoint_OriginalPlanAndTrustedKeyAreRequired()
    {
        using var data = new CheckpointTestData();
        DatabaseMigrationCheckpoint signed = data.Sign(data.Checkpoint);
        var untrusted = new DatabaseMigrationCheckpointVerifier(data.Options with { TrustStore = new ReceiptAttestationTrustStore([]) });
        _ = Assert.Throws<MigrationExecutionException>(() => untrusted.Validate(signed, signed.Shadow));
        var differentPlan = new DatabaseMigrationCheckpointVerifier(data.Options with { SchemaPlan = data.Plan with { CapturedAtUtc = data.Plan.CapturedAtUtc.AddSeconds(1) } });
        _ = Assert.Throws<MigrationExecutionException>(() => differentPlan.Validate(signed, signed.Shadow));
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.Validate(signed with { AttestationSignature = "not-base64" }, signed.Shadow));
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.Validate(signed with { AttestationSignature = null }, signed.Shadow));
    }

    [Fact]
    public void Checkpoint_SignedSequenceValuesCanBeNegativeAndDifferFromCaptureTime()
    {
        using var data = new CheckpointTestData();
        DatabaseMigrationCheckpoint signed = data.Sign(Change(data.Checkpoint, "sequence-value"));
        data.Verifier.Validate(signed, signed.Shadow);
    }

    private static DatabaseMigrationCheckpoint Change(DatabaseMigrationCheckpoint value, string field)
    {
        TableReconciliationEvidence table = value.Reconciliation.Tables[0];
        return field switch
        {
            "run" => value with { Identity = value.Identity with { RunId = Guid.NewGuid() } },
            "source" => value with { Identity = value.Identity with { SourceCommitSha = new string('f', 40) } },
            "plan" => value with { Identity = value.Identity with { SchemaPlanSha256 = new string('f', 64) } },
            "backup" => value with { Identity = value.Identity with { BackupManifestSha256 = new string('f', 64) } },
            "runner" => value with { Identity = value.Identity with { RunnerDigestSha256 = new string('f', 64) } },
            "generation" => value with { Identity = value.Identity with { TargetGeneration = "other" } },
            "owner" => value with { Shadow = value.Shadow with { OwnerRunId = Guid.NewGuid().ToString("D") } },
            "attempt" => value with { Shadow = value.Shadow with { OwnerAttempt = 2 } },
            "fence" => value with { Shadow = value.Shadow with { FencingToken = Guid.NewGuid() } },
            "name" => value with { Shadow = value.Shadow with { Name = "different" } },
            "database" => value with { Database = value.Database with { Database = "other" } },
            "schema" => value with { Reconciliation = value.Reconciliation with { TargetSchemaSha256 = new string('f', 64) } },
            "source-schema" => value with { Reconciliation = value.Reconciliation with { SourceSchemaSha256 = new string('f', 64) } },
            "rows" => value with { Database = value.Database with { TotalRows = 2 } },
            "hash" => value with { Database = value.Database with { ContentSha256 = new string('f', 64) } },
            "missing-table" => value with { Reconciliation = value.Reconciliation with { Tables = [] } },
            "duplicate-table" => value with { Reconciliation = value.Reconciliation with { Tables = [table, table] } },
            "extra-table" => value with { Reconciliation = value.Reconciliation with { Tables = [table, table with { Table = "public.Extra" }] } },
            "missing-column" => WithTable(table with { NullCounts = new Dictionary<string, long>() }),
            "extra-column" => WithTable(table with { NullCounts = new Dictionary<string, long> { ["ID"] = 0, ["Value"] = 0, ["Extra"] = 0 } }),
            "negative-count" => WithTable(table with { NullCounts = new Dictionary<string, long> { ["ID"] = -1, ["Value"] = 0 } }),
            "excess-count" => WithTable(table with { NullCounts = new Dictionary<string, long> { ["ID"] = 3, ["Value"] = 0 } }),
            "missing-orphan" => WithTable(table with { ForeignKeyOrphanCounts = new Dictionary<string, long>() }),
            "extra-orphan" => WithTable(table with { ForeignKeyOrphanCounts = new Dictionary<string, long> { ["FK_Items"] = 0, ["Extra"] = 0 } }),
            "missing-relationship" => WithTable(table with { ForeignKeyRelationshipCounts = new Dictionary<string, long>() }),
            "extra-relationship" => WithTable(table with { ForeignKeyRelationshipCounts = new Dictionary<string, long> { ["FK_Items"] = 1, ["Extra"] = 1 } }),
            "missing-sequence" => value with { Reconciliation = value.Reconciliation with { SequenceNextValues = new Dictionary<string, long>() } },
            "extra-sequence" => value with { Reconciliation = value.Reconciliation with { SequenceNextValues = new Dictionary<string, long> { ["public.Items.ID"] = 2, ["Extra"] = 1 } } },
            "sequence-value" => value with { Reconciliation = value.Reconciliation with { SequenceNextValues = new Dictionary<string, long> { ["public.Items.ID"] = -9 } } },
            "time" => value with { CommittedAtUtc = value.CommittedAtUtc.AddSeconds(1) },
            "database-attempt" => value with { Database = value.Database with { OwnerAttempt = 2 } },
            "database-fence" => value with { Database = value.Database with { FencingToken = Guid.NewGuid() } },
            "nonzero-orphan" => WithTable(table with { ForeignKeyOrphanCounts = new Dictionary<string, long> { ["FK_Items"] = 1 } }),
            "null-shadow-database" => value with { Shadow = value.Shadow with { Database = null! } },
            "null-tables" => value with { Reconciliation = value.Reconciliation with { Tables = null! } },
            "null-counts" => WithTable(table with { NullCounts = null! }),
            "null-evidence" => value with { Reconciliation = null! },
            "bad-table-hash" => WithTable(table with { AggregateSha256 = "bad" }),
            "negative-row" => WithTable(table with { RowCount = -1 }),
            _ => throw new ArgumentOutOfRangeException(nameof(field)),
        };

        DatabaseMigrationCheckpoint WithTable(TableReconciliationEvidence changed)
        {
            return value with { Reconciliation = value.Reconciliation with { Tables = [changed] } };
        }
    }
}

internal sealed class CheckpointTestData : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public CheckpointTestData()
    {
        var table = new TableCopyPlan("dbo", "Items", "public", "Items", ["ID", "Value"], ["ID"])
        {
            Identities = [new("ID", 1, 1, 1, true)],
            ForeignKeys = [new("FK_Items", ["ID"], "public", "Items", ["ID"])],
        };
        var databasePlan = new DatabaseSchemaPlan("Order", "1.0", new string('a', 64), new string('b', 64), [table]);
        Plan = new("2.0", DateTimeOffset.UtcNow.AddMinutes(-1), new string('a', 40), [databasePlan]);
        Identity = new(Guid.NewGuid(), Plan.SourceCommitSha, SchemaPlanCanonicalizer.ComputeSha256(Plan), new string('c', 64), new string('d', 64), "checkpoint-test");
        var shadow = new ShadowDatabase(GuardedShadowMigrationRunner.CreateShadowName("Order", Identity.RunId), Identity.RunId.ToString("D"), "Order")
        {
            OwnerAttempt = 1,
            FencingToken = Guid.NewGuid(),
        };
        var evidence = new TableReconciliationEvidence("public.Items", 1, new string('c', 64), new string('d', 64),
            new Dictionary<string, long> { ["ID"] = 0, ["Value"] = 0 }, new Dictionary<string, long> { ["FK_Items"] = 0 })
        {
            ForeignKeyRelationshipCounts = new Dictionary<string, long> { ["FK_Items"] = 1 },
        };
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes($"public.Items|1|{new string('c', 64)}|{new string('d', 64)}"))).ToLowerInvariant();
        Checkpoint = new(Identity, shadow, new("Order", shadow.Name, 1, hash) { OwnerAttempt = 1, FencingToken = shadow.FencingToken },
            new("Order", databasePlan.SourceSchemaSha256, databasePlan.TargetSchemaSha256, [evidence])
            {
                SequenceNextValues = new Dictionary<string, long> { ["public.Items.ID"] = 2 },
            }, DateTimeOffset.UtcNow, "checkpoint-key", null);
        Options = new(Identity, Plan, new ReceiptAttestationTrustStore([new("checkpoint-key", _key.ExportSubjectPublicKeyInfo())]));
    }

    public FreshSchemaPlan Plan { get; }
    public MigrationRunIdentity Identity { get; }
    public DatabaseMigrationCheckpoint Checkpoint { get; }
    public DatabaseMigrationCheckpointVerificationOptions Options { get; }
    public DatabaseMigrationCheckpointVerifier Verifier => new(Options);

    public DatabaseMigrationCheckpoint Sign(DatabaseMigrationCheckpoint value)
    {
        return value with
        {
            AttestationSignature = Convert.ToBase64String(_key.SignData(MigrationEvidenceAttestation.CreatePayload(value), HashAlgorithmName.SHA256)),
        };
    }

    public DatabaseMigrationCheckpoint ForLease(MigrationRunLease lease)
    {
        return Sign(Checkpoint with
        {
            Shadow = Checkpoint.Shadow with { OwnerAttempt = lease.Attempt, FencingToken = lease.FencingToken },
            Database = Checkpoint.Database with { OwnerAttempt = lease.Attempt, FencingToken = lease.FencingToken },
        });
    }

    public void Dispose()
    {
        _key.Dispose();
    }
}
