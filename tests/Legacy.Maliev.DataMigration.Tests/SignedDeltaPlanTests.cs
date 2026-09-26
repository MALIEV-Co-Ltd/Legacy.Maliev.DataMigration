using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SignedDeltaPlanTests : IDisposable
{
    private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public void Produces_and_verifies_exact23_canonical_plan_without_row_values()
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(Request(), signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);

        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
        Assert.Equal(DatabaseInventory.ActiveDatabases, plan.Databases.Select(database => database.Database));
        Assert.DoesNotContain("private-row-value", System.Text.Json.JsonSerializer.Serialize(plan), StringComparison.Ordinal);
        Assert.DoesNotContain("SourceObservationSha256", System.Text.Json.JsonSerializer.Serialize(plan), StringComparison.Ordinal);
        Assert.Matches("^[0-9a-f]{64}$", DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan));
    }

    [Fact]
    public void Rejects_tampering_in_operations_or_target_fence()
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(Request(), signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        DeltaDatabasePlan first = plan.Databases[0];
        DeltaTablePlan table = first.Tables[0];
        DeltaSynchronizationPlan changedCount = plan with
        {
            Databases = [first with { Tables = [table with { InsertCount = table.InsertCount + 1 }] }, .. plan.Databases.Skip(1)],
        };
        DeltaSynchronizationPlan changedFence = plan with { TargetGeneration = "changed-generation" };
        DeltaSynchronizationPlan changedRole = plan with { BackupKeyFingerprintSha256 = new('1', 64) };

        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedCount, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedFence, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(changedRole, trust, Now()));
    }

    [Theory]
    [InlineData("incomplete-inventory")]
    [InlineData("stale-cutoff")]
    [InlineData("reused-backup-key")]
    [InlineData("reused-authorization-key")]
    public void Refuses_unreviewable_or_role_reused_plan(string scenario)
    {
        using var signer = new P256MigrationEvidenceSigner("delta-plan-20260908", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = Request();
        if (scenario == "incomplete-inventory") { request = request with { Databases = request.Databases.Skip(1).ToArray() }; }
        if (scenario == "stale-cutoff") { request = request with { SourceCutoffUtc = Now().AddHours(-27) }; }
        if (scenario == "reused-backup-key") { request = request with { BackupKeyFingerprintSha256 = signer.PublicKeyFingerprintSha256 }; }
        if (scenario == "reused-authorization-key") { request = request with { ExecutionAuthorizationKeyFingerprintSha256 = signer.PublicKeyFingerprintSha256 }; }

        DeltaPlanException exception = Assert.Throws<DeltaPlanException>(
            () => DeltaSynchronizationPlanProducer.Produce(request, signer, Now()));

        Assert.StartsWith("delta_plan_", exception.Code, StringComparison.Ordinal);
    }

    private static DateTimeOffset Now()
    {
        return new(2026, 9, 8, 8, 50, 0, TimeSpan.Zero);
    }

    private static DeltaPlanSigningRequest Request()
    {
        string hashA = new('a', 64);
        string hashB = new('b', 64);
        string hashC = new('c', 64);
        string hashD = new('d', 64);
        CanonicalDeltaOperation[] operations =
        [
            new(DeltaOperationKind.Insert, hashB, hashC, null),
            new(DeltaOperationKind.Update, hashC, hashD, hashA),
            new(DeltaOperationKind.Delete, hashD, null, hashB),
        ];
        string operationsHash = DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(operations);
        IReadOnlyList<DeltaDatabasePlan> databases = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new DeltaDatabasePlan(database,
            [
                new DeltaTablePlan("public.items", 1, 1, 1, 7, operationsHash, operations),
            ]))];
        return new(
            "5ac7d045c51194edd9e64d8564f1b726b001be34",
            Now().AddMinutes(-5),
            hashA,
            hashB,
            hashC,
            "maliev-legacy",
            "legacy-postgres-main",
            "resource-version-123",
            hashD,
            new('e', 64),
            new('f', 64),
            databases)
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                "gke://maliev-website/us-central1-a/maliev-legacy/legacy-postgres-main/uid-1", hashD),
        };
    }

    public void Dispose()
    {
        _key.Dispose();
    }

    [Fact]
    public void Local_aspire_authority_requires_the_dedicated_local_target_identity()
    {
        DateTimeOffset now = Now();
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = Request() with
        {
            TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                "aspire://legacy-postgres-main-local/legacy-maliev-exact23-postgres-data", new('9', 64)),
            TargetNamespace = "local-aspire",
            TargetCluster = "legacy-postgres-main-local",
        };

        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(request, signer, now);

        Assert.Equal(DeltaTargetAuthorityKind.LocalAspire, plan.TargetAuthority!.Kind);
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, now));
        _ = Assert.Throws<DeltaPlanException>(() => DeltaSynchronizationPlanProducer.Produce(
            request with { TargetCluster = "legacy-postgres-main" }, signer, now));
    }

    [Fact]
    public void Live_read_only_plan_is_explicit_and_binds_the_source_capture_window()
    {
        using var signer = new P256MigrationEvidenceSigner("live-plan", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = Request() with
        {
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = new('9', 64),
            SourceCaptureCompletedAtUtc = Now().AddMinutes(-1),
        };
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(request, signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);

        Assert.Equal("1.2", plan.SchemaVersion);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with
        {
            SourceObservationSha256 = new('8', 64),
        }, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with
        {
            SourceCaptureCompletedAtUtc = Now().AddMinutes(1),
        }, trust, Now()));
        _ = Assert.Throws<DeltaPlanException>(() => DeltaSynchronizationPlanProducer.Produce(request with
        {
            SourceCaptureCompletedAtUtc = request.SourceCutoffUtc.AddHours(2),
        }, signer, Now()));
    }

    [Fact]
    public void Live_mode_cannot_be_silently_added_to_a_legacy_backup_plan()
    {
        using var signer = new P256MigrationEvidenceSigner("backup-plan", _key.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(Request(), signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);

        Assert.Equal("1.1", plan.SchemaVersion);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with
        {
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = new('9', 64),
            SourceCaptureCompletedAtUtc = Now(),
        }, trust, Now()));
    }

    [Fact]
    public void Captured_source_plan_binds_exact23_encrypted_artifacts_and_rejects_tampering()
    {
        using var signer = new P256MigrationEvidenceSigner("captured-plan", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = CapturedRequest();
        DeltaSynchronizationPlan plan = DeltaSynchronizationPlanProducer.Produce(request, signer, Now());
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);

        Assert.Equal("1.3", plan.SchemaVersion);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, Now()));
        DeltaSourceCaptureManifest manifest = plan.SourceCaptureManifest!;
        DeltaDatabaseCaptureBinding first = manifest.Databases[0];
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with
        {
            SourceCaptureManifest = manifest with
            {
                Databases = [first with
                {
                    Tables = [first.Tables[0] with { EncryptedSha256 = new('1', 64) }],
                }, .. manifest.Databases.Skip(1)],
            },
        }, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with { SourceCaptureManifest = null }, trust, Now()));
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(plan with { SchemaVersion = "1.2" }, trust, Now()));
    }

    [Theory]
    [InlineData("missing-database")]
    [InlineData("duplicate-capture-id")]
    [InlineData("wrong-row-count")]
    [InlineData("reused-key")]
    public void Captured_source_plan_rejects_inconsistent_bindings(string scenario)
    {
        using var signer = new P256MigrationEvidenceSigner("captured-plan", _key.ExportECPrivateKeyPem());
        DeltaPlanSigningRequest request = CapturedRequest();
        DeltaSourceCaptureManifest manifest = request.SourceCaptureManifest!;
        DeltaDatabaseCaptureBinding first = manifest.Databases[0];
        DeltaDatabaseCaptureBinding second = manifest.Databases[1];
        request = scenario switch
        {
            "missing-database" => request with
            {
                SourceCaptureManifest = manifest with { Databases = manifest.Databases.Skip(1).ToArray() },
            },
            "duplicate-capture-id" => request with
            {
                SourceCaptureManifest = manifest with
                {
                    Databases = [first, second with
                    {
                        Tables = [second.Tables[0] with { CaptureId = first.Tables[0].CaptureId }],
                    }, .. manifest.Databases.Skip(2)],
                },
            },
            "wrong-row-count" => request with
            {
                SourceCaptureManifest = manifest with
                {
                    Databases = [first with
                    {
                        SourceReconciliation = first.SourceReconciliation with
                        {
                            Tables = [first.SourceReconciliation.Tables[0] with { RowCount = 8 }],
                        },
                    }, .. manifest.Databases.Skip(1)],
                },
            },
            "reused-key" => request with
            {
                SourceCaptureManifest = manifest with
                {
                    EncryptionKeyFingerprintSha256 = signer.PublicKeyFingerprintSha256,
                },
            },
            _ => throw new InvalidOperationException(scenario),
        };

        DeltaPlanException failure = Assert.Throws<DeltaPlanException>(
            () => DeltaSynchronizationPlanProducer.Produce(request, signer, Now()));
        Assert.Equal("delta_plan_capture_invalid", failure.Code);
    }

    private static DeltaPlanSigningRequest CapturedRequest()
    {
        DeltaPlanSigningRequest request = Request() with
        {
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = new('9', 64),
            SourceCaptureCompletedAtUtc = Now().AddMinutes(-1),
        };
        IReadOnlyList<DeltaDatabaseCaptureBinding> bindings = [.. request.Databases.Select(database =>
        {
            byte[] digest = SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(database.Database));
            string hash = Convert.ToHexString(digest).ToLowerInvariant();
            DeltaTablePlan table = database.Tables[0];
            return new DeltaDatabaseCaptureBinding(database.Database,
                Now().AddMinutes(-4), Now().AddMinutes(-2),
                new DatabaseReconciliationEvidence(database.Database, new('a', 64), new('b', 64),
                [
                    new TableReconciliationEvidence(table.Table, 9, new('c', 64), new('d', 64),
                        new Dictionary<string, long>(), new Dictionary<string, long>()),
                ]),
                [new DeltaTableCaptureBinding(table.Table, Guid.NewGuid(), hash, hash, 2, table.OperationsSha256)]);
        })];
        return request with
        {
            SourceCaptureManifest = new DeltaSourceCaptureManifest(new('8', 64), bindings),
        };
    }
}
