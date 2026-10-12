using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class Exact23DeltaPlanCoordinatorTests
{
    private static readonly DateTimeOffset WindowEpoch = DateTimeOffset.Parse(
        "2026-09-08T06:00:00Z", CultureInfo.InvariantCulture);

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Source_read_windows_default_preserves_database_bytes_and_single_clock_read(bool live)
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        var rows = new Rows(_ => []);
        DeltaSynchronizationPlan plan = await new Exact23DeltaPlanCoordinator(rows, rows, signer, clock)
            .ProduceAsync(WindowRequest(signer) with
            {
                RecordSourceReadWindows = false,
                SourceMode = live ? DeltaSourceMode.LiveReadOnly : null,
                SourceObservationSha256 = live ? Hash('7') : null,
            }, CancellationToken.None);

        Assert.Equal(1, clock.Reads);
        Assert.All(plan.Databases, database =>
        {
            Assert.Null(database.SourceReadWindow);
            string historical = JsonSerializer.Serialize(new { database.Database, database.Tables });
            Assert.Equal(historical, JsonSerializer.Serialize(database));
        });
        Assert.DoesNotContain("SourceReadWindow", Encoding.UTF8.GetString(
            DeltaSynchronizationPlanCanonicalizer.CreatePayload(plan)), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Source_read_windows_cover_awaited_lobs_and_provider_disposal_and_are_signed()
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        var source = new WindowRows(clock);
        var target = new Rows(_ => []);
        DeltaSynchronizationPlan plan = await new Exact23DeltaPlanCoordinator(source, target, signer, clock)
            .ProduceAsync(WindowRequest(signer), CancellationToken.None);

        Assert.Equal("1.2", plan.SchemaVersion);
        Assert.Equal(47, clock.Reads);
        Assert.Equal(23, source.LobsConsumed);
        Assert.Equal(23, source.Disposals.Count);
        for (int index = 0; index < plan.Databases.Count; index++)
        {
            DeltaSourceReadWindow window = Assert.IsType<DeltaSourceReadWindow>(plan.Databases[index].SourceReadWindow);
            Assert.Equal(WindowEpoch.AddSeconds(index * 2), window.StartedAtUtc);
            Assert.Equal(source.Disposals[index], window.CompletedAtUtc);
            Assert.Equal(window.StartedAtUtc.AddSeconds(2), window.CompletedAtUtc);
        }
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(plan, trust, clock.Utc));
        DeltaDatabasePlan changed = plan.Databases[0] with
        {
            SourceReadWindow = plan.Databases[0].SourceReadWindow! with { CompletedAtUtc = WindowEpoch.AddSeconds(1) },
        };
        DeltaSynchronizationPlan tampered = plan with { Databases = [changed, .. plan.Databases.Skip(1)] };
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(tampered, trust, clock.Utc));
        Assert.Equal(DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(plan.Databases[0]),
            DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(changed));
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public async Task Source_read_windows_reject_unsupported_request_before_provider_or_clock(bool live, bool transition)
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        var rows = new Rows(_ => []);
        Exact23DeltaPlanRequest request = WindowRequest(signer) with
        {
            SourceMode = live ? DeltaSourceMode.LiveReadOnly : null,
            UseQuotationPhysicalTransition = transition,
        };
        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            new Exact23DeltaPlanCoordinator(rows, rows, signer, clock).ProduceAsync(request, CancellationToken.None));
        Assert.Equal("delta_plan_source_read_window_mode_invalid", error.Code);
        Assert.Equal(0, rows.Reads);
        Assert.Equal(0, clock.Reads);
    }

    [Theory]
    [InlineData("enumeration")]
    [InlineData("lob")]
    [InlineData("disposal")]
    [InlineData("cancel")]
    public async Task Source_read_windows_never_return_partial_plan_when_provider_fails(string failure)
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        using var cancellation = new CancellationTokenSource();
        var source = new WindowRows(clock, failure, cancellation);
        var coordinator = new Exact23DeltaPlanCoordinator(source, new Rows(_ => []), signer, clock);
        _ = await Assert.ThrowsAnyAsync<Exception>(() => coordinator.ProduceAsync(WindowRequest(signer), cancellation.Token));
        _ = Assert.Single(source.Disposals);
        Assert.Equal(1, clock.Reads); // no completed-window clock and no final signing clock
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Source_read_windows_captured_coordinator_rejects_before_dependency_access(bool persistentOptIn)
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        // Poison dependencies prove the mode guard runs before any provider, archive or inspector access.
        var coordinator = new Exact23CapturedDeltaPlanCoordinator(null!, null!, null!, null!, signer, clock);
        Exact23DeltaPlanRequest request = WindowRequest(signer);
        DeltaPlanException error = persistentOptIn
            ? await Assert.ThrowsAsync<DeltaPlanException>(() => coordinator.ProducePairedAsync(
                request with { RecordSourceReadWindows = false }, request,
                new WindowPoisonSnapshot(), signer,
                ReadOnlyMemory<byte>.Empty, CancellationToken.None))
            : await Assert.ThrowsAsync<DeltaPlanException>(() => coordinator.ProduceAsync(
                request, ReadOnlyMemory<byte>.Empty, CancellationToken.None));
        Assert.Equal("delta_plan_source_read_window_mode_invalid", error.Code);
        Assert.Equal(0, clock.Reads);
    }

    [Fact]
    public async Task Source_read_windows_producer_and_verifier_reject_signed_partial_windows()
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var clock = new WindowClock(WindowEpoch);
        var rows = new Rows(_ => []);
        DeltaSynchronizationPlan valid = await new Exact23DeltaPlanCoordinator(rows, rows, signer, clock)
            .ProduceAsync(WindowRequest(signer), CancellationToken.None);
        DeltaSynchronizationPlan partial = valid with
        {
            Databases = [valid.Databases[0] with { SourceReadWindow = null }, .. valid.Databases.Skip(1)],
        };
        var signingRequest = new DeltaPlanSigningRequest(partial.SourceCommitSha, partial.SourceCutoffUtc,
            partial.BackupManifestSha256, partial.SchemaPlanSha256, partial.RunnerDigestSha256,
            partial.TargetNamespace, partial.TargetCluster, partial.TargetGeneration, partial.TargetObservationSha256,
            partial.BackupKeyFingerprintSha256, partial.ExecutionAuthorizationKeyFingerprintSha256, partial.Databases)
        {
            TargetAuthority = partial.TargetAuthority,
            SourceMode = partial.SourceMode,
            SourceObservationSha256 = partial.SourceObservationSha256,
            SourceCaptureCompletedAtUtc = partial.SourceCaptureCompletedAtUtc,
        };
        Assert.Equal("delta_plan_source_read_window_invalid", Assert.Throws<DeltaPlanException>(() =>
            DeltaSynchronizationPlanProducer.Produce(signingRequest, signer, clock.Utc)).Code);
        partial = partial with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                DeltaSynchronizationPlanCanonicalizer.CreatePayload(partial))),
        };
        var trust = new ReceiptAttestationTrustStore([new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(partial, trust, clock.Utc));
    }

    [Theory]
    [InlineData("partial")]
    [InlineData("offset-start")]
    [InlineData("offset-end")]
    [InlineData("backward")]
    [InlineData("overlap")]
    [InlineData("before-cutoff")]
    [InlineData("after-completion")]
    [InlineData("captured")]
    [InlineData("wrong-mode")]
    [InlineData("missing-completion")]
    [InlineData("offset-completion")]
    [InlineData("created-before-completion")]
    public void Source_read_windows_validate_all_or_none_utc_order_and_containment(string invalid)
    {
        DeltaDatabasePlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select((name, index) =>
            new DeltaDatabasePlan(name, [])
            {
                SourceReadWindow = new(WindowEpoch.AddSeconds(index * 2), WindowEpoch.AddSeconds((index * 2) + 1)),
            })];
        DeltaSourceReadWindow first = databases[0].SourceReadWindow!;
        databases[0] = databases[0] with
        {
            SourceReadWindow = invalid switch
            {
                "partial" => null,
                "offset-start" => first with { StartedAtUtc = first.StartedAtUtc.ToOffset(TimeSpan.FromHours(7)) },
                "offset-end" => first with { CompletedAtUtc = first.CompletedAtUtc.ToOffset(TimeSpan.FromHours(7)) },
                "backward" => first with { CompletedAtUtc = first.StartedAtUtc.AddTicks(-1) },
                "overlap" => first with { CompletedAtUtc = WindowEpoch.AddSeconds(3) },
                "before-cutoff" => first with { StartedAtUtc = WindowEpoch.AddTicks(-1) },
                "after-completion" => first with { CompletedAtUtc = WindowEpoch.AddMinutes(2) },
                _ => first,
            },
        };
        DeltaPlanException error = Assert.Throws<DeltaPlanException>(() =>
            DeltaSynchronizationPlanProducer.ValidateSourceReadWindows(databases,
                invalid == "wrong-mode" ? null : DeltaSourceMode.LiveReadOnly,
                WindowEpoch, invalid switch
                {
                    "missing-completion" => null,
                    "offset-completion" => WindowEpoch.AddMinutes(1).ToOffset(TimeSpan.FromHours(7)),
                    _ => WindowEpoch.AddMinutes(1),
                }, invalid == "created-before-completion" ? WindowEpoch : WindowEpoch.AddMinutes(1),
                invalid == "captured"));
        Assert.Equal("delta_plan_source_read_window_invalid", error.Code);
    }

    [Theory]
    [InlineData(false, false, false, false)]
    [InlineData(true, true, false, false)]
    [InlineData(true, false, true, false)]
    [InlineData(true, false, false, true)]
    public void Source_read_windows_console_rejects_nonordinary_modes(bool live, bool capture, bool transition, bool paired)
    {
        DeltaCommandConfiguration configuration = WindowConfiguration() with
        {
            SourceMode = live ? DeltaSourceMode.LiveReadOnly : null,
            UseCapturedSource = capture,
            UseQuotationPhysicalTransition = transition,
        };
        _ = Assert.Throws<DeltaPlanException>(() =>
            DefaultGuardedDeltaConsoleRuntime.RequireSourceReadWindowMode(configuration, paired));
        DefaultGuardedDeltaConsoleRuntime.RequireSourceReadWindowMode(
            configuration with { RecordSourceReadWindows = false }, paired);
    }

    [Fact]
    public void Source_read_windows_console_requires_explicit_opt_in_and_accepts_ordinary_live()
    {
        DeltaCommandConfiguration configuration = WindowConfiguration();
        DefaultGuardedDeltaConsoleRuntime.RequireSourceReadWindowMode(configuration, paired: false);
        string serialized = JsonSerializer.Serialize(configuration with { RecordSourceReadWindows = false });
        using JsonDocument document = JsonDocument.Parse(serialized);
        Assert.False(document.RootElement.GetProperty("RecordSourceReadWindows").GetBoolean());
        JsonObject historical = Assert.IsType<JsonObject>(JsonNode.Parse(serialized));
        Assert.True(historical.Remove("RecordSourceReadWindows"));
        DeltaCommandConfiguration decoded = Assert.IsType<DeltaCommandConfiguration>(
            JsonSerializer.Deserialize<DeltaCommandConfiguration>(historical.ToJsonString()));
        Assert.False(decoded.RecordSourceReadWindows);
    }

    [Fact]
    public async Task Source_read_windows_console_runtime_rejects_capture_before_observation_or_session_creation()
    {
        using var signer = new P256MigrationEvidenceSigner("plan", _key.ExportECPrivateKeyPem());
        var factory = new WindowPoisonFactory();
        var runtime = new DefaultGuardedDeltaConsoleRuntime(factory);
        var request = new DeltaPlanRuntimeRequest(Schema(WindowEpoch), "not a connection string",
            "not a connection string", WindowConfiguration() with { UseCapturedSource = true }, Hash('f'), signer);
        DeltaPlanException error = await Assert.ThrowsAsync<DeltaPlanException>(() =>
            runtime.PlanAsync(request, CancellationToken.None));
        Assert.Equal("delta_plan_source_read_window_mode_invalid", error.Code);
        Assert.Equal(0, factory.Calls);
    }

    private static DeltaCommandConfiguration WindowConfiguration()
    {
        var key = new DeltaTrustedKeyReference("key", "unused");
        return new("unused", "unused", "unused", "unused", key, key, key, Hash('2'),
            WindowEpoch, Hash('3'), Hash('4'), "maliev-legacy", "legacy-postgres-main", "generation", Hash('5'),
            new(DeltaTargetAuthorityKind.ProductionCloudNativePg, "gke://maliev-website/test", Hash('6')))
        {
            SourceMode = DeltaSourceMode.LiveReadOnly,
            RecordSourceReadWindows = true,
        };
    }

    private static Exact23DeltaPlanRequest WindowRequest(P256MigrationEvidenceSigner signer)
    {
        return Request(Schema(WindowEpoch), signer, WindowEpoch) with
        {
            SourceMode = DeltaSourceMode.LiveReadOnly,
            SourceObservationSha256 = Hash('7'),
            RecordSourceReadWindows = true,
        };
    }

    private sealed class WindowClock(DateTimeOffset utc) : TimeProvider
    {
        internal DateTimeOffset Utc { get; private set; } = utc;
        internal int Reads { get; private set; }
        internal void Advance()
        {
            Utc = Utc.AddSeconds(1);
        }

        public override DateTimeOffset GetUtcNow()
        {
            Reads++;
            return Utc;
        }
    }

    private sealed class WindowPoisonFactory : IMigrationSourceFactory
    {
        internal int Calls { get; private set; }
        public IMigrationSourceSession Create(string protectedConnectionReference)
        {
            Calls++;
            throw new InvalidOperationException("Source session must not be created.");
        }
    }

    private sealed class WindowPoisonSnapshot : IDeltaDatabaseSnapshotRowSource
    {
        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No snapshot access allowed.");
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No snapshot access allowed.");
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No snapshot access allowed.");
        }

        public IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
                    CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("No stream access allowed.");
        }
    }

    private sealed class WindowRows(WindowClock clock, string? failure = null,
        CancellationTokenSource? cancellation = null) : IDeltaOrderedRowSource
    {
        internal List<DateTimeOffset> Disposals { get; } = [];
        internal int LobsConsumed { get; private set; }
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            try
            {
                await Task.Yield();
                if (failure == "enumeration")
                {
                    throw new IOException("test stream failure");
                }
                byte[] bytes = Encoding.UTF8.GetBytes("ข้อความ");
                var lob = new StreamingLob(StreamingLobKind.Text, bytes.Length, async (destination, token) =>
                {
                    await Task.Yield();
                    if (failure == "lob")
                    {
                        throw new IOException("test LOB failure");
                    }
                    if (failure == "cancel")
                    {
                        cancellation!.Cancel();
                    }
                    token.ThrowIfCancellationRequested();
                    await destination.WriteAsync(bytes, token);
                    clock.Advance();
                    LobsConsumed++;
                });
                yield return new(new Dictionary<string, object?> { ["id"] = 1, ["value"] = lob });
                cancellationToken.ThrowIfCancellationRequested();
            }
            finally
            {
                await Task.Yield();
                clock.Advance();
                Disposals.Add(clock.Utc);
                if (failure == "disposal")
                {
#pragma warning disable CA2219 // Deliberate disposal fault proves that an incomplete read window cannot be signed.
                    throw new IOException("test asynchronous disposal failure");
#pragma warning restore CA2219
                }
            }
        }
    }
}
