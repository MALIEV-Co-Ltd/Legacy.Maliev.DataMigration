using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests : IDisposable
{
    [Fact]
    public void Local_transition_preflight_rejects_mid_scan_metadata_replay_or_rollback()
    {
        var pending = new PairedLocalTransitionMetadataObservation(
            PairedLocalTransitionMetadataState.Pending, Hash('1'));
        PairedLocalTransitionPreflight.RequireMetadataUnchanged(pending, pending);
        foreach (PairedLocalTransitionMetadataState changed in new[]
            { PairedLocalTransitionMetadataState.Unprovisioned, PairedLocalTransitionMetadataState.Replayed })
        {
            Assert.Equal("delta_paired_local_metadata_changed",
                Assert.Throws<DeltaExecutionException>(() =>
                    PairedLocalTransitionPreflight.RequireMetadataUnchanged(pending,
                        new(changed, Hash('1')))).Code);
        }
        Assert.Equal("delta_paired_local_metadata_changed",
            Assert.Throws<DeltaExecutionException>(() =>
                PairedLocalTransitionPreflight.RequireMetadataUnchanged(pending,
                    new(PairedLocalTransitionMetadataState.Pending, Hash('2')))).Code);
    }

    private readonly ECDsa _planKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _localPlanKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private readonly ECDsa _continuityKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    [Fact]
    public async Task Historical_local_current_target_review_compares_all_23_without_authorizing_execution()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        HistoricalCurrentLocalObservation observation = CurrentObservation(fixture);
        var observations = 0;

        HistoricalPairedLocalCurrentTargetReview result = await HistoricalPairedLocalCurrentTargetReviewer
            .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                _ =>
                {
                    observations++;
                    return Task.FromResult(observation);
                },
                new CurrentEvidenceInspector(fixture.Schema), new FixedTime(fixture.Now.AddDays(1)),
                CancellationToken.None);

        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, result.DatabasesCompared);
        Assert.Equal(fixture.LocalPlan.SourceCutoffUtc, result.HistoricalSourceCutoffUtc);
        Assert.Equal(2, observations);
        Assert.False(HistoricalPairedLocalCurrentTargetReview.AuthorizesExecution);
    }

    [Fact]
    public async Task Historical_local_current_target_review_rejects_schema_rows_and_identity_drift()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        HistoricalCurrentLocalObservation observation = CurrentObservation(fixture);
        var clock = new FixedTime(fixture.Now.AddDays(1));
        var inspector = new CurrentEvidenceInspector(fixture.Schema);

        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt,
                    fixture.Schema with { CapturedAtUtc = fixture.Schema.CapturedAtUtc.AddMinutes(1) },
                    fixture.Trust, _ => Task.FromResult(observation), inspector, clock,
                    CancellationToken.None))).Code);
        Assert.Equal("shadow_reconciliation_failed",
            (await Assert.ThrowsAsync<MigrationExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema, driftRow: true),
                    clock, CancellationToken.None))).Code);
        Assert.Equal("shadow_reconciliation_failed",
            (await Assert.ThrowsAsync<MigrationExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema, driftContent: true),
                    clock, CancellationToken.None))).Code);
        Assert.Equal("shadow_reconciliation_failed",
            (await Assert.ThrowsAsync<MigrationExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema, driftSequence: true),
                    clock, CancellationToken.None))).Code);
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation with { SystemIdentifierSha256 = Hash('9') }),
                    inspector, clock, CancellationToken.None))).Code);
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation with
                    {
                        VolumeCreatedAtUtc = observation.VolumeCreatedAtUtc.AddMilliseconds(1),
                    }), inspector, clock, CancellationToken.None))).Code);
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(observation with { VolumeMountpoint = string.Empty }),
                    inspector, clock, CancellationToken.None))).Code);
        var count = 0;
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => HistoricalPairedLocalCurrentTargetReviewer
                .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                    _ => Task.FromResult(++count == 1 ? observation :
                        CurrentObservation(fixture, '9')),
                    inspector, clock, CancellationToken.None))).Code);
        Assert.Equal(2, count);
    }

    [Fact]
    public async Task Historical_postgresql_inspector_uses_disposable_read_only_snapshot_without_old_permit()
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string admin = container.GetConnectionString();
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true, physicalTargetHashes: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        DatabaseSchemaPlan schema = fixture.Schema.Databases.Single(item => item.Database == "ContactRequest");
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync();
            await using var command = new NpgsqlCommand("CREATE DATABASE \"ContactRequest\" TEMPLATE template0;", connection);
            _ = await command.ExecuteNonQueryAsync();
        }
        string target = new NpgsqlConnectionStringBuilder(admin)
        {
            Database = schema.Database,
            Pooling = false,
        }.ConnectionString;
        await using (var connection = new NpgsqlConnection(target))
        {
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
                ownsResources: false);
            await writer.ApplySchemaAsync(schema, CancellationToken.None);
            await writer.FinalizeSchemaAsync(schema, CancellationToken.None);
            await transaction.CommitAsync();
        }
        var inspector = new HistoricalPostgreSqlDeltaReconciliationInspector(admin,
            fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust, fixture.Now.AddDays(1));

        DatabaseReconciliationEvidence observed = await inspector.InspectAsync(schema, CancellationToken.None);

        Assert.Equal(schema.Database, observed.Database);
        Assert.Equal(0, Assert.Single(observed.Tables).RowCount);
        await using var verify = new NpgsqlConnection(target);
        await verify.OpenAsync();
        await using var count = new NpgsqlCommand("SELECT count(*) FROM public.items;", verify);
        Assert.Equal(0L, await count.ExecuteScalarAsync());
    }

    [Fact]
    public async Task Historical_local_command_uses_public_only_trust_and_never_observes_a_tampered_receipt()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        string directory = Path.Combine(Path.GetTempPath(), "historical-local-review-" + Guid.NewGuid().ToString("N"));
        OwnerProtectedDirectory.CreateNew(directory);
        try
        {
            string planPath = Path.Combine(directory, "plan.json");
            string receiptPath = Path.Combine(directory, "receipt.json");
            string schemaPath = Path.Combine(directory, "schema.json");
            string connectionPath = Path.Combine(directory, "target.connection");
            string planKeyPath = Path.Combine(directory, "plan.public");
            string evidenceKeyPath = Path.Combine(directory, "evidence.public");
            await MigrationConsole.WriteNewJsonForTestsAsync(planPath, fixture.LocalPlan, CancellationToken.None);
            await MigrationConsole.WriteNewJsonForTestsAsync(receiptPath, receipt, CancellationToken.None);
            await MigrationConsole.WriteNewJsonForTestsAsync(schemaPath, fixture.Schema, CancellationToken.None);
            await WriteOwnerOnlyTextAsync(connectionPath,
                "Host=127.0.0.1;Port=5432;Database=postgres;Username=unused;Password=unused");
            await WriteOwnerOnlyTextAsync(planKeyPath,
                Convert.ToBase64String(_localPlanKey.ExportSubjectPublicKeyInfo()));
            await WriteOwnerOnlyTextAsync(evidenceKeyPath,
                Convert.ToBase64String(_evidenceKey.ExportSubjectPublicKeyInfo()));
            var request = new HistoricalLocalReviewCommandConfiguration(planPath, receiptPath, schemaPath,
                connectionPath, Hash('8'), 5432, new(fixture.LocalPlan.AttestationKeyId, planKeyPath),
                new(receipt.AttestationKeyId, evidenceKeyPath), Path.Combine(directory, "review.json"));
            string configPath = Path.Combine(directory, "config.json");
            await MigrationConsole.WriteNewJsonForTestsAsync(configPath,
                new { historicalLocalReview = request }, CancellationToken.None);
            var runtime = new HistoricalRuntime(fixture);
            static string? EnvironmentValue(string key)
            {
                return key switch
                {
                    "LEGACY_DEPLOY_ENABLED" => "false",
                    "LEGACY_MIGRATION_CALLER" => "owner",
                    _ => null,
                };
            }
            using var output = new StringWriter();
            using var error = new StringWriter();
            int result = await MigrationConsole.RunHistoricalLocalReviewForTestsAsync(
                ["review-historical-local-target", "--config", configPath], output, error,
                EnvironmentValue, runtime, CancellationToken.None);

            Assert.Equal(0, result);
            Assert.Equal(2, runtime.Observations);
            Assert.Equal(string.Empty, error.ToString());
            Assert.Equal("review_historical_local_target_complete" + Environment.NewLine, output.ToString());
            Assert.True(OwnerProtectedFilePolicy.IsOwnerOnly(request.OutputPath));
            string reviewJson = await File.ReadAllTextAsync(request.OutputPath);
            Assert.DoesNotContain("Password", reviewJson, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain("authorization", reviewJson, StringComparison.OrdinalIgnoreCase);

            var diagnostic = new ReconciliationDiagnostic("ContactRequest", "public.Message",
                "ordered-content", Hash('a'), Hash('b'))
            {
                Field = "secret customer value",
            };
            string driftConfigPath = Path.Combine(directory, "drift-config.json");
            HistoricalLocalReviewCommandConfiguration driftRequest = request with
            {
                OutputPath = Path.Combine(directory, "drift-review.json"),
            };
            await MigrationConsole.WriteNewJsonForTestsAsync(driftConfigPath,
                new { historicalLocalReview = driftRequest }, CancellationToken.None);
            var driftRuntime = new HistoricalRuntime(fixture, diagnostic);
            using var driftOutput = new StringWriter();
            using var driftError = new StringWriter();
            int driftResult = await MigrationConsole.RunHistoricalLocalReviewForTestsAsync(
                ["review-historical-local-target", "--config", driftConfigPath], driftOutput, driftError,
                EnvironmentValue, driftRuntime, CancellationToken.None);
            Assert.Equal(65, driftResult);
            Assert.False(File.Exists(driftRequest.OutputPath));
            string[] driftLines = driftError.ToString().Split(Environment.NewLine,
                StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal("shadow_reconciliation_failed", driftLines[0]);
            using (JsonDocument driftDetail = JsonDocument.Parse(Assert.Single(driftLines.Skip(1))))
            {
                Assert.Equal(["database", "table", "check"],
                    driftDetail.RootElement.EnumerateObject().Select(property => property.Name));
                Assert.Equal("ContactRequest", driftDetail.RootElement.GetProperty("database").GetString());
                Assert.Equal("public.Message", driftDetail.RootElement.GetProperty("table").GetString());
                Assert.Equal("ordered-content", driftDetail.RootElement.GetProperty("check").GetString());
            }
            Assert.DoesNotContain(Hash('a'), driftError.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain(Hash('b'), driftError.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("secret customer value", driftError.ToString(), StringComparison.Ordinal);

            var malformedCodeRuntime = new HistoricalRuntime(fixture, diagnostic, "private_secret");
            using var malformedCodeError = new StringWriter();
            int malformedCodeResult = await MigrationConsole.RunHistoricalLocalReviewForTestsAsync(
                ["review-historical-local-target", "--config", driftConfigPath], TextWriter.Null,
                malformedCodeError, EnvironmentValue, malformedCodeRuntime, CancellationToken.None);
            Assert.Equal(65, malformedCodeResult);
            Assert.StartsWith("shadow_reconciliation_failed" + Environment.NewLine,
                malformedCodeError.ToString(), StringComparison.Ordinal);
            Assert.DoesNotContain("private_secret", malformedCodeError.ToString(), StringComparison.Ordinal);

            string badReceiptPath = Path.Combine(directory, "bad-receipt.json");
            await MigrationConsole.WriteNewJsonForTestsAsync(badReceiptPath,
                receipt with { PlanSha256 = Hash('9') }, CancellationToken.None);
            string badConfigPath = Path.Combine(directory, "bad-config.json");
            HistoricalLocalReviewCommandConfiguration badRequest = request with
            {
                HistoricalReceiptPath = badReceiptPath,
                OutputPath = Path.Combine(directory, "bad-review.json"),
            };
            await MigrationConsole.WriteNewJsonForTestsAsync(badConfigPath,
                new { historicalLocalReview = badRequest }, CancellationToken.None);
            var rejectedRuntime = new HistoricalRuntime(fixture);
            using var rejectedOutput = new StringWriter();
            using var rejectedError = new StringWriter();
            int rejected = await MigrationConsole.RunHistoricalLocalReviewForTestsAsync(
                ["review-historical-local-target", "--config", badConfigPath], rejectedOutput,
                rejectedError, EnvironmentValue, rejectedRuntime, CancellationToken.None);
            Assert.Equal(65, rejected);
            Assert.Equal(0, rejectedRuntime.Observations);
            Assert.False(File.Exists(Path.Combine(directory, "bad-review.json")));

            var disabledRuntime = new HistoricalRuntime(fixture);
            using var disabledOutput = new StringWriter();
            using var disabledError = new StringWriter();
            int disabled = await MigrationConsole.RunHistoricalLocalReviewForTestsAsync(
                ["review-historical-local-target", "--config", configPath], disabledOutput,
                disabledError, key => key == "LEGACY_DEPLOY_ENABLED" ? "true" : "owner",
                disabledRuntime, CancellationToken.None);
            Assert.Equal(65, disabled);
            Assert.Equal(0, disabledRuntime.Observations);
            Assert.Contains("delta_deploy_gate_invalid", disabledError.ToString(), StringComparison.Ordinal);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    [Fact]
    public async Task Historical_local_diagnostic_rejects_untrusted_identifiers_and_details()
    {
        using var error = new StringWriter();
        await MigrationConsole.WriteSafeHistoricalLocalDiagnosticAsync(error,
            new("ContactRequest", "public.customer@example.com", "schema", "private-expected", "private-observed"));
        using (JsonDocument detail = JsonDocument.Parse(error.ToString()))
        {
            Assert.Equal(JsonValueKind.Null, detail.RootElement.GetProperty("table").ValueKind);
            Assert.Equal("schema", detail.RootElement.GetProperty("check").GetString());
        }
        Assert.DoesNotContain("private", error.ToString(), StringComparison.Ordinal);
        _ = error.GetStringBuilder().Clear();
        await MigrationConsole.WriteSafeHistoricalLocalDiagnosticAsync(error,
            new("Customer@example.com", "public.Message", "schema", null, null));
        await MigrationConsole.WriteSafeHistoricalLocalDiagnosticAsync(error,
            new("ContactRequest", "public.Message", "secret-check", null, null));
        Assert.Equal(string.Empty, error.ToString());
    }

    [Fact]
    public void Historical_local_docker_observation_rejects_old_container_or_unbound_mountpoint()
    {
        string oldId = Hash('7');
        string currentId = Hash('8');
        DefaultHistoricalLocalReviewRuntime.RequireContainerInventory(currentId + "\n", oldId, currentId);
        Assert.Equal("delta_historical_local_old_container_present",
            Assert.Throws<MigrationConsoleException>(() =>
                DefaultHistoricalLocalReviewRuntime.RequireContainerInventory(
                    oldId + "\n" + currentId + "\n", oldId, currentId)).Code);
        Assert.Equal("delta_historical_local_docker_invalid",
            Assert.Throws<MigrationConsoleException>(() =>
                DefaultHistoricalLocalReviewRuntime.RequireContainerInventory(oldId + "\n", oldId,
                    currentId)).Code);
        Assert.Equal("/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data",
            DefaultHistoricalLocalReviewRuntime.ReadMountpoint(
                JsonSerializer.Serialize(new[]
                {
                    new { Mountpoint = "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data" },
                })));
        Assert.Equal("delta_historical_local_volume_invalid",
            Assert.Throws<MigrationConsoleException>(() =>
                DefaultHistoricalLocalReviewRuntime.ReadMountpoint(
                    JsonSerializer.Serialize(new[] { new { Mountpoint = string.Empty } }))).Code);
        string container = JsonSerializer.Serialize(new[]
        {
            new
            {
                Mounts = new[]
                {
                    new { Type = "volume", Name = "legacy-maliev-exact23-postgres-data", Source = "/actual/volume" },
                },
            },
        });
        DefaultHistoricalLocalReviewRuntime.RequireMountSource(container,
            "legacy-maliev-exact23-postgres-data", "/actual/volume");
        Assert.Equal("delta_historical_local_volume_invalid",
            Assert.Throws<MigrationConsoleException>(() =>
                DefaultHistoricalLocalReviewRuntime.RequireMountSource(container,
                    "legacy-maliev-exact23-postgres-data", "/reused/name")).Code);
    }

    [Fact]
    public async Task Historical_continuity_attestation_is_signed_but_never_authorizes_fence_adoption()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        HistoricalCurrentLocalObservation observation = CurrentObservation(fixture);
        DateTimeOffset comparedAt = fixture.Now.AddDays(1);
        HistoricalPairedLocalCurrentTargetReview review = await HistoricalPairedLocalCurrentTargetReviewer
            .CompareAsync(fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema),
                new FixedTime(comparedAt), CancellationToken.None);
        HistoricalLocalMetadataBinding[] metadata = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new HistoricalLocalMetadataBinding(database, PairedLocalTransitionMetadataState.SettledPrior, Hash('f')))];
        using var signer = new P256MigrationEvidenceSigner("continuity-review", _continuityKey.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(fixture.LocalPlan.AttestationKeyId, _localPlanKey.ExportSubjectPublicKeyInfo()),
                new(receipt.AttestationKeyId, _evidenceKey.ExportSubjectPublicKeyInfo()),
                new(signer.KeyId, signer.ExportSubjectPublicKeyInfo())]);
        string futurePlan = Hash('d');
        Guid futureAuthorization = Guid.NewGuid();
        DateTimeOffset issuedAt = comparedAt.AddMinutes(1);
        var unsigned = new HistoricalLocalContinuityAttestation("1.0", Guid.NewGuid(),
            DeltaSynchronizationPlanCanonicalizer.ComputeSha256(fixture.LocalPlan),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(receipt),
            SchemaPlanCanonicalizer.ComputeSha256(fixture.Schema), fixture.LocalPlan.SourceCutoffUtc,
            fixture.LocalPlan.TargetGeneration, observation.DockerGeneration,
            HistoricalLocalContinuityAttestationCanonicalizer.ComputeObservationSha256(observation),
            HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(review), true,
            metadata, futurePlan, futureAuthorization, issuedAt, issuedAt.AddMinutes(10), signer.KeyId, null);
        HistoricalLocalContinuityAttestation Sign(HistoricalLocalContinuityAttestation value)
        {
            return value with
            {
                AttestationSignature = Convert.ToBase64String(signer.Sign(
                    HistoricalLocalContinuityAttestationCanonicalizer.CreatePayload(value))),
            };
        }
        HistoricalLocalContinuityAttestation signed = Sign(unsigned);
        HistoricalLocalContinuityReview result = HistoricalLocalContinuityAttestationVerifier.Verify(
            signed, fixture.LocalPlan, receipt, fixture.Schema, review, observation, metadata,
            futurePlan, futureAuthorization, trust, issuedAt.AddMinutes(1));
        HistoricalLocalContinuityReview fresh = await HistoricalLocalContinuityAttestationVerifier
            .VerifyFreshAsync(signed, fixture.LocalPlan, receipt, fixture.Schema, review,
                _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema),
                _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(metadata),
                futurePlan, futureAuthorization, trust, new FixedTime(issuedAt.AddMinutes(1)),
                CancellationToken.None);
        Assert.Equal(result.AttestationSha256, fresh.AttestationSha256);
        Assert.Equal("shadow_reconciliation_failed", (await Assert.ThrowsAsync<MigrationExecutionException>(
            () => HistoricalLocalContinuityAttestationVerifier.VerifyFreshAsync(signed,
                fixture.LocalPlan, receipt, fixture.Schema, review, _ => Task.FromResult(observation),
                new CurrentEvidenceInspector(fixture.Schema, driftContent: true),
                _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(metadata),
                futurePlan, futureAuthorization, trust, new FixedTime(issuedAt.AddMinutes(1)),
                CancellationToken.None))).Code);
        int metadataObservations = 0;
        Assert.Equal("delta_historical_local_continuity_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                HistoricalLocalContinuityAttestationVerifier.VerifyFreshAsync(signed,
                    fixture.LocalPlan, receipt, fixture.Schema, review,
                    _ => Task.FromResult(observation), new CurrentEvidenceInspector(fixture.Schema),
                    _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(
                        ++metadataObservations == 1 ? metadata : metadata[..^1]),
                    futurePlan, futureAuthorization, trust, new FixedTime(issuedAt.AddMinutes(1)),
                    CancellationToken.None))).Code);
        Assert.Equal(2, metadataObservations);
        Assert.Equal("delta_historical_local_continuity_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                HistoricalLocalContinuityAttestationVerifier.VerifyFreshAsync(signed,
                    fixture.LocalPlan, receipt, fixture.Schema, review,
                    _ => Task.FromResult(observation with { VolumeMountpoint = "/replaced-volume" }),
                    new CurrentEvidenceInspector(fixture.Schema),
                    _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(metadata),
                    futurePlan, futureAuthorization, trust, new FixedTime(issuedAt.AddMinutes(1)),
                    CancellationToken.None))).Code);
        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, result.MetadataBindingsVerified);
        Assert.Equal(fixture.LocalPlan.SourceCutoffUtc, result.HistoricalSourceCutoffUtc);
        Assert.False(HistoricalLocalContinuityAttestation.AuthorizesExecution);
        Assert.False(HistoricalLocalContinuityReview.AuthorizesExecution);

        void Reject(HistoricalLocalContinuityAttestation candidate,
            HistoricalCurrentLocalObservation? current = null,
            IReadOnlyList<HistoricalLocalMetadataBinding>? observed = null,
            DateTimeOffset? at = null,
            string? expectedFuturePlan = null)
        {
            Assert.Equal("delta_historical_local_continuity_invalid",
                Assert.Throws<DeltaExecutionException>(() => HistoricalLocalContinuityAttestationVerifier
                    .Verify(candidate, fixture.LocalPlan, receipt, fixture.Schema, review,
                        current ?? observation, observed ?? metadata, expectedFuturePlan ?? futurePlan,
                        futureAuthorization, trust, at ?? issuedAt.AddMinutes(1))).Code);
        }
        Reject(signed with { CurrentReviewSha256 = Hash('9') });
        Reject(signed with { AttestationSignature = Convert.ToBase64String(new byte[64]) });
        Reject(Sign(unsigned with { FutureAuthorizationId = Guid.NewGuid() }));
        Reject(Sign(unsigned with { FormerContainerAbsentObserved = false }));
        Reject(Sign(unsigned with { PriorMetadata = metadata[..^1] }));
        HistoricalLocalMetadataBinding[] pending = [.. metadata];
        pending[0] = pending[0] with { State = PairedLocalTransitionMetadataState.Pending };
        Reject(Sign(unsigned with { PriorMetadata = pending }));
        Reject(signed, current: observation with { VolumeMountpoint = "/different" });
        Reject(signed, observed: metadata[..^1]);
        Reject(signed, at: issuedAt.AddMinutes(10));
        Reject(signed, expectedFuturePlan: Hash('a'));
        using var reusedSigner = new P256MigrationEvidenceSigner(fixture.LocalPlan.AttestationKeyId,
            _localPlanKey.ExportECPrivateKeyPem());
        HistoricalLocalContinuityAttestation reusedUnsigned = unsigned with
        {
            AttestationKeyId = reusedSigner.KeyId,
        };
        HistoricalLocalContinuityAttestation reused = reusedUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(reusedSigner.Sign(
                HistoricalLocalContinuityAttestationCanonicalizer.CreatePayload(reusedUnsigned))),
        };
        Reject(reused);
    }

    [Fact]
    public async Task Historical_continuity_issuer_binds_fresh_authorization_and_rejects_drift()
    {
        Fixture historical = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(historical);
        Fixture future = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, historicalLocal: true,
            futureDocker: true, at: historical.Now.AddDays(1));
        HistoricalCurrentLocalObservation observation = CurrentObservation(historical);
        HistoricalLocalMetadataBinding[] metadata = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new HistoricalLocalMetadataBinding(database, PairedLocalTransitionMetadataState.SettledPrior, Hash('f')))];
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        using var continuitySigner = new P256MigrationEvidenceSigner("continuity-review",
            _continuityKey.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(historical.LocalPlan.AttestationKeyId, _localPlanKey.ExportSubjectPublicKeyInfo()),
                new(receipt.AttestationKeyId, _evidenceKey.ExportSubjectPublicKeyInfo()),
                new(future.ProofPlan.AttestationKeyId, _planKey.ExportSubjectPublicKeyInfo()),
                new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo()),
                new(continuitySigner.KeyId, continuitySigner.ExportSubjectPublicKeyInfo())]);
        DateTimeOffset issuedAt = future.Now.AddMinutes(1);
        var plans = new PairedCapturedDeltaPlans(future.ProofPlan, future.LocalPlan);

        Task<HistoricalLocalContinuityIssuance> Issue(
            HistoricalCurrentLocalObservation? observed = null,
            HistoricalLocalMetadataBinding[]? prior = null,
            PairedCapturedDeltaPlans? candidatePlans = null,
            IDeltaReconciliationInspector? inspector = null,
            DateTimeOffset? expiry = null)
        {
            return HistoricalLocalContinuityIssuer.IssueAsync(historical.LocalPlan, receipt,
                historical.Schema, candidatePlans ?? plans, future.ProofResult, future.Schema, trust,
                _ => Task.FromResult(observed ?? observation),
                inspector ?? new CurrentEvidenceInspector(historical.Schema),
                _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(prior ?? metadata),
                expiry ?? issuedAt.AddMinutes(10), authorizationSigner, continuitySigner,
                new FixedTime(issuedAt), CancellationToken.None);
        }

        HistoricalLocalContinuityIssuance issued = await Issue();
        // The public bundle must retain the exact review signed into the attestation.
        // Recomputing this scan at a later time changes ComparedAtUtc and its hash.
        var wireOptions = new JsonSerializerOptions(
            JsonSerializerDefaults.Web);
        byte[] wire = JsonSerializer.SerializeToUtf8Bytes(issued, wireOptions);
        using var document = JsonDocument.Parse(wire);
        Assert.True(document.RootElement.TryGetProperty("currentTargetReview", out var reviewJson));
        HistoricalPairedLocalCurrentTargetReview publishedReview =
            reviewJson.Deserialize<HistoricalPairedLocalCurrentTargetReview>(wireOptions)!;
        Assert.Equal(issued.Attestation.CurrentReviewSha256,
            HistoricalLocalContinuityAttestationCanonicalizer.ComputeReviewSha256(publishedReview));
        Assert.False(HistoricalLocalContinuityIssuance.AuthorizesExecution);
        Assert.Equal(future.LocalPlan.PlanId, issued.FutureAuthorization.PersistentPlanId);
        Assert.Equal(issued.FutureAuthorization.AuthorizationId, issued.Attestation.FutureAuthorizationId);
        Assert.Equal(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(future.LocalPlan),
            issued.Attestation.FuturePlanSha256);
        Assert.Equal(23, issued.Attestation.PriorMetadata.Count);
        Assert.Equal("shadow_reconciliation_failed", (await Assert.ThrowsAsync<MigrationExecutionException>(
            () => Issue(inspector: new CurrentEvidenceInspector(historical.Schema, driftContent: true)))).Code);
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => Issue(observed: observation with
            {
                SystemIdentifierSha256 = Hash('9'),
            }))).Code);
        int observations = 0;
        Assert.Equal("delta_historical_local_current_target_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                HistoricalLocalContinuityIssuer.IssueAsync(historical.LocalPlan, receipt,
                    historical.Schema, plans, future.ProofResult, future.Schema, trust,
                    _ => Task.FromResult(++observations == 1 ? observation : observation with
                    {
                        VolumeMountpoint = "/replaced-volume",
                    }), new CurrentEvidenceInspector(historical.Schema),
                    _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(metadata),
                    issuedAt.AddMinutes(10), authorizationSigner, continuitySigner,
                    new FixedTime(issuedAt), CancellationToken.None))).Code);
        HistoricalLocalMetadataBinding[] pending = [.. metadata];
        pending[0] = pending[0] with { State = PairedLocalTransitionMetadataState.Pending };
        Assert.Equal("delta_historical_local_continuity_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => Issue(prior: pending))).Code);
        int metadataReads = 0;
        Assert.Equal("delta_historical_local_continuity_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                HistoricalLocalContinuityIssuer.IssueAsync(historical.LocalPlan, receipt,
                    historical.Schema, plans, future.ProofResult, future.Schema, trust,
                    _ => Task.FromResult(observation), new CurrentEvidenceInspector(historical.Schema),
                    _ => Task.FromResult<IReadOnlyList<HistoricalLocalMetadataBinding>>(
                        ++metadataReads == 1 ? metadata : pending),
                    issuedAt.AddMinutes(10), authorizationSigner, continuitySigner,
                    new FixedTime(issuedAt), CancellationToken.None))).Code);
        Assert.Equal(2, metadataReads);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => Issue(expiry: issuedAt))).Code);
        Assert.Equal("delta_historical_local_continuity_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => Issue(candidatePlans:
                plans with { Persistent = plans.Persistent with { TargetGeneration = Hash('9') } }))).Code);
    }

    [Fact]
    public async Task Historical_continuity_issue_command_is_owner_only_before_reading_config()
    {
        Fixture fixture = await CreateAsync();
        var runtime = new HistoricalRuntime(fixture);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int result = await MigrationConsole.RunHistoricalLocalContinuityIssueForTestsAsync(
            ["issue-historical-local-continuity", "--config", "nonexistent.json"],
            output, error, key => key switch
            {
                "LEGACY_DEPLOY_ENABLED" => "false",
                "LEGACY_MIGRATION_CALLER" => "operator",
                _ => null,
            }, runtime, CancellationToken.None);
        Assert.Equal(65, result);
        Assert.Equal("delta_caller_invalid", error.ToString().Trim());
        Assert.Equal(0, runtime.Observations);
    }

    private static async Task WriteOwnerOnlyTextAsync(string path, string content)
    {
        var options = new FileStreamOptions
        {
            Mode = FileMode.CreateNew,
            Access = FileAccess.Write,
            Share = FileShare.None,
            Options = FileOptions.Asynchronous,
        };
        if (!OperatingSystem.IsWindows())
        {
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        }
        await using var stream = new FileStream(path, options);
        await stream.WriteAsync(Encoding.UTF8.GetBytes(content));
        await stream.FlushAsync();
    }

    private sealed class HistoricalRuntime(Fixture fixture, ReconciliationDiagnostic? failure = null,
        string failureCode = "shadow_reconciliation_failed")
        : IHistoricalLocalReviewRuntime
    {
        public int Observations { get; private set; }

        public Task<HistoricalCurrentLocalObservation> ObserveAsync(HistoricalLocalReviewCommandConfiguration _,
            string __, DeltaSynchronizationPlan ___, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            Observations++;
            return Task.FromResult(CurrentObservation(fixture));
        }

        public IDeltaReconciliationInspector CreateInspector(string _, DeltaSynchronizationPlan __,
            Exact23DeltaReconciliationResult ___, FreshSchemaPlan ____, ReceiptAttestationTrustStore _____,
            DateTimeOffset ______)
        {
            return failure is null
                ? new CurrentEvidenceInspector(fixture.Schema)
                : new FailingHistoricalInspector(failure, failureCode);
        }
    }

    private sealed class FailingHistoricalInspector(ReconciliationDiagnostic diagnostic, string code)
        : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan _,
            CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            throw new MigrationExecutionException(code, "secret provider detail")
            {
                Reconciliation = diagnostic,
            };
        }
    }

    private static HistoricalCurrentLocalObservation CurrentObservation(Fixture fixture, char id = '8')
    {
        string containerId = Hash(id);
        return new(containerId, $"docker:{containerId}:4:5:3",
            "legacy-maliev-exact23-postgres-data", DateTimeOffset.FromUnixTimeMilliseconds(3),
            "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data",
            "/var/lib/postgresql/data", "/var/lib/postgresql/data/pgdata",
            fixture.LocalPlan.TargetAuthority!.SystemIdentifierSha256);
    }

    private sealed class CurrentEvidenceInspector(FreshSchemaPlan schema, bool driftRow = false,
        bool driftContent = false, bool driftSequence = false)
        : IDeltaReconciliationInspector
    {
        public async Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan database,
            CancellationToken cancellationToken)
        {
            DatabaseReconciliationEvidence evidence = await new Inspector(pairedTransition: true, schema)
                .InspectAsync(database, cancellationToken);
            return database.Database != "ContactRequest"
                ? evidence
                : (driftRow, driftContent, driftSequence) switch
                {
                    (true, _, _) => evidence with { Tables = [evidence.Tables[0] with { RowCount = 2 }] },
                    (_, true, _) => evidence with { Tables = [evidence.Tables[0] with { ContentSha256 = Hash('f') }] },
                    (_, _, true) => evidence with
                    {
                        SequenceNextValues = new Dictionary<string, long> { ["public.items.Id"] = 2 },
                    },
                    _ => evidence,
                };
        }
    }

    [Fact]
    public async Task Historical_persistent_local_receipt_is_reviewable_but_never_authorizes_execution()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        DateTimeOffset later = fixture.Now.AddMonths(1);

        HistoricalPairedLocalEvidenceReview review = HistoricalPairedLocalEvidenceReviewer.Verify(
            fixture.LocalPlan, receipt, fixture.Trust, later);

        Assert.Equal(DatabaseInventory.ActiveDatabases.Count, review.DatabasesVerified);
        Assert.Equal(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(fixture.LocalPlan), review.PlanSha256);
        Assert.False(HistoricalPairedLocalEvidenceReview.AuthorizesExecution);
        Assert.False(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, later));
    }

    [Fact]
    public async Task Historical_persistent_local_review_rejects_missing_tampered_or_foreign_evidence()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        DateTimeOffset later = fixture.Now.AddMonths(1);

        void Reject(DeltaSynchronizationPlan? plan, Exact23DeltaReconciliationResult? result,
            IReceiptAttestationTrustStore? trust = null)
        {
            Assert.Equal("delta_historical_local_evidence_invalid",
                Assert.Throws<DeltaExecutionException>(() => HistoricalPairedLocalEvidenceReviewer.Verify(
                    plan, result, trust ?? fixture.Trust, later)).Code);
        }

        Reject(null, receipt);
        Reject(fixture.LocalPlan, null);
        Reject(fixture.LocalPlan, fixture.ProofResult);
        Reject(fixture.LocalPlan with { SourceCaptureManifest = null }, receipt);
        Reject(fixture.LocalPlan with { TargetGeneration = $"docker:{Hash('9')}:1:2:3" }, receipt);
        Reject(fixture.LocalPlan, receipt with { PlanSha256 = Hash('9') });
        Reject(fixture.LocalPlan, receipt with { Checkpoints = receipt.Checkpoints.Skip(1).ToArray() });
        Reject(fixture.LocalPlan, receipt with
        {
            Checkpoints = [receipt.Checkpoints[0] with { OperationsSha256 = Hash('9') },
                .. receipt.Checkpoints.Skip(1)],
        });
        Reject(fixture.LocalPlan, receipt with
        {
            Databases = [receipt.Databases[0] with { Tables = [] }, .. receipt.Databases.Skip(1)],
        });
        Reject(fixture.LocalPlan, receipt, new ReceiptAttestationTrustStore([]));
        Reject(fixture.LocalPlan, receipt with { ReconciledAtUtc = later.AddDays(1) });
    }

    private async Task<Exact23DeltaReconciliationResult> HistoricalReceiptAsync(Fixture fixture, bool postgresTimestamps = false)
    {
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence",
            _evidenceKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust,
            fixture.LocalPlan.TargetAuthority!, fixture.LocalPlan.TargetObservationSha256,
            fixture.LocalPlan.QuotationTransitionSchemaSha256!, fixture.Now.AddMinutes(-1),
            fixture.Now.AddMinutes(5), authorizationSigner);
        PairedLocalTransitionExecutionPermit permit = PairedLocalTransitionExecutionPermit.Admit(
            plans, fixture.ProofResult, authorization, fixture.Schema, fixture.Trust,
            fixture.LocalPlan.TargetAuthority!, fixture.LocalPlan.TargetObservationSha256,
            new FixedTime(fixture.Now));
        var inspector = new Inspector(pairedTransition: true, fixture.Schema);
        return await new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(fixture.LocalPlan, fixture.Schema, pairedTransition: true,
                postgresTimestamps: postgresTimestamps),
            new FixedTime(fixture.Now), evidenceSigner, localPermit: permit)
            .ReconcileAsync(fixture.LocalPlan, fixture.Schema, CancellationToken.None);
    }

    [Fact]
    public async Task Historical_local_metadata_accepts_only_PostgreSQL_precision_of_signed_source_cutoff()
    {
        DateTimeOffset cutoff = new DateTimeOffset(2026, 10, 1, 17, 5, 39, TimeSpan.Zero).AddTicks(1654853);
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true, at: cutoff.AddMinutes(5));
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture, postgresTimestamps: true);
        Assert.Equal(cutoff, fixture.LocalPlan.SourceCutoffUtc);
        Assert.Equal(cutoff, receipt.SourceCutoffUtc);
        Assert.All(receipt.Checkpoints, checkpoint =>
            Assert.Equal(cutoff.AddTicks(-3), checkpoint.SourceCutoffUtc));
        HistoricalLocalMetadataSnapshot[] snapshots = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new HistoricalLocalMetadataSnapshot(database,
                new HistoricalLocalFence(database, fixture.LocalPlan.SchemaPlanSha256,
                    receipt.Databases.Single(item => item.Database == database).TargetSchemaSha256,
                    fixture.LocalPlan.TargetGeneration, fixture.LocalPlan.TargetObservationSha256),
                [receipt.Checkpoints.Single(item => item.Database == database)]))];
        Assert.Equal(23, HistoricalLocalMetadataReceiptBinder.Bind(fixture.LocalPlan, receipt,
            fixture.Schema, fixture.Trust, snapshots, fixture.Now.AddDays(1)).Count);
        HistoricalLocalMetadataSnapshot[] changed =
            [snapshots[0] with { Journal = [snapshots[0].Journal[0] with
                { SourceCutoffUtc = snapshots[0].Journal[0].SourceCutoffUtc.AddTicks(10) }] }, .. snapshots.Skip(1)];
        Assert.Equal("delta_historical_local_metadata_invalid",
            Assert.Throws<DeltaExecutionException>(() => HistoricalLocalMetadataReceiptBinder.Bind(
                fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust, changed,
                fixture.Now.AddDays(1))).Code);
    }

    [Fact]
    public async Task Historical_local_metadata_binds_all_settled_journals_to_signed_receipt()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        HistoricalLocalMetadataSnapshot[] snapshots = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new HistoricalLocalMetadataSnapshot(database,
                new HistoricalLocalFence(database, fixture.LocalPlan.SchemaPlanSha256,
                    receipt.Databases.Single(item => item.Database == database).TargetSchemaSha256,
                    fixture.LocalPlan.TargetGeneration, fixture.LocalPlan.TargetObservationSha256),
                [receipt.Checkpoints.Single(item => item.Database == database)]))];
        IReadOnlyList<HistoricalLocalMetadataBinding> bound = HistoricalLocalMetadataReceiptBinder.Bind(
            fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust, snapshots, fixture.Now.AddDays(1));
        Assert.Equal(DatabaseInventory.ActiveDatabases, bound.Select(item => item.Database));
        Assert.All(bound, item => Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior, item.State));
        Assert.Equal("delta_historical_local_metadata_invalid",
            Assert.Throws<DeltaExecutionException>(() => HistoricalLocalMetadataReceiptBinder.Bind(
                fixture.LocalPlan, receipt, fixture.Schema with { SchemaVersion = "1.0" },
                fixture.Trust, snapshots, fixture.Now.AddDays(1))).Code);
        HistoricalLocalMetadataSnapshot[] withEarlierJournal =
            [snapshots[0] with { Journal = [snapshots[0].Journal[0] with
                { PlanSha256 = Hash('9'), PlanId = Guid.NewGuid(),
                    CommittedAtUtc = snapshots[0].Journal[0].CommittedAtUtc.AddMinutes(-1) },
                snapshots[0].Journal[0]] }, .. snapshots.Skip(1)];
        Assert.Equal(23, HistoricalLocalMetadataReceiptBinder.Bind(fixture.LocalPlan, receipt,
            fixture.Schema, fixture.Trust, withEarlierJournal, fixture.Now.AddDays(1)).Count);

        void Reject(HistoricalLocalMetadataSnapshot[] changed)
        {
            Assert.Equal("delta_historical_local_metadata_invalid",
                Assert.Throws<DeltaExecutionException>(() => HistoricalLocalMetadataReceiptBinder.Bind(
                    fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust, changed,
                    fixture.Now.AddDays(1))).Code);
        }
        Reject(snapshots[..^1]);
        Reject([snapshots[0] with { Fence = snapshots[0].Fence with { TargetGeneration = $"docker:{Hash('9')}:1:2:3" } }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Fence = snapshots[0].Fence with { TargetSchemaSha256 = Hash('9') } }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0] with { ReconciliationSha256 = Hash('9') }] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0] with { OperationsSha256 = Hash('9') }] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0] with { ReconciliationSha256 = null! }] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0] with { CommittedAtUtc =
            snapshots[0].Journal[0].CommittedAtUtc.AddSeconds(1) }] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0], snapshots[0].Journal[0]] }, .. snapshots.Skip(1)]);
        Reject([snapshots[0] with { Journal = [snapshots[0].Journal[0], snapshots[0].Journal[0] with
            { PlanSha256 = Hash('9'), PlanId = Guid.NewGuid(), CommittedAtUtc = receipt.ReconciledAtUtc.AddSeconds(1) }] }, .. snapshots.Skip(1)]);
    }

    [Fact]
    public async Task Historical_local_metadata_reader_uses_disposable_read_only_exact23_snapshots()
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        var settings = new NpgsqlConnectionStringBuilder(container.GetConnectionString())
        {
            Host = "127.0.0.1",
            Database = "postgres",
        };
        string admin = settings.ConnectionString;
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        Exact23DeltaReconciliationResult receipt = await HistoricalReceiptAsync(fixture);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync();
                await using var create = new NpgsqlCommand($"CREATE DATABASE \"{database}\" TEMPLATE template0;", connection);
                _ = await create.ExecuteNonQueryAsync();
            }
            string target = new NpgsqlConnectionStringBuilder(admin) { Database = database }.ConnectionString;
            DeltaDatabaseCheckpointEvidence checkpoint = receipt.Checkpoints.Single(item => item.Database == database);
            string physical = receipt.Databases.Single(item => item.Database == database).TargetSchemaSha256;
            await using var targetConnection = new NpgsqlConnection(target);
            await targetConnection.OpenAsync();
            await using var setup = new NpgsqlCommand("""
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal.delta_fence(
                    database_name text PRIMARY KEY, schema_plan_sha256 text NOT NULL,
                    target_schema_sha256 text NOT NULL, target_generation text NOT NULL,
                    target_observation_sha256 text NOT NULL);
                CREATE TABLE legacy_migration_internal.delta_journal(
                    plan_sha256 text PRIMARY KEY, plan_id uuid NOT NULL UNIQUE,
                    source_cutoff_utc timestamptz NOT NULL, target_observation_sha256 text NOT NULL,
                    operations_sha256 text NOT NULL, reconciliation_sha256 text NOT NULL,
                    committed_at_utc timestamptz NOT NULL);
                """, targetConnection);
            _ = await setup.ExecuteNonQueryAsync();
            await using var fence = new NpgsqlCommand(
                "INSERT INTO legacy_migration_internal.delta_fence VALUES ($1,$2,$3,$4,$5);", targetConnection);
            _ = fence.Parameters.AddWithValue(database);
            _ = fence.Parameters.AddWithValue(fixture.LocalPlan.SchemaPlanSha256);
            _ = fence.Parameters.AddWithValue(physical);
            _ = fence.Parameters.AddWithValue(fixture.LocalPlan.TargetGeneration);
            _ = fence.Parameters.AddWithValue(fixture.LocalPlan.TargetObservationSha256);
            _ = await fence.ExecuteNonQueryAsync();
            await using var journal = new NpgsqlCommand(
                "INSERT INTO legacy_migration_internal.delta_journal VALUES ($1,$2,$3,$4,$5,$6,$7);",
                targetConnection);
            _ = journal.Parameters.AddWithValue(checkpoint.PlanSha256);
            _ = journal.Parameters.AddWithValue(checkpoint.PlanId);
            _ = journal.Parameters.AddWithValue(checkpoint.SourceCutoffUtc);
            _ = journal.Parameters.AddWithValue(checkpoint.TargetObservationSha256);
            _ = journal.Parameters.AddWithValue(checkpoint.OperationsSha256);
            _ = journal.Parameters.AddWithValue(checkpoint.ReconciliationSha256);
            _ = journal.Parameters.AddWithValue(checkpoint.CommittedAtUtc);
            _ = await journal.ExecuteNonQueryAsync();
            if (database == DatabaseInventory.ActiveDatabases[0])
            {
                await using var earlier = new NpgsqlCommand(
                    "INSERT INTO legacy_migration_internal.delta_journal VALUES ($1,$2,$3,$4,$5,$6,$7);",
                    targetConnection);
                _ = earlier.Parameters.AddWithValue(Hash('0'));
                _ = earlier.Parameters.AddWithValue(Guid.NewGuid());
                _ = earlier.Parameters.AddWithValue(checkpoint.SourceCutoffUtc.AddMinutes(-1));
                _ = earlier.Parameters.AddWithValue(checkpoint.TargetObservationSha256);
                _ = earlier.Parameters.AddWithValue(Hash('1'));
                _ = earlier.Parameters.AddWithValue(Hash('2'));
                _ = earlier.Parameters.AddWithValue(checkpoint.CommittedAtUtc.AddMinutes(-1));
                _ = await earlier.ExecuteNonQueryAsync();
            }
        }
        var reader = new HistoricalPostgreSqlLocalMetadataInspector(admin);
        Assert.Equal(2, (await reader.ReadDatabaseAsync(DatabaseInventory.ActiveDatabases[0],
            CancellationToken.None)).Journal.Count);
        IReadOnlyList<HistoricalLocalMetadataBinding> observed = await reader.InspectAsync(
            fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
            fixture.Now.AddDays(1), CancellationToken.None);
        Assert.Equal(23, observed.Count);
        Assert.False(HistoricalLocalMetadataReceiptBinder.AuthorizesExecution);
        Assert.Equal("delta_historical_local_metadata_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => reader.InspectAsync(
                fixture.LocalPlan, receipt, fixture.Schema with { SchemaVersion = "1.0" },
                fixture.Trust, fixture.Now.AddDays(1), CancellationToken.None))).Code);

        string first = DatabaseInventory.ActiveDatabases[0];
        var futurePlan = fixture.LocalPlan with
        {
            PlanId = Guid.NewGuid(),
            SchemaPlanSha256 = Hash('9'),
            TargetObservationSha256 = Hash('8'),
        };
        PairedLocalTransitionMetadataObservation transactionalShape =
            await new PairedLocalTransitionMetadataInspector(admin).InspectAsync(futurePlan,
                fixture.Schema.Databases.Single(item => item.Database == first), CancellationToken.None);
        Assert.Equal(PairedLocalTransitionMetadataState.SettledPrior, transactionalShape.State);
        Assert.Equal(observed[0].FingerprintSha256, transactionalShape.FingerprintSha256);
        string changedTarget = new NpgsqlConnectionStringBuilder(admin) { Database = first }.ConnectionString;
        await using (var connection = new NpgsqlConnection(changedTarget))
        {
            await connection.OpenAsync();
            await using var change = new NpgsqlCommand(
                "UPDATE legacy_migration_internal.delta_journal SET reconciliation_sha256=$1;", connection);
            _ = change.Parameters.AddWithValue(Hash('9'));
            _ = await change.ExecuteNonQueryAsync();
        }
        Assert.Equal("delta_historical_local_metadata_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => reader.InspectAsync(
                fixture.LocalPlan, receipt, fixture.Schema, fixture.Trust,
                fixture.Now.AddDays(1), CancellationToken.None))).Code);
        Assert.Equal("delta_historical_local_metadata_invalid",
            Assert.Throws<DeltaExecutionException>(() =>
                new HistoricalPostgreSqlLocalMetadataInspector(
                    new NpgsqlConnectionStringBuilder(admin) { Host = "remote.example" }.ConnectionString)).Code);
    }

    [Fact]
    public async Task Fresh_signed_disposable_reconciliation_admits_distinct_local_target()
    {
        Fixture fixture = await CreateAsync();

        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(fixture.ProofResult, fixture.Trust));
        Assert.Equal(fixture.ProofPlan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(fixture.Schema));

        DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Rejects_same_target_or_tampered_reconciliation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.ProofPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Rejects_expired_proof_and_changed_source_observation()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan with { SourceObservationSha256 = Hash('9') },
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Rejects_new_rows_after_disposable_proof()
    {
        Fixture fixture = await CreateAsync(changedLocalOperations: true);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Captured_proof_requires_identical_full_source_evidence_not_only_matching_operations()
    {
        Fixture matching = await CreateAsync(captured: true);
        DisposableDeltaProofVerifier.Verify(matching.ProofPlan, matching.ProofResult,
            matching.LocalPlan, matching.Schema, matching.Trust, matching.Now);

        Fixture drifted = await CreateAsync(captured: true, changedLocalEvidence: true);
        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(drifted.ProofPlan, drifted.ProofResult,
                drifted.LocalPlan, drifted.Schema, drifted.Trust, drifted.Now));
        Assert.Equal("delta_disposable_proof_invalid", failure.Code);
    }

    [Fact]
    public async Task Captured_proof_rejects_a_separate_archive_even_with_identical_operations_and_source_evidence()
    {
        Fixture separate = await CreateAsync(captured: true, changedLocalArchive: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(separate.LocalPlan, separate.Trust, separate.Now));

        Assert.Equal("delta_paired_plan_publication_invalid", Assert.Throws<DeltaPlanException>(() =>
            PairedCapturedDeltaPlanPublicationGate.Verify(
                new(separate.ProofPlan, separate.LocalPlan), separate.Schema,
                separate.Trust, separate.Now)).Code);

        DeltaExecutionException failure = Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(separate.ProofPlan, separate.ProofResult,
                separate.LocalPlan, separate.Schema, separate.Trust, separate.Now));
        Assert.Equal("delta_disposable_proof_invalid", failure.Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Captured_proof_rejects_a_changed_key_or_database_cutoff(
        bool changedKey, bool changedWindow)
    {
        Fixture fixture = await CreateAsync(captured: true,
            changedLocalCaptureKey: changedKey, changedLocalCaptureWindow: changedWindow);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Reviewed_quotation_disposition_admits_signed_target_inventory(bool captured)
    {
        Fixture fixture = await CreateAsync(captured: captured, quotationDisposition: true);
        Assert.Equal(captured ? "1.3" : "1.2", fixture.ProofPlan.SchemaVersion);
        Assert.Equal(["legacy_compatibility.GoogleAnalyticsOutbox", "public.QuotationAcceptedOutcome"],
            fixture.ProofPlan.Databases.Single(database => database.Database == "Quotation")
                .Tables.Select(table => table.Table));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(fixture.ProofResult, fixture.Trust));

        DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Reviewed_quotation_disposition_rejects_signed_unexpected_local_target()
    {
        Fixture fixture = await CreateAsync(quotationDisposition: true, changedLocalTableInventory: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            DisposableDeltaProofVerifier.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_admits_signed_same_capture_and_distinct_target()
    {
        Fixture fixture = await CreateAsync(captured: true, quotationDisposition: true,
            matchingInsertOperations: true);
        Assert.Contains(fixture.ProofPlan.Databases.SelectMany(database => database.Tables),
            table => table.InsertCount == 1);
        PairedCapturedDeltaPlanPublicationGate.Verify(
            new(fixture.ProofPlan, fixture.LocalPlan), fixture.Schema, fixture.Trust, fixture.Now);

        ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_uncaptured_pair()
    {
        Fixture fixture = await CreateAsync();

        Assert.Equal("delta_zero_delete_captured_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_tampered_or_stale_proof()
    {
        Fixture fixture = await CreateAsync(captured: true);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
    }

    [Fact]
    public async Task Zero_delete_validator_rejects_a_signed_matched_delete()
    {
        Fixture fixture = await CreateAsync(captured: true, deleteOperations: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.ProofPlan, fixture.Trust, fixture.Now));
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan, fixture.Trust, fixture.Now));

        Assert.Equal("delta_zero_delete_captured_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Zero_delete_validator_rejects_changed_capture_or_operations(
        bool changedArchive, bool changedOperations)
    {
        Fixture fixture = await CreateAsync(captured: true,
            changedLocalArchive: changedArchive, changedLocalOperations: changedOperations);

        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now)).Code);
    }

    [Fact]
    public async Task Signed_schema14_pair_accepts_later_disposable_proof_without_authorizing_local_execution()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        Assert.True(fixture.ProofResult.ReconciledAtUtc > fixture.LocalPlan.CreatedAtUtc);
        Assert.Equal("1.4", fixture.LocalPlan.SchemaVersion);
        ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
            fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now);

        Fixture changedCapture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, changedLocalArchive: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(changedCapture.ProofPlan,
                changedCapture.ProofResult, changedCapture.LocalPlan, changedCapture.Schema,
                changedCapture.Trust, changedCapture.Now)).Code);
        Fixture wrongHash = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true, changedLocalTransitionHash: true);
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(wrongHash.LocalPlan,
            wrongHash.Trust, wrongHash.Now));
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(wrongHash.ProofPlan,
                wrongHash.ProofResult, wrongHash.LocalPlan, wrongHash.Schema,
                wrongHash.Trust, wrongHash.Now)).Code);
        Fixture changedOperations = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, changedLocalOperations: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(changedOperations.ProofPlan,
                changedOperations.ProofResult, changedOperations.LocalPlan,
                changedOperations.Schema, changedOperations.Trust, changedOperations.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan,
                fixture.ProofResult with { PlanSha256 = Hash('9') }, fixture.LocalPlan,
                fixture.Schema, fixture.Trust, fixture.Now)).Code);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(fixture.ProofPlan, fixture.ProofResult,
                fixture.LocalPlan, fixture.Schema, fixture.Trust, fixture.Now.AddHours(13))).Code);
        Fixture deletes = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, deleteOperations: true);
        Assert.Equal("delta_disposable_proof_invalid", Assert.Throws<DeltaExecutionException>(() =>
            ZeroDeleteCapturedDeltaProofValidator.Verify(deletes.ProofPlan, deletes.ProofResult,
                deletes.LocalPlan, deletes.Schema, deletes.Trust, deletes.Now)).Code);
    }

    [Fact]
    public async Task Local_transition_authorization_binds_exact_proof_and_target_but_cannot_enter_current_apply()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        DeltaTargetAuthority localAuthority = fixture.LocalPlan.TargetAuthority!;
        string physicalHash = fixture.LocalPlan.QuotationTransitionSchemaSha256!;
        PairedLocalTransitionAuthorization authorization =
            PairedLocalTransitionAuthorizationPolicy.Produce(plans, fixture.ProofResult,
                fixture.Schema, fixture.Trust, localAuthority,
                fixture.LocalPlan.TargetObservationSha256, physicalHash,
                fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer);

        void Verify(PairedLocalTransitionAuthorization candidate,
            PairedCapturedDeltaPlans? pair = null,
            Exact23DeltaReconciliationResult? result = null,
            DeltaTargetAuthority? authority = null,
            string? targetObservation = null,
            string? schemaHash = null,
            DateTimeOffset? now = null)
        {
            PairedLocalTransitionAuthorizationPolicy.Verify(candidate, pair ?? plans,
                result ?? fixture.ProofResult, fixture.Schema, fixture.Trust,
                authority ?? localAuthority,
                targetObservation ?? fixture.LocalPlan.TargetObservationSha256,
                schemaHash ?? physicalHash, now ?? fixture.Now);
        }

        Verify(authorization);
        Assert.Equal(DeltaSynchronizationPlanCanonicalizer.ComputeSha256(fixture.LocalPlan),
            authorization.PersistentPlanSha256);
        Assert.Equal(Exact23DeltaReconciliationCoordinator.ComputeSha256(fixture.ProofResult),
            authorization.DisposableReconciliationSha256);
        PairedLocalTransitionAuthorization wrongProofUnsigned = authorization with
        {
            DisposableReconciliationSha256 = Hash('f'),
            AttestationSignature = null,
        };
        PairedLocalTransitionAuthorization wrongProofSigned = wrongProofUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(wrongProofUnsigned))),
        };
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(wrongProofSigned)).Code);
        using var localSigner = new P256MigrationEvidenceSigner("local-plan",
            _localPlanKey.ExportECPrivateKeyPem());
        DeltaSynchronizationPlan replayedUnsigned = fixture.LocalPlan with
        {
            PlanId = Guid.NewGuid(),
            AttestationSignature = null,
        };
        DeltaSynchronizationPlan replayedPlan = replayedUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(localSigner.Sign(
                DeltaSynchronizationPlanCanonicalizer.CreatePayload(replayedUnsigned))),
        };
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(replayedPlan,
            fixture.Trust, fixture.Now));
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                pair: new(fixture.ProofPlan, replayedPlan))).Code);
        PairedLocalTransitionAuthorization earlyUnsigned = authorization with
        {
            IssuedAtUtc = fixture.ProofResult.ReconciledAtUtc.AddSeconds(-1),
            AttestationSignature = null,
        };
        PairedLocalTransitionAuthorization earlySigned = earlyUnsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                PairedLocalTransitionAuthorizationCanonicalizer.CreatePayload(earlyUnsigned))),
        };
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(earlySigned)).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                result: fixture.ProofResult with { PlanSha256 = Hash('f') })).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                authority: localAuthority with { SystemIdentifierSha256 = Hash('f') })).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                targetObservation: Hash('f'))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                schemaHash: Hash('f'))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                now: fixture.Now.AddMinutes(6))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => Verify(authorization,
                authority: new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                    "gke://maliev-website/production-test", Hash('f')))).Code);

        Assert.Equal("delta_execution_authorization_request_invalid",
            Assert.Throws<DeltaExecutionException>(() => DeltaExecutionAuthorizationProducer.Produce(
                fixture.LocalPlan, fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer)).Code);
        Assert.Equal("delta_quotation_transition_plan_invalid",
            Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(
                fixture.LocalPlan, fixture.Schema.Databases.Single(database => database.Database == "Quotation"))).Code);
        Assert.Equal("delta_quotation_transition_plan_invalid",
            (await Assert.ThrowsAsync<DeltaPlanException>(() =>
                new PostgreSqlDeltaMetadataProvisioner(new("Host=should-not-connect",
                    localAuthority)).ProvisionAsync(fixture.LocalPlan, fixture.Schema,
                    CancellationToken.None))).Code);
    }

    [Fact]
    public async Task Local_transition_execution_permit_requires_fresh_signed_zero_delete_pair()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        DeltaTargetAuthority authority = fixture.LocalPlan.TargetAuthority!;
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust, authority,
            fixture.LocalPlan.TargetObservationSha256, fixture.LocalPlan.QuotationTransitionSchemaSha256!,
            fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer);

        var clock = new FixedTime(fixture.Now);
        PairedLocalTransitionExecutionPermit permit = PairedLocalTransitionExecutionPermit.Admit(
            plans, fixture.ProofResult, authorization, fixture.Schema, fixture.Trust,
            authority, fixture.LocalPlan.TargetObservationSha256, clock);
        var generationChecks = 0;
        await new PairedLocalTransitionExecutionGate(permit, fixture.Schema, _ =>
        {
            generationChecks++;
            return Task.CompletedTask;
        }).ValidateAsync(fixture.LocalPlan, "Quotation", CancellationToken.None);
        Assert.Equal(1, generationChecks);
        DeltaExecutionException generationDrift = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            new PairedLocalTransitionExecutionGate(permit, fixture.Schema, _ =>
                throw new DeltaExecutionException("delta_paired_local_runtime_drift", "changed"))
                .ValidateAsync(fixture.LocalPlan, "Quotation", CancellationToken.None));
        Assert.Equal("delta_paired_local_runtime_drift", generationDrift.Code);
        permit.Require(fixture.LocalPlan, fixture.Schema.Databases.Single(item => item.Database == "Quotation"),
            fixture.Now);
        Assert.Equal(fixture.LocalPlan.QuotationTransitionSchemaSha256,
            QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(fixture.LocalPlan,
                fixture.Schema.Databases.Single(item => item.Database == "Quotation"), permit));
        _ = Assert.Throws<DeltaPlanException>(() => QuotationDeltaPhysicalSchemaGuard.ExpectedPhysicalSchema(
            fixture.LocalPlan, fixture.Schema.Databases.Single(item => item.Database == "Quotation")));
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => permit.Require(fixture.LocalPlan,
                fixture.Schema.Databases.Single(item => item.Database == "Quotation"),
                fixture.Now.AddMinutes(6))).Code);
        clock.UtcNow = fixture.Now.AddMinutes(6);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() =>
                new PairedLocalTransitionExecutionGate(permit, fixture.Schema).ValidateAsync(
                    fixture.LocalPlan, "Quotation", CancellationToken.None))).Code);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() => permit.Require(fixture.LocalPlan with
            {
                TargetAuthority = new(DeltaTargetAuthorityKind.ProductionCloudNativePg,
                    "gke://maliev-website/production-test", Hash('f')),
            }, fixture.Schema.Databases.Single(item => item.Database == "Quotation"), fixture.Now)).Code);
    }

    [Fact]
    public async Task Local_transition_target_rolls_back_new_metadata_and_replays_only_matching_atomic_checkpoint()
    {
        await using PostgreSqlContainer container = new PostgreSqlBuilder("postgres:18-alpine").Build();
        await container.StartAsync();
        string admin = container.GetConnectionString();
        string identity;
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync();
            await using var identifier = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();",
                connection);
            identity = Convert.ToString(await identifier.ExecuteScalarAsync(),
                System.Globalization.CultureInfo.InvariantCulture)!;
            await using var create = new NpgsqlCommand("CREATE DATABASE \"ContactRequest\" TEMPLATE template0;",
                connection);
            _ = await create.ExecuteNonQueryAsync();
        }
        string systemHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(identity)))
            .ToLowerInvariant();
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, localSystemHash: systemHash, physicalTargetHashes: true);
        DatabaseSchemaPlan schema = fixture.Schema.Databases.Single(item => item.Database == "ContactRequest");
        string databaseConnection = new NpgsqlConnectionStringBuilder(admin)
        {
            Database = schema.Database,
            Pooling = false,
        }.ConnectionString;
        await using (var connection = new NpgsqlConnection(databaseConnection))
        {
            await connection.OpenAsync();
            await using var transaction = await connection.BeginTransactionAsync();
            await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
                ownsResources: false);
            await writer.ApplySchemaAsync(schema, CancellationToken.None);
            await writer.FinalizeSchemaAsync(schema, CancellationToken.None);
            await transaction.CommitAsync();
        }
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust,
            fixture.LocalPlan.TargetAuthority!, fixture.LocalPlan.TargetObservationSha256,
            fixture.LocalPlan.QuotationTransitionSchemaSha256!, fixture.Now.AddMinutes(-1),
            fixture.Now.AddMinutes(5), signer);
        var permit = PairedLocalTransitionExecutionPermit.Admit(plans, fixture.ProofResult,
            authorization, fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
            fixture.LocalPlan.TargetObservationSha256, new FixedTime(fixture.Now));
        var target = new PostgreSqlDeltaCanonicalTarget(new(databaseConnection, schema.Database,
            fixture.LocalPlan.TargetGeneration)
        { LocalTransitionPermit = permit });
        await using (IDeltaCanonicalTransaction abandoned = await target.BeginAsync(fixture.LocalPlan,
            schema, schema.Database, CancellationToken.None))
        {
            Assert.Equal(DeltaExecutionDisposition.Pending, abandoned.Disposition);
        }
        await using (var connection = new NpgsqlConnection(databaseConnection))
        {
            await connection.OpenAsync();
            await using var catalog = new NpgsqlCommand(
                "SELECT to_regclass('legacy_migration_internal.delta_journal')::text;", connection);
            Assert.Null(await catalog.ExecuteScalarAsync() as string);
        }
        DatabaseReconciliationEvidence empty = await new PostgreSqlDeltaReconciliationInspector(
            new(admin) { Plan = fixture.LocalPlan, LocalTransitionPermit = permit })
            .InspectAsync(schema, CancellationToken.None);
        string planHash = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(fixture.LocalPlan);
        await using (IDeltaCanonicalTransaction committed = await target.BeginAsync(fixture.LocalPlan,
            schema, schema.Database, CancellationToken.None))
        {
            string reconciliationHash = await committed.ReconcileAsync(empty, CancellationToken.None);
            await committed.CommitAsync(planHash, reconciliationHash, CancellationToken.None);
        }
        await using IDeltaCanonicalTransaction replay = await target.BeginAsync(fixture.LocalPlan,
            schema, schema.Database, CancellationToken.None);
        Assert.Equal(DeltaExecutionDisposition.AlreadyCommitted, replay.Disposition);
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            (await Assert.ThrowsAsync<DeltaExecutionException>(() => target.BeginAsync(
                fixture.LocalPlan with { TargetGeneration = "other" }, schema, schema.Database,
                CancellationToken.None))).Code);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public async Task Local_transition_authorization_refuses_signed_delete_or_wrong_transition_hash(
        bool plannedDeletes, bool wrongTransitionHash)
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, deleteOperations: plannedDeletes,
            matchingInsertOperations: !plannedDeletes,
            changedLocalTransitionHash: wrongTransitionHash);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        Assert.True(DeltaSynchronizationPlanVerifier.Verify(fixture.LocalPlan,
            fixture.Trust, fixture.Now));

        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() =>
                PairedLocalTransitionAuthorizationPolicy.Produce(
                    new(fixture.ProofPlan, fixture.LocalPlan), fixture.ProofResult,
                    fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
                    fixture.LocalPlan.TargetObservationSha256,
                    fixture.LocalPlan.QuotationTransitionSchemaSha256!,
                    fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), signer)).Code);
    }

    [Fact]
    public async Task Local_transition_authorization_rejects_reused_disposable_evidence_key()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true,
            reuseProofEvidenceAsAuthorization: true);
        using var reusedSigner = new P256MigrationEvidenceSigner("proof-evidence",
            _evidenceKey.ExportECPrivateKeyPem());
        Assert.Equal("delta_paired_local_transition_authorization_invalid",
            Assert.Throws<DeltaExecutionException>(() =>
                PairedLocalTransitionAuthorizationPolicy.Produce(
                    new(fixture.ProofPlan, fixture.LocalPlan), fixture.ProofResult,
                    fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
                    fixture.LocalPlan.TargetObservationSha256,
                    fixture.LocalPlan.QuotationTransitionSchemaSha256!,
                    fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), reusedSigner)).Code);
    }

    [Fact]
    public async Task Local_transition_preflight_checks_signed_admission_before_target_and_stops_on_identity_or_schema_drift()
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, matchingInsertOperations: true);
        using var signer = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        PairedCapturedDeltaPlans plans = new(fixture.ProofPlan, fixture.LocalPlan);
        PairedLocalTransitionAuthorization admission = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust,
            fixture.LocalPlan.TargetAuthority!, fixture.LocalPlan.TargetObservationSha256,
            fixture.LocalPlan.QuotationTransitionSchemaSha256!, fixture.Now.AddMinutes(-1),
            fixture.Now.AddMinutes(5), signer);
        string directory = Path.Combine(Path.GetTempPath(), "paired-local-preflight-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(directory);
        try
        {
            var clock = new FixedTime(fixture.Now);
            var observations = new List<string>();
            Task Identity(CancellationToken _)
            {
                observations.Add("identity");
                throw new DeltaExecutionException("delta_target_identity_changed", "Target changed.");
            }
            Task Physical(DatabaseSchemaPlan _, bool transition, CancellationToken __)
            {
                observations.Add("physical");
                throw new DeltaPlanException("delta_schema_drift", "Physical schema changed.");
            }
            Task<PairedLocalTransitionPreflightResult> Preflight(
                PairedLocalTransitionAuthorization candidate,
                Func<CancellationToken, Task> identity)
            {
                return PairedLocalTransitionPreflight.VerifyAsync(plans, fixture.ProofResult, candidate,
                    fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
                    fixture.LocalPlan.TargetObservationSha256, identity, Physical,
                    (_, _, _) => throw new InvalidOperationException("Metadata must not be inspected."), directory,
                    RandomNumberGenerator.GetBytes(32), new EmptyRows(), clock, CancellationToken.None);
            }

            PairedLocalTransitionAuthorization tampered = admission with
            {
                DisposableReconciliationSha256 = Hash('f'),
            };
            Assert.Equal("delta_paired_local_transition_authorization_invalid",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => Preflight(tampered, Identity))).Code);
            Assert.Empty(observations);
            Assert.Equal("delta_target_identity_changed",
                (await Assert.ThrowsAsync<DeltaExecutionException>(() => Preflight(admission, Identity))).Code);
            Assert.Equal(["identity"], observations);
            observations.Clear();
            Assert.Equal("delta_schema_drift",
                (await Assert.ThrowsAsync<DeltaPlanException>(() => Preflight(admission, _ =>
                {
                    observations.Add("identity");
                    return Task.CompletedTask;
                }))).Code);
            Assert.Equal(["identity", "physical"], observations);
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private sealed class EmptyRows : IDeltaOrderedRowSource
    {
        public async IAsyncEnumerable<MigrationRow> ReadOrderedAsync(string database, TableCopyPlan table,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    private async Task<Fixture> CreateAsync(bool changedLocalOperations = false,
        bool captured = false, bool changedLocalEvidence = false, bool quotationDisposition = false,
        bool changedLocalTableInventory = false, bool changedLocalArchive = false,
        bool changedLocalCaptureKey = false, bool changedLocalCaptureWindow = false,
        bool deleteOperations = false, bool matchingInsertOperations = false,
        bool pairedTransition = false, bool changedLocalTransitionHash = false,
        bool reuseProofEvidenceAsAuthorization = false, bool historicalLocal = false,
        string? localSystemHash = null, bool physicalTargetHashes = false,
        bool futureDocker = false, DateTimeOffset? at = null)
    {
        DateTimeOffset now = at ?? new DateTimeOffset(2026, 9, 25, 8, 0, 0, TimeSpan.Zero);
        TableCopyPlan[] quotationOutboxes =
        [
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.GoogleAnalyticsOutbox,
                "PK_GoogleAnalyticsOutbox", "UX_GoogleAnalyticsOutbox_EventKey", uniqueIndex: true),
            ApprovedSourceDispositionManifestTests.Outbox(CurrentQuotationSourceContract.QuotationOutcomeOutbox,
                "PK_QuotationOutcomeOutbox", "UQ_QuotationOutcomeOutbox_EventKey", uniqueIndex: false),
        ];
        FreshSchemaPlan schema = new("2.0", now.AddMinutes(-10), new string('a', 40),
            [.. DatabaseInventory.ActiveDatabases.Select(name =>
            {
                bool disposed = quotationDisposition && name == "Quotation";
                var database = new DatabaseSchemaPlan(name, "1.0",
                Hash('a'), Hash('b'), disposed ? quotationOutboxes : [new TableCopyPlan("dbo", "items", "public", "items", ["id"], ["id"])
                {
                    ColumnTypes = new Dictionary<string, string> { ["id"] = "integer" },
                    PrimaryKey = new("pk_items", ["id"]),
                }])
                {
                    TargetExtensionProfile = ApprovedTargetExtensionManifest.ProfileForDatabase(name),
                    SourceDispositionProfile = disposed ? ApprovedSourceDispositionManifest.QuotationOutboxesV1 : null,
                    SourceTableDispositions = disposed
                        ? ApprovedSourceDispositionManifest.DispositionsForDatabase(name, quotationOutboxes) : [],
                };
                return disposed || physicalTargetHashes ? database with
                {
                    TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(database),
                } : database;
            })]);
        using var planSigner = new P256MigrationEvidenceSigner("proof-plan", _planKey.ExportECPrivateKeyPem());
        using var localPlanSigner = new P256MigrationEvidenceSigner("local-plan", _localPlanKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore(
            [new(planSigner.KeyId, planSigner.ExportSubjectPublicKeyInfo()),
                new(localPlanSigner.KeyId, localPlanSigner.ExportSubjectPublicKeyInfo()),
                new(evidenceSigner.KeyId, evidenceSigner.ExportSubjectPublicKeyInfo()),
                new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo())]);
        DeltaSynchronizationPlan proofPlan = MakePlan("disposable-proof", Hash('1'), now.AddMinutes(-3),
            matchingInsertOperations);
        DeltaSynchronizationPlan localPlan = MakePlan("persistent-main", localSystemHash ?? Hash('2'),
            now.AddMinutes(pairedTransition ? -3 : -1),
            changedLocalOperations || matchingInsertOperations, changedLocalTableInventory);
        var inspector = new Inspector(pairedTransition, schema);
        var coordinator = new Exact23DeltaReconciliationCoordinator(inspector, inspector,
            new Checkpoints(proofPlan, schema, pairedTransition),
            new FixedTime(now.AddMinutes(-2)), evidenceSigner);
        Exact23DeltaReconciliationResult result = await coordinator.ReconcileAsync(proofPlan, schema,
            CancellationToken.None);
        return new(proofPlan, result, localPlan, schema, trust, now);

        DeltaSynchronizationPlan MakePlan(string id, string systemHash, DateTimeOffset created,
            bool changedOperations = false, bool changedTableInventory = false)
        {
            CanonicalDeltaOperation[] changed = [new(
                deleteOperations ? DeltaOperationKind.Delete : DeltaOperationKind.Insert,
                Hash('e'), deleteOperations ? null : Hash('f'),
                deleteOperations ? Hash('f') : null)];
            DeltaDatabasePlan[] databases = [.. DatabaseInventory.ActiveDatabases.Select(name => new DeltaDatabasePlan(name,
                [.. new QuotationDeltaExecutionMapping(schema.Databases.Single(item => item.Database == name))
                    .TargetSchema.Tables.Select(table => new DeltaTablePlan(
                        changedTableInventory && name == "Quotation" && table.TargetTable == "QuotationAcceptedOutcome"
                            ? "public.QuotationOutcomeOutbox" : $"{table.TargetSchema}.{table.TargetTable}",
                        changedOperations && name == "ContactRequest" && !deleteOperations ? 1 : 0,
                        0, deleteOperations && name == "ContactRequest" ? 1 : 0,
                        changedOperations && name == "ContactRequest" ? 0 : 1,
                        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(
                            (changedOperations || deleteOperations) && name == "ContactRequest" ? changed : []),
                        (changedOperations || deleteOperations) && name == "ContactRequest" ? changed : []))]))];
            var request = new DeltaPlanSigningRequest(schema.SourceCommitSha, now.AddMinutes(-5), Hash('3'),
                SchemaPlanCanonicalizer.ComputeSha256(schema), Hash('4'), "local-aspire",
                "legacy-postgres-main-local",
                historicalLocal && id == "persistent-main" ?
                    futureDocker ? $"docker:{Hash('8')}:4:5:3" :
                        $"docker:{Hash('7')}:1:2:3" : "generation-1",
                Hash('5'), Hash('6'),
                reuseProofEvidenceAsAuthorization ? evidenceSigner.PublicKeyFingerprintSha256 :
                    authorizationSigner.PublicKeyFingerprintSha256,
                databases)
            {
                TargetAuthority = new(DeltaTargetAuthorityKind.LocalAspire,
                    historicalLocal && id == "persistent-main"
                        ? $"aspire://legacy-postgres-main-local/persistent-{Hash(futureDocker ? '8' : '7')[..12]}"
                        : $"aspire://legacy-postgres-main-local/{id}", systemHash),
                SourceMode = DeltaSourceMode.LiveReadOnly,
                SourceObservationSha256 = Hash('8'),
                SourceCaptureCompletedAtUtc = now.AddMinutes(-4),
                SourceCaptureManifest = captured ? new(Hash(changedLocalCaptureKey && id == "persistent-main" ? '9' : '0'),
                    [.. DatabaseInventory.ActiveDatabases.Select(name =>
                    {
                        DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == name);
                        DeltaDatabasePlan databasePlan = databases.Single(item => item.Database == name);
                        DatabaseReconciliationEvidence evidence = new Inspector().InspectAsync(databaseSchema,
                            CancellationToken.None).GetAwaiter().GetResult();
                        if (changedLocalEvidence && id == "persistent-main" && name == "ContactRequest")
                        {
                            evidence = evidence with
                            {
                                Tables = [evidence.Tables[0] with { ContentSha256 = Hash('e') }],
                            };
                        }
                        return new DeltaDatabaseCaptureBinding(name,
                            now.AddMinutes(-4).AddSeconds(changedLocalCaptureWindow && id == "persistent-main" ? -29 : -30),
                            now.AddMinutes(-4).AddSeconds(-10), evidence,
                            [.. databasePlan.Tables.Select(tablePlan => new DeltaTableCaptureBinding(tablePlan.Table,
                                CaptureId(name + tablePlan.Table),
                                CaptureDigest(changedLocalArchive && id == "persistent-main" ? id : "shared", name + tablePlan.Table), Hash('a'),
                                tablePlan.InsertCount + tablePlan.UpdateCount, tablePlan.OperationsSha256))]);
                    })]) : null,
                QuotationTransitionSchemaSha256 = pairedTransition
                    ? changedLocalTransitionHash && id == "persistent-main" ? Hash('f') :
                        PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(
                            schema.Databases.Single(item => item.Database == "Quotation"), true)
                    : null,
                PairedTransitionPlanOnly = pairedTransition && id == "persistent-main" ? true : null,
            };
            return DeltaSynchronizationPlanProducer.Produce(request,
                id.StartsWith("disposable-", StringComparison.Ordinal) ? planSigner : localPlanSigner, created);
        }
    }

    private static string CaptureDigest(string id, string database)
    {
        return Convert.ToHexString(SHA256.HashData(
            Encoding.UTF8.GetBytes(id + ":" + database))).ToLowerInvariant();
    }

    private static Guid CaptureId(string table)
    {
        byte[] digest = SHA256.HashData(Encoding.UTF8.GetBytes(table));
        return new Guid(digest.AsSpan(0, 16));
    }

    private static string Hash(char value)
    {
        return new(value, 64);
    }

    public void Dispose()
    {
        _planKey.Dispose();
        _localPlanKey.Dispose();
        _evidenceKey.Dispose();
        _authorizationKey.Dispose();
        _continuityKey.Dispose();
    }

    private sealed record Fixture(DeltaSynchronizationPlan ProofPlan,
        Exact23DeltaReconciliationResult ProofResult, DeltaSynchronizationPlan LocalPlan,
        FreshSchemaPlan Schema, ReceiptAttestationTrustStore Trust, DateTimeOffset Now);

    private sealed class Inspector(bool pairedTransition = false, FreshSchemaPlan? fullSchema = null)
        : IDeltaReconciliationInspector
    {
        public Task<DatabaseReconciliationEvidence> InspectAsync(DatabaseSchemaPlan schema,
            CancellationToken cancellationToken)
        {
            TableReconciliationEvidence[] tables = [.. new QuotationDeltaExecutionMapping(schema).TargetSchema.Tables
                .Select(table => new TableReconciliationEvidence($"{table.TargetSchema}.{table.TargetTable}",
                    1, Hash('c'), Hash('d'), new Dictionary<string, long>(),
                    new Dictionary<string, long>()))];
            string physicalHash = pairedTransition && schema.Database == "Quotation"
                ? PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(
                    fullSchema!.Databases.Single(item => item.Database == "Quotation"), true)
                : schema.TargetSchemaSha256;
            return Task.FromResult(new DatabaseReconciliationEvidence(schema.Database,
                schema.SourceSchemaSha256, physicalHash, tables)
            {
                TargetExtensionStateSha256 = schema.TargetExtensionProfile is null ? null : Hash('e'),
            });
        }
    }

    private sealed class Checkpoints(DeltaSynchronizationPlan plan, FreshSchemaPlan schema,
        bool pairedTransition = false, bool postgresTimestamps = false)
        : IExact23DeltaCheckpointReader
    {
        public Task<IReadOnlyList<DeltaDatabaseCheckpointEvidence>> ReadAsync(
            DeltaSynchronizationPlan requestedPlan, FreshSchemaPlan schemaPlan,
            CancellationToken cancellationToken)
        {
            IReadOnlyList<DeltaDatabaseCheckpointEvidence> values =
                [.. DatabaseInventory.ActiveDatabases.Select(name =>
                {
                    DeltaDatabasePlan database = plan.Databases.Single(item => item.Database == name);
                    DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == name);
                    DatabaseReconciliationEvidence evidence = new Inspector(pairedTransition, schema).InspectAsync(databaseSchema,
                        cancellationToken).GetAwaiter().GetResult();
                    return new DeltaDatabaseCheckpointEvidence(name, plan.PlanId,
                        DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan), Timestamp(plan.SourceCutoffUtc),
                        plan.TargetObservationSha256,
                        DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(database),
                        DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(evidence),
                        Timestamp(plan.SourceCutoffUtc.AddMinutes(1)));
                })];
            return Task.FromResult(values);
        }

        private DateTimeOffset Timestamp(DateTimeOffset value)
        {
            return postgresTimestamps ? value.AddTicks(-(value.Ticks % 10)) : value;
        }
    }

    private sealed class FixedTime(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset UtcNow { get; set; } = now;

        public override DateTimeOffset GetUtcNow()
        {
            return UtcNow;
        }
    }
}
