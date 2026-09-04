using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class GuardedShadowMigrationRunnerTests
{
    [Fact]
    public async Task Runtime_attestation_drift_stops_before_the_run_journal_or_any_shadow_mutation()
    {
        Harness harness = CreateHarness(new RejectingRuntimeVerifier());

        RuntimeAttestationException exception = await Assert.ThrowsAsync<RuntimeAttestationException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("runtime_target_drift", exception.Code);
        Assert.Equal(0, harness.Journal.TryBeginCount);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public void CreateShadowName_AllExact23NamesAreDeterministicCollisionSafeAndWithinPostgresLimit()
    {
        Guid runId = Guid.Parse("01234567-89ab-cdef-0123-456789abcdef");
        string[] names = DatabaseInventory.ActiveDatabases
            .Select(database => GuardedShadowMigrationRunner.CreateShadowName(database, runId))
            .ToArray();

        Assert.Equal(23, names.Length);
        Assert.Equal(23, names.Distinct(StringComparer.Ordinal).Count());
        Assert.All(names, name =>
        {
            Assert.True(Encoding.UTF8.GetByteCount(name) <= 63, name);
            Assert.Matches("^[a-z][a-z0-9_]+$", name);
        });
        Assert.Equal(
            GuardedShadowMigrationRunner.CreateShadowName("DataProtectionKeysEmployee", runId),
            GuardedShadowMigrationRunner.CreateShadowName("DataProtectionKeysEmployee", runId));
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 29, 14, 0, 0, TimeSpan.Zero);
    private static readonly ECDsa SigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private static readonly ECDsa ExecutionSigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private const string KeyId = "migration-authorizer-1";
    private const string ExecutionKeyId = "migration-execution-1";
    private const string CurrentSourceCommit = CurrentQuotationSourceContract.SourceCommitSha;
    private static readonly string RunnerDigest = Hash("guarded-shadow-runner-v1");

    [Fact]
    public async Task ExecuteAsync_ApprovedRequest_CopiesEveryDatabaseIntoUniqueEmptyCommittedShadow()
    {
        Harness harness = CreateHarness();

        MigrationExecutionResult result = await harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None);

        Assert.Equal(MigrationExecutionStatus.Completed, result.Status);
        Assert.Equal(23, result.Receipt.Databases.Count);
        Assert.Equal(Now, result.Receipt.CompletedAtUtc);
        Assert.Equal(23, harness.Source.SchemaInspections.Count);
        Assert.Equal(23, harness.Source.SnapshotsStarted.Count);
        Assert.Equal(23, harness.Source.SnapshotsCompleted.Count);
        Assert.Empty(harness.Source.SnapshotsRolledBack);
        Assert.Equal(23, harness.Target.Created.Count);
        Assert.Equal(23, harness.Target.Transactions.Count(transaction => transaction.Committed));
        Assert.All(harness.Target.Transactions, transaction => Assert.True(transaction.VerifiedBeforeCommit));
        Assert.Equal(23, harness.Target.Created.Select(shadow => shadow.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.All(harness.Target.Created, shadow => Assert.StartsWith("legacy_shadow_", shadow.Name, StringComparison.Ordinal));
        Assert.All(result.Receipt.Databases, migrated =>
        {
            Assert.True(migrated.OwnerAttempt > 0);
            Assert.NotEqual(Guid.Empty, migrated.FencingToken);
        });
        Assert.Empty(harness.Target.Deleted);
        Assert.True(MigrationEvidenceAttestation.CreatePayload(result.Receipt).Length > 0);
        Assert.True(ExecutionSigningKey.VerifyData(
            MigrationEvidenceAttestation.CreatePayload(result.Receipt),
            Convert.FromBase64String(result.Receipt.AttestationSignature!),
            HashAlgorithmName.SHA256));
        _ = Assert.Single(harness.Journal.Completed);
    }

    [Fact]
    public async Task ExecuteAsync_ReceiptRetainsObservedRelationshipAndSequenceEvidence()
    {
        Harness harness = CreateHarness();
        string database = DatabaseInventory.ActiveDatabases[0];
        FreshSchemaPlan plan = MutateDatabasePlan(CreateSchemaPlan(), database, item => item with
        {
            Tables = [item.Tables[0] with
            {
                IdentityColumns = ["ID"],
                Identities = [new IdentityCopyPlan("ID", 1, 1, 1, true)],
                ForeignKeys = [new ForeignKeyCopyPlan("FK_Primary_Self", ["ID"], "public", "Primary", ["ID"])
                {
                    SourceReferencedSchema = "dbo",
                    SourceReferencedTable = "Primary",
                    SourceReferencedColumns = ["ID"],
                }],
            }],
        });

        MigrationExecutionResult result = await harness.Runner.ExecuteAsync(CreateRequest(plan), CancellationToken.None);

        DatabaseReconciliationEvidence evidence = result.Receipt.Reconciliation.Single(item => item.Database == database);
        Assert.Equal(1, Assert.Single(evidence.Tables).ForeignKeyRelationshipCounts["FK_Primary_Self"]);
        Assert.Equal(2, evidence.SequenceNextValues["public.Primary.ID"]);
    }

    [Fact]
    public async Task ExecuteAsync_TargetCopyFails_RollsBackCurrentTransactionAndPreservesEveryRunOwnedShadow()
    {
        Harness harness = CreateHarness();
        harness.Target.FailCopyForDatabase = DatabaseInventory.ActiveDatabases[1];

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_copy_failed", exception.Code);
        Assert.Contains(harness.Target.Transactions, transaction => transaction.RolledBack);
        Assert.Contains(DatabaseInventory.ActiveDatabases[1], harness.Source.SnapshotsRolledBack);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Journal.Completed);
        Assert.Empty(harness.Journal.Cleanup);
    }

    [Fact]
    public async Task ExecuteAsync_RecoveredPendingShadow_RequiresAdmittedRecoveryAndPreservesBeforeSnapshot()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        MigrationRunIdentity identity = MigrationRunIdentity.FromRequest(request);
        var abandoned = new ShadowDatabase(
            $"legacy_shadow_order_{Guid.NewGuid():N}",
            identity.RunId.ToString("D"),
            "Order");
        harness.Journal.SeedPendingShadow(identity, abandoned);
        harness.Target.BeforeDelete = () => Assert.Empty(harness.Source.SnapshotsStarted);

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("resume_authority_required", failure.Code);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Journal.Cleanup);
        Assert.Empty(harness.Source.SnapshotsStarted);
    }

    [Fact]
    public async Task ExecuteAsync_CompletedRunReplayed_ReturnsReceiptWithoutAnyDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        MigrationExecutionResult first = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        harness.Source.Reset();
        harness.Target.Reset();

        MigrationExecutionResult second = await harness.Runner.ExecuteAsync(request, CancellationToken.None);

        Assert.Equal(MigrationExecutionStatus.AlreadyCompleted, second.Status);
        Assert.Equal(first.Receipt, second.Receipt);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_CompletedRunWithTamperedSignature_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        _ = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        harness.Journal.Completed[0] = harness.Journal.Completed[0] with
        {
            AttestationSignature = Convert.ToBase64String([1, 2, 3]),
        };
        harness.Source.Reset();
        harness.Target.Reset();

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("completed_receipt_invalid", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_JournalClaimsCompletedWithMismatchedIdentity_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        MigrationExecutionResult first = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        MigrationExecutionReceipt mismatched = first.Receipt with { TargetGeneration = "tampered-generation" };
        harness.Journal.ForceCompletedResult(mismatched);
        harness.Source.Reset();
        harness.Target.Reset();

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("completed_receipt_invalid", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_SameRunAlreadyInProgress_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        harness.Journal.ForceInProgress(MigrationRunIdentity.FromRequest(request));

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("run_already_in_progress", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_CompletedRunReplayedAfterAuthorizationExpiry_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        _ = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        harness.Source.Reset();
        harness.Target.Reset();
        harness.TimeProvider.Advance(TimeSpan.FromHours(2));

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("execution_authorization_expired", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_CompletedRunReplayedWithStaleSchemaPlan_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        _ = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        harness.Source.Reset();
        harness.Target.Reset();
        harness.TimeProvider.Advance(TimeSpan.FromHours(7));

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("schema_plan_stale", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_RunIdentifierReusedForDifferentPlan_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        _ = await harness.Runner.ExecuteAsync(request, CancellationToken.None);
        harness.Source.Reset();
        harness.Target.Reset();
        FreshSchemaPlan modifiedPlan = request.SchemaPlan with { CapturedAtUtc = request.SchemaPlan.CapturedAtUtc.AddMinutes(1) };
        GuardedMigrationRequest replay = request with
        {
            SchemaPlan = modifiedPlan,
            Authorization = SignAuthorization(CreateAuthorization(request.Authorization.RunId, modifiedPlan)),
        };

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(replay, CancellationToken.None));

        Assert.Equal("run_replay_mismatch", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_StaleSourceCommitInPlan_FailsClosedBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        FreshSchemaPlan stalePlan = CreateSchemaPlan() with
        {
            SourceCommitSha = "6de82fd9760e86c71ddba3085879a63b43faff9f",
        };
        GuardedMigrationRequest request = CreateRequest(stalePlan);

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("schema_plan_source_commit_stale", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_ObservedSourceSchemaDoesNotMatchPlan_PreservesCreatedShadowsAndFailsClosed()
    {
        Harness harness = CreateHarness();
        harness.Source.SchemaOverrides[DatabaseInventory.ActiveDatabases[1]] = Hash("unexpected-live-schema");

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("source_schema_drift", exception.Code);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Journal.Completed);
    }

    [Theory]
    [InlineData("missing-column")]
    [InlineData("unexpected-column")]
    [InlineData("unexpected-table")]
    [InlineData("metadata-mismatch")]
    public async Task ExecuteAsync_ObservedSourceInventoryDiffersFromSignedPlan_FailsClosed(string drift)
    {
        Harness harness = CreateHarness();
        harness.Source.InventoryDrift = drift;

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("source_inventory_drift", exception.Code);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Journal.Completed);
    }

    [Fact]
    public async Task ExecuteAsync_UnknownTargetSchemaVersion_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        FreshSchemaPlan plan = MutateDatabasePlan(CreateSchemaPlan(), DatabaseInventory.ActiveDatabases[0], database =>
            database with { TargetSchemaVersion = "2.0-unknown" });

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(plan), CancellationToken.None));

        Assert.Equal("target_schema_version_unknown", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Theory]
    [InlineData("MachineLearning")]
    [InlineData("MachineLearningData")]
    [InlineData("UnknownDatabase")]
    public async Task ExecuteAsync_ForbiddenOrUnknownDispositionInSchemaPlan_FailsBeforeDatabaseIo(string database)
    {
        Harness harness = CreateHarness();
        FreshSchemaPlan plan = CreateSchemaPlan() with
        {
            Databases = [.. CreateSchemaPlan().Databases, CreateDatabasePlan(database)],
        };

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(plan), CancellationToken.None));

        Assert.Equal("schema_plan_database_coverage_invalid", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_ShadowReportedNonEmpty_PreservesRunOwnedShadowAndStops()
    {
        Harness harness = CreateHarness();
        harness.Target.NonEmptyDatabase = DatabaseInventory.ActiveDatabases[0];

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_database_not_empty", exception.Code);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Target.Transactions);
    }

    [Fact]
    public async Task ExecuteAsync_InvalidAuthorizationSignature_FailsBeforeDatabaseIo()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        request = request with
        {
            Authorization = request.Authorization with { AttestationSignature = Convert.ToBase64String([1, 2, 3]) },
        };

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("execution_authorization_signature_invalid", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_CallerCannotExtendAuthorizationFreshnessPolicy()
    {
        Harness harness = CreateHarness();
        GuardedMigrationRequest request = CreateRequest();
        ExecutionAuthorizationReceipt extended = request.Authorization with { ExpiresAtUtc = Now.AddHours(2) };
        request = request with { Authorization = SignAuthorization(extended) };

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(request, CancellationToken.None));

        Assert.Equal("execution_authorization_lifetime_invalid", exception.Code);
        Assert.Empty(harness.Source.SchemaInspections);
        Assert.Empty(harness.Target.Created);
    }

    [Fact]
    public async Task ExecuteAsync_CancelledCopy_RollsBackAndPreservesEveryRunOwnedShadow()
    {
        Harness harness = CreateHarness();
        harness.Target.CancelCopyForDatabase = DatabaseInventory.ActiveDatabases[1];

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Contains(harness.Target.Transactions, transaction => transaction.RolledBack);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(harness.Journal.Completed);
    }

    [Theory]
    [InlineData("drop")]
    [InlineData("duplicate")]
    [InlineData("transform")]
    public async Task ExecuteAsync_TargetRowsDifferFromSnapshot_RollsBackAndPreservesShadows(string corruption)
    {
        Harness harness = CreateHarness();
        harness.Target.CorruptDatabase = DatabaseInventory.ActiveDatabases[0];
        harness.Target.Corruption = corruption;

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", exception.Code);
        Assert.True(Assert.Single(harness.Target.Transactions).RolledBack);
        Assert.Empty(harness.Target.Deleted);
        MigrationFailureReceipt failure = Assert.Single(harness.Journal.Failed);
        Assert.False(string.IsNullOrWhiteSpace(failure.AttestationSignature));
    }

    [Fact]
    public async Task ExecuteAsync_TargetRetainsOnlyPrefix_StillExhaustsSourceAndFailsReconciliation()
    {
        Harness harness = CreateHarness();
        harness.Source.RowsPerTable = 10_000;
        harness.Target.CorruptDatabase = DatabaseInventory.ActiveDatabases[0];
        harness.Target.Corruption = "prefix";

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", exception.Code);
        Assert.Equal(10_000, harness.Source.RowsYielded);
        Assert.InRange(Assert.Single(harness.Target.Transactions).MaximumBatchSize, 1, GuardedRunnerPolicy.CopyBatchSize);
    }

    [Fact]
    public async Task ExecuteAsync_LargeLobRows_AreSplitByPayloadBytesInsteadOfOnlyRowCount()
    {
        Harness harness = CreateHarness();
        harness.Source.RowsPerTable = 3;
        harness.Source.ValueFactory = _ => new string('x', 3 * 1024 * 1024);

        MigrationExecutionResult result = await harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None);

        Assert.Equal(MigrationExecutionStatus.Completed, result.Status);
        Assert.All(harness.Target.Transactions, transaction => Assert.Equal(1, transaction.MaximumBatchSize));
    }

    [Fact]
    public async Task ExecuteAsync_SmallStreamedRows_AreBufferedAndBatched()
    {
        Harness harness = CreateHarness();
        harness.Source.RowsPerTable = 3;
        harness.Source.ValueFactory = _ => new StreamingLob(
            StreamingLobKind.Text,
            4,
            async (destination, cancellationToken) =>
                await destination.WriteAsync("test"u8.ToArray(), cancellationToken));

        MigrationExecutionResult result = await harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None);

        Assert.Equal(MigrationExecutionStatus.Completed, result.Status);
        Assert.All(harness.Target.Transactions, transaction => Assert.Equal(3, transaction.MaximumBatchSize));
    }

    [Fact]
    public async Task ExecuteAsync_RowLargerThanByteLimit_FailsClosedInsteadOfCreatingUnboundedBatch()
    {
        Harness harness = CreateHarness();
        harness.Source.ValueFactory = _ => new string('x', (int)GuardedRunnerPolicy.CopyBatchByteLimit + 1);

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("source_row_exceeds_batch_byte_limit", exception.Code);
        Assert.All(harness.Target.Transactions, transaction => Assert.Equal(0, transaction.MaximumBatchSize));
        Assert.Empty(harness.Target.Deleted);
    }

    [Fact]
    public async Task ExecuteAsync_MalformedLease_IsPreservedAndFailsClosed()
    {
        Harness harness = CreateHarness();
        harness.Target.ReturnMalformedLease = true;

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_ownership_invalid", exception.Code);
        _ = Assert.Single(harness.Target.Created);
        Assert.Empty(harness.Target.Deleted);
        Assert.Empty(Assert.Single(harness.Journal.Failed).Cleanup);
    }

    [Fact]
    public async Task ExecuteAsync_DeleteWouldFail_NeverDeletesAndRecordsPrimaryFailure()
    {
        Harness harness = CreateHarness();
        harness.Target.NonEmptyDatabase = DatabaseInventory.ActiveDatabases[0];
        harness.Target.FailDelete = true;

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_database_not_empty", exception.Code);
        MigrationFailureReceipt receipt = Assert.Single(harness.Journal.Failed);
        Assert.Equal("shadow_database_not_empty", receipt.FailureCode);
        Assert.Empty(receipt.Cleanup);
        Assert.Empty(harness.Target.Deleted);
        Assert.True(ExecutionSigningKey.VerifyData(
            MigrationEvidenceAttestation.CreatePayload(receipt),
            Convert.FromBase64String(receipt.AttestationSignature!),
            HashAlgorithmName.SHA256));
    }

    [Theory]
    [InlineData("schema", null, null)]
    [InlineData("row-count", "public.Primary", null)]
    [InlineData("ordered-content", "public.Primary", null)]
    [InlineData("aggregate", "public.Primary", null)]
    [InlineData("null-count", "public.Primary", "Value")]
    [InlineData("orphan", "public.Primary", "FK_Primary_Self")]
    [InlineData("relationship", "public.Primary", "FK_Primary_Self")]
    [InlineData("sequence", "public.Primary", "public.Primary.ID")]
    [InlineData("null-count-missing", "public.Primary", "Value")]
    [InlineData("orphan-missing", "public.Primary", "FK_Primary_Self")]
    [InlineData("relationship-missing", "public.Primary", "FK_Primary_Self")]
    [InlineData("sequence-missing", "public.Primary", "public.Primary.ID")]
    [InlineData("null-count-extra", "public.Primary", "Unexpected")]
    [InlineData("orphan-extra", "public.Primary", "Unexpected")]
    [InlineData("relationship-extra", "public.Primary", "Unexpected")]
    [InlineData("sequence-extra", null, "Unexpected")]
    public async Task ExecuteAsync_IndependentReconciliationMismatch_ReportsNonRowEvidence(
        string corruption, string? table, string? field)
    {
        Harness harness = CreateHarness();
        harness.Target.CorruptDatabase = "Order";
        harness.Target.Corruption = corruption;
        harness.Source.ValueFactory = _ => "private-row-value;Password=must-not-appear";
        FreshSchemaPlan plan = WithOrderRelationshipsAndIdentity();

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(plan), CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", failure.Code);
        ReconciliationDiagnostic? diagnostic = failure.Reconciliation;
        Assert.NotNull(diagnostic);
        JsonElement details = JsonSerializer.SerializeToElement(diagnostic);
        Assert.Equal("Order", details.GetProperty("Database").GetString());
        Assert.Equal(table, details.GetProperty("Table").GetString());
        Assert.Equal(corruption.Replace("-missing", string.Empty, StringComparison.Ordinal)
            .Replace("-extra", string.Empty, StringComparison.Ordinal), details.GetProperty("Check").GetString());
        Assert.Equal(field, details.GetProperty("Field").GetString());
        Assert.NotEqual(details.GetProperty("Expected").ToString(), details.GetProperty("Observed").ToString());
        if (corruption.EndsWith("-missing", StringComparison.Ordinal))
        {
            Assert.Equal(JsonValueKind.Null, details.GetProperty("Observed").ValueKind);
        }
        else if (corruption.EndsWith("-extra", StringComparison.Ordinal))
        {
            Assert.Null(diagnostic.Expected);
            Assert.Equal("0", diagnostic.Observed);
        }
        else if (corruption is "schema" or "ordered-content" or "aggregate")
        {
            Assert.Matches("^[0-9a-f]{64}$", diagnostic.Expected);
            Assert.Matches("^[0-9a-f]{64}$", diagnostic.Observed);
        }
        else
        {
            Assert.Equal(corruption switch { "row-count" or "relationship" => "1", "sequence" => "2", _ => "0" }, diagnostic.Expected);
            Assert.Equal(corruption switch { "row-count" or "relationship" => "2", "sequence" => "3", _ => "1" }, diagnostic.Observed);
        }
        string rendered = details.GetRawText() + failure.Message;
        Assert.DoesNotContain("private-row-value", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain("Password=", rendered, StringComparison.Ordinal);
        Assert.DoesNotContain(Assert.Single(harness.Journal.Failed).Reconciliation, item => item.Database == "Order");
        Assert.Empty(harness.Target.Deleted);
    }

    [Fact]
    public async Task ExecuteAsync_CommitFails_ExcludesUnconfirmedDatabaseFromSignedEvidence()
    {
        Harness harness = CreateHarness();
        harness.Target.FailCommitForDatabase = "Order";

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_copy_failed", failure.Code);
        MigrationFailureReceipt receipt = Assert.Single(harness.Journal.Failed);
        Assert.DoesNotContain(receipt.Reconciliation, item => item.Database == "Order");
        Assert.Equal(harness.Target.Transactions.Count(item => item.Committed), receipt.Reconciliation.Count);
        Assert.True(ExecutionSigningKey.VerifyData(MigrationEvidenceAttestation.CreatePayload(receipt),
            Convert.FromBase64String(receipt.AttestationSignature!), HashAlgorithmName.SHA256));
    }

    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    [InlineData(true, true)]
    public async Task ExecuteAsync_RollbackAlsoFails_PreservesPrimaryReconciliationCode(
        bool sourceRollbackFails, bool targetRollbackFails)
    {
        Harness harness = CreateHarness();
        harness.Target.CorruptDatabase = "Order";
        harness.Target.Corruption = "schema";
        harness.Source.FailRollback = sourceRollbackFails;
        harness.Target.FailRollback = targetRollbackFails;

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", failure.Code);
        Assert.Equal("Order", failure.Reconciliation?.Database);
        if (sourceRollbackFails)
        {
            Assert.Equal(true, failure.Data["source_rollback_failed"]);
        }
        if (targetRollbackFails)
        {
            Assert.Equal(true, failure.Data["shadow_rollback_failed"]);
        }
        Assert.Equal("shadow_reconciliation_failed", Assert.Single(harness.Journal.Failed).FailureCode);
        Assert.Empty(harness.Target.Deleted);
    }

    [Fact]
    public async Task ExecuteAsync_RollbackAndDisposeFail_PreservesPrimaryReconciliationCode()
    {
        Harness harness = CreateHarness();
        harness.Target.CorruptDatabase = "Order";
        harness.Target.Corruption = "schema";
        harness.Target.FailRollback = true;
        harness.Target.FailDisposeAfterRollback = true;

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_reconciliation_failed", failure.Code);
        Assert.Equal("Order", failure.Reconciliation?.Database);
        Assert.Equal(true, failure.Data["shadow_dispose_failed"]);
    }

    private static FreshSchemaPlan WithOrderRelationshipsAndIdentity()
    {
        return MutateDatabasePlan(CreateSchemaPlan(), "Order", item => item with
        {
            Tables = [item.Tables[0] with
            {
                IdentityColumns = ["ID"],
                Identities = [new IdentityCopyPlan("ID", 1, 1, 1, true)],
                ForeignKeys = [new ForeignKeyCopyPlan("FK_Primary_Self", ["ID"], "public", "Primary", ["ID"])
                {
                    SourceReferencedSchema = "dbo",
                    SourceReferencedTable = "Primary",
                    SourceReferencedColumns = ["ID"],
                }],
            }],
        });
    }

    private static Harness CreateHarness(IRuntimeAttestationVerifier? runtimeAttestationVerifier = null)
    {
        TrustedAttestationKey trustedKey = new(KeyId, SigningKey.ExportSubjectPublicKeyInfo());
        var trustStore = new ReceiptAttestationTrustStore([trustedKey]);
        var executionTrustStore = new ReceiptAttestationTrustStore(
            [new TrustedAttestationKey(ExecutionKeyId, ExecutionSigningKey.ExportSubjectPublicKeyInfo())]);
        FakeSource source = new();
        FakeTarget target = new();
        InMemoryJournal journal = new();
        target.IsRegistered = journal.IsRegistered;
        MutableTimeProvider timeProvider = new(Now);
        var runner = new GuardedShadowMigrationRunner(
            new PreflightService(new NeverExternalCommandExecutor(), trustStore),
            trustStore,
            executionTrustStore,
            source,
            target,
            journal,
            new TestEvidenceSigner(ExecutionKeyId, ExecutionSigningKey),
            timeProvider,
            new GuardedRunnerPolicy(CurrentSourceCommit, RunnerDigest),
            runtimeAttestationVerifier ?? new AcceptingRuntimeVerifier());
        return new(runner, source, target, journal, timeProvider);
    }

    private static GuardedMigrationRequest CreateRequest(FreshSchemaPlan? plan = null)
    {
        FreshSchemaPlan schemaPlan = plan ?? CreateSchemaPlan();
        Guid runId = Guid.Parse("08e86003-b953-4234-96a7-7b40f8017331");
        return new(
            CreateBackupReceipt(),
            schemaPlan,
            SignAuthorization(CreateAuthorization(runId, schemaPlan)));
    }

    private static FreshSchemaPlan CreateSchemaPlan()
    {
        return new(
            SchemaVersion: "2.0",
            CapturedAtUtc: Now.AddMinutes(-10),
            SourceCommitSha: CurrentSourceCommit,
            Databases: [.. DatabaseInventory.ActiveDatabases.Select(CreateDatabasePlan)]);
    }

    private static DatabaseSchemaPlan CreateDatabasePlan(string database)
    {
        return new(
            database,
            "1.0",
            Hash($"source:{database}"),
            Hash($"target:{database}"),
            [new TableCopyPlan("dbo", "Primary", "public", "Primary", ["ID", "Value"], ["ID"])
            {
                SourceColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "int",
                    ["Value"] = "nvarchar",
                },
                SourceColumns =
                [
                    new("ID", "int", Hash("ID:int"), null),
                    new("Value", "nvarchar", Hash("Value:nvarchar"), null),
                ],
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "integer",
                    ["Value"] = "text",
                },
                PrimaryKey = new PrimaryKeyCopyPlan("PK_Primary", ["ID"]),
            }]);
    }

    private static FreshSchemaPlan MutateDatabasePlan(
        FreshSchemaPlan plan,
        string database,
        Func<DatabaseSchemaPlan, DatabaseSchemaPlan> mutation)
    {
        return plan with
        {
            Databases = [.. plan.Databases.Select(item => item.Database == database ? mutation(item) : item)],
        };
    }

    private static ExecutionAuthorizationReceipt CreateAuthorization(Guid runId, FreshSchemaPlan plan)
    {
        return new(
            SchemaVersion: "2.0",
            RunId: runId,
            IssuedAtUtc: Now.AddMinutes(-5),
            ExpiresAtUtc: Now.AddMinutes(55),
            SourceCommitSha: CurrentSourceCommit,
            SchemaPlanSha256: SchemaPlanCanonicalizer.ComputeSha256(plan),
            BackupManifestSha256: CreateBackupReceipt().ManifestSha256,
            RunnerDigestSha256: RunnerDigest,
            TargetGeneration: "review-20260829-a",
            AuthorizedDatabases: DatabaseInventory.ActiveDatabases,
            Mode: "shadow-only",
            AttestationKeyId: KeyId,
            AttestationSignature: null);
    }

    private static ExecutionAuthorizationReceipt SignAuthorization(ExecutionAuthorizationReceipt authorization)
    {
        Assert.True(ExecutionAuthorizationAttestation.TryCreatePayload(authorization, out byte[] payload));
        return authorization with
        {
            AttestationSignature = Convert.ToBase64String(SigningKey.SignData(payload, HashAlgorithmName.SHA256)),
        };
    }

    private static BackupReceipt CreateBackupReceipt()
    {
        List<BackupArtifact?> artifacts = [.. DatabaseInventory.ActiveDatabases.Select(database =>
        {
            string hash = Hash(database);
            return (BackupArtifact?)new BackupArtifact(
                database,
                "Full",
                $"Full_{database}_2026-08-29_120000.bak",
                1024,
                hash,
                hash)
            {
                CompletedAtUtc = Now.AddHours(-1),
                GcsObject = $"database/full/2026-08-30/run-1/Full_{database}.bak",
                GcsGeneration = 1,
                GcsSha256 = hash,
            };
        })];
        string manifestHash = ComputeManifestSha256(artifacts);
        BackupReceipt receipt = new(
            "1.1",
            Now.AddHours(-1),
            DatabaseInventory.InventorySha256,
            manifestHash,
            artifacts,
            KeyId,
            null)
        {
            SourceObservedAtUtc = Now.AddHours(-2),
        };
        Assert.True(ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload));
        return receipt with
        {
            AttestationSignature = Convert.ToBase64String(SigningKey.SignData(payload, HashAlgorithmName.SHA256)),
        };
    }

    private static string ComputeManifestSha256(IEnumerable<BackupArtifact?> artifacts)
    {
        string canonical = string.Join(
            '\n',
            artifacts.Select(Assert.IsType<BackupArtifact>)
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .Select(artifact => string.Join(
                    '|', artifact.Database, artifact.BackupType, artifact.FileName, artifact.ByteLength,
                    artifact.Sha256!.ToLowerInvariant(), artifact.ObservedSha256!.ToLowerInvariant())));
        return Hash(canonical);
    }

    private static string Hash(string value)
    {
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
    }

    private sealed record Harness(
        GuardedShadowMigrationRunner Runner,
        FakeSource Source,
        FakeTarget Target,
        InMemoryJournal Journal,
        MutableTimeProvider TimeProvider);

    private sealed class MutableTimeProvider(DateTimeOffset current) : TimeProvider
    {
        private DateTimeOffset _current = current;

        public override DateTimeOffset GetUtcNow()
        {
            return _current;
        }

        public void Advance(TimeSpan duration)
        {
            _current = _current.Add(duration);
        }
    }

    private sealed class TestEvidenceSigner(string keyId, ECDsa signingKey) : IMigrationEvidenceSigner
    {
        public string KeyId => keyId;

        public string PublicKeyFingerprintSha256 { get; } = Convert.ToHexString(
            SHA256.HashData(signingKey.ExportSubjectPublicKeyInfo())).ToLowerInvariant();

        public byte[] Sign(ReadOnlySpan<byte> payload)
        {
            return signingKey.SignData(payload, HashAlgorithmName.SHA256);
        }
    }

    private sealed class NeverExternalCommandExecutor : IExternalCommandExecutor
    {
        public Task<int> ExecuteAsync(string command, CancellationToken cancellationToken)
        {
            throw new InvalidOperationException("External commands are forbidden.");
        }
    }

    private sealed class FakeSource : IReadOnlySqlServerMigrationSource
    {
        public List<string> SchemaInspections { get; } = [];
        public List<string> SnapshotsStarted { get; } = [];
        public List<string> SnapshotsCompleted { get; } = [];
        public List<string> SnapshotsRolledBack { get; } = [];
        public Dictionary<string, string> SchemaOverrides { get; } = new(StringComparer.Ordinal);
        public int RowsPerTable { get; set; } = 1;
        public int RowsYielded { get; private set; }
        public string? InventoryDrift { get; set; }
        public bool FailRollback { get; set; }
        public Func<string, object?> ValueFactory { get; set; } = database => database;

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsStarted.Add(database);
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            SchemaInspections.Add(database);
            SourceColumnInventory Id()
            {
                return new("ID", "int", Hash("ID:int"), null);
            }

            SourceColumnInventory Value(string type = "nvarchar")
            {
                return new("Value", type, Hash($"Value:{type}"), null);
            }

            IReadOnlyList<SourceTableInventory> inventory = InventoryDrift switch
            {
                "missing-column" => [new("dbo", "Primary", [Id()])],
                "unexpected-column" => [new("dbo", "Primary", [Id(), Value(), new("Extra", "int", Hash("Extra:int"), null)])],
                "unexpected-table" => [new("dbo", "Primary", [Id(), Value()]), new("dbo", "Extra", [Id()])],
                "metadata-mismatch" => [new("dbo", "Primary", [Id(), Value("nvarchar(max)")])],
                _ => [new("dbo", "Primary", [Id(), Value()])],
            };
            return Task.FromResult(new SourceSchemaEvidence(
                database,
                SchemaOverrides.GetValueOrDefault(database, Hash($"source:{database}")),
                inventory));
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(
            string database,
            TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            for (int index = 1; index <= RowsPerTable; index++)
            {
                RowsYielded++;
                yield return new MigrationRow(new Dictionary<string, object?>
                {
                    ["ID"] = index,
                    ["Value"] = ValueFactory(database),
                });
                await Task.Yield();
            }
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyOrphansAsync(
            string database,
            TableCopyPlan table,
            CancellationToken cancellationToken)
        {
            IReadOnlyDictionary<string, long> result = table.ForeignKeys.ToDictionary(
                foreignKey => foreignKey.Name,
                _ => 0L,
                StringComparer.Ordinal);
            return Task.FromResult(result);
        }

        public Task<IReadOnlyDictionary<string, long>> InspectForeignKeyRelationshipsAsync(
            string database,
            TableCopyPlan table,
            CancellationToken cancellationToken)
        {
            IReadOnlyDictionary<string, long> result = table.ForeignKeys.ToDictionary(
                foreignKey => foreignKey.Name,
                _ => (long)RowsPerTable,
                StringComparer.Ordinal);
            return Task.FromResult(result);
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
            string database,
            DatabaseSchemaPlan plan,
            CancellationToken cancellationToken)
        {
            IReadOnlyDictionary<string, long> result = plan.Tables.SelectMany(table => table.Identities.Select(identity =>
                    new KeyValuePair<string, long>(
                        $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}",
                        identity.IsCalled ? identity.CurrentValue + identity.IncrementValue : identity.CurrentValue)))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
            return Task.FromResult(result);
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsCompleted.Add(database);
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsRolledBack.Add(database);
            return FailRollback ? throw new InvalidOperationException("simulated source rollback failure") : Task.CompletedTask;
        }

        public void Reset()
        {
            SchemaInspections.Clear();
            SnapshotsStarted.Clear();
            SnapshotsCompleted.Clear();
            SnapshotsRolledBack.Clear();
            RowsYielded = 0;
        }
    }

    private sealed class FakeTarget : IPostgreSqlShadowTarget
    {
        public List<ShadowDatabase> Created { get; } = [];
        public List<string> Deleted { get; } = [];
        public List<FakeTransaction> Transactions { get; } = [];
        public string? FailCopyForDatabase { get; set; }
        public string? CancelCopyForDatabase { get; set; }
        public string? NonEmptyDatabase { get; set; }
        public string? CorruptDatabase { get; set; }
        public string? Corruption { get; set; }
        public bool ReturnMalformedLease { get; set; }
        public bool FailDelete { get; set; }
        public bool FailRollback { get; set; }
        public string? FailCommitForDatabase { get; set; }
        public bool FailDisposeAfterRollback { get; set; }
        public Func<ShadowDatabase, bool>? IsRegistered { get; set; }
        public Action? BeforeDelete { get; set; }

        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
            ShadowDatabase requested,
            CancellationToken cancellationToken)
        {
            Assert.True(IsRegistered?.Invoke(requested) ?? false, "Shadow inventory must be durable before CREATE DATABASE.");
            var shadow = ReturnMalformedLease
                ? requested with { Name = requested.Name + "_malformed" }
                : requested;
            Created.Add(shadow);
            return Task.FromResult(shadow);
        }

        public Task<bool> IsEmptyAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            return Task.FromResult(!string.Equals(shadow.Database, NonEmptyDatabase, StringComparison.Ordinal));
        }

        public Task<IPostgreSqlWholeDatabaseTransaction> BeginWholeDatabaseTransactionAsync(
            ShadowDatabase shadow,
            CancellationToken cancellationToken)
        {
            var transaction = new FakeTransaction(
                string.Equals(shadow.Database, FailCopyForDatabase, StringComparison.Ordinal),
                string.Equals(shadow.Database, CancelCopyForDatabase, StringComparison.Ordinal),
                string.Equals(shadow.Database, CorruptDatabase, StringComparison.Ordinal) ? Corruption : null,
                string.Equals(shadow.Database, FailCommitForDatabase, StringComparison.Ordinal),
                FailRollback,
                FailDisposeAfterRollback);
            Transactions.Add(transaction);
            return Task.FromResult<IPostgreSqlWholeDatabaseTransaction>(transaction);
        }

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            BeforeDelete?.Invoke();
            if (FailDelete)
            {
                throw new InvalidOperationException("simulated cleanup failure");
            }

            Deleted.Add(shadow.Name);
            return Task.CompletedTask;
        }

        public void Reset()
        {
            Created.Clear();
            Deleted.Clear();
            Transactions.Clear();
        }
    }

    private sealed class FakeTransaction(bool failCopy, bool cancelCopy, string? corruption, bool failCommit, bool failRollback, bool failDisposeAfterRollback)
        : IPostgreSqlWholeDatabaseTransaction
    {
        public bool Committed { get; private set; }
        public bool RolledBack { get; private set; }
        public bool VerifiedBeforeCommit { get; private set; }
        private bool _verified;
        private readonly List<MigrationRow> _rows = [];
        public int MaximumBatchSize { get; private set; }

        public Task ApplySchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public Task FinalizeSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public async Task<long> CopyBatchAsync(
            TableCopyPlan table,
            IReadOnlyList<MigrationRow> rows,
            CancellationToken cancellationToken)
        {
            if (cancelCopy)
            {
                throw new OperationCanceledException(cancellationToken);
            }

            if (failCopy)
            {
                throw new InvalidOperationException("simulated copy failure");
            }

            foreach (StreamingLob lob in rows.SelectMany(row => row.Values.Values.OfType<StreamingLob>()))
            {
                await lob.ConsumeAsync(Stream.Null, cancellationToken);
            }

            MaximumBatchSize = Math.Max(MaximumBatchSize, rows.Count);
            if (corruption != "prefix" || _rows.Count == 0)
            {
                _rows.AddRange(rows);
            }

            return rows.Count;
        }

        public Task<string> InspectSchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            _verified = true;
            return Task.FromResult(corruption == "schema" ? Hash("schema-drift") : plan.TargetSchemaSha256);
        }

        public Task<TableReconciliationEvidence> InspectTableAsync(
            TableCopyPlan table,
            CancellationToken cancellationToken)
        {
            List<MigrationRow> observed = [.. _rows];
            if (corruption == "drop")
            {
                observed.Clear();
            }
            else if (corruption == "duplicate" && observed.Count > 0)
            {
                observed.Add(observed[0]);
            }
            else if (corruption == "transform" && observed.Count > 0)
            {
                observed[0] = new MigrationRow(new Dictionary<string, object?>(observed[0].Values, StringComparer.Ordinal)
                {
                    ["Value"] = "corrupted",
                });
            }

            using var collector = new TableEvidenceCollector(table);
            foreach (MigrationRow row in observed)
            {
                collector.Append(row);
            }

            TableReconciliationEvidence evidence = collector.Finish();
            evidence = evidence with
            {
                ForeignKeyRelationshipCounts = new Dictionary<string, long>(
                    table.ForeignKeys.ToDictionary(item => item.Name, _ => (long)observed.Count, StringComparer.Ordinal),
                    StringComparer.Ordinal),
            };
            return Task.FromResult(corruption switch
            {
                "row-count" => evidence with { RowCount = evidence.RowCount + 1 },
                "ordered-content" => evidence with { ContentSha256 = Hash("ordered-drift") },
                "aggregate" => evidence with { AggregateSha256 = Hash("aggregate-drift") },
                "null-count" => evidence with { NullCounts = ChangeCount(evidence.NullCounts, "Value", false) },
                "null-count-missing" => evidence with { NullCounts = ChangeCount(evidence.NullCounts, "Value", true) },
                "null-count-extra" => evidence with { NullCounts = AddUnexpectedCount(evidence.NullCounts) },
                "orphan" => evidence with { ForeignKeyOrphanCounts = ChangeCount(evidence.ForeignKeyOrphanCounts, "FK_Primary_Self", false) },
                "orphan-missing" => evidence with { ForeignKeyOrphanCounts = ChangeCount(evidence.ForeignKeyOrphanCounts, "FK_Primary_Self", true) },
                "orphan-extra" => evidence with { ForeignKeyOrphanCounts = AddUnexpectedCount(evidence.ForeignKeyOrphanCounts) },
                "relationship" => evidence with { ForeignKeyRelationshipCounts = ChangeCount(evidence.ForeignKeyRelationshipCounts, "FK_Primary_Self", false) },
                "relationship-missing" => evidence with { ForeignKeyRelationshipCounts = ChangeCount(evidence.ForeignKeyRelationshipCounts, "FK_Primary_Self", true) },
                "relationship-extra" => evidence with { ForeignKeyRelationshipCounts = AddUnexpectedCount(evidence.ForeignKeyRelationshipCounts) },
                _ => evidence,
            });
        }

        public Task<IReadOnlyDictionary<string, long>> InspectSequenceNextValuesAsync(
            DatabaseSchemaPlan plan,
            CancellationToken cancellationToken)
        {
            IReadOnlyDictionary<string, long> result = plan.Tables.SelectMany(table => table.Identities.Select(identity =>
                    new KeyValuePair<string, long>(
                        $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}",
                        identity.IsCalled ? identity.CurrentValue + identity.IncrementValue : identity.CurrentValue)))
                .ToDictionary(item => item.Key, item => item.Value, StringComparer.Ordinal);
            return Task.FromResult(corruption is "sequence" or "sequence-missing"
                ? ChangeCount(result, "public.Primary.ID", corruption == "sequence-missing")
                : corruption == "sequence-extra" ? AddUnexpectedCount(result) : result);
        }

        public Task CommitAsync(CancellationToken cancellationToken)
        {
            VerifiedBeforeCommit = _verified;
            if (failCommit)
            {
                throw new InvalidOperationException("simulated commit failure");
            }
            Committed = true;
            return Task.CompletedTask;
        }

        public Task RollbackAsync(CancellationToken cancellationToken)
        {
            RolledBack = true;
            return failRollback ? throw new InvalidOperationException("simulated target rollback failure") : Task.CompletedTask;
        }

        private static Dictionary<string, long> ChangeCount(IReadOnlyDictionary<string, long> values, string key, bool remove)
        {
            var result = new Dictionary<string, long>(values, StringComparer.Ordinal);
            if (remove)
            {
                _ = result.Remove(key);
            }
            else
            {
                result[key] = result.GetValueOrDefault(key) + 1;
            }
            return result;
        }

        private static Dictionary<string, long> AddUnexpectedCount(IReadOnlyDictionary<string, long> values)
        {
            return new Dictionary<string, long>(values, StringComparer.Ordinal) { ["Unexpected"] = 0 };
        }

        public ValueTask DisposeAsync()
        {
            return RolledBack && failDisposeAfterRollback
                ? throw new InvalidOperationException("simulated disposal rollback failure")
                : ValueTask.CompletedTask;
        }
    }

    private sealed class RejectingRuntimeVerifier : IRuntimeAttestationVerifier
    {
        public Task VerifyAsync(ExecutionAuthorizationReceipt authorization, CancellationToken cancellationToken)
        {
            return Task.FromException(new RuntimeAttestationException("runtime_target_drift", "target drift"));
        }
    }

    private sealed class AcceptingRuntimeVerifier : IRuntimeAttestationVerifier
    {
        public Task VerifyAsync(ExecutionAuthorizationReceipt authorization, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }
    }

    private sealed class InMemoryJournal : IMigrationRunJournal
    {
        public Task RecordCheckpointAsync(MigrationRunLease lease, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public Task<IReadOnlyList<DatabaseMigrationCheckpoint>> GetCheckpointsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            throw new NotSupportedException();
        }

        public int TryBeginCount { get; private set; }
        public List<MigrationExecutionReceipt> Completed { get; } = [];
        public List<MigrationFailureReceipt> Failed { get; } = [];
        public List<ShadowCleanupOutcome> Cleanup { get; } = [];
        private readonly Dictionary<Guid, MigrationRunIdentity> _inProgress = [];
        private readonly Dictionary<Guid, MigrationRunLease> _leases = [];
        private readonly Dictionary<Guid, List<ShadowDatabase>> _pendingShadows = [];
        private MigrationExecutionReceipt? _forcedCompleted;

        public Task<MigrationRunStartResult> TryBeginAsync(
            MigrationRunIdentity identity,
            CancellationToken cancellationToken)
        {
            TryBeginCount++;
            if (_forcedCompleted is not null)
            {
                return Task.FromResult(new MigrationRunStartResult(
                    MigrationRunStartStatus.AlreadyCompleted,
                    _forcedCompleted));
            }

            MigrationExecutionReceipt? completed = Completed.SingleOrDefault(receipt => receipt.RunId == identity.RunId);
            if (completed is not null)
            {
                return Task.FromResult(new MigrationRunStartResult(
                    MigrationRunIdentity.FromReceipt(completed) == identity
                        ? MigrationRunStartStatus.AlreadyCompleted
                        : MigrationRunStartStatus.Conflict,
                    completed));
            }

            if (_inProgress.TryGetValue(identity.RunId, out MigrationRunIdentity? existing))
            {
                return Task.FromResult(new MigrationRunStartResult(
                    existing == identity ? MigrationRunStartStatus.InProgress : MigrationRunStartStatus.Conflict,
                    null));
            }

            _inProgress.Add(identity.RunId, identity);
            var lease = new MigrationRunLease(identity, "test-runner", 1, DateTimeOffset.MaxValue)
            {
                FencingToken = Guid.NewGuid(),
            };
            _leases.Add(identity.RunId, lease);
            IReadOnlyList<ShadowDatabase> pending = _pendingShadows.TryGetValue(identity.RunId, out List<ShadowDatabase>? shadows)
                ? [.. shadows]
                : [];
            return Task.FromResult(new MigrationRunStartResult(MigrationRunStartStatus.Acquired, null, lease, pending));
        }

        public Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            _ = _inProgress.Remove(receipt.RunId);
            Completed.Add(receipt);
            return Task.CompletedTask;
        }

        public Task RecordCompletedAsync(
            MigrationRunLease lease,
            MigrationExecutionReceipt receipt,
            CancellationToken cancellationToken)
        {
            return RecordCompletedAsync(receipt, cancellationToken);
        }

        public Task RecordFailedAsync(MigrationFailureReceipt receipt, CancellationToken cancellationToken)
        {
            _ = _inProgress.Remove(receipt.RunId);
            Failed.Add(receipt);
            return Task.CompletedTask;
        }

        public Task RecordFailedAsync(
            MigrationRunLease lease,
            MigrationFailureReceipt receipt,
            CancellationToken cancellationToken)
        {
            return RecordFailedAsync(receipt, cancellationToken);
        }

        public Task<MigrationRunLease> HeartbeatAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            return Task.FromResult(lease);
        }

        public Task RegisterShadowAsync(MigrationRunLease lease, ShadowDatabase shadow, CancellationToken cancellationToken)
        {
            if (!_pendingShadows.TryGetValue(lease.Identity.RunId, out List<ShadowDatabase>? shadows))
            {
                shadows = [];
                _pendingShadows.Add(lease.Identity.RunId, shadows);
            }

            shadows.Add(shadow);
            return Task.CompletedTask;
        }

        public Task<IReadOnlyList<ShadowDatabase>> GetPendingShadowsAsync(MigrationRunLease lease, CancellationToken cancellationToken)
        {
            IReadOnlyList<ShadowDatabase> shadows = _pendingShadows.TryGetValue(lease.Identity.RunId, out List<ShadowDatabase>? pending)
                ? pending
                : [];
            return Task.FromResult(shadows);
        }

        public Task RecordShadowCleanupAsync(MigrationRunLease lease, ShadowCleanupOutcome outcome, CancellationToken cancellationToken)
        {
            Cleanup.Add(outcome);
            if (outcome.Deleted && _pendingShadows.TryGetValue(lease.Identity.RunId, out List<ShadowDatabase>? pending))
            {
                _ = pending.RemoveAll(shadow => string.Equals(shadow.Name, outcome.ShadowName, StringComparison.Ordinal));
            }

            return Task.CompletedTask;
        }

        public void SeedPendingShadow(MigrationRunIdentity identity, ShadowDatabase shadow)
        {
            _pendingShadows[identity.RunId] = [shadow];
        }

        public bool IsRegistered(ShadowDatabase shadow)
        {
            return Guid.TryParse(shadow.OwnerRunId, out Guid runId) &&
                _pendingShadows.TryGetValue(runId, out List<ShadowDatabase>? pending) &&
                pending.Contains(shadow);
        }

        public void ForceInProgress(MigrationRunIdentity identity)
        {
            _inProgress.Add(identity.RunId, identity);
        }

        public void ForceCompletedResult(MigrationExecutionReceipt receipt)
        {
            _forcedCompleted = receipt;
        }
    }
}
