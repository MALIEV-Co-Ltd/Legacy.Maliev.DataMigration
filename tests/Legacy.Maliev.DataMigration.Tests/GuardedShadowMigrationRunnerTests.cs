using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class GuardedShadowMigrationRunnerTests
{
    private static readonly DateTimeOffset Now = new(2026, 8, 29, 14, 0, 0, TimeSpan.Zero);
    private static readonly ECDsa SigningKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
    private const string KeyId = "migration-authorizer-1";
    private const string CurrentSourceCommit = "25418c95b5ac79400029ce274541f0e51728da3e";
    private static readonly string RunnerDigest = Hash("guarded-shadow-runner-v1");

    [Fact]
    public async Task ExecuteAsync_ApprovedRequest_CopiesEveryDatabaseIntoUniqueEmptyCommittedShadow()
    {
        Harness harness = CreateHarness();

        MigrationExecutionResult result = await harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None);

        Assert.Equal(MigrationExecutionStatus.Completed, result.Status);
        Assert.Equal(21, result.Receipt.Databases.Count);
        Assert.Equal(21, harness.Source.SchemaInspections.Count);
        Assert.Equal(21, harness.Source.SnapshotsStarted.Count);
        Assert.Equal(21, harness.Source.SnapshotsCompleted.Count);
        Assert.Empty(harness.Source.SnapshotsRolledBack);
        Assert.Equal(21, harness.Target.Created.Count);
        Assert.Equal(21, harness.Target.Transactions.Count(transaction => transaction.Committed));
        Assert.All(harness.Target.Transactions, transaction => Assert.True(transaction.VerifiedBeforeCommit));
        Assert.Equal(21, harness.Target.Created.Select(shadow => shadow.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.All(harness.Target.Created, shadow => Assert.StartsWith("legacy_shadow_", shadow.Name, StringComparison.Ordinal));
        Assert.Empty(harness.Target.Deleted);
        _ = Assert.Single(harness.Journal.Completed);
    }

    [Fact]
    public async Task ExecuteAsync_TargetCopyFails_RollsBackCurrentTransactionAndDeletesEveryRunOwnedShadow()
    {
        Harness harness = CreateHarness();
        harness.Target.FailCopyForDatabase = DatabaseInventory.ActiveDatabases[1];

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_copy_failed", exception.Code);
        Assert.Contains(harness.Target.Transactions, transaction => transaction.RolledBack);
        Assert.Contains(DatabaseInventory.ActiveDatabases[1], harness.Source.SnapshotsRolledBack);
        Assert.Equal(harness.Target.Created.Select(shadow => shadow.Name).Order(), harness.Target.Deleted.Order());
        Assert.Empty(harness.Journal.Completed);
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
    public async Task ExecuteAsync_ObservedSourceSchemaDoesNotMatchPlan_CleansCreatedShadowsAndFailsClosed()
    {
        Harness harness = CreateHarness();
        harness.Source.SchemaOverrides[DatabaseInventory.ActiveDatabases[1]] = Hash("unexpected-live-schema");

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("source_schema_drift", exception.Code);
        Assert.Equal(harness.Target.Created.Select(shadow => shadow.Name).Order(), harness.Target.Deleted.Order());
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
    [InlineData("Log")]
    [InlineData("Hangfire")]
    [InlineData("MachineLearning")]
    [InlineData("MachineLearningData")]
    [InlineData("ContactRequest")]
    [InlineData("LocationData")]
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
    public async Task ExecuteAsync_ShadowReportedNonEmpty_DeletesRunOwnedShadowAndStops()
    {
        Harness harness = CreateHarness();
        harness.Target.NonEmptyDatabase = DatabaseInventory.ActiveDatabases[0];

        MigrationExecutionException exception = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Equal("shadow_database_not_empty", exception.Code);
        Assert.Equal(harness.Target.Created.Select(shadow => shadow.Name), harness.Target.Deleted);
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
    public async Task ExecuteAsync_CancelledCopy_RollsBackAndDeletesEveryRunOwnedShadow()
    {
        Harness harness = CreateHarness();
        harness.Target.CancelCopyForDatabase = DatabaseInventory.ActiveDatabases[1];

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            harness.Runner.ExecuteAsync(CreateRequest(), CancellationToken.None));

        Assert.Contains(harness.Target.Transactions, transaction => transaction.RolledBack);
        Assert.Equal(harness.Target.Created.Select(shadow => shadow.Name).Order(), harness.Target.Deleted.Order());
        Assert.Empty(harness.Journal.Completed);
    }

    private static Harness CreateHarness()
    {
        TrustedAttestationKey trustedKey = new(KeyId, SigningKey.ExportSubjectPublicKeyInfo());
        var trustStore = new ReceiptAttestationTrustStore([trustedKey]);
        FakeSource source = new();
        FakeTarget target = new();
        InMemoryJournal journal = new();
        var runner = new GuardedShadowMigrationRunner(
            new PreflightService(new NeverExternalCommandExecutor(), trustStore),
            trustStore,
            source,
            target,
            journal,
            new GuardedRunnerPolicy(CurrentSourceCommit, RunnerDigest));
        return new(runner, source, target, journal);
    }

    private static GuardedMigrationRequest CreateRequest(FreshSchemaPlan? plan = null)
    {
        FreshSchemaPlan schemaPlan = plan ?? CreateSchemaPlan();
        Guid runId = Guid.Parse("08e86003-b953-4234-96a7-7b40f8017331");
        return new(
            CreateBackupReceipt(),
            schemaPlan,
            SignAuthorization(CreateAuthorization(runId, schemaPlan)),
            Now,
            TimeSpan.FromHours(26),
            TimeSpan.FromHours(6));
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
                ColumnTypes = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["ID"] = "integer",
                    ["Value"] = "text",
                },
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
            ExpiresAtUtc: Now.AddHours(1),
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
                hash);
        })];
        string manifestHash = ComputeManifestSha256(artifacts);
        BackupReceipt receipt = new(
            "1.0",
            Now.AddHours(-1),
            DatabaseInventory.InventorySha256,
            manifestHash,
            artifacts,
            KeyId,
            null);
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
        InMemoryJournal Journal);

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

        public Task BeginDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsStarted.Add(database);
            return Task.CompletedTask;
        }

        public Task<SourceSchemaEvidence> InspectSchemaAsync(string database, CancellationToken cancellationToken)
        {
            SchemaInspections.Add(database);
            return Task.FromResult(new SourceSchemaEvidence(
                database,
                SchemaOverrides.GetValueOrDefault(database, Hash($"source:{database}"))));
        }

        public async IAsyncEnumerable<MigrationRow> ReadTableAsync(
            string database,
            TableCopyPlan table,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            yield return new MigrationRow(new Dictionary<string, object?> { ["ID"] = 1, ["Value"] = database });
            await Task.CompletedTask;
        }

        public Task CompleteDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsCompleted.Add(database);
            return Task.CompletedTask;
        }

        public Task RollbackDatabaseSnapshotAsync(string database, CancellationToken cancellationToken)
        {
            SnapshotsRolledBack.Add(database);
            return Task.CompletedTask;
        }

        public void Reset()
        {
            SchemaInspections.Clear();
            SnapshotsStarted.Clear();
            SnapshotsCompleted.Clear();
            SnapshotsRolledBack.Clear();
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

        public Task<ShadowDatabase> CreateUniqueEmptyShadowAsync(
            string database,
            string shadowName,
            string ownerRunId,
            CancellationToken cancellationToken)
        {
            var shadow = new ShadowDatabase(shadowName, ownerRunId, database);
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
                shadow.Database,
                string.Equals(shadow.Database, FailCopyForDatabase, StringComparison.Ordinal),
                string.Equals(shadow.Database, CancelCopyForDatabase, StringComparison.Ordinal));
            Transactions.Add(transaction);
            return Task.FromResult<IPostgreSqlWholeDatabaseTransaction>(transaction);
        }

        public Task DeleteRunOwnedShadowAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
        {
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

    private sealed class FakeTransaction(string database, bool failCopy, bool cancelCopy)
        : IPostgreSqlWholeDatabaseTransaction
    {
        public bool Committed { get; private set; }
        public bool RolledBack { get; private set; }
        public bool VerifiedBeforeCommit { get; private set; }
        private bool _verified;

        public Task ApplySchemaAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
        {
            return Task.CompletedTask;
        }

        public async Task<long> CopyTableAsync(
            TableCopyPlan table,
            IAsyncEnumerable<MigrationRow> rows,
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

            long count = 0;
            await foreach (MigrationRow _ in rows.WithCancellation(cancellationToken))
            {
                count++;
            }

            return count;
        }

        public Task<DatabaseReconciliationResult> ReconcileAsync(
            DatabaseSchemaPlan plan,
            IReadOnlyDictionary<string, long> copiedRows,
            CancellationToken cancellationToken)
        {
            _verified = true;
            return Task.FromResult(new DatabaseReconciliationResult(true, copiedRows.Values.Sum(), Hash(database), []));
        }

        public Task CommitAsync(CancellationToken cancellationToken)
        {
            VerifiedBeforeCommit = _verified;
            Committed = true;
            return Task.CompletedTask;
        }

        public Task RollbackAsync(CancellationToken cancellationToken)
        {
            RolledBack = true;
            return Task.CompletedTask;
        }

        public ValueTask DisposeAsync()
        {
            return ValueTask.CompletedTask;
        }
    }

    private sealed class InMemoryJournal : IMigrationRunJournal
    {
        public List<MigrationExecutionReceipt> Completed { get; } = [];
        private readonly Dictionary<Guid, MigrationRunIdentity> _inProgress = [];

        public Task<MigrationRunStartResult> TryBeginAsync(
            MigrationRunIdentity identity,
            CancellationToken cancellationToken)
        {
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
            return Task.FromResult(new MigrationRunStartResult(MigrationRunStartStatus.Acquired, null));
        }

        public Task RecordCompletedAsync(MigrationExecutionReceipt receipt, CancellationToken cancellationToken)
        {
            _ = _inProgress.Remove(receipt.RunId);
            Completed.Add(receipt);
            return Task.CompletedTask;
        }

        public Task RecordFailedAsync(Guid runId, CancellationToken cancellationToken)
        {
            _ = _inProgress.Remove(runId);
            return Task.CompletedTask;
        }

        public void ForceInProgress(MigrationRunIdentity identity)
        {
            _inProgress.Add(identity.RunId, identity);
        }
    }
}
