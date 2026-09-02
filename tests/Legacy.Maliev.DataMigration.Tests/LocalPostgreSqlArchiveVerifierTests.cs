using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class LocalPostgreSqlArchiveVerifierTests(LocalArchiveVerificationFixture fixture) : IClassFixture<LocalArchiveVerificationFixture>
{
    private static readonly string[] ExpectedFiles = [".store.lock", "archive.aes256", "artifact.json"];
    [PostgreSql18SnapshotIntegrationFact]
    public async Task ExecutionReadiness_AuthenticatesRestorePassword_AndCleansOnlyOwnedProbe()
    {
        string before = await fixture.CatalogAsync();
        object? roles = await fixture.ScalarAsync("postgres", "SELECT json_agg(r ORDER BY oid)::text FROM pg_roles r;");
        await fixture.Verifier().VerifyExecutionReadinessAsync(default);
        Assert.Equal(before, await fixture.CatalogAsync());
        Assert.Equal(roles, await fixture.ScalarAsync("postgres", "SELECT json_agg(r ORDER BY oid)::text FROM pg_roles r;"));
        LocalPostgreSqlArchiveVerificationOptions bad = fixture.Options with
        {
            RestoreConnectionString = new NpgsqlConnectionStringBuilder(fixture.Options.RestoreConnectionString) { Password = Guid.NewGuid().ToString("N") }.ConnectionString,
        };
        // Read-only planning deliberately cannot authenticate this login without a new DB.
        await fixture.Verifier(bad).PreflightAsync(default);
        PostgresException error = await Assert.ThrowsAsync<PostgresException>(() => fixture.Verifier(bad).VerifyExecutionReadinessAsync(default));
        Assert.Equal(PostgresErrorCodes.InvalidPassword, error.SqlState);
        Assert.Equal(before, await fixture.CatalogAsync());
        Assert.Equal(42, await fixture.ScalarAsync("protected_archive_fixture", "SELECT value FROM sentinel;"));
        Assert.Equal(0L, await fixture.ScalarAsync("postgres", "SELECT count(*) FROM pg_stat_activity WHERE usename='local_archive_restore';"));
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Preflight_ReadOnlyAndNotCached_RejectsChangedRoleOrResourceBeforeCreate()
    {
        string before = await fixture.CatalogAsync();
        object? roles = await fixture.ScalarAsync("postgres", "SELECT json_agg(r ORDER BY oid)::text FROM pg_roles r;");
        object? databases = await fixture.ScalarAsync("postgres", "SELECT json_agg(d ORDER BY oid)::text FROM pg_database d;");
        LocalPostgreSqlArchiveVerifier verifier = fixture.Verifier();
        await verifier.PreflightAsync(default);
        Assert.Equal(before, await fixture.CatalogAsync());
        Assert.Equal(roles, await fixture.ScalarAsync("postgres", "SELECT json_agg(r ORDER BY oid)::text FROM pg_roles r;"));
        Assert.Equal(databases, await fixture.ScalarAsync("postgres", "SELECT json_agg(d ORDER BY oid)::text FROM pg_database d;"));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier(fixture.Options with { SystemIdentifier = "1" }).PreflightAsync(default));
        await fixture.ExecuteAsync("postgres", $"GRANT CONNECT ON DATABASE protected_archive_fixture TO {LocalArchiveVerificationFixture.RestoreRole};");
        try
        {
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => verifier.PreflightAsync(default));
            using var stream = new MemoryStream(fixture.Archive);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => verifier.VerifyAsync(stream, fixture.Checkpoint, default));
            Assert.Equal(0, stream.Position);
            Assert.Equal(before, await fixture.CatalogAsync());
        }
        finally { await fixture.ExecuteAsync("postgres", $"REVOKE CONNECT ON DATABASE protected_archive_fixture FROM {LocalArchiveVerificationFixture.RestoreRole};"); }
        Assert.Equal(0L, await fixture.ScalarAsync("postgres", "SELECT count(*) FROM pg_stat_activity WHERE datname='postgres' AND pid <> pg_backend_pid();"));
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Delivery_EncryptedReplayFailure_PreservesVerifiedArtifactWithoutPlaintextFiles()
    {
        string root = Path.Combine(Path.GetTempPath(), "real-local-verifier-" + Guid.NewGuid().ToString("N"));
        byte[] key = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        try
        {
            var checkpointVerifier = new DatabaseMigrationCheckpointVerifier(fixture.CheckpointOptions);
            var dump = new PgDumpSource(LocalArchiveVerificationFixture.Tool("PG_DUMP_PATH"), fixture.Admin);
            using (var store = new IncrementalLocalSnapshotStore(root, "full-pg18", key, checkpointVerifier, dump, fixture.Verifier(), _ => Task.CompletedTask))
            {
                await store.DeliverAndVerifyAsync(fixture.Checkpoint, default);
                _ = Assert.Single(await store.ReadVerifiedCheckpointsAsync(default));
            }
            string[] paths = Directory.GetFiles(root, "*", SearchOption.AllDirectories).Order(StringComparer.Ordinal).ToArray();
            Assert.Equal(ExpectedFiles, paths.Select(Path.GetFileName).Order(StringComparer.Ordinal));
            byte[][] before = await Task.WhenAll(paths.Select(path => File.ReadAllBytesAsync(path)));
            using var replay = new IncrementalLocalSnapshotStore(root, "full-pg18", key, checkpointVerifier, dump,
                fixture.Verifier(fixture.Options with { SystemIdentifier = "1" }), _ => Task.CompletedTask);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => replay.DeliverAndVerifyAsync(fixture.Checkpoint, default));
            for (int i = 0; i < paths.Length; i++) { Assert.Equal(before[i], await File.ReadAllBytesAsync(paths[i])); }
        }
        finally { System.Security.Cryptography.CryptographicOperations.ZeroMemory(key); if (Directory.Exists(root)) { Directory.Delete(root, recursive: true); } }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_CancelDuringInput_ObservesProcessAndCleansExactDatabase()
    {
        string before = await fixture.CatalogAsync();
        using var cancellation = new CancellationTokenSource();
        using var stream = new CallbackInput(fixture.Archive, cancellation.CancelAsync);
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, cancellation.Token));
        Assert.Equal(before, await fixture.CatalogAsync());
        Assert.Equal(0L, await fixture.ScalarAsync("postgres", "SELECT count(*) FROM pg_stat_activity WHERE usename='local_archive_restore';"));
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_RestoreAndCleanupBothFail_PreservesPrimaryAndRefusesChangedOwnership()
    {
        string? local = null;
        string before = await fixture.CatalogAsync();
        using var stream = new CallbackInput("not an archive"u8.ToArray(), async () =>
        {
            local = (await fixture.CatalogAsync()).Split('\n').Except(before.Split('\n'), StringComparer.Ordinal).Single();
            Assert.StartsWith("local_archive_verify_", local, StringComparison.Ordinal);
            await fixture.ExecuteAsync("postgres", $"COMMENT ON DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(local)} IS 'changed-ownership';");
        });
        try
        {
            AggregateException error = await Assert.ThrowsAsync<AggregateException>(() => fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, default));
            Assert.Equal("local_archive_restore_failed", Assert.IsType<MigrationExecutionException>(error.InnerExceptions[0]).Code);
            Assert.Equal("local_archive_cleanup_ownership", Assert.IsType<MigrationExecutionException>(error.InnerExceptions[1]).Code);
            Assert.Contains(local, (await fixture.CatalogAsync()).Split('\n'));
            Assert.Equal(42, await fixture.ScalarAsync("protected_archive_fixture", "SELECT value FROM sentinel;"));
        }
        finally
        {
            // Test-owned isolated cluster resource; production deliberately preserved it.
            if (local is not null) { await fixture.ExecuteAsync("postgres", $"DROP DATABASE {PostgreSqlShadowTarget.QuoteIdentifier(local)} WITH(FORCE);"); }
        }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_FullSignedPlan_StreamsRestoreAndCleansOnlyItsTemporaryDatabase()
    {
        string before = await fixture.CatalogAsync();
        using var stream = new MemoryStream(fixture.Archive);
        await fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, default);
        Assert.Equal(stream.Length, stream.Position);
        Assert.Equal(before, await fixture.CatalogAsync());
        Assert.Equal(42, await fixture.ScalarAsync("protected_archive_fixture", "SELECT value FROM sentinel;"));
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_InvalidIdentityAndUnrestrictedRole_RejectBeforeCreateAndBeforeInput()
    {
        LocalPostgreSqlArchiveVerificationOptions options = fixture.Options;
        foreach (LocalPostgreSqlArchiveVerificationOptions invalid in new[]
        {
            options with { ContainerId = new string('0', 64) }, options with { ImageId = "sha256:" + new string('0', 64) },
            options with { SystemIdentifier = "1" }, options with { ImageId = "" },
            options with { AdministrativeConnectionString = new NpgsqlConnectionStringBuilder(options.AdministrativeConnectionString) { Host = "localhost" }.ConnectionString },
            options with { RestoreConnectionString = options.AdministrativeConnectionString },
            options with { RestoreConnectionString = new NpgsqlConnectionStringBuilder(options.RestoreConnectionString) { Port = 1 }.ConnectionString },
        })
        {
            string before = await fixture.CatalogAsync();
            using var stream = new MemoryStream(fixture.Archive);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier(invalid).VerifyAsync(stream, fixture.Checkpoint, default));
            Assert.Equal(0, stream.Position);
            Assert.Equal(before, await fixture.CatalogAsync());
        }
        await fixture.ExecuteAsync("postgres", $"GRANT CONNECT ON DATABASE protected_archive_fixture TO {LocalArchiveVerificationFixture.RestoreRole};");
        try
        {
            using var stream = new MemoryStream(fixture.Archive);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, default));
            Assert.Equal(0, stream.Position);
        }
        finally { await fixture.ExecuteAsync("postgres", $"REVOKE CONNECT ON DATABASE protected_archive_fixture FROM {LocalArchiveVerificationFixture.RestoreRole};"); }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_AlteredSignedEvidenceOrUnsignedCheckpoint_RejectsAndCleans()
    {
        DatabaseMigrationCheckpoint checkpoint = fixture.Checkpoint;
        TableReconciliationEvidence table = checkpoint.Reconciliation.Tables[0];
        var changedNulls = new Dictionary<string, long>(table.NullCounts) { ["Name"] = 0 };
        foreach (DatabaseMigrationCheckpoint wrong in new[]
        {
            checkpoint with { AttestationSignature = "invalid" },
            fixture.Sign(checkpoint with { Reconciliation = checkpoint.Reconciliation with { SequenceNextValues = new Dictionary<string, long> { ["sales.parents.Id"] = 99 } } }),
            fixture.Sign(checkpoint with { Reconciliation = checkpoint.Reconciliation with { Tables = [table with { NullCounts = changedNulls }, checkpoint.Reconciliation.Tables[1]] } }),
            fixture.Sign(checkpoint with { Reconciliation = checkpoint.Reconciliation with { Tables = [table, checkpoint.Reconciliation.Tables[1] with { ForeignKeyRelationshipCounts = new Dictionary<string, long> { ["FK_child_parent"] = 0 } }] } }),
        })
        {
            string before = await fixture.CatalogAsync();
            using var stream = new MemoryStream(fixture.Archive);
            MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier().VerifyAsync(stream, wrong, default));
            Assert.Equal(wrong.AttestationSignature == "invalid" ? "checkpoint_invalid" : "shadow_reconciliation_failed", error.Code);
            Assert.Equal(before, await fixture.CatalogAsync());
        }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_ChangedSchemaRowsRelationshipsAndSequences_RejectsRealArchives()
    {
        foreach ((string change, string restore) in new[]
        {
            ("ALTER TABLE sales.children ADD COLUMN extra integer;", "ALTER TABLE sales.children DROP COLUMN extra;"),
            ("UPDATE sales.parents SET \"Name\"='changed' WHERE \"Id\"=1;", "UPDATE sales.parents SET \"Name\"='ไทย' WHERE \"Id\"=1;"),
            ("UPDATE sales.children SET \"ParentId\"=2 WHERE \"Id\"=10;", "UPDATE sales.children SET \"ParentId\"=1 WHERE \"Id\"=10;"),
            ("SELECT setval('sales.\"parents_Id_seq\"',99,true);", "SELECT setval('sales.\"parents_Id_seq\"',2,true);"),
        })
        {
            await fixture.ExecuteAsync(fixture.Checkpoint.Shadow.Name, change);
            try
            {
                string before = await fixture.CatalogAsync();
                using var stream = new MemoryStream(await fixture.DumpAsync());
                MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, default));
                Assert.Equal("shadow_reconciliation_failed", error.Code);
                Assert.Equal(before, await fixture.CatalogAsync());
            }
            finally { await fixture.ExecuteAsync(fixture.Checkpoint.Shadow.Name, restore); }
        }
    }

    [PostgreSql18SnapshotIntegrationFact]
    public async Task Verify_ArchivePrivilegedSql_CannotCreateRoleOrMutateProtectedDatabase()
    {
        string source = fixture.Checkpoint.Shadow.Name;
        await fixture.ExecuteAsync(source, "CREATE FUNCTION sales.attack(integer) RETURNS boolean LANGUAGE plpgsql AS 'BEGIN RETURN true; END'; ALTER TABLE sales.parents ADD CONSTRAINT attack CHECK(sales.attack(\"Id\")); CREATE OR REPLACE FUNCTION sales.attack(integer) RETURNS boolean LANGUAGE plpgsql AS 'BEGIN EXECUTE ''CREATE ROLE escaped_archive_restore''; RETURN true; END';");
        try
        {
            string before = await fixture.CatalogAsync();
            using var stream = new MemoryStream(await fixture.DumpAsync());
            MigrationExecutionException error = await Assert.ThrowsAsync<MigrationExecutionException>(() => fixture.Verifier().VerifyAsync(stream, fixture.Checkpoint, default));
            Assert.Equal("local_archive_restore_failed", error.Code);
            Assert.Equal(0L, await fixture.ScalarAsync("postgres", "SELECT count(*) FROM pg_roles WHERE rolname='escaped_archive_restore';"));
            Assert.Equal(42, await fixture.ScalarAsync("protected_archive_fixture", "SELECT value FROM sentinel;"));
            Assert.Equal(before, await fixture.CatalogAsync());
        }
        finally { await fixture.ExecuteAsync(source, "ALTER TABLE sales.parents DROP CONSTRAINT attack; DROP FUNCTION sales.attack(integer);"); }
    }

    private sealed class CallbackInput(byte[] bytes, Func<Task> beforeCopy) : MemoryStream(bytes)
    {
        public override async Task CopyToAsync(Stream destination, int bufferSize, CancellationToken cancellationToken)
        {
            await beforeCopy();
            cancellationToken.ThrowIfCancellationRequested();
            await base.CopyToAsync(destination, bufferSize, cancellationToken);
        }
    }
}
