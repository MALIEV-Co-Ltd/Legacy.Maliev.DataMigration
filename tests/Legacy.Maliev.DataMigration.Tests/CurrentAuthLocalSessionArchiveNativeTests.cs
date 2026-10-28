using System.Data;
using System.Net;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using NpgsqlTypes;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed partial class CurrentAuthLocalSessionArchiveNativeTests(ITestOutputHelper output)
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    [WindowsLocalRunTheory]
    [InlineData("10.0.12")]
    [InlineData("10.0.10")]
    public Task Exact_typed_delete_preserves_private_state_and_target_history_through_rollback_commit_independent_readback(string historyVersion)
    {
        return RunOwnedAsync(async (admin, token) =>
        {
            string endpoint = await BootstrapAsync(admin, historyVersion, token);
            // Establish genuine owner-C closure through the fixed native collation
            // precursor; this is synthetic fixture setup, never history adoption.
            await using (var setup = new NpgsqlConnection(endpoint))
            {
                await setup.OpenAsync(token); await using var tx = await setup.BeginTransactionAsync(IsolationLevel.Serializable, token);
                await CandidateAsync(setup, tx, token); await tx.CommitAsync(token);
            }
            string binding = new('a', 64); CurrentAuthLocalSessionArchiveObservation before;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token); Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                before = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token);
                Assert.Equal(2, before.Sessions.Count);
                await DeleteAsync(connection, tx, before, token);
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before,
                    await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token));
                await tx.RollbackAsync(token);
            }
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                CurrentAuthLocalSessionArchiveObservation restored = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token);
                CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(restored, before);
                await DeleteAsync(connection, tx, restored, token);
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before,
                    await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token));
                await tx.CommitAsync(token);
            }
            // Prior writer and transaction have been disposed before this backend.
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", token, tx);
                var after = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, binding, token);
                CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, after);
                Assert.Empty(after.Sessions);
                Assert.Equal(historyVersion, await ScalarAsync<string>(connection, "SELECT min(\"ProductVersion\") FROM public.\"__EFMigrationsHistory\";", token));
                await tx.RollbackAsync(token);
            }
        });
    }
    [WindowsLocalRunTheory]
    [InlineData("unknown-index")]
    [InlineData("index-default-collation")]
    [InlineData("private-inbound-fk")]
    public Task Unsupported_current_native_shape_or_delete_dependency_fails_before_delete(string fault)
    {
        return RunOwnedAsync(async (admin, token) =>
        {
            string endpoint = await BootstrapAsync(admin, "10.0.12", token);
            await using var connection = new NpgsqlConnection(endpoint); await connection.OpenAsync(token);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
            await CandidateAsync(connection, tx, token);
            if (fault == "unknown-index")
            { await ExecuteAsync(connection, "CREATE INDEX unreviewed_session_index ON public.refresh_sessions(\"IdentityKind\");", token, tx); }
            else if (fault == "private-inbound-fk")
            { await ExecuteAsync(connection, "CREATE TABLE private.session_reference(id uuid REFERENCES public.refresh_sessions(\"Id\"));", token, tx); }
            else
            {
                IndexCopyPlan index = ApprovedCurrentAuthSchema.Tables(true).Single(x => x.TargetTable == "refresh_sessions").Indexes
                    .Single(x => x.Unique && x.Columns.SequenceEqual(["TokenHash"]));
                await ExecuteAsync(connection, "DROP INDEX public." + Quote(index.Name) + "; CREATE UNIQUE INDEX " + Quote(index.Name) +
                    " ON public.refresh_sessions(\"TokenHash\" COLLATE \"default\");", token, tx);
            }
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, new string('a', 64), token));
            Assert.Equal(2L, await ScalarAsync<long>(connection, "SELECT count(*) FROM public.refresh_sessions;", token));
            await tx.RollbackAsync(token);
        });
    }
    [WindowsLocalRunTheory]
    [InlineData("session-cas")]
    [InlineData("private-journal")]
    [InlineData("private-sequence")]
    [InlineData("target-history")]
    public Task Fresh_CAS_and_complete_preservation_reject_native_state_changes(string fault)
    {
        return RunOwnedAsync(async (admin, token) =>
        {
            string endpoint = await BootstrapAsync(admin, "10.0.12", token);
            await using var connection = new NpgsqlConnection(endpoint); await connection.OpenAsync(token);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
            await CandidateAsync(connection, tx, token);
            var before = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, new string('a', 64), token);
            string sql = fault switch
            {
                "session-cas" => "UPDATE public.refresh_sessions SET \"SecurityStamp\"='synthetic-changed';",
                "private-journal" => "UPDATE private.journal SET evidence='synthetic-changed';",
                "private-sequence" => "SELECT nextval('private.allocation');",
                "target-history" => "UPDATE public.\"__EFMigrationsHistory\" SET \"ProductVersion\"='10.0.99';",
                _ => throw new InvalidOperationException(),
            };
            await ExecuteAsync(connection, sql, token, tx);
            var after = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, new string('a', 64), token);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(after, before));
            await tx.RollbackAsync(token);
        });
    }
    private static async Task DeleteAsync(NpgsqlConnection connection, NpgsqlTransaction tx,
        CurrentAuthLocalSessionArchiveObservation before, CancellationToken token)
    {
        await ExecuteAsync(connection, "SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='30s'; LOCK TABLE public.\"__EFMigrationsHistory\",public.refresh_sessions,public.google_identity_nonces,public.identity_action_tokens IN ACCESS EXCLUSIVE MODE;", token, tx);
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(
            await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, before.TargetBindingSha256, token), before);
        await using var command = new NpgsqlCommand("DELETE FROM public.refresh_sessions WHERE \"Id\"=ANY(@ids) RETURNING " + CurrentAuthLocalSessionArchiveObservation.Fields + ";", connection, tx);
        _ = command.Parameters.AddWithValue("ids", NpgsqlDbType.Array | NpgsqlDbType.Uuid, before.Sessions.Select(x => x.Id).ToArray());
        CurrentAuthLocalSessionArchivePolicy.RequireRows(await CurrentAuthLocalSessionArchiveObservation.ReadRowsAsync(command, token), before.Sessions);
    }
    private static async Task<string> BootstrapAsync(string admin, string productVersion, CancellationToken token)
    {
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync(token);
            Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
            Assert.Equal("180004", await ScalarAsync<string>(connection, "SHOW server_version_num;", token));
            await ExecuteAsync(connection, "CREATE DATABASE \"Auth\" TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", token);
        }
        string endpoint = new NpgsqlConnectionStringBuilder(admin)
        { Database = "Auth", Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
        await using var auth = new NpgsqlConnection(endpoint);
        await auth.OpenAsync(token);
        foreach (TableCopyPlan table in ApprovedCurrentAuthSchema.Tables(false))
        {
            PrimaryKeyCopyPlan key = table.PrimaryKey ?? throw new InvalidOperationException("Missing fixed primary key");
            string[] columns = [.. table.OrderedColumns.Select(name => Quote(name) + " " + table.ColumnTypes[name] +
                (table.NullableColumns.Contains(name, StringComparer.Ordinal) ? "" : " NOT NULL"))];
            string primary = "CONSTRAINT " + Quote(key.Name) + " PRIMARY KEY (" + string.Join(',', key.Columns.Select(Quote)) + ")";
            string[] checks = [.. table.CheckConstraints.Select(check => "CONSTRAINT " + Quote(check.Name) + " CHECK (" +
                (check.Name == "CK_identity_action_tokens_employee_binding"
                    ? "\"RecoveryVersion\" IS NULL OR (\"RecoveryVersion\" = 1 AND \"Purpose\" IN ('employee-password-reset', 'employee-email-confirmation') AND \"OriginalTokenSha256\" IS NOT NULL AND length(\"OriginalTokenSha256\") = 64 AND \"OwnerSubject\" IS NOT NULL AND length(\"OwnerSubject\") > 0 AND \"BoundNormalizedEmail\" IS NOT NULL AND length(\"BoundNormalizedEmail\") > 0 AND \"BoundSecurityStamp\" IS NOT NULL AND length(\"BoundSecurityStamp\") > 0)"
                    : check.Expression) + ")")];
            await ExecuteAsync(auth, "CREATE TABLE public." + Quote(table.TargetTable) + " (" + string.Join(',', columns.Append(primary).Concat(checks)) + ");", token);
            foreach (IndexCopyPlan index in table.Indexes)
            { await ExecuteAsync(auth, "CREATE " + (index.Unique ? "UNIQUE " : "") + "INDEX " + Quote(index.Name) + " ON public." + Quote(table.TargetTable) + " (" + string.Join(',', index.Columns.Select(Quote)) + ");", token); }
        }
        foreach (string id in new[] { "20260715104357_InitialRefreshSessions", "20260715140429_AddIdentityActionTokens", "20260726184305_AddGoogleIdentityNonces", "20260727193121_AddIdentityActionTokenTargetEmail", "20260930125706_AddEmployeeRecoveryBinding" })
        {
            await using var command = new NpgsqlCommand("INSERT INTO public.\"__EFMigrationsHistory\" VALUES ($1,$2);", auth);
            _ = command.Parameters.AddWithValue(id); _ = command.Parameters.AddWithValue(productVersion);
            _ = await command.ExecuteNonQueryAsync(token);
        }
        await ExecuteAsync(auth, """
            CREATE SCHEMA private;
            CREATE TABLE private.journal(id integer PRIMARY KEY,evidence text NOT NULL);
            INSERT INTO private.journal VALUES (1,'synthetic immutable journal');
            CREATE SEQUENCE private.allocation START WITH 77;
            INSERT INTO public.refresh_sessions VALUES
              ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000010','ไทย '' \\',1,NULL,'session-one',
               timestamptz '2000-01-01 01:02:03.123456+00',timestamptz '2000-01-02 01:02:03+00',NULL,NULL,NULL),
              ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000020','synthetic-two',2,'ไทย stamp','session-two',
               timestamptz '2001-01-01 01:02:03+00',timestamptz '2001-01-02 01:02:03+00',timestamptz '2001-01-01 02:02:03+00',
               timestamptz '2001-01-01 03:02:03+00','00000000-0000-0000-0000-000000000003');
            INSERT INTO public.google_identity_nonces VALUES ('00000000-0000-0000-0000-000000000030','nonce-one','ไทย service','synthetic',now(),now());
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt") VALUES
              ('00000000-0000-0000-0000-000000000040','ไทย','action-one','synthetic',now(),now()),
              ('00000000-0000-0000-0000-000000000041','ไทย','action-two','synthetic',now(),now());
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt",
              "ConsumedAt","TargetEmail","BoundNormalizedEmail","BoundSecurityStamp","EffectActionId","FinalizedAt",
              "OriginalTokenSha256","OwnerSubject","RecoveryVersion") VALUES
              ('00000000-0000-0000-0000-000000000046','synthetic-employee','action-bound','employee-password-reset',now(),now(),
               now(),'synthetic@example.invalid','SYNTHETIC@EXAMPLE.INVALID','ไทย stamp','00000000-0000-0000-0000-000000000046',now(),
               repeat('a',64),'ไทย synthetic owner',1);
            """, token);
        return endpoint;
    }

    private static async Task CandidateAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken token)
    {
        CurrentAuthNativePreservation.RequireBefore(await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token));
        await ExecuteAsync(connection, "SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='30s'; LOCK TABLE public.\"__EFMigrationsHistory\",public.refresh_sessions,public.google_identity_nonces,public.identity_action_tokens IN ACCESS EXCLUSIVE MODE;", token, tx);
        foreach (IGrouping<string, CurrentAuthCollationOperand> group in ApprovedCurrentAuthSchema.CollationOperands().GroupBy(x => x.Table))
        {
            string changes = string.Join(',', group.Select(x => "ALTER COLUMN " + Quote(x.Column) + " TYPE " + x.PostgreSqlType + " COLLATE \"C\""));
            await ExecuteAsync(connection, "ALTER TABLE public." + Quote(group.Key) + " " + changes + ";", token, tx);
        }
    }

    private async Task RunOwnedAsync(Func<string, CancellationToken, Task> body)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows owned archive native proof required."); }
        Guid run = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        string name = "auth-session-archive-proof-" + run.ToString("N");
        WriteLedger(run, "attempt", new { run, name, began, expires, persistent = false });
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithName(name).WithCleanUp(false).WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "current-auth-session-archive-native-proof").WithLabel("codex.repair.operation", run.ToString("D"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 512 * 1024 * 1024; parameters.HostConfig.MemorySwap = 512 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 750000000;
                parameters.HostConfig.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,nosuid,size=384m" };
                foreach (IList<PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                { foreach (PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; } }
            }).Build();
        string? ownedId = null; bool removed = false;
        try
        {
            await container.StartAsync(lifetime.Token);
            ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(name, lifetime.Token);
            RequireOwnership(metadata); ownedId = metadata.ID;
            using (var capacityDeadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
            {
                capacityDeadline.CancelAfter(TimeSpan.FromSeconds(5));
                var capacity = await container.ExecAsync(["df", "-B1", "/var/lib/postgresql"], capacityDeadline.Token);
                if (capacity.Stdout.Length > 4096 || capacity.Stderr.Length > 4096)
                { throw new InvalidOperationException("Bounded disposable filesystem observation exceeded."); }
                string[] lines = capacity.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                string[] cells = lines.Length == 2 ? lines[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) : [];
                if (capacity.ExitCode != 0 || !string.IsNullOrEmpty(capacity.Stderr) || cells.Length != 6 || cells[0] != "tmpfs" ||
                    cells[5] != "/var/lib/postgresql" ||
                    !long.TryParse(cells[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long bytes) ||
                    bytes != 384L * 1024 * 1024)
                { throw new InvalidOperationException("Actual disposable tmpfs capacity mismatch."); }
                WriteLedger(run, "filesystem-capacity", new { run, containerId = ownedId, capacityBytes = bytes });
            }
            WriteLedger(run, "observed", new { run, name, containerId = ownedId, began, expires, persistent = false });
            output.WriteLine(JsonSerializer.Serialize(new
            {
                run,
                Purpose = "current-auth-session-archive-native-proof",
                ContainerId = ownedId,
                began,
                expires,
                Owned = true,
                Removed = false,
                PersistentData = false
            }));
            await body(container.GetConnectionString(), lifetime.Token);
        }
        finally
        {
            await CompleteCleanupAsync();
        }

        async Task CompleteCleanupAsync()
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try
            {
                ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(ownedId ?? name, cleanup.Token);
                RequireOwnership(metadata); ownedId ??= metadata.ID;
                if (metadata.ID != ownedId) { throw new InvalidOperationException("Disposable ownership changed"); }
                _ = await docker.Containers.StopContainerAsync(ownedId, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token);
                metadata = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token);
                RequireOwnership(metadata);
                if ((metadata.State ?? throw new InvalidOperationException("Owned disposable state missing")).Running) { throw new InvalidOperationException("Owned disposable did not stop"); }
                await docker.Containers.RemoveContainerAsync(ownedId, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, cleanup.Token);
                try { _ = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { removed = true; }
                if (!removed) { throw new InvalidOperationException("Owned disposable removal not verified"); }
            }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound && ownedId is null) { removed = true; }
            finally
            {
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    run,
                    Purpose = "current-auth-session-archive-native-proof",
                    ContainerId = ownedId,
                    began,
                    expires,
                    Removed = removed,
                    CleanupFailed = !removed,
                    PersistentData = false
                }));
                bool disposed = false;
                try
                {
                    // The library may dispose only after exact owned removal. A
                    // changed/uncertain owner is retained with its finite lease.
                    if (removed) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None); disposed = true; }
                }
                finally { WriteLedger(run, "disposed", new { run, containerId = ownedId, removed, disposed, cleanupFailed = !removed || !disposed, expires, completedAtUtc = DateTimeOffset.UtcNow }); }
            }
        }

        void RequireOwnership(ContainerInspectResponse metadata)
        {
            JsonElement json = JsonSerializer.SerializeToElement(metadata);
            DateTimeOffset created = json.GetProperty("Created").GetDateTimeOffset();
            if (metadata.Config is not { } config || metadata.HostConfig is not { } host || metadata.NetworkSettings is not { } network ||
                metadata.ID.Length != 64 || metadata.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != Image || config.Labels["codex.repair.purpose"] != "current-auth-session-archive-native-proof" ||
                config.Labels["codex.repair.operation"] != run.ToString("D") ||
                metadata.Mounts.Count != 0 || host.Mounts is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
                host.Tmpfs is not { } tmpfsMounts || tmpfsMounts.Count != 1 || !tmpfsMounts.TryGetValue("/var/lib/postgresql", out string? tmpfs) ||
                tmpfs != "rw,nosuid,size=384m" || host.MemorySwap != 512 * 1024 * 1024 ||
                host.Memory != 512 * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                network.Ports.Values.SelectMany(x => x ?? []).Any(binding => binding.HostIP != "127.0.0.1"))
            { throw new InvalidOperationException("Disposable resource ownership mismatch"); }
        }
    }

    private static void WriteLedger(Guid run, string phase, object record)
    {
        string? directory = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_NATIVE_LEDGER");
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory) || !Directory.Exists(directory)) { throw new InvalidOperationException("Owner-protected archive native resource ledger is required before startup"); }
        SecureSnapshotFileCreation.ValidateRestrictedDirectory(directory);
        using var file = new FileStream(Path.Combine(directory, run.ToString("N") + "-" + phase + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken token, NpgsqlTransaction? tx = null)
    { await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 }; _ = await command.ExecuteNonQueryAsync(token); }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken token)
    { await using var command = new NpgsqlCommand(sql, connection); return (T)(await command.ExecuteScalarAsync(token) ?? throw new InvalidOperationException("Missing synthetic evidence")); }
}
