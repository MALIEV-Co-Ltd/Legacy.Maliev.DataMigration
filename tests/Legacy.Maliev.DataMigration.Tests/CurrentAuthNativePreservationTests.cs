using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CurrentAuthNativeProofGroup
{
    public const string Name = "Current Auth disposable preservation";
}

/// <summary>Generated synthetic physical fixtures only; no archive, authority or history copying.</summary>
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthNativePreservationTests(ITestOutputHelper output)
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    [WindowsLocalRunTheory]
    [InlineData("10.0.12")]
    [InlineData("10.0.10")]
    public Task Fixed_transition_preserves_populated_rows_private_state_and_independent_history_through_rollback_commit_readback(string syntheticHistoryVersion)
    {
        return RunOwnedAsync(async (admin, token) =>
        {
            string endpoint = await BootstrapAsync(admin, syntheticHistoryVersion, token);
            CurrentAuthNativeObservation before;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token);
                Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                before = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token);
                foreach (CheckConstraintCopyPlan check in ApprovedCurrentAuthSchema.Tables(false).SelectMany(table => table.CheckConstraints))
                {
                    JsonObject constraint = before.Read("pg_constraint").Single(row => row["conname"]!.ToString() == check.Name);
                    output.WriteLine("Synthetic fixed check {0}: expected={1}; native={2}", check.Name, check.Expression,
                        before.Expression(constraint["oid"]!.ToString()));
                }
                CurrentAuthNativePreservation.RequireBefore(before);
                Assert.Equal(2, before.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "refresh_sessions").Rows);
                await CandidateAsync(connection, tx, token);
                CurrentAuthNativeObservation after = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token);
                foreach (CheckConstraintCopyPlan check in ApprovedCurrentAuthSchema.Tables(true).SelectMany(table => table.CheckConstraints))
                {
                    JsonObject constraint = after.Read("pg_constraint").Single(row => row["conname"]!.ToString() == check.Name);
                    output.WriteLine("Synthetic rebuilt check {0}: native={1}", check.Name,
                        after.Expression(constraint["oid"]!.ToString()));
                }
                CurrentAuthNativePreservation.RequirePreserved(before, after);
                RequireMaliciousNegatives(before, after);
                await tx.RollbackAsync(token);
            }
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                CurrentAuthNativeObservation rollback = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token);
                Assert.Equal(before.Snapshot.Sha256, rollback.Snapshot.Sha256);
                CurrentAuthNativePreservation.RequireBefore(rollback);
                await CandidateAsync(connection, tx, token);
                CurrentAuthNativePreservation.RequirePreserved(before, await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token));
                await tx.CommitAsync(token);
            }
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", token, tx);
                CurrentAuthNativeObservation readback = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token);
                CurrentAuthNativePreservation.RequirePreserved(before, readback);
                _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequireBefore(readback));
                await tx.RollbackAsync(token);
            }
            await RequireNativeNullUniquenessAsync(endpoint, token);
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(token);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", token, tx);
                CurrentAuthNativePreservation.RequirePreserved(before, await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token));
                await tx.RollbackAsync(token);
            }
        });
    }

    [WindowsLocalRunTheory]
    [InlineData("CREATE INDEX unreviewed_auth_expression ON public.refresh_sessions(lower(\"IdentityId\"));")]
    [InlineData("CREATE STATISTICS unreviewed_auth_statistics ON \"IdentityId\",\"TokenHash\" FROM public.refresh_sessions;")]
    [InlineData("ANALYZE public.refresh_sessions;")]
    [InlineData("ALTER TABLE public.refresh_sessions ADD COLUMN unreviewed text;")]
    [InlineData("ALTER TABLE public.refresh_sessions ALTER COLUMN \"TokenHash\" TYPE varchar(64) COLLATE \"C\";")]
    public Task Unsupported_preimage_fails_before_candidate(string unexpected)
    {
        return RunOwnedAsync(async (admin, token) =>
    {
        string endpoint = await BootstrapAsync(admin, "10.0.12", token);
        await using var connection = new NpgsqlConnection(endpoint);
        await connection.OpenAsync(token);
        await ExecuteAsync(connection, unexpected, token);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
        CurrentAuthNativeObservation before = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequireBefore(before));
        await tx.RollbackAsync(token);
    });
    }

    [Fact]
    public void Expression_binding_and_index_storage_do_not_accept_untyped_changes()
    {
        const string var = "{VAR :varno 1 :varattno 4 :vartype 1043 :varlevelsup 0 :varcollid 100 :location -1}";
        var columns = new Dictionary<int, int> { [4] = 1043 };
        Assert.Equal(CurrentAuthNativePreservation.NormalizeExpression(var, columns, "100"),
            CurrentAuthNativePreservation.NormalizeExpression(var.Replace("100", "950", StringComparison.Ordinal), columns, "950", after: true));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.NormalizeExpression(var.Replace("varno 1", "varno 2", StringComparison.Ordinal), columns, "100"));
        var row = new JsonObject { ["relfilenode"] = "42", ["relpages"] = "2", ["reltuples"] = "2" };
        CurrentAuthNativePreservation.RequireIndexStorage(row, 42, 2, 2, rebuilt: true);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequireIndexStorage(row, 42, 3, 2, rebuilt: true));
    }

    private static void RequireMaliciousNegatives(CurrentAuthNativeObservation before, CurrentAuthNativeObservation after)
    {
        string nonText = before.Read("pg_class").Single(x => x["relname"]!.ToString() == "PK_refresh_sessions")["oid"]!.ToString();
        CurrentAuthNativeObservation nonTextCollation = Mutate(before, "pg_index", x => x["indexrelid"]!.ToString() == nonText,
            x => x["indcollation"] = "100");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequireBefore(nonTextCollation));
        string affected = after.Read("pg_class").Single(x => x["relname"]!.ToString() == "IX_identity_action_tokens_OriginalTokenSha256_Purpose")["oid"]!.ToString();
        foreach (string field in new[] { "indnullsnotdistinct", "indclass", "indoption", "indcollation" })
        {
            CurrentAuthNativeObservation changed = Mutate(after, "pg_index", x => x["indexrelid"]!.ToString() == affected,
                x => x[field] = field switch { "indnullsnotdistinct" => JsonValue.Create(true), "indclass" => JsonValue.Create("3126 3127"), "indoption" => JsonValue.Create("0 1"), _ => JsonValue.Create("950 100") });
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before, changed));
        }
        CurrentAuthNativeObservation catalog = Mutate(after, "pg_namespace", x => x["nspname"]!.ToString() == "private", x => x["nspowner"] = 1);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before, catalog));
        CurrentAuthNativeObservation storage = Mutate(after, "pg_class", x => x["oid"]!.ToString() == affected, x => x["relpages"] = 999999);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before, storage));
        CurrentAuthNativeObservation check = Mutate(after, "pg_constraint", x => x["conname"]!.ToString() == "CK_identity_action_tokens_employee_binding",
            x => x["conbin"] = x["conbin"]!.ToString().Replace(":constisnull false", ":constisnull true", StringComparison.Ordinal));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before, check));
        Dictionary<string, string[]> duplicateTuples = after.CopyTuples();
        string duplicate = duplicateTuples["pg_depend"][0], duplicateHash = Hash(duplicate);
        CurrentAppOwnedCatalogFact duplicateFact = after.Snapshot.Catalog.First(x => x.Catalog == "pg_depend" && x.Sha256 == duplicateHash);
        int occurrence = after.Snapshot.Catalog.Count(x => x.Catalog == "pg_depend" && x.Sha256 == duplicateHash) + 1;
        duplicateTuples["pg_depend"] = [.. duplicateTuples["pg_depend"], duplicate];
        CurrentAppOwnedDatabaseSnapshot duplicateSnapshot = after.Snapshot with
        { Catalog = after.Snapshot.Catalog.Append(duplicateFact with { Key = duplicateHash + "/" + occurrence.ToString(System.Globalization.CultureInfo.InvariantCulture) }).ToArray() };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before,
            new(duplicateSnapshot, duplicateTuples, after.CopyStorage(), after.CopyExpressions())));
        foreach (string name in new[] { "refresh_sessions", "__EFMigrationsHistory", "journal" })
        {
            CurrentAppOwnedDatabaseSnapshot snapshot = after.Snapshot with
            { Relations = after.Snapshot.Relations.Select(x => x.Name == name ? x with { RowSha256 = new string('e', 64) } : x).ToArray() };
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before,
                new(snapshot, after.CopyTuples(), after.CopyStorage(), after.CopyExpressions())));
        }
        CurrentAppOwnedDatabaseSnapshot sequence = after.Snapshot with
        { Sequences = after.Snapshot.Sequences.Select(x => x with { TupleSha256 = new string('e', 64) }).ToArray() };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNativePreservation.RequirePreserved(before,
            new(sequence, after.CopyTuples(), after.CopyStorage(), after.CopyExpressions())));
    }

    private static CurrentAuthNativeObservation Mutate(CurrentAuthNativeObservation original, string catalog,
        Func<JsonObject, bool> select, Action<JsonObject> mutate)
    {
        Dictionary<string, string[]> tuples = original.CopyTuples();
        int position = Array.FindIndex(tuples[catalog], text => select(JsonNode.Parse(text)!.AsObject()));
        Assert.True(position >= 0);
        string oldHash = Hash(tuples[catalog][position]);
        JsonObject row = JsonNode.Parse(tuples[catalog][position])!.AsObject();
        mutate(row); tuples[catalog][position] = row.ToJsonString();
        string newHash = Hash(tuples[catalog][position]);
        CurrentAppOwnedDatabaseSnapshot snapshot = original.Snapshot with
        {
            Catalog = original.Snapshot.Catalog.Select(x => x.Catalog == catalog && x.Sha256 == oldHash ?
            x with { Sha256 = newHash, Key = catalog == "pg_index" ? newHash + "/1" : x.Key } : x).ToArray()
        };
        return new(snapshot, tuples, original.CopyStorage(), original.CopyExpressions());
    }

    private static string Hash(string value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(value)));
    }

    private static async Task<string> BootstrapAsync(string admin, string productVersion, CancellationToken token)
    {
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync(token);
            Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
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

    private static async Task RequireNativeNullUniquenessAsync(string endpoint, CancellationToken token)
    {
        await using var connection = new NpgsqlConnection(endpoint);
        await connection.OpenAsync(token);
        await using var tx = await connection.BeginTransactionAsync(token);
        await ExecuteAsync(connection, """
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt","OriginalTokenSha256") VALUES
              ('00000000-0000-0000-0000-000000000042','other','one','same-purpose',now(),now(),'literal-original'),
              ('00000000-0000-0000-0000-000000000043','other','two','same-purpose',now(),now(),NULL),
              ('00000000-0000-0000-0000-000000000044','other','three','same-purpose',now(),now(),NULL);
            """, token, tx);
        PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() => ExecuteAsync(connection, """
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt","OriginalTokenSha256")
            VALUES ('00000000-0000-0000-0000-000000000045','other','four','same-purpose',now(),now(),'literal-original');
            """, token, tx));
        Assert.Equal("23505", failure.SqlState);
        await tx.RollbackAsync(token);
    }

    private async Task RunOwnedAsync(Func<string, CancellationToken, Task> body)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows owned native proof required."); }
        Guid run = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        string name = "auth-closure-proof-" + run.ToString("N");
        WriteLedger(run, "attempt", new { run, name, began, expires, persistent = false });
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithName(name).WithCleanUp(false).WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "current-auth-native-proof").WithLabel("codex.repair.operation", run.ToString("D"))
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
                string[] lines = capacity.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries);
                string[] cells = lines.Length == 2 ? lines[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) : [];
                if (capacity.ExitCode != 0 || !string.IsNullOrEmpty(capacity.Stderr) || cells.Length != 6 || cells[0] != "tmpfs" ||
                    !long.TryParse(cells[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long bytes) ||
                    bytes != 384L * 1024 * 1024)
                { throw new InvalidOperationException("Actual disposable tmpfs capacity mismatch."); }
                WriteLedger(run, "filesystem-capacity", new { run, containerId = ownedId, capacityBytes = bytes });
            }
            WriteLedger(run, "observed", new { run, name, containerId = ownedId, began, expires, persistent = false });
            output.WriteLine(JsonSerializer.Serialize(new
            {
                run,
                Purpose = "current-auth-native-proof",
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
                    Purpose = "current-auth-native-proof",
                    ContainerId = ownedId,
                    began,
                    expires,
                    Removed = removed,
                    CleanupFailed = !removed,
                    PersistentData = false
                }));
                if (removed) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); }
                WriteLedger(run, "disposed", new { run, containerId = ownedId, removed, completedAtUtc = DateTimeOffset.UtcNow });
            }
        }

        void RequireOwnership(ContainerInspectResponse metadata)
        {
            JsonElement json = JsonSerializer.SerializeToElement(metadata);
            DateTimeOffset created = json.GetProperty("Created").GetDateTimeOffset();
            if (metadata.Config is not { } config || metadata.HostConfig is not { } host || metadata.NetworkSettings is not { } network ||
                metadata.ID.Length != 64 || metadata.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != Image || config.Labels["codex.repair.purpose"] != "current-auth-native-proof" ||
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
        string? directory = Environment.GetEnvironmentVariable("MALIEV_AUTH_NATIVE_LEDGER");
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory) || !Directory.Exists(directory))
        { throw new InvalidOperationException("Existing owner-protected native ledger directory required."); }
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
