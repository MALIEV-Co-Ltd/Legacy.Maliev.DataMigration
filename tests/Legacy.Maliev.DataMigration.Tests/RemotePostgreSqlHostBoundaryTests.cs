using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Npgsql;
using Testcontainers.PostgreSql;
using DotNet.Testcontainers.Configurations;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RemotePostgreSqlHostFixture : IAsyncLifetime
{
    internal HostTlsTestServer Tls { get; } = new();
    private PostgreSqlContainer _postgres = null!;
    internal string ConnectionString = string.Empty;
    internal CloudNativePgTargetObservation Target = null!;
    internal string AdminConnection => _postgres.GetConnectionString();

    public async Task InitializeAsync()
    {
        using RSA key = Tls.Server.GetRSAPrivateKey()!;
        _postgres = new PostgreSqlBuilder("postgres:18-alpine")
            .WithResourceMapping(Encoding.UTF8.GetBytes(Tls.Server.ExportCertificatePem()), "/tmp/host-test.crt")
            .WithResourceMapping(Encoding.UTF8.GetBytes(key.ExportPkcs8PrivateKeyPem()), "/tmp/host-test.key")
            .WithEntrypoint("/bin/sh", "-c")
            .WithCommand(new OverwriteEnumerable<string>(["chown postgres:postgres /tmp/host-test.key; chmod 600 /tmp/host-test.key; exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/host-test.crt -c ssl_key_file=/tmp/host-test.key"]))
            .Build();
        try { await _postgres.StartAsync(); }
        catch (Exception exception) { throw new InvalidOperationException((await _postgres.GetLogsAsync()).ToString(), exception); }
        await using var admin = new NpgsqlConnection(AdminConnection); await admin.OpenAsync();
        string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(24));
        await using var create = new NpgsqlCommand($"CREATE ROLE host_restricted LOGIN PASSWORD '{password}';", admin);
        _ = await create.ExecuteNonQueryAsync();
        await using var identity = new NpgsqlCommand("SELECT system_identifier::text FROM pg_catalog.pg_control_system();", admin);
        string systemId = (string)(await identity.ExecuteScalarAsync())!;
        Tls.ResponseBody = ClusterJson(systemId); Tls.ResponseStatusCode = 200;
        using JsonDocument json = JsonDocument.Parse(Tls.ResponseBody);
        Target = CloudNativePgTargetObservationParser.Parse(json.RootElement, "maliev-legacy", "legacy-postgres-main");
        ConnectionString = new NpgsqlConnectionStringBuilder(AdminConnection)
        {
            Host = "localhost",
            Username = "host_restricted",
            Password = password,
            SslMode = SslMode.VerifyFull,
            RootCertificate = Tls.CaPath,
            Pooling = false,
        }.ConnectionString;
    }

    internal CloudNativePgTargetObserver Observer()
    {
        return CloudNativePgTargetObserver.CreateForHost(new(Tls.Address, Tls.TokenPath, Tls.CaPath));
    }

    internal static string ClusterJson(string systemId)
    {
        return $$$"""
        {"metadata":{"name":"legacy-postgres-main","namespace":"maliev-legacy","uid":"uid-a","resourceVersion":"1","generation":1},
         "spec":{"instances":1},"status":{"phase":"Cluster in healthy state","instances":1,"readyInstances":1,"observedGeneration":1,
         "currentPrimary":"p1","targetPrimary":"p1","systemID":"{{{systemId}}}","pvcCount":1,"instanceNames":["p1"],
         "instancesStatus":{"healthy":["p1"]},"healthyPVC":["pvc1"],"danglingPVC":[],"initializingPVC":[],"resizingPVC":[],"unusablePVC":[],
         "conditions":[{"type":"Ready","status":"True","reason":"ClusterIsReady"},{"type":"ConsistentSystemID","status":"True","reason":"Unique"},
         {"type":"ContinuousArchiving","status":"True","reason":"ContinuousArchivingSuccess"},{"type":"LastBackupSucceeded","status":"True","reason":"LastBackupSucceeded"}]}}
        """;
    }

    public async Task DisposeAsync() { await _postgres.DisposeAsync(); await Tls.DisposeAsync(); }
}

public sealed class RemotePostgreSqlHostBoundaryTests(RemotePostgreSqlHostFixture fixture) : IClassFixture<RemotePostgreSqlHostFixture>
{
    [Theory]
    [InlineData("create")]
    [InlineData("write")]
    [InlineData("cancel")]
    public async Task HostDump_DestinationFailureSurvivesAwaitedNativeCleanup(string fault)
    {
        string name = HostKubernetesBoundaryTests.Shadow().Name;
        string app = $"dump_destination_{Guid.NewGuid():N}";
        string blockedPath = Path.Combine(fixture.Tls.Root, $"blocked-{Guid.NewGuid():N}");
        _ = Directory.CreateDirectory(blockedPath);
        await using var admin = new NpgsqlConnection(fixture.AdminConnection); await admin.OpenAsync();
        await using var create = new NpgsqlCommand($"CREATE DATABASE {name} OWNER host_restricted", admin); _ = await create.ExecuteNonQueryAsync();
        try
        {
            await using var holder = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = name }.ConnectionString); await holder.OpenAsync();
            await using var table = new NpgsqlCommand("CREATE TABLE public.blocked(id integer)", holder); _ = await table.ExecuteNonQueryAsync();
            await using NpgsqlTransaction transaction = await holder.BeginTransactionAsync();
            await using var locked = new NpgsqlCommand("LOCK TABLE public.blocked IN ACCESS EXCLUSIVE MODE", holder, transaction); _ = await locked.ExecuteNonQueryAsync();
            using var observer = fixture.Observer();
            var boundary = new RemotePostgreSqlHostBoundary(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { ApplicationName = app }.ConnectionString, fixture.Target, observer);
            Stream native = await PgDumpSource.CreateForHost(DumpPath, boundary).OpenDumpAsync("Order", name, default);
            var dump = new ObservedDumpDisposal(native);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await using var waiting = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')", admin);
            _ = waiting.Parameters.AddWithValue(app);
            while (!true.Equals(await waiting.ExecuteScalarAsync(deadline.Token))) { await Task.Delay(25, deadline.Token); }
            using var cancellation = new CancellationTokenSource();
            var writeFailure = new IOException("controlled destination write failure");
            Exception? primary = null;
            Task<SnapshotEncryptionResult> consuming = IncrementalLocalSnapshotStore.ConsumeDumpAsync(dump, async source =>
            {
                try
                {
                    using Stream destination = fault == "create"
                        ? new FileStream(blockedPath, FileMode.CreateNew, FileAccess.Write)
                        : new FailedEncryptedDestination(writeFailure, fault == "cancel" ? cancellation : null);
                    return await SnapshotEncryption.EncryptStagingAsync(source, destination, new byte[32],
                        SnapshotArchiveContext.Create("destination-test", "Order", new string('a', 64)), cancellation.Token);
                }
                catch (Exception failure) { primary = failure; throw; }
            });
            await dump.DisposalStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
            bool returnedBeforeCleanup = consuming.IsCompleted;
            dump.ReleaseDisposal.SetResult();
            Exception observed = await Record.ExceptionAsync(() => consuming.WaitAsync(TimeSpan.FromSeconds(15)));
            Assert.False(returnedBeforeCleanup);
            Assert.True(dump.DisposalCompleted);
            Assert.Same(primary, observed);
            Assert.Equal(nameof(MigrationExecutionException), observed.Data["snapshot_dump_cleanup_failure"]);
            if (fault == "write") { Assert.Same(writeFailure, observed); }
            if (fault == "create") { _ = Assert.IsType<UnauthorizedAccessException>(observed); }
            if (fault == "cancel") { Assert.Equal(cancellation.Token, Assert.IsType<OperationCanceledException>(observed, exactMatch: false).CancellationToken); }
            await transaction.RollbackAsync();
            using var settled = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await using var remaining = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1)", admin);
            _ = remaining.Parameters.AddWithValue(app);
            while (true.Equals(await remaining.ExecuteScalarAsync(settled.Token))) { await Task.Delay(25, settled.Token); }
        }
        finally
        {
            Directory.Delete(blockedPath);
            await using var drop = new NpgsqlCommand($"DROP DATABASE {name} WITH (FORCE)", admin); _ = await drop.ExecuteNonQueryAsync();
        }
    }

    private sealed class FailedEncryptedDestination(Exception failure, CancellationTokenSource? cancellation) : MemoryStream
    {
        public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            if (cancellation is null) { return ValueTask.FromException(failure); }
            cancellation.Cancel();
            return ValueTask.FromCanceled(cancellation.Token);
        }
    }

    private sealed class ObservedDumpDisposal(Stream inner) : Stream
    {
        public TaskCompletionSource DisposalStarted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public TaskCompletionSource ReleaseDisposal { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public bool DisposalCompleted { get; private set; }
        public override async ValueTask DisposeAsync()
        {
            _ = DisposalStarted.TrySetResult();
            await ReleaseDisposal.Task;
            try { await inner.DisposeAsync(); }
            finally { DisposalCompleted = true; await base.DisposeAsync(); }
            GC.SuppressFinalize(this);
        }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            return inner.ReadAsync(buffer, cancellationToken);
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return inner.Read(buffer, offset, count);
        }

        public override bool CanRead => inner.CanRead;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }
    }

    [Theory]
    [InlineData("SSL Mode", "Require")]
    [InlineData("Host", "localhost,other.example")]
    [InlineData("Search Path", "untrusted")]
    [InlineData("Options", "-c search_path=untrusted")]
    [InlineData("SSL Negotiation", "Direct")]
    [InlineData("GSS Encryption Mode", "Require")]
    [InlineData("Command Timeout", "120")]
    [InlineData("Root Certificate", "relative.pem")]
    public void Configuration_UnsupportedOrUnsafeOptionsRejectBeforeObservation(string key, string value)
    {
        var settings = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { [key] = value };
        using var observer = fixture.Observer();
        int before = fixture.Tls.Requests;
        _ = Assert.Throws<MigrationExecutionException>(() => new RemotePostgreSqlHostBoundary(settings.ConnectionString, fixture.Target, observer));
        Assert.Equal(before, fixture.Tls.Requests);
    }

    [Fact]
    public async Task ActualConnection_ChangedCredentialsEndpointOrTlsRejects()
    {
        using var observer = fixture.Observer();
        var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
        await using var wrong = new NpgsqlConnection(fixture.AdminConnection); await wrong.OpenAsync();
        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => boundary.VerifyOpenConnectionAsync(wrong, default));
        Assert.Equal("host_postgres_connection_invalid", failure.Code);
    }

    [Fact]
    public async Task ActualIdentity_RepeatObservationRejectsPostPreflightTargetDrift()
    {
        using var observer = fixture.Observer();
        var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
        string database = new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database!;
        await boundary.VerifyEndpointAsync(database, default);
        string original = fixture.Tls.ResponseBody;
        try
        {
            fixture.Tls.ResponseBody = original.Replace("uid-a", "uid-b", StringComparison.Ordinal);
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => boundary.VerifyEndpointAsync(database, default));
            Assert.Equal("host_postgres_target_drift", failure.Code);
        }
        finally { fixture.Tls.ResponseBody = original; }
    }

    [Theory]
    [InlineData("hostname")]
    [InlineData("ca")]
    public async Task ActualSqlTls_WrongHostnameOrCaCannotAuthenticate(string fault)
    {
        await using var other = new HostTlsTestServer();
        var settings = new NpgsqlConnectionStringBuilder(fixture.ConnectionString);
        if (fault == "hostname") { settings.Host = "127.0.0.1"; }
        else { settings.RootCertificate = other.CaPath; }
        // Npgsql's real handshake is the validator's input boundary, never bypassed by a callback.
        await using var connection = new NpgsqlConnection(settings.ConnectionString);
        _ = await Assert.ThrowsAsync<NpgsqlException>(connection.OpenAsync);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostDump_NativeFailureOrIncompleteConsumptionCannotBeAccepted(bool incomplete)
    {
        string name = HostKubernetesBoundaryTests.Shadow().Name;
        await using var admin = new NpgsqlConnection(fixture.AdminConnection); await admin.OpenAsync();
        await using var create = new NpgsqlCommand($"CREATE DATABASE {name} OWNER host_restricted", admin); _ = await create.ExecuteNonQueryAsync();
        try
        {
            if (!incomplete)
            {
                await using var local = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = name }.ConnectionString); await local.OpenAsync();
                await using var table = new NpgsqlCommand("CREATE TABLE public.denied(id integer)", local); _ = await table.ExecuteNonQueryAsync();
            }
            using var observer = fixture.Observer();
            var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
            var source = PgDumpSource.CreateForHost(DumpPath, boundary);
            Stream stream = await source.OpenDumpAsync("Order", name, default);
            if (!incomplete)
            {
                MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => stream.CopyToAsync(Stream.Null));
                Assert.Equal("snapshot_dump_failed", failure.Code);
            }
            MigrationExecutionException disposed = await Assert.ThrowsAsync<MigrationExecutionException>(() => stream.DisposeAsync().AsTask());
            Assert.Equal(incomplete ? "host_dump_incomplete" : "snapshot_dump_failed", disposed.Code);
        }
        finally { await using var drop = new NpgsqlCommand($"DROP DATABASE {name} WITH (FORCE)", admin); _ = await drop.ExecuteNonQueryAsync(); }
    }

    [Fact]
    public async Task HostDump_CancellationObservesNativeExitAndRetainsPrimary()
    {
        string name = HostKubernetesBoundaryTests.Shadow().Name;
        string app = $"dump_cancel_{Guid.NewGuid():N}";
        await using var admin = new NpgsqlConnection(fixture.AdminConnection); await admin.OpenAsync();
        await using var create = new NpgsqlCommand($"CREATE DATABASE {name} OWNER host_restricted", admin); _ = await create.ExecuteNonQueryAsync();
        try
        {
            await using var holder = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = name }.ConnectionString); await holder.OpenAsync();
            await using var table = new NpgsqlCommand("CREATE TABLE public.blocked(id integer)", holder); _ = await table.ExecuteNonQueryAsync();
            await using NpgsqlTransaction transaction = await holder.BeginTransactionAsync();
            await using var locked = new NpgsqlCommand("LOCK TABLE public.blocked IN ACCESS EXCLUSIVE MODE", holder, transaction); _ = await locked.ExecuteNonQueryAsync();
            using var observer = fixture.Observer();
            var boundary = new RemotePostgreSqlHostBoundary(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { ApplicationName = app }.ConnectionString, fixture.Target, observer);
            using var cancellation = new CancellationTokenSource();
            Stream stream = await PgDumpSource.CreateForHost(DumpPath, boundary).OpenDumpAsync("Order", name, cancellation.Token);
            Task reading = stream.CopyToAsync(Stream.Null);
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await using var waiting = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock')", admin);
            _ = waiting.Parameters.AddWithValue(app);
            while (!true.Equals(await waiting.ExecuteScalarAsync(deadline.Token))) { await Task.Delay(25, deadline.Token); }
            await cancellation.CancelAsync();
            OperationCanceledException primary = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => reading);
            Exception disposed = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => stream.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(15)));
            Assert.Same(primary, disposed);
            // A PostgreSQL backend blocked on a server-side lock need not notice the
            // terminated client's EOF until that lock settles. Release only this fixture lock.
            await transaction.RollbackAsync();
            using var settled = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await using var remaining = new NpgsqlCommand("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1)", admin);
            _ = remaining.Parameters.AddWithValue(app);
            while (true.Equals(await remaining.ExecuteScalarAsync(settled.Token))) { await Task.Delay(25, settled.Token); }
        }
        finally { await using var drop = new NpgsqlCommand($"DROP DATABASE {name} WITH (FORCE)", admin); _ = await drop.ExecuteNonQueryAsync(); }
    }

    private static string DumpPath => Environment.GetEnvironmentVariable("PG_DUMP_PATH") ?? "C:/Program Files/PostgreSQL/18/bin/pg_dump.exe";
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task HostDump_RechecksIdentityBeforeSuccessfulEof(bool drift)
    {
        string name = HostKubernetesBoundaryTests.Shadow().Name;
        await using var admin = new NpgsqlConnection(fixture.AdminConnection); await admin.OpenAsync();
        await using var create = new NpgsqlCommand($"CREATE DATABASE {name} OWNER host_restricted", admin); _ = await create.ExecuteNonQueryAsync();
        string original = fixture.Tls.ResponseBody;
        try
        {
            using var observer = fixture.Observer();
            var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
            IPostgreSqlDumpSource source = PgDumpSource.CreateForHost(Environment.GetEnvironmentVariable("PG_DUMP_PATH") ?? "C:/Program Files/PostgreSQL/18/bin/pg_dump.exe", boundary);
            int before = fixture.Tls.Requests;
            Stream stream = await source.OpenDumpAsync("Order", name, default);
            Assert.True(fixture.Tls.Requests > before);
            if (drift) { fixture.Tls.ResponseBody = RemotePostgreSqlHostFixture.ClusterJson("123"); }
            try
            {
                if (drift)
                {
                    MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => stream.CopyToAsync(Stream.Null));
                    Assert.Equal("host_postgres_target_drift", failure.Code);
                }
                else { await stream.CopyToAsync(Stream.Null); Assert.True(fixture.Tls.Requests >= before + 2); }
            }
            finally
            {
                if (drift) { _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => stream.DisposeAsync().AsTask()); }
                else { await stream.DisposeAsync(); }
            }
        }
        finally
        {
            fixture.Tls.ResponseBody = original;
            await using var drop = new NpgsqlCommand($"DROP DATABASE {name} WITH (FORCE)", admin); _ = await drop.ExecuteNonQueryAsync();
        }
    }

    [Fact]
    public async Task ActualRestrictedRole_DefaultPermissionObservesIdentityWithoutBroadGrant()
    {
        using var observer = fixture.Observer();
        var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
        await using var connection = new NpgsqlConnection(fixture.ConnectionString); await connection.OpenAsync();
        await boundary.VerifyOpenConnectionAsync(connection, default);
        await using var roles = new NpgsqlCommand("SELECT NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole AND NOT pg_has_role(current_user,'pg_monitor','member') FROM pg_roles WHERE rolname=current_user", connection);
        Assert.True((bool)(await roles.ExecuteScalarAsync())!);
    }

    [Fact]
    public async Task ActualIdentity_WrongServerDespiteMatchingConfigurationRejects()
    {
        using var observer = fixture.Observer();
        var wrong = fixture.Target with { SystemId = "123" };
        string original = fixture.Tls.ResponseBody;
        fixture.Tls.ResponseBody = RemotePostgreSqlHostFixture.ClusterJson("123");
        try
        {
            var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, wrong, observer);
            await using var connection = new NpgsqlConnection(fixture.ConnectionString); await connection.OpenAsync();
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => boundary.VerifyOpenConnectionAsync(connection, default));
            Assert.Equal("host_postgres_identity_mismatch", failure.Code);
        }
        finally { fixture.Tls.ResponseBody = original; }
    }

    [Fact]
    public async Task ActualIdentity_DeniedNarrowFunctionRejectsWithoutGranting()
    {
        using var observer = fixture.Observer();
        var boundary = new RemotePostgreSqlHostBoundary(fixture.ConnectionString, fixture.Target, observer);
        await using var admin = new NpgsqlConnection(fixture.AdminConnection); await admin.OpenAsync();
        await using var revoke = new NpgsqlCommand("REVOKE EXECUTE ON FUNCTION pg_catalog.pg_control_system() FROM PUBLIC", admin);
        _ = await revoke.ExecuteNonQueryAsync();
        try
        {
            MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(() => boundary.VerifyEndpointAsync(new NpgsqlConnectionStringBuilder(fixture.ConnectionString).Database!, default));
            Assert.Equal("host_postgres_identity_permission_required", failure.Code);
            await using var role = new NpgsqlConnection(fixture.ConnectionString); await role.OpenAsync();
            await using var permission = new NpgsqlCommand("SELECT has_function_privilege(current_user,'pg_catalog.pg_control_system()','EXECUTE')", role);
            Assert.False((bool)(await permission.ExecuteScalarAsync())!);
        }
        finally
        {
            await using var restore = new NpgsqlCommand("GRANT EXECUTE ON FUNCTION pg_catalog.pg_control_system() TO PUBLIC", admin);
            _ = await restore.ExecuteNonQueryAsync();
        }
    }
}
