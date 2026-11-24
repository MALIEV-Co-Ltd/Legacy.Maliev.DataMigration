using System.Data;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Only the accepted Console resolves this exact type/factory; no caller connection or SQL is accepted.
internal sealed class SourceOrderOwnerIsoOwnedProofLease : ISourceOrderOwnerIsoOwnedProofLease
{
    private readonly CurrentAuthNamedClosedFixture _fixture;
    private readonly CurrentAuthClosedTemplateCapture _capture;
    private readonly CurrentAppOwnedSnapshotInternPool _snapshotPool = new();
    private readonly IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> _secretIds;
    private bool _disposed;
    public Guid OperationId => _fixture.Operation;
    public string SourceFullSha256 { get; }
    public bool CompanyAlreadyApplied { get; private set; }
    public string ConnectionString { get; }
    public string OrdinaryConnectionString { get; private set; } = string.Empty;
    public string TargetGeneration => _capture.State.TargetGeneration;
    public CurrentAppOwnedRepairTargetPins TargetPins => SourceOrderOwnerIsoProtocol.Copy(_capture.TargetPins);
    public CurrentAppOwnedMaintenancePin Maintenance => _capture.Maintenance;
    public DeltaTargetAuthority Target => _capture.Target;
    public string ContainerId => _fixture.ContainerId;
    public string Volume => _fixture.Name;
    private SourceOrderOwnerIsoOwnedProofLease(CurrentAuthNamedClosedFixture fixture, CurrentAuthClosedTemplateCapture capture, string source, string connection,
        IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> secretIds)
    { _fixture = fixture; _capture = capture; SourceFullSha256 = source; ConnectionString = connection; _secretIds = secretIds; }
    internal static async Task<ISourceOrderOwnerIsoOwnedProofLease> CreateAsync(string parent, FreshSchemaPlan source, bool companyAlreadyApplied, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != source.SourceCommitSha) { throw Invalid(); }
        CurrentAuthNamedClosedFixture? fixture = null;
        var secretIds = new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        try
        {
            fixture = await CurrentAuthNamedClosedFixture.CreateAsync(parent, ct);
            using var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            var state = await CurrentAuthClosedTemplate.PrepareAsync(files, fixture.Binding, fixture.Operation, fixture.ContainerId, source, fixture.AdminConnection, ct);
            foreach (string name in SecretNames)
            {
                string path = Path.Combine(fixture.Root, name); using var held = SecureLocalFile.OpenReadShared(path);
                secretIds.Add(path, CompanyStorageSecretCustody.Observe(held, path));
            }
            await CurrentAuthClosedTemplate.InstallPolicyAsync(files, fixture.Binding, state, fixture.AdminConnection, "success", ct);
            var capture = await CurrentAuthClosedTemplate.CaptureAsync(files, fixture.Binding, state, source, false, ct);
            // CaptureAsync retains operator.txt exclusively. Release that custody before
            // opening the generated credentials; do not reacquire the already-held run lock.
            files.Dispose(); using var credentials = new CurrentAppOwnedRepairCustody(authority);
            string connectionText = Encoding.UTF8.GetString(credentials.Read(Path.Combine(fixture.Root, "operator.txt"), sharedReader: true, maximumBytes: 65536));
            var endpoint = new NpgsqlConnectionStringBuilder(connectionText) { Database = "Customer", Pooling = false };
            var result = new SourceOrderOwnerIsoOwnedProofLease(fixture, capture, SchemaPlanCanonicalizer.ComputeSha256(source), endpoint.ConnectionString, secretIds)
            {
                OrdinaryConnectionString = Encoding.UTF8.GetString(credentials.Read(Path.Combine(fixture.Root, "ordinary.txt"), sharedReader: true, maximumBytes: 65536)),
                CompanyAlreadyApplied = companyAlreadyApplied
            };
            await PrepareRowsAsync(endpoint.ConnectionString, companyAlreadyApplied, ct);
            fixture = null; return result;
        }
        catch (Exception primary)
        {
            try
            {
                if (fixture is not null)
                {
                    await DisposeFixtureAsync(fixture, began, secretIds);
                }
            }
            catch (Exception cleanup) { throw new AggregateException(primary, cleanup); }
            throw;
        }
    }
    public async Task RequireAsync(CancellationToken ct)
    {
        ObjectDisposedException.ThrowIf(_disposed, this); _fixture.Token.ThrowIfCancellationRequested();
        using var authority = WindowsLocalRunAuthority.AcquireResume(_fixture.Root, _fixture.Binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        authority.ValidateHeld();
        string container = await DockerAsync(["inspect", ContainerId], files, ct);
        string volume = await DockerAsync(["volume", "inspect", Volume], files, ct);
        var observed = DockerLocalTargetObservation.Parse(container, volume, ContainerId, Volume, new NpgsqlConnectionStringBuilder(ConnectionString).Port, false);
        if (LocalDockerGenerationGuard.ComposeGeneration(observed) != _capture.State.TargetGeneration) { throw Invalid(); }
        using var containers = JsonDocument.Parse(container); using var volumes = JsonDocument.Parse(volume);
        var c = containers.RootElement[0]; var v = volumes.RootElement[0];
        var mounts = c.GetProperty("Mounts").EnumerateArray().ToArray(); var options = v.GetProperty("Options");
        var host = c.GetProperty("HostConfig");
        if (v.GetProperty("Driver").GetString() != "local" || v.GetProperty("Scope").GetString() != "local" ||
            (options.ValueKind != JsonValueKind.Null && (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any())) ||
            mounts.Length != 1 || mounts[0].GetProperty("Name").GetString() != Volume || mounts[0].GetProperty("Type").GetString() != "volume" ||
            mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" || !mounts[0].GetProperty("RW").GetBoolean() ||
            c.GetProperty("Config").GetProperty("Image").GetString() != CurrentAuthNamedClosedFixture.Image ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
            host.GetProperty("NanoCpus").GetInt64() != 750_000_000 || host.GetProperty("Privileged").GetBoolean()) { throw Invalid(); }
        RequireLabels(c.GetProperty("Config").GetProperty("Labels")); RequireLabels(v.GetProperty("Labels"));
        string consumers = await DockerAsync(["ps", "--all", "--no-trunc", "--filter", "volume=" + Volume, "--format", "{{.ID}}"], files, ct);
        CurrentAppOwnedRepairLocalTarget.RequireVolumeConsumers(consumers, ContainerId);
        void RequireLabels(JsonElement labels)
        {
            if (labels.GetProperty("codex.repair.purpose").GetString() != "current-auth-repair-proof" ||
                labels.GetProperty("codex.repair.operation").GetString() != OperationId.ToString("D") ||
                labels.GetProperty("codex.repair.run-binding").GetString() != _fixture.Binding.ComputeSha256()) { throw Invalid(); }
        }
    }
    public async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> CaptureFleetAsync(CancellationToken ct)
    {
        await RequireAsync(ct);
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>();
        string[] databases = [.. _capture.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)];
        var cohort = _snapshotPool.BeginCohort(databases);
        foreach (string database in databases)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ConnectionString) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction)) { _ = await readOnly.ExecuteNonQueryAsync(ct); }
            if (database == "postgres")
            {
                var flags = new List<ReviewedRepairDatabaseFlag>();
                await using var command = new NpgsqlCommand("SELECT datname,datistemplate,datallowconn FROM pg_database ORDER BY datname COLLATE \"C\";", connection, transaction);
                await using (var reader = await command.ExecuteReaderAsync(ct))
                { while (await reader.ReadAsync(ct)) { flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2))); } }
                ReviewedProductionRepairInventory.RequireComplete(Target.Kind, flags, _capture.BeforeDatabaseSha256.Keys);
            }
            snapshots.Add(cohort.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct)));
            await transaction.RollbackAsync(ct);
        }
        await RequireAsync(ct); cohort.Complete(); return snapshots;
    }
    public async Task RequireAbsentAsync(CancellationToken ct)
    {
        if (!_disposed) { throw Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(_fixture.Root, _fixture.Binding); using var files = new CurrentAppOwnedRepairCustody(authority);
        string containers = await DockerAsync(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], files, ct);
        string volumes = await DockerAsync(["volume", "ls", "--format", "{{.Name}}"], files, ct);
        if (containers.Split('\n').Any(x => x.StartsWith(ContainerId + "|", StringComparison.Ordinal) || x.Split('|')[^1].Trim() == Volume) || volumes.Split('\n').Any(x => x.Trim() == Volume))
        { throw Invalid(); }
    }
    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        await DisposeFixtureAsync(_fixture, _capture.State.IssuedAtUtc, _secretIds);
    }
    private static ValueTask DisposeFixtureAsync(CurrentAuthNamedClosedFixture fixture, DateTimeOffset created,
        IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> identities)
    {
        return fixture.DisposeForCompanyAsync(
            CompanyStorageFixtureSecretOwnership.FromCreatedFiles(fixture.Root, fixture.Binding, created, identities));
    }
    private Task<string> DockerAsync(IReadOnlyList<string> arguments, CurrentAppOwnedRepairCustody files, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, async frame =>
            {
                await files.WriteNewAsync(Path.Combine(_fixture.Root, "source-order-iso-lease-resource-" + frame.RunId.ToString("N") + ".json"), JsonSerializer.SerializeToUtf8Bytes(frame), CancellationToken.None);
                if (frame.CleanupFailed) { throw Invalid(); }
            });
    }

    private static readonly string[] SecretNames = ["operator.txt", "ordinary.txt"];
    private static async Task PrepareRowsAsync(string endpoint, bool companyAlreadyApplied, CancellationToken ct)
    {
        foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint) { Database = database }.ConnectionString); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            await using var command = new NpgsqlCommand("""
                INSERT INTO public."Country" ("ID","Name","Continent","CountryCode","ISO2","ISO3","CreatedDate","ModifiedDate")
                SELECT g,'synthetic ไทย 😀 '||g::text,'synthetic','synthetic',
                  CASE g%4 WHEN 0 THEN NULL WHEN 1 THEN 'TH' WHEN 2 THEN 'T ' ELSE '😀 ' END,
                  CASE g%4 WHEN 0 THEN NULL WHEN 1 THEN 'THA' WHEN 2 THEN 'A  ' ELSE '😀  ' END,
                  TIMESTAMP '2026-01-01 01:02:03.123456',NULL FROM generate_series(1,65) rows(g);
                SELECT setval(pg_get_serial_sequence('public."Country"','ID'),65,true);
                ALTER TABLE public."Country" OWNER TO legacy_local;
                ALTER SEQUENCE public."Country_ID_seq" OWNER TO legacy_local;
                CREATE SCHEMA legacy_iso_source_order_proof;
                CREATE TABLE legacy_iso_source_order_proof.journal(id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,effect text NOT NULL);
                INSERT INTO legacy_iso_source_order_proof.journal(effect) VALUES ('synthetic preserved ไทย 😀 effect');
                """, connection, tx) { CommandTimeout = 30 };
            _ = await command.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint) { Database = "Upload" }.ConnectionString))
        {
            await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            await using var seed = new NpgsqlCommand("CREATE SCHEMA IF NOT EXISTS legacy_migration_internal;" + ConsumerColumnBootstrapUploadFaultPreservation.CreateSql, connection, tx);
            _ = await seed.ExecuteNonQueryAsync(ct); await tx.CommitAsync(ct);
        }
        if (companyAlreadyApplied)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint) { Database = "Customer" }.ConnectionString); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
            // Disposable desired-state preparation, not evidence of a Company operational execution.
            await using (var ddl = new NpgsqlCommand(ApprovedCustomerCompanyStorageRepair.CandidateSql, connection, tx)) { _ = await ddl.ExecuteNonQueryAsync(ct); }
            await tx.CommitAsync(ct);
        }
    }
    private static MigrationExecutionException Invalid()
    {
        return SourceOrderOwnerIsoProtocol.Invalid();
    }
}
