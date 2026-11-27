using System.Data;
using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CompanyStorageRuntime : IDisposable
{
    private readonly CompanyStorageRepairInputs _inputs;
    private readonly CompanyStorageAcceptedCodeCustody _code;
    private readonly CurrentAppOwnedSnapshotInternPool _snapshotPool = new();
    private readonly CompanyStoragePersistentTarget? _target;
    private readonly string _ordinary;
    private readonly string _connection;
    internal ConsumerColumnBootstrapSourceCapture Source { get; }
    internal ApprovedCustomerCompanyStorageRepair Contract { get; }
    private CompanyStorageRuntime(CompanyStorageRepairInputs inputs, ConsumerColumnBootstrapSourceCapture source, ApprovedCustomerCompanyStorageRepair contract)
    {
        _inputs = inputs; Source = source; Contract = contract; _code = CompanyStorageAcceptedCodeCustody.Acquire();
        try
        {
            _connection = inputs.Secret(inputs.Configuration.OperatorConnection); _ordinary = inputs.Secret(inputs.Configuration.OrdinaryConnection);
            _target = new(MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(inputs.Read(inputs.Configuration.TargetPins)), inputs.Files, inputs.Authority.Binding.ArtifactRootCanonicalPath);
        }
        catch { _code.Dispose(); throw; }
    }
    internal static async Task<CompanyStorageRuntime> OpenAsync(CompanyStorageRepairInputs inputs, CancellationToken ct)
    {
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        if (System.Reflection.Assembly.GetEntryAssembly() != typeof(CompanyStorageRuntime).Assembly) { throw Invalid(); }
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(inputs.Secret(inputs.Configuration.SourceCredential), inputs.Intent.SourceIdentitySha256, accepted, ct);
        var owner = await OwnerAsync(inputs, ct);
        var contract = CompanyStorageRepairProtocol.RequireIntent(inputs.Intent, source.Plan, owner, DateTimeOffset.UtcNow);
        var result = new CompanyStorageRuntime(inputs, source, contract);
        try { await result.RequireAsync(ct); return result; }
        catch { result.Dispose(); throw; }
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        _code.Require();
        Source.Require(_inputs.Intent.SourceCommitSha, _inputs.Intent.SourceIdentitySha256, DateTimeOffset.UtcNow);
        if (DateTimeOffset.UtcNow - Source.BeganAtUtc > TimeSpan.FromMinutes(5) ||
            await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != Source.Plan.SourceCommitSha ||
            await ConsumerColumnBootstrapProofSourceCapture.ObserveIdentityAsync(_inputs.Secret(_inputs.Configuration.SourceCredential), ct) != _inputs.Intent.SourceIdentitySha256)
        { throw Invalid(); }
        var owner = await OwnerAsync(_inputs, ct);
        _ = _owned is null ? CompanyStorageRepairProtocol.RequireIntent(_inputs.Intent, Source.Plan, owner, DateTimeOffset.UtcNow) :
            CompanyStorageRepairProtocol.RequireOwnedIntent(_inputs.Intent, Source.Plan, owner, DateTimeOffset.UtcNow);
        _inputs.Authority.ValidateHeld(); _inputs.Files.Require();
        var endpoint = new NpgsqlConnectionStringBuilder(_connection); var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != _inputs.Intent.Maintenance.Role ||
            string.IsNullOrWhiteSpace(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options) || endpoint.Pooling || ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port ||
            ordinary.Username == endpoint.Username || string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options))
        { throw Invalid(); }
        if (_owned is null) { await (_target ?? throw Invalid()).RequireAsync(_inputs.Intent, endpoint.Port, ct); }
        else
        {
            await _owned.RequireAsync(ct);
            if (!DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(_inputs.Intent.Target) || _inputs.Intent.Target != _owned.Lease.Target ||
                _inputs.Intent.TargetGeneration != _owned.Lease.TargetGeneration || endpoint.Port != new NpgsqlConnectionStringBuilder(_owned.Lease.ConnectionString).Port ||
                (_fault is not null && !_fault.IsOwnedBy(_owned))) { throw Invalid(); }
        }
        try
        {
            await using var blocked = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_ordinary) { Database = "postgres", Pooling = false, Timeout = 3 }.ConnectionString);
            await blocked.OpenAsync(ct);
        }
        catch (PostgresException failure) when (failure.SqlState == PostgresErrorCodes.InvalidAuthorizationSpecification) { return; }
        throw Invalid();
    }
    internal NpgsqlConnection Connect(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(_fault?.Route(_connection) ?? _connection)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
    }

    internal async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> FleetAsync(bool after, CancellationToken ct)
    {
        await RequireAsync(ct);
        await using (var connection = Connect("postgres"))
        {
            await connection.OpenAsync(ct); await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, transaction, ct); await RequirePolicyAsync(connection, transaction, _inputs.Intent.Maintenance, _inputs.Intent.Target, ct);
            await using var command = new NpgsqlCommand("SELECT datname,datistemplate,datallowconn FROM pg_database ORDER BY datname COLLATE \"C\";", connection, transaction);
            var flags = new List<ReviewedRepairDatabaseFlag>();
            await using (var reader = await command.ExecuteReaderAsync(ct))
            { while (await reader.ReadAsync(ct)) { flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2))); } }
            ReviewedProductionRepairInventory.RequireComplete(_inputs.Intent.Target.Kind, flags, _inputs.Intent.BeforeDatabaseSha256.Keys);
            await transaction.RollbackAsync(ct);
        }
        string[] databases = [.. _inputs.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)];
        var cohort = _snapshotPool.BeginCohort(databases);
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (string database in databases)
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            await using var connection = Connect(database); await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, transaction, ct); await RequirePolicyAsync(connection, transaction, _inputs.Intent.Maintenance, _inputs.Intent.Target, ct);
            if (Source.Plan.Databases.Any(x => x.Database == database))
            {
                var expected = database == "Customer" && after ? Contract.After() : CompanyStorageRepairProtocol.PhysicalBefore(Source.Plan, database, _inputs.Intent.OwnerIsoAlreadyApplied);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                if (await inspector.InspectSchemaAsync(expected, ct) != expected.TargetSchemaSha256) { throw Invalid(); }
            }
            snapshots.Add(cohort.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct)));
            await transaction.RollbackAsync(ct);
        }
        await RequireAsync(ct); cohort.Complete(); return snapshots;
    }
    internal static async Task<CustomerCompanyStorageRepairOwner> OwnerAsync(CompanyStorageRepairInputs inputs, CancellationToken ct)
    {
        async Task Frame(CurrentAppOwnedDockerResource resource)
        { _ = await inputs.PublishAsync("owner-" + resource.RunId.ToString("N"), resource, Guid.Empty, CancellationToken.None); if (resource.CleanupFailed) { throw Invalid(); } }
        string head = (await CurrentCustomerSequenceOwnerProcess.RunGitAsync("head", Frame, ct)).Trim();
        if (!string.IsNullOrWhiteSpace(await CurrentCustomerSequenceOwnerProcess.RunGitAsync("status", Frame, ct))) { throw Invalid(); }
        const string root = @"B:\maliev-legacy\Legacy.Maliev.CustomerService";
        string[] names = ["Legacy.Maliev.CustomerService.Data/CustomerDbContext.cs", "Legacy.Maliev.CustomerService.Data/Migrations/CustomerDbContextModelSnapshot.cs",
            "Legacy.Maliev.CustomerService.Data/Migrations/20261024150000_EnforceCompanySourceStorage.cs", "Legacy.Maliev.CustomerService.Data/CompanySourceConstraints.cs"];
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string name in names)
        {
            using var held = new FileStream(Path.Combine(root, name), FileMode.Open, FileAccess.Read, FileShare.Read);
            hashes.Add(name, Convert.ToHexStringLower(SHA256.HashData(held)));
        }
        return (await CurrentCustomerSequenceOwnerProcess.RunGitAsync("head", Frame, ct)).Trim() != head ||
            !string.IsNullOrWhiteSpace(await CurrentCustomerSequenceOwnerProcess.RunGitAsync("status", Frame, ct))
            ? throw Invalid()
            : new(head, true, DateTimeOffset.UtcNow, hashes);
    }
    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction); _ = await command.ExecuteNonQueryAsync(ct); }
    public void Dispose() { try { _target?.Dispose(); } finally { _code.Dispose(); } }
    private static MigrationExecutionException Invalid()
    {
        return CompanyStorageRepairProtocol.Invalid();
    }
}
