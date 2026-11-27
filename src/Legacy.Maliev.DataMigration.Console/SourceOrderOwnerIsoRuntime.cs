using System.Data;
using System.Security.Cryptography;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class SourceOrderOwnerIsoRuntime : IDisposable
{
    private readonly SourceOrderOwnerIsoInputs _input;
    private readonly CurrentAppOwnedSnapshotInternPool _snapshotPool = new();
    private readonly SourceOrderOwnerIsoPersistentTarget? _target;
    private readonly CompanyStorageAcceptedCodeCustody _code;
    private readonly string _operator, _ordinary;
    private readonly SourceOrderOwnerIsoOwnedSession? _owned;
    private readonly SourceOrderOwnerIsoFaultControl? _fault;
    internal ConsumerColumnBootstrapSourceCapture Source { get; }
    internal SourceOrderOwnerIsoContract Contract { get; }
    private SourceOrderOwnerIsoRuntime(SourceOrderOwnerIsoInputs input, ConsumerColumnBootstrapSourceCapture source, SourceOrderOwnerIsoContract contract,
        SourceOrderOwnerIsoOwnedSession? owned, SourceOrderOwnerIsoFaultControl? fault)
    {
        _input = input; Source = source; Contract = contract; _owned = owned; _fault = fault;
        _code = CompanyStorageAcceptedCodeCustody.Acquire();
        try
        {
            _operator = owned?.Lease.ConnectionString ?? input.Secret(input.Configuration.OperatorConnection);
            _ordinary = owned?.Lease.OrdinaryConnectionString ?? input.Secret(input.Configuration.OrdinaryConnection);
            if (owned is null) { _target = new(MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(input.Read(input.Configuration.TargetPins)), input.Files, input.Authority.Binding.ArtifactRootCanonicalPath); }
        }
        catch { _code.Dispose(); throw; }
    }
    internal static async Task<SourceOrderOwnerIsoRuntime> OpenAsync(SourceOrderOwnerIsoInputs input, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(MigrationConsole).Assembly) { throw Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(input.Secret(input.Configuration.SourceCredential), input.Intent.SourceIdentitySha256, accepted, ct);
        var contract = SourceOrderOwnerIsoProtocol.Require(input.Intent, ConsumerOverlaySelection.CurrentConsumerSchemaV3, source.Plan, await OwnersAsync(input, ct), DateTimeOffset.UtcNow, false);
        var runtime = new SourceOrderOwnerIsoRuntime(input, source, contract, null, null);
        try { await runtime.RequireAsync(ct); return runtime; } catch { runtime.Dispose(); throw; }
    }
    private static async Task<SourceOrderOwnerIsoRuntime> OpenOwnedAsync(SourceOrderOwnerIsoInputs input, ConsumerColumnBootstrapSourceCapture source,
        SourceOrderOwnerIsoOwnedSession owned, SourceOrderOwnerIsoFaultControl? fault, CancellationToken ct)
    {
        await owned.RequireAsync(ct);
        if (input.Intent.Target != owned.Lease.Target || input.Intent.TargetGeneration != owned.Lease.TargetGeneration || input.Intent.TargetObservationSha256 != SourceOrderOwnerIsoProtocol.Hash(owned.Lease.TargetPins)) { throw Invalid(); }
        var contract = SourceOrderOwnerIsoProtocol.Require(input.Intent, ConsumerOverlaySelection.CurrentConsumerSchemaV3, source.Plan, await OwnersAsync(input, ct), DateTimeOffset.UtcNow, true);
        var runtime = new SourceOrderOwnerIsoRuntime(input, source, contract, owned, fault);
        try { await runtime.RequireAsync(ct); return runtime; } catch { runtime.Dispose(); throw; }
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        _code.Require(); _input.Files.Require();
        Source.Require(_input.Intent.SourceCommitSha, _input.Intent.SourceIdentitySha256, DateTimeOffset.UtcNow);
        if (DateTimeOffset.UtcNow - Source.BeganAtUtc > TimeSpan.FromMinutes(5) || await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct) != Source.Plan.SourceCommitSha ||
            await ConsumerColumnBootstrapProofSourceCapture.ObserveIdentityAsync(_input.Secret(_input.Configuration.SourceCredential), ct) != Source.SourceIdentitySha256) { throw Invalid(); }
        _ = SourceOrderOwnerIsoProtocol.Require(_input.Intent, ConsumerOverlaySelection.CurrentConsumerSchemaV3, Source.Plan, await OwnersAsync(_input, ct), DateTimeOffset.UtcNow, _owned is not null);
        var op = new NpgsqlConnectionStringBuilder(_operator); var ordinary = new NpgsqlConnectionStringBuilder(_ordinary);
        if (op.Host != "127.0.0.1" || op.Port is < 1 or > 65535 || op.Pooling || op.Username != _input.Intent.Maintenance.Role || string.IsNullOrWhiteSpace(op.Password) ||
            !string.IsNullOrEmpty(op.Options) || ordinary.Host != op.Host || ordinary.Port != op.Port || ordinary.Username == op.Username || string.IsNullOrWhiteSpace(ordinary.Password) || !string.IsNullOrEmpty(ordinary.Options)) { throw Invalid(); }
        if (_owned is null) { await (_target ?? throw Invalid()).RequireAsync(_input.Intent, op.Port, ct); }
        else
        {
            await _owned.RequireAsync(ct);
            if (_input.Intent.Target != _owned.Lease.Target || (_fault is not null && !_fault.IsOwnedBy(_owned))) { throw Invalid(); }
        }
        try { await using var blocked = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_ordinary) { Database = "postgres", Pooling = false, Timeout = 3 }.ConnectionString); await blocked.OpenAsync(ct); }
        catch (PostgresException failure) when (failure.SqlState == PostgresErrorCodes.InvalidAuthorizationSpecification) { return; }
        throw Invalid();
    }
    internal async Task VerifyAsync(CancellationToken ct)
    {
        await RequireAsync(ct); RequireFleet(await FleetAsync(_input.Intent.Selected, ct), new Dictionary<string, string>());
        foreach (string database in SourceOrderOwnerIsoProtocol.Databases)
        { if ((await NativeAsync(database, _input.Intent.Selected[database], ct)).Sha256 != _input.Intent.NativePreimageSha256[database]) { throw Invalid(); } }
    }
    private NpgsqlConnection Connect(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(_fault?.Route(_operator) ?? _operator)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString);
    }

    private async Task<SourceOrderOwnerIsoNativeWitness> NativeAsync(string database, bool selected, CancellationToken ct)
    {
        await using var connection = Connect(database); await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await ReadOnlyAsync(connection, tx, ct); await PolicyAsync(connection, tx, ct);
        var value = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, Contract, selected, ct);
        _ = await OwnerAsync(connection, tx, value, ct); await tx.RollbackAsync(ct); return value;
    }
    private async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> FleetAsync(IReadOnlyDictionary<string, bool> selected, CancellationToken ct)
    {
        await RequireAsync(ct); var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>();
        string[] databases = [.. _input.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)];
        var cohort = _snapshotPool.BeginCohort(databases);
        foreach (string database in databases)
        {
            await using var connection = Connect(database); await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ReadOnlyAsync(connection, tx, ct); await PolicyAsync(connection, tx, ct);
            if (database == "postgres")
            {
                var flags = new List<ReviewedRepairDatabaseFlag>();
                await using var command = new NpgsqlCommand("SELECT datname,datistemplate,datallowconn FROM pg_database ORDER BY datname COLLATE \"C\";", connection, tx);
                await using (var reader = await command.ExecuteReaderAsync(ct)) { while (await reader.ReadAsync(ct)) { flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2))); } }
                ReviewedProductionRepairInventory.RequireComplete(_input.Intent.Target.Kind, flags, _input.Intent.BeforeDatabaseSha256.Keys);
            }
            if (Source.Plan.Databases.Any(x => x.Database == database))
            {
                var physical = Contract.PhysicalPlan(database, selected.GetValueOrDefault(database));
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct) != physical.TargetSchemaSha256) { throw Invalid(); }
                if (database == "Customer" && Contract.CompanyAlreadyApplied) { await CustomerCompanyStorageManifest.RequireNormalizerAsync(physical, connection, tx, ct); }
            }
            snapshots.Add(cohort.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct))); await tx.RollbackAsync(ct);
        }
        await RequireAsync(ct); cohort.Complete(); return snapshots;
    }
    private void RequireFleet(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual, IReadOnlyDictionary<string, string> committed)
    {
        if (actual.Count != _input.Intent.BeforeDatabaseSha256.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
            actual.Any(x => !_input.Intent.BeforeDatabaseSha256.TryGetValue(x.Database, out string? old) || x.Sha256 != committed.GetValueOrDefault(x.Database, old))) { throw Invalid(); }
    }
    private Task PolicyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        return CompanyStorageRuntime.RequirePolicyAsync(connection, tx, _input.Intent.Maintenance, _input.Intent.Target, ct);
    }

    private Task<string> OwnerAsync(NpgsqlConnection connection, NpgsqlTransaction tx, SourceOrderOwnerIsoNativeWitness native, CancellationToken ct)
    {
        return CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, connection.Database == "Country" ? CurrentRepairOperandOwnerPurpose.CountryIsoLiteral : CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral,
                _input.Intent.Target, native.Native.Snapshot, ct);
    }

    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx); _ = await command.ExecuteNonQueryAsync(ct); }
    internal static async Task<CurrentOwnerIsoSourceObservation[]> OwnersAsync(SourceOrderOwnerIsoInputs input, CancellationToken ct)
    {
        var result = new List<CurrentOwnerIsoSourceObservation>();
        foreach (string repository in OwnerRepositories)
        {
            string root = repository == "Legacy.Maliev.CountryService" ? @"B:\maliev-legacy\Legacy.Maliev.CountryService" : @"B:\maliev-legacy\Legacy.Maliev.CatalogService";
            async Task Frame(CurrentAppOwnedDockerResource frame)
            { _ = await input.PublishAsync("owner-" + frame.RunId.ToString("N"), frame, Guid.Empty, CancellationToken.None); if (frame.CleanupFailed) { throw Invalid(); } }
            string head = (await CurrentOwnerIsoOwnerProcess.RunGitAsync(repository, "head", Frame, ct)).Trim();
            if (!string.IsNullOrWhiteSpace(await CurrentOwnerIsoOwnerProcess.RunGitAsync(repository, "status", Frame, ct))) { throw Invalid(); }
            var hashes = new Dictionary<string, string>(StringComparer.Ordinal); var held = new List<FileStream>();
            try
            {
                foreach (string file in SourceOrderOwnerIsoContract.OwnerFiles(repository).Keys)
                { var stream = new FileStream(Path.Combine(root, file), FileMode.Open, FileAccess.Read, FileShare.Read); held.Add(stream); hashes.Add(file, Convert.ToHexStringLower(SHA256.HashData(stream))); }
                if ((await CurrentOwnerIsoOwnerProcess.RunGitAsync(repository, "head", Frame, ct)).Trim() != head || !string.IsNullOrWhiteSpace(await CurrentOwnerIsoOwnerProcess.RunGitAsync(repository, "status", Frame, ct))) { throw Invalid(); }
                result.Add(new(repository, head, true, DateTimeOffset.UtcNow, hashes));
            }
            finally { foreach (var stream in held) { stream.Dispose(); } }
        }
        return result.ToArray();
    }
    private static readonly string[] OwnerRepositories = ["Legacy.Maliev.CountryService", "Legacy.Maliev.CatalogService"];
    public void Dispose() { try { _target?.Dispose(); } finally { _code.Dispose(); } }
    private static MigrationExecutionException Invalid()
    {
        return SourceOrderOwnerIsoProtocol.Invalid();
    }
}
