using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class OrderSubtotalRuntime : IDisposable
{
    private readonly OrderSubtotalPersistentTarget _target;
    private readonly OrderSubtotalAcceptedCodeCustody _code;
    private readonly string _ordinary;
    private bool _observing;
    private readonly CurrentAppOwnedSnapshotInternPool _pool = new();
    internal ConsumerColumnBootstrapSourceCapture Source { get; }
    internal OrderSubtotalExpressionRepairContract Contract { get; }
    internal OrderSubtotalRepairInputs Inputs { get; }
    internal string DirectConnection { get; }
    private OrderSubtotalRuntime(OrderSubtotalRepairInputs inputs, ConsumerColumnBootstrapSourceCapture source,
        OrderSubtotalExpressionRepairContract contract, string connection, string ordinary, OrderSubtotalPersistentTarget target, OrderSubtotalAcceptedCodeCustody code)
    { Inputs = inputs; Source = source; Contract = contract; DirectConnection = connection; _ordinary = ordinary; _target = target; _code = code; }
    internal static async Task<OrderSubtotalRuntime> OpenAsync(OrderSubtotalRepairInputs inputs, CancellationToken ct)
    {
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(inputs.Secret(inputs.Configuration.SourceCredential), inputs.Intent.SourceIdentitySha256, accepted, ct).ConfigureAwait(false);
        var contract = OrderSubtotalRepairProtocol.RequireIntent(inputs.Intent, source.Plan, DateTimeOffset.UtcNow);
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(inputs.Read(inputs.Configuration.TargetPins));
        var code = OrderSubtotalAcceptedCodeCustody.Acquire();
        OrderSubtotalPersistentTarget target;
        try { target = new(pins, inputs.Files, inputs.Authority.Binding.ArtifactRootCanonicalPath); }
        catch { code.Dispose(); throw; }
        OrderSubtotalRuntime? runtime = null;
        try
        {
            runtime = new(inputs, source, contract, inputs.Secret(inputs.Configuration.OperatorConnection), inputs.Secret(inputs.Configuration.OrdinaryConnection), target, code);
            await runtime.VerifyAsync(ct).ConfigureAwait(false); return runtime;
        }
        catch (Exception primary)
        {
            try { if (runtime is not null) { runtime.Dispose(); } else { try { target.Dispose(); } finally { code.Dispose(); } } }
            catch (Exception cleanup) { primary.Data["OrderRuntimeOpenCleanup"] = cleanup; }
            throw;
        }
    }
    internal static OrderSubtotalRuntime ForReadOnlyObservation(OrderSubtotalRepairInputs inputs, ConsumerColumnBootstrapSourceCapture source, OrderSubtotalExpressionRepairContract contract)
    {
        var pins = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedRepairTargetPins>(inputs.Read(inputs.Configuration.TargetPins));
        var code = OrderSubtotalAcceptedCodeCustody.Acquire(); OrderSubtotalPersistentTarget? target = null;
        try
        {
            target = new(pins, inputs.Files, inputs.Authority.Binding.ArtifactRootCanonicalPath);
            return new(inputs, source, contract, inputs.Secret(inputs.Configuration.OperatorConnection), inputs.Secret(inputs.Configuration.OrdinaryConnection), target, code) { _observing = true };
        }
        catch { try { target?.Dispose(); } finally { code.Dispose(); } throw; }
    }
    internal async Task RequireAsync(CancellationToken ct)
    {
        Inputs.Files.Require(); Inputs.Authority.ValidateHeld(); _code.Require();
        if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != Inputs.Intent.SourceCommitSha ||
            await ConsumerColumnBootstrapProofSourceCapture.ObserveIdentityAsync(Inputs.Secret(Inputs.Configuration.SourceCredential), ct).ConfigureAwait(false) != Inputs.Intent.SourceIdentitySha256)
        { throw Invalid(); }
        if (!_observing) { _ = OrderSubtotalRepairProtocol.RequireIntent(Inputs.Intent, Source.Plan, DateTimeOffset.UtcNow); }
        var endpoint = new NpgsqlConnectionStringBuilder(DirectConnection); var denied = new NpgsqlConnectionStringBuilder(_ordinary);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port is < 1 or > 65535 || endpoint.Username != Inputs.Intent.Maintenance.Role ||
            string.IsNullOrWhiteSpace(endpoint.Password) || endpoint.Pooling || !string.IsNullOrEmpty(endpoint.Options) ||
            denied.Host != endpoint.Host || denied.Port != endpoint.Port || denied.Username == endpoint.Username || string.IsNullOrWhiteSpace(denied.Password) || !string.IsNullOrEmpty(denied.Options))
        { throw Invalid(); }
        await _target.RequireAsync(Inputs.Intent, endpoint.Port, ct).ConfigureAwait(false);
        bool rejected = false;
        try { await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(_ordinary) { Database = "postgres", Pooling = false, Timeout = 3 }.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false); }
        catch (PostgresException denial) when (denial.SqlState == PostgresErrorCodes.InvalidAuthorizationSpecification) { rejected = true; }
        if (!rejected) { throw Invalid(); }
    }
    internal NpgsqlConnection Connect(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(DirectConnection)
        { Database = database, Pooling = false, IncludeErrorDetail = false, Timeout = 5, CommandTimeout = 60 }.ConnectionString);
    }

    internal async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> FleetAsync(bool after, CancellationToken ct)
    {
        await RequireAsync(ct).ConfigureAwait(false);
        var result = new List<CurrentAppOwnedDatabaseSnapshot>();
        var cohort = _pool.BeginCohort(Inputs.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal));
        await using (var inventory = Connect("postgres"))
        {
            await inventory.OpenAsync(ct).ConfigureAwait(false); await using var tx = await inventory.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(inventory, tx, ct).ConfigureAwait(false); await RequirePolicyAsync(inventory, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
            await ReviewedProductionRepairInventoryObservation.RequireAsync(inventory, tx, Inputs.Intent.Target.Kind,
                Inputs.Intent.Target.SystemIdentifierSha256, Inputs.Intent.BeforeDatabaseSha256.Keys.ToArray(), ct).ConfigureAwait(false);
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        foreach (string database in Inputs.Intent.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthArchiveCapacity.Require(admission: false);
            await using var connection = Connect(database); await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequirePolicyAsync(connection, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
            if (Source.Plan.Databases.Any(x => x.Database == database))
            {
                DatabaseSchemaPlan shape = database == "Order" ? after ? Contract.AfterPhysical() : Contract.BeforePhysical() : OrderSubtotalRepairProtocol.PhysicalBefore(Source.Plan, database);
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(shape, ct).ConfigureAwait(false) != shape.TargetSchemaSha256) { throw Invalid(); }
            }
            result.Add(cohort.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false)));
            await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        cohort.Complete(); return result;
    }
    internal async Task<OrderSubtotalExpressionRepairNativeObservation> NativeAsync(bool after, CancellationToken ct)
    {
        await using var connection = Connect("Order"); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await ReadOnlyAsync(connection, tx, ct).ConfigureAwait(false); await RequirePolicyAsync(connection, tx, Inputs.Intent.Maintenance, Inputs.Intent.Target, ct).ConfigureAwait(false);
        var native = await OrderSubtotalExpressionRepairNativePreservation.CaptureAsync(connection, tx, Contract, after, ct).ConfigureAwait(false);
        string owner = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx,
            "SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid='public.\"Order\"'::regclass;", ct).ConfigureAwait(false);
        if (owner != Inputs.Intent.OrderOwnerName) { throw Invalid(); }
        await tx.RollbackAsync(ct).ConfigureAwait(false); return native;
    }
    internal async Task VerifyAsync(CancellationToken ct)
    {
        RequireFleet(await FleetAsync(false, ct).ConfigureAwait(false), null);
        var native = await NativeFleetAsync(ct).ConfigureAwait(false);
        if (!native.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(Inputs.Intent.BeforeNativeDatabaseSha256.OrderBy(x => x.Key, StringComparer.Ordinal))) { throw Invalid(); }
        if (OrderSubtotalRepairProtocol.NativeSha(await NativeAsync(false, ct).ConfigureAwait(false)) != Inputs.Intent.NativePreimageSha256) { throw Invalid(); }
    }
    private void RequireFleet(IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> actual, string? afterOrder)
    {
        if (actual.Count != Inputs.Intent.BeforeDatabaseSha256.Count || actual.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != actual.Count ||
            actual.Any(x => !Inputs.Intent.BeforeDatabaseSha256.TryGetValue(x.Database, out string? expected) || x.Sha256 != (x.Database == "Order" && afterOrder is not null ? afterOrder : expected)))
        { throw Invalid(); }
    }
    private static async Task ReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    { await using var query = new NpgsqlCommand("SET TRANSACTION READ ONLY; SET LOCAL search_path=pg_catalog,public;", connection, tx); _ = await query.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    public void Dispose() { try { _target.Dispose(); } finally { _code.Dispose(); } }
    private static MigrationExecutionException Invalid()
    {
        return OrderSubtotalRepairProtocol.Invalid();
    }
}
