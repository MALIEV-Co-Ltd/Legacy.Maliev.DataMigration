using System.Data;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveGenuineOwnedPair
{
    private async Task RequireRecoveryCustodyAsync(CancellationToken ct)
    {
        if (_disposed || _first is null || _second is null || _firstAuthority is null || _secondAuthority is null ||
            _firstFiles is null || _secondFiles is null || _firstPolicy is null || _secondPolicy is null || DateTimeOffset.UtcNow >= Scope.ExpiresAtUtc) { throw Invalid(); }
        _bundle.Require(); await _inputs.RequireAsync(ct);
        await _first.RequireHealthyHeldAsync(_firstAuthority, ct); await _second.RequireHealthyHeldAsync(_secondAuthority, ct);
        await CurrentAuthOwnerSourceReader.RequireAsync(resource => _inputs.ParentFiles.WriteNewAsync(Path.Combine(
            _inputs.ParentAuthority.Binding.ArtifactRootCanonicalPath, "recovery-owner-resource-" + Guid.NewGuid().ToString("N") + ".json"),
            JsonSerializer.SerializeToUtf8Bytes(resource), CancellationToken.None), ct);
        _firstFiles.Require(); _secondFiles.Require(); _bundle.Require();
        if (_recoveryCapture is not null) { await _recoveryCapture.RequireAsync(ct); }
        if (_recoveryFinal6Capture is not null) { await _recoveryFinal6Capture.RequireAsync(ct); }
    }

    private async Task<CurrentAuthArchiveFleet> CaptureRecoveryFleetAsync(bool comparison, CancellationToken ct)
    {
        var policy = comparison ? Scope.ProductionObservationPolicy : Scope.LocalObservationPolicy;
        var before = await CatalogAsync(); DateTimeOffset began = DateTimeOffset.UtcNow;
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>(); CurrentAuthLocalSessionArchiveObservation? auth = null;
        foreach (string database in policy.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthArchiveCapacity.Require(admission: false);
            await using var connection = RecoveryConnection(comparison, database); await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await RecoveryReadOnlyAsync(connection, transaction, ct);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, policy, ct);
            if (database == "Auth")
            { auth = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, transaction, policy.RunBindingSha256, ct); snapshots.Add(auth.Native.Snapshot); }
            else { snapshots.Add(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct)); }
            var source = _inputs.Source.Databases.SingleOrDefault(item => item.Database == database);
            if (source is not null)
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                if (await inspector.InspectSchemaAsync(source, ct) != source.TargetSchemaSha256) { throw Invalid(); }
            }
            await transaction.RollbackAsync(ct);
        }
        DateTimeOffset ended = DateTimeOffset.UtcNow; var after = await CatalogAsync();
        var catalogs = new CurrentAuthArchiveFleetCatalogs(before, after, began, ended);
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, comparison, snapshots.Select(item => item.Database), before.BeganAtUtc, DateTimeOffset.UtcNow);
        return new(auth ?? throw Invalid(), snapshots.AsReadOnly(), began, ended, catalogs);

        async Task<CurrentAuthArchiveCatalogObservation> CatalogAsync()
        {
            await RequireRecoveryCustodyAsync(ct);
            await using var connection = RecoveryConnection(comparison, "postgres"); await connection.OpenAsync(ct);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct); await RecoveryReadOnlyAsync(connection, transaction, ct);
            await PostgreSqlCurrentAuthRepair.RequireInstalledPolicyAsync(connection, transaction, policy, ct);
            DateTimeOffset started = DateTimeOffset.UtcNow;
            await using var command = new NpgsqlCommand("SELECT d.datname,d.datistemplate,d.datallowconn,encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),current_setting('transaction_read_only')='on' FROM pg_database d CROSS JOIN pg_control_system() ORDER BY d.datname COLLATE \"C\";", connection, transaction);
            var flags = new List<ReviewedRepairDatabaseFlag>();
            await using (var reader = await command.ExecuteReaderAsync(ct))
            {
                while (await reader.ReadAsync(ct))
                { if (reader.GetString(3) != policy.Target.SystemIdentifierSha256 || !reader.GetBoolean(4)) { throw Invalid(); } flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2))); }
            }
            ReviewedProductionRepairInventory.RequireComplete(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), flags, policy.BeforeDatabaseSha256.Keys);
            await transaction.RollbackAsync(ct);
            return new(policy.RunBindingSha256, policy.TargetObservationSha256, policy.Target.SystemIdentifierSha256, true, flags.AsReadOnly(), started, DateTimeOffset.UtcNow);
        }
    }
    private static async Task RecoveryReadOnlyAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, CancellationToken ct)
    {
        await using var command = new NpgsqlCommand("SET TRANSACTION READ ONLY; SET LOCAL timezone='UTC'; SET LOCAL datestyle='ISO, YMD'; SET LOCAL extra_float_digits=3;", connection, transaction); _ = await command.ExecuteNonQueryAsync(ct);
    }
}
