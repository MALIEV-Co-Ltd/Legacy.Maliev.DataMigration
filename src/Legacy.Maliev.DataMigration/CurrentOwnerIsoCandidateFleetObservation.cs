using System.Data;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentOwnerIsoCandidateFleet(string Database, DateTimeOffset ObservedAtUtc,
    Guid OperationId, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> ActualFleet,
    CurrentOwnerIsoNativeObservation ActualCandidate);

internal static class CurrentOwnerIsoCandidateFleetObservation
{
    // Called at the real provider boundary with its STILL PRIVATE transaction, before Prepared publication.
    // This never derives a candidate from a receipt hash or a previously captured baseline.
    internal static async Task<CurrentOwnerIsoCandidateFleet> CaptureAsync(NpgsqlConnection privateConnection,
        NpgsqlTransaction privateTransaction, CurrentOwnerIsoRepairScope scope, ApprovedCurrentOwnerIsoOverlay contract,
        string maintenanceConnectionString, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> expectedPhase,
        CancellationToken ct)
    {
        if (scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) ||
            DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target) ||
            privateTransaction.Connection != privateConnection || privateTransaction.IsolationLevel != IsolationLevel.Serializable ||
            privateConnection.Database is not ("Country" or "Material") || expectedPhase.Count != 26 ||
            expectedPhase.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 ||
            !expectedPhase.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var builder = new NpgsqlConnectionStringBuilder(maintenanceConnectionString)
        { Pooling = false, Timeout = 5, CommandTimeout = 20, IncludeErrorDetail = false };
        if (builder.Host != "127.0.0.1" || builder.Username != scope.Maintenance.Role || string.IsNullOrEmpty(builder.Password) || !string.IsNullOrEmpty(builder.Options))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var native = await CurrentOwnerIsoNativePreservation.CaptureAsync(privateConnection, privateTransaction, contract, true, ct).ConfigureAwait(false);
        var actual = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (var expected in expectedPhase)
        {
            if (expected.Database == privateConnection.Database) { actual.Add(native.Snapshot); continue; }
            builder.Database = expected.Database;
            await using var connection = new NpgsqlConnection(builder.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
            { _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, scope.Maintenance.Role, scope.Target.Kind, ct).ConfigureAwait(false);
            var observed = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
            if (observed.Sha256 != expected.Sha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            actual.Add(observed); await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        return new(privateConnection.Database, DateTimeOffset.UtcNow, scope.OperationId, actual, native);
    }
}
