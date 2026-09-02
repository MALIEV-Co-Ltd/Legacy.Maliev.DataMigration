using System.Collections.ObjectModel;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public interface IPostgreSqlShadowRecoveryTarget
{
    Task<IPostgreSqlShadowRecoverySession> BeginReadOnlyRecoveryAsync(ShadowDatabase originalShadow, CancellationToken cancellationToken);
}

public interface IPostgreSqlShadowRecoverySession : IAsyncDisposable
{
    Task<PostgreSqlShadowRecoveryInspection> InspectAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken);
}

// Observed target evidence only. The caller must independently compare source/checkpoint
// evidence before reuse/publication; nonempty does not establish a completed migration.
public sealed record PostgreSqlShadowRecoveryInspection(
    ShadowDatabase OriginalShadow,
    bool IsVerifiedEmpty,
    string? TargetSchemaSha256,
    IReadOnlyList<TableReconciliationEvidence> Tables,
    IReadOnlyDictionary<string, long> SequenceNextValues);

public sealed partial class PostgreSqlShadowTarget : IPostgreSqlShadowRecoveryTarget
{
    public async Task<IPostgreSqlShadowRecoverySession> BeginReadOnlyRecoveryAsync(ShadowDatabase originalShadow, CancellationToken cancellationToken)
    {
        (NpgsqlConnection connection, NpgsqlTransaction transaction) =
            await BeginSettledShadowAsync(originalShadow, readOnly: true, cancellationToken).ConfigureAwait(false);
        return new PostgreSqlShadowRecoverySession(connection, transaction, originalShadow);
    }

    private async Task<(NpgsqlConnection, NpgsqlTransaction)> BeginSettledShadowAsync(
        ShadowDatabase shadow, bool readOnly, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(shadow);
        ValidateShadowIdentity(shadow);
        NpgsqlConnection connection = CreateShadowConnection(shadow.Name);
        NpgsqlTransaction transaction = await PostgreSqlShadowTransactionGate.BeginAsync(
            connection, shadow.Name, readOnly, _settlementTimeout, cancellationToken).ConfigureAwait(false);
        try
        {
            // All observations are on the locked actual target, after prior settlement.
            _ = await AssertOwnershipAsync(connection, shadow, allowMissing: false, cancellationToken).ConfigureAwait(false);
            await PostgreSqlMigrationRuntimeBoundaryValidator.ValidateOwnedShadowConnectionAsync(connection, _expectedRuntimeRole,
                shadow.Name, new NpgsqlConnectionStringBuilder(_administrativeConnectionString).Database!, cancellationToken).ConfigureAwait(false);
            await AssertDatabaseBoundaryAsync(connection, shadow.Name, _expectedRuntimeRole, cancellationToken).ConfigureAwait(false);
            const string aclSql = """
                SELECT NOT EXISTS (
                    SELECT 1 FROM pg_database d,
                        aclexplode(COALESCE(d.datacl, acldefault('d', d.datdba))) acl
                    WHERE d.datname = current_database() AND acl.grantee <> d.datdba
                      AND NOT (acl.grantee = 0 AND acl.privilege_type = 'TEMPORARY' AND NOT acl.is_grantable));
                """;
            await using var acl = new NpgsqlCommand(aclSql, connection, transaction);
            return !true.Equals(await acl.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false))
                ? throw new MigrationExecutionException("shadow_database_boundary_invalid", "The target grants access outside the reviewed owner-only database boundary.")
                : ((NpgsqlConnection, NpgsqlTransaction))(connection, transaction);
        }
        catch (Exception primary)
        {
            await PostgreSqlShadowTransactionGate.DisposeFailedAsync(connection, transaction, primary).ConfigureAwait(false);
            throw;
        }
    }
}

internal sealed class PostgreSqlShadowRecoverySession(
    NpgsqlConnection connection,
    NpgsqlTransaction transaction,
    ShadowDatabase originalShadow) : IPostgreSqlShadowRecoverySession
{
    private readonly PostgreSqlWholeDatabaseTransaction _inspection = new(connection, transaction);
    private bool _disposed;

    public async Task<PostgreSqlShadowRecoveryInspection> InspectAsync(DatabaseSchemaPlan plan, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentNullException.ThrowIfNull(plan);
        if (!string.Equals(plan.Database, originalShadow.Database, StringComparison.Ordinal) || plan.Tables.Count == 0)
        {
            throw new MigrationExecutionException("shadow_recovery_plan_invalid", "Recovery requires the full plan for the original shadow database.");
        }
        bool empty = await PostgreSqlShadowRecoveryObjects.InspectAsync(connection, transaction, plan, cancellationToken).ConfigureAwait(false);
        if (empty)
        {
            return new(originalShadow, true, null, [], ReadOnlyDictionary<string, long>.Empty);
        }
        string schema = await _inspection.InspectSchemaAsync(plan, cancellationToken).ConfigureAwait(false);
        ReconciliationDiagnostics.CompareSchema(plan.Database, plan.TargetSchemaSha256, schema);
        List<TableReconciliationEvidence> tables = [];
        foreach (TableCopyPlan table in plan.Tables)
        {
            tables.Add(await _inspection.InspectTableAsync(table, cancellationToken).ConfigureAwait(false));
        }
        IReadOnlyDictionary<string, long> sequences =
            await _inspection.InspectSequenceNextValuesAsync(plan, cancellationToken).ConfigureAwait(false);
        return new(originalShadow, false, schema, tables.AsReadOnly(), sequences);
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) { return; }
        _disposed = true;
        await _inspection.DisposeAsync().ConfigureAwait(false);
    }
}
