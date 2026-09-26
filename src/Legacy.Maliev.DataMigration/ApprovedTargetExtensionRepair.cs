using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>
/// Atomically creates only the reviewed PostgreSQL-only service tables in an otherwise
/// exact source-owned database. This is a schema repair, never a row-delta operation.
/// </summary>
public static class ApprovedTargetExtensionRepair
{
    /// <summary>Returns <c>created</c> or <c>already-current</c>; any other state fails closed.</summary>
    public static async Task<string> ExecuteAsync(
        DatabaseSchemaPlan plan,
        string targetConnectionString,
        string expectedDatabaseName,
        string expectedSystemIdentifierSha256,
        string reviewedMissingTables,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetConnectionString);
        IReadOnlyList<TableCopyPlan> extensions = ApprovedTargetExtensionManifest.TablesFor(plan);
        if (extensions.Count == 0 || plan.Database is not ("Material" or "QuotationRequest") ||
            expectedSystemIdentifierSha256.Length != 64 ||
            !expectedSystemIdentifierSha256.All(Uri.IsHexDigit))
        {
            throw Invalid("target_extension_repair_configuration_invalid");
        }

        string expectedMissing = string.Join(';', extensions
            .Select(table => $"{table.TargetSchema}.{table.TargetTable}")
            .Order(StringComparer.Ordinal));
        var builder = new NpgsqlConnectionStringBuilder(targetConnectionString) { Pooling = false };
        if (!string.Equals(builder.Database, expectedDatabaseName, StringComparison.Ordinal))
        {
            throw Invalid("target_extension_repair_boundary_invalid");
        }

        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.Serializable, cancellationToken).ConfigureAwait(false);
        await using (var lockCommand = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended($1, 0));", connection, transaction))
        {
            _ = lockCommand.Parameters.AddWithValue($"legacy-maliev-target-extension-repair:{plan.Database}");
            _ = await lockCommand.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }

        await using (var identifier = new NpgsqlCommand(
            "SELECT system_identifier::text FROM pg_control_system();", connection, transaction))
        {
            string systemIdentifier = (string)(await identifier.ExecuteScalarAsync(cancellationToken)
                .ConfigureAwait(false) ?? throw Invalid("target_extension_repair_identity_invalid"));
            string observedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(systemIdentifier)))
                .ToLowerInvariant();
            if (!CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(expectedSystemIdentifierSha256.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(observedHash)))
            {
                throw Invalid("target_extension_repair_identity_invalid");
            }
        }

        string[] present;
        await using (var inventory = new NpgsqlCommand(
            "SELECT c.relname FROM pg_catalog.pg_class AS c " +
            "JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace " +
            "WHERE n.nspname='public' AND c.relkind IN ('r','p') AND c.relname=ANY($1) ORDER BY c.relname;",
            connection, transaction))
        {
            _ = inventory.Parameters.AddWithValue(extensions.Select(table => table.TargetTable).ToArray());
            var observed = new List<string>();
            await using NpgsqlDataReader reader = await inventory.ExecuteReaderAsync(cancellationToken)
                .ConfigureAwait(false);
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                observed.Add(reader.GetString(0));
            }
            present = [.. observed];
        }

        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        if (present.Length == extensions.Count)
        {
            if (!string.Equals(reviewedMissingTables, expectedMissing, StringComparison.Ordinal) ||
                !string.Equals(await inspector.InspectSchemaAsync(plan, cancellationToken)
                    .ConfigureAwait(false), plan.TargetSchemaSha256, StringComparison.Ordinal))
            {
                throw Invalid("target_extension_repair_schema_drift");
            }
            await ValidateExtensionSequencesAsync(connection, transaction, extensions, cancellationToken)
                .ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
            await VerifyPostCommitAsync(plan, targetConnectionString, expectedSystemIdentifierSha256,
                cancellationToken).ConfigureAwait(false);
            return "already-current";
        }

        if (present.Length != 0 || !string.Equals(reviewedMissingTables, expectedMissing, StringComparison.Ordinal))
        {
            throw Invalid("target_extension_repair_missing_set_invalid");
        }

        DatabaseSchemaPlan sourceOnly = plan with { TargetExtensionProfile = null };
        string sourceOnlyHash = PostgreSqlSchemaFingerprint.ComputeExpected(sourceOnly);
        if (!string.Equals(await inspector.InspectSchemaAsync(sourceOnly, cancellationToken)
            .ConfigureAwait(false), sourceOnlyHash, StringComparison.Ordinal))
        {
            throw Invalid("target_extension_repair_schema_drift");
        }

        DatabaseSchemaPlan extensionsOnly = plan with { Tables = [] };
        await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        await writer.ApplySchemaAsync(extensionsOnly, cancellationToken).ConfigureAwait(false);
        await writer.FinalizeSchemaAsync(extensionsOnly, cancellationToken).ConfigureAwait(false);
        if (!string.Equals(await writer.InspectSchemaAsync(plan, cancellationToken)
            .ConfigureAwait(false), plan.TargetSchemaSha256, StringComparison.Ordinal))
        {
            throw Invalid("target_extension_repair_schema_drift");
        }
        await ValidateExtensionSequencesAsync(connection, transaction, extensions, cancellationToken)
            .ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await VerifyPostCommitAsync(plan, targetConnectionString, expectedSystemIdentifierSha256,
            cancellationToken).ConfigureAwait(false);
        return "created";
    }

    internal static async Task VerifyPostCommitAsync(
        DatabaseSchemaPlan plan, string targetConnectionString,
        string expectedSystemIdentifierSha256, CancellationToken cancellationToken)
    {
        var builder = new NpgsqlConnectionStringBuilder(targetConnectionString) { Pooling = false };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await ValidateSystemIdentifierAsync(connection, transaction, expectedSystemIdentifierSha256,
            cancellationToken).ConfigureAwait(false);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        if (!string.Equals(await inspector.InspectSchemaAsync(plan, cancellationToken)
            .ConfigureAwait(false), plan.TargetSchemaSha256, StringComparison.Ordinal))
        {
            throw Invalid("target_extension_repair_schema_drift");
        }
        await ValidateExtensionSequencesAsync(connection, transaction,
            ApprovedTargetExtensionManifest.TablesFor(plan), cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task ValidateExtensionSequencesAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        IReadOnlyList<TableCopyPlan> extensions, CancellationToken cancellationToken)
    {
        foreach (TableCopyPlan table in extensions)
        {
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                string qualifiedTable = $"{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetSchema)}." +
                    PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable);
                await using var name = new NpgsqlCommand("SELECT pg_get_serial_sequence($1, $2);",
                    connection, transaction);
                _ = name.Parameters.AddWithValue(qualifiedTable);
                _ = name.Parameters.AddWithValue(identity.Column);
                string? sequence = (string?)await name.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(sequence))
                {
                    throw Invalid("target_extension_repair_sequence_drift");
                }
                await using var definition = new NpgsqlCommand(
                    "SELECT seqstart, seqincrement, seqmin, seqmax, seqcache, seqcycle, " +
                    "seqtypid = 'integer'::regtype FROM pg_catalog.pg_sequence WHERE seqrelid=$1::regclass;",
                    connection, transaction);
                _ = definition.Parameters.AddWithValue(sequence);
                await using NpgsqlDataReader reader = await definition.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                    reader.GetInt64(0) != identity.SeedValue ||
                    reader.GetInt64(1) != identity.IncrementValue ||
                    reader.GetInt64(2) != 1 || reader.GetInt64(3) != int.MaxValue ||
                    reader.GetInt64(4) != 1 || reader.GetBoolean(5) || !reader.GetBoolean(6))
                {
                    throw Invalid("target_extension_repair_sequence_drift");
                }
            }
        }
    }

    private static async Task ValidateSystemIdentifierAsync(
        NpgsqlConnection connection, NpgsqlTransaction transaction,
        string expectedSystemIdentifierSha256, CancellationToken cancellationToken)
    {
        await using var identifier = new NpgsqlCommand(
            "SELECT system_identifier::text FROM pg_control_system();", connection, transaction);
        string observed = (string)(await identifier.ExecuteScalarAsync(cancellationToken)
            .ConfigureAwait(false) ?? throw Invalid("target_extension_repair_identity_invalid"));
        string observedHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(observed)))
            .ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(expectedSystemIdentifierSha256.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(observedHash)))
        {
            throw Invalid("target_extension_repair_identity_invalid");
        }
    }

    private static MigrationExecutionException Invalid(string code)
    {
        return new(code,
        "The reviewed target-only extension repair is not safe for this target state.");
    }
}
