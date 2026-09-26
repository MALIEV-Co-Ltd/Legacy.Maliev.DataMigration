using System.Data;
using System.Security.Cryptography;
using System.Text;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Creates only the two reviewed Quotation disposition targets while retaining the exact source-shaped outboxes.</summary>
public static class QuotationDispositionTargetBootstrap
{
    /// <summary>Returns created or already-current after an exact, target-bound schema check.</summary>
    public static async Task<string> ExecuteAsync(DatabaseSchemaPlan plan, string targetConnectionString,
        string expectedDatabaseName, string expectedSystemIdentifierSha256, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentException.ThrowIfNullOrWhiteSpace(targetConnectionString);
        if (string.IsNullOrWhiteSpace(expectedDatabaseName) || expectedSystemIdentifierSha256.Length != 64 ||
            !expectedSystemIdentifierSha256.All(Uri.IsHexDigit))
        {
            throw Invalid("quotation_target_bootstrap_boundary_invalid");
        }

        string targetHash = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(plan, true);
        TableCopyPlan[] targets = ApprovedSourceDispositionManifest.TargetTablesFor(plan)
            .Where(table => (table.TargetSchema == "legacy_compatibility" && table.TargetTable == "GoogleAnalyticsOutbox") ||
                            (table.TargetSchema == "public" && table.TargetTable == "QuotationAcceptedOutcome"))
            .ToArray();
        if (targets.Length != 2)
        {
            throw Invalid("quotation_target_bootstrap_plan_invalid");
        }

        var builder = new NpgsqlConnectionStringBuilder(targetConnectionString) { Pooling = false };
        if (builder.Database != expectedDatabaseName)
        {
            throw Invalid("quotation_target_bootstrap_boundary_invalid");
        }

        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable,
            cancellationToken).ConfigureAwait(false);
        await using (var advisoryLock = new NpgsqlCommand(
            "SELECT pg_advisory_xact_lock(hashtextextended('legacy-maliev-quotation-disposition-bootstrap', 0));",
            connection, transaction))
        {
            _ = await advisoryLock.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        }
        await VerifyIdentifierAsync(connection, transaction, expectedSystemIdentifierSha256, cancellationToken)
            .ConfigureAwait(false);

        const string inventorySql = """
            SELECT n.nspname || '.' || c.relname FROM pg_catalog.pg_class AS c
            JOIN pg_catalog.pg_namespace AS n ON n.oid=c.relnamespace
            WHERE c.relkind IN ('r','p') AND
                ((n.nspname='public' AND c.relname IN ('GoogleAnalyticsOutbox',
                    'QuotationOutcomeOutbox', 'QuotationAcceptedOutcome')) OR
                 (n.nspname='legacy_compatibility' AND c.relname='GoogleAnalyticsOutbox'))
            ORDER BY n.nspname, c.relname;
            """;
        var present = new HashSet<string>(StringComparer.Ordinal);
        await using (var inventory = new NpgsqlCommand(inventorySql, connection, transaction))
        await using (NpgsqlDataReader reader = await inventory.ExecuteReaderAsync(cancellationToken)
            .ConfigureAwait(false))
        {
            while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
            {
                _ = present.Add(reader.GetString(0));
            }
        }
        if (!present.Contains("public.GoogleAnalyticsOutbox") ||
            !present.Contains("public.QuotationOutcomeOutbox"))
        {
            throw Invalid("quotation_target_bootstrap_retained_set_invalid");
        }
        int targetCount = targets.Count(table => present.Contains($"{table.TargetSchema}.{table.TargetTable}"));
        if (targetCount is not (0 or 2))
        {
            throw Invalid("quotation_target_bootstrap_missing_set_invalid");
        }

        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        if (targetCount == 0)
        {
            string beforeHash = PostgreSqlSchemaFingerprint.ComputeExpectedSourceShape(plan);
            if (await inspector.InspectSchemaAsync(plan, cancellationToken).ConfigureAwait(false) != beforeHash)
            {
                throw Invalid("quotation_target_bootstrap_schema_drift");
            }
            DatabaseSchemaPlan additions = plan with
            {
                Tables = targets,
                SourceDispositionProfile = null,
                SourceTableDispositions = [],
                TargetExtensionProfile = null,
            };
            await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
                ownsResources: false);
            await writer.ApplySchemaAsync(additions, cancellationToken).ConfigureAwait(false);
            await writer.FinalizeSchemaAsync(additions, cancellationToken).ConfigureAwait(false);
        }
        if (await inspector.InspectSchemaAsync(plan, cancellationToken).ConfigureAwait(false) != targetHash)
        {
            throw Invalid("quotation_target_bootstrap_schema_drift");
        }
        await VerifySequencesAsync(connection, transaction, targets, cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        await VerifyPostCommitAsync(plan, targetConnectionString, expectedDatabaseName, expectedSystemIdentifierSha256,
            cancellationToken).ConfigureAwait(false);
        return targetCount == 0 ? "created" : "already-current";
    }

    /// <summary>Reopens the target read-only to catch post-commit DDL or identity drift.</summary>
    public static async Task VerifyPostCommitAsync(DatabaseSchemaPlan plan, string targetConnectionString,
        string expectedDatabaseName, string expectedSystemIdentifierSha256, CancellationToken cancellationToken)
    {
        string expectedHash = PostgreSqlSchemaFingerprint.ComputeQuotationBootstrapExpected(plan, true);
        var builder = new NpgsqlConnectionStringBuilder(targetConnectionString) { Pooling = false };
        if (builder.Database != expectedDatabaseName)
        {
            throw Invalid("quotation_target_bootstrap_boundary_invalid");
        }
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead,
            cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        await VerifyIdentifierAsync(connection, transaction, expectedSystemIdentifierSha256, cancellationToken)
            .ConfigureAwait(false);
        await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction,
            ownsResources: false);
        if (await inspector.InspectSchemaAsync(plan, cancellationToken).ConfigureAwait(false) != expectedHash)
        {
            throw Invalid("quotation_target_bootstrap_schema_drift");
        }
        await VerifySequencesAsync(connection, transaction,
            ApprovedSourceDispositionManifest.TargetTablesFor(plan).Where(table =>
                (table.TargetSchema == "legacy_compatibility" && table.TargetTable == "GoogleAnalyticsOutbox") ||
                (table.TargetSchema == "public" && table.TargetTable == "QuotationAcceptedOutcome")),
            cancellationToken).ConfigureAwait(false);
        await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
    }

    private static async Task VerifySequencesAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        IEnumerable<TableCopyPlan> tables, CancellationToken cancellationToken)
    {
        foreach (TableCopyPlan table in tables)
        {
            foreach (IdentityCopyPlan identity in table.Identities)
            {
                string qualified = $"{PostgreSqlShadowTarget.QuoteIdentifier(table.TargetSchema)}." +
                    PostgreSqlShadowTarget.QuoteIdentifier(table.TargetTable);
                await using var sequenceName = new NpgsqlCommand("SELECT pg_get_serial_sequence($1, $2);",
                    connection, transaction);
                _ = sequenceName.Parameters.AddWithValue(qualified);
                _ = sequenceName.Parameters.AddWithValue(identity.Column);
                string? sequence = (string?)await sequenceName.ExecuteScalarAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(sequence))
                {
                    throw Invalid("quotation_target_bootstrap_sequence_drift");
                }
                await using var definition = new NpgsqlCommand(
                    "SELECT seqstart, seqincrement, seqmin, seqmax, seqcache, seqcycle, " +
                    "seqtypid = 'bigint'::regtype FROM pg_catalog.pg_sequence WHERE seqrelid=$1::regclass;",
                    connection, transaction);
                _ = definition.Parameters.AddWithValue(sequence);
                await using NpgsqlDataReader reader = await definition.ExecuteReaderAsync(cancellationToken)
                    .ConfigureAwait(false);
                if (!await reader.ReadAsync(cancellationToken).ConfigureAwait(false) ||
                    reader.GetInt64(0) != identity.SeedValue ||
                    reader.GetInt64(1) != identity.IncrementValue || reader.GetInt64(2) != 1 ||
                    reader.GetInt64(3) != long.MaxValue || reader.GetInt64(4) != 1 ||
                    reader.GetBoolean(5) || !reader.GetBoolean(6))
                {
                    throw Invalid("quotation_target_bootstrap_sequence_drift");
                }
            }
        }
    }

    private static async Task VerifyIdentifierAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        string expectedSha256, CancellationToken cancellationToken)
    {
        await using var identifier = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();",
            connection, transaction);
        string value = (string)(await identifier.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
            ?? throw Invalid("quotation_target_bootstrap_identity_invalid"));
        string observed = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(value))).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(expectedSha256.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(observed)))
        {
            throw Invalid("quotation_target_bootstrap_identity_invalid");
        }
    }

    private static MigrationExecutionException Invalid(string code)
    {
        return new(code, "The reviewed Quotation target bootstrap is not safe for this target state.");
    }
}
