using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

public interface IExact23RepresentativeServiceQueryExecutor
{
    Task<bool> ExecuteAsync(string database, TableCopyPlan table, CancellationToken cancellationToken);
}

public sealed class PostgreSqlExact23RepresentativeServiceQueryExecutor(string administrativeConnectionString)
    : IExact23RepresentativeServiceQueryExecutor
{
    public async Task<bool> ExecuteAsync(string database, TableCopyPlan table, CancellationToken cancellationToken)
    {
        if (!DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("local_delta_query_database_invalid",
                "Representative queries are restricted to the exact active database inventory.");
        }
        ArgumentNullException.ThrowIfNull(table);
        var builder = new NpgsqlConnectionStringBuilder(administrativeConnectionString)
        {
            Database = database,
            Pooling = false,
        };
        await using var connection = new NpgsqlConnection(builder.ConnectionString);
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(
            IsolationLevel.RepeatableRead, cancellationToken).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
        {
            _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
        }
        string qualified = $"{Quote(table.TargetSchema)}.{Quote(table.TargetTable)}";
        await using var command = new NpgsqlCommand($"SELECT EXISTS (SELECT 1 FROM {qualified} LIMIT 1);", connection, transaction);
        object? result = await command.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false);
        await transaction.RollbackAsync(cancellationToken).ConfigureAwait(false);
        return result is bool;
    }

    private static string Quote(string identifier)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(identifier);
        return '"' + identifier.Replace("\"", "\"\"", StringComparison.Ordinal) + '"';
    }
}

public sealed class Exact23RepresentativeServiceQueryValidator(
    IExact23RepresentativeServiceQueryExecutor executor,
    IReceiptAttestationTrustStore terminalReceiptTrust,
    TimeProvider timeProvider)
{
    public async Task<Exact23RepresentativeServiceQueryEvidence> ValidateAsync(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        Exact23DeltaReconciliationResult terminalReceipt,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(terminalReceipt);
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        if (!Exact23DeltaReconciliationCoordinator.Verify(terminalReceipt, terminalReceiptTrust) ||
            terminalReceipt.PlanId != plan.PlanId || !Fixed(terminalReceipt.PlanSha256, planSha256) ||
            !Fixed(plan.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(schema)) ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("local_delta_terminal_receipt_invalid",
                "Representative queries require the signed journal-bound exact-23 terminal receipt.");
        }

        var results = new List<RepresentativeServiceQueryResult>(DatabaseInventory.ActiveDatabases.Count);
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            TableCopyPlan table = database.Tables.OrderBy(item => item.TargetSchema, StringComparer.Ordinal)
                .ThenBy(item => item.TargetTable, StringComparer.Ordinal).FirstOrDefault() ??
                throw new DeltaExecutionException("local_delta_query_schema_empty",
                    "Every active database requires a mapped table for representative service validation.");
            bool succeeded = await executor.ExecuteAsync(database.Database, table, cancellationToken).ConfigureAwait(false);
            results.Add(new(database.Database, DatabaseInventory.Entries[database.Database].Owner,
                $"{database.Database}:exists:{table.TargetSchema}.{table.TargetTable}", succeeded));
        }
        return new("1.0", plan.PlanId, planSha256, plan.SourceCutoffUtc, timeProvider.GetUtcNow(), results);
    }

    private static bool Fixed(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}

public static class Exact23LocalDeltaAppHostEvidenceV2Producer
{
    private static readonly JsonSerializerOptions OutputJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = true,
    };

    public static AppHostMigrationEvidenceV2Document Produce(
        DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema,
        Exact23DeltaReconciliationResult terminalReceipt,
        Exact23RepresentativeServiceQueryEvidence queries,
        LocalSnapshotManifest snapshot,
        IReceiptAttestationTrustStore terminalReceiptTrust,
        IMigrationEvidenceSigner signer,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(schema);
        ArgumentNullException.ThrowIfNull(terminalReceipt);
        ArgumentNullException.ThrowIfNull(queries);
        ArgumentNullException.ThrowIfNull(snapshot);
        ArgumentNullException.ThrowIfNull(terminalReceiptTrust);
        ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(timeProvider);
        string planSha256 = DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan);
        if (plan.TargetAuthority?.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !Exact23DeltaReconciliationCoordinator.Verify(terminalReceipt, terminalReceiptTrust) ||
            terminalReceipt.PlanId != plan.PlanId || !Fixed(terminalReceipt.PlanSha256, planSha256) ||
            queries.PlanId != plan.PlanId || !Fixed(queries.PlanSha256, planSha256) ||
            !queries.Queries.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            queries.Queries.Any(item => !item.Succeeded) ||
            !snapshot.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            snapshot.Databases.Any(item => item.Database != item.ShadowDatabase) ||
            !schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw new DeltaExecutionException("local_delta_apphost_evidence_invalid",
                "AppHost evidence requires matching exact-23 local delta terminal, query, and snapshot evidence.");
        }

        JsonArray databases = new([.. terminalReceipt.Databases.Select(database => (JsonNode)new JsonObject
        {
            ["database"] = database.Database,
            ["owner"] = DatabaseInventory.Entries[database.Database].Owner,
            ["reconciliationSha256"] = DeltaReconciliationEvidenceCanonicalizer.ComputeSha256(database),
            ["queryId"] = queries.Queries.Single(item => item.Database == database.Database).QueryId,
            ["snapshotSha256"] = snapshot.Databases.Single(item => item.Database == database.Database).EncryptedSha256,
        })]);
        JsonObject root = new()
        {
            ["schemaVersion"] = 2,
            ["source"] = new JsonObject
            {
                ["cutoffUtc"] = Utc(plan.SourceCutoffUtc),
                ["commitSha"] = plan.SourceCommitSha,
                ["backupManifestSha256"] = plan.BackupManifestSha256,
            },
            ["mapping"] = new JsonObject
            {
                ["schemaPlanVersion"] = schema.SchemaVersion,
                ["schemaPlanSha256"] = plan.SchemaPlanSha256,
                ["planId"] = plan.PlanId.ToString("D"),
                ["planSha256"] = planSha256,
            },
            ["target"] = new JsonObject
            {
                ["system"] = "postgresql",
                ["authority"] = "local-aspire",
                ["cluster"] = plan.TargetCluster,
                ["namespace"] = plan.TargetNamespace,
                ["mode"] = "incremental",
                ["generation"] = plan.TargetGeneration,
                ["observedAtUtc"] = Utc(terminalReceipt.ReconciledAtUtc),
            },
            ["inventory"] = new JsonObject { ["count"] = 23, ["sha256"] = DatabaseInventory.InventorySha256 },
            ["snapshot"] = new JsonObject
            {
                ["id"] = snapshot.SnapshotId,
                ["format"] = snapshot.Format,
                ["encryption"] = snapshot.Encryption,
                ["manifestSha256"] = snapshot.ManifestDigestSha256,
            },
            ["databases"] = databases,
            ["parity"] = "exact",
            ["constraints"] = new JsonObject
            {
                ["productionDataWritesAllowed"] = false,
                ["databaseReplacementAllowed"] = false,
                ["cutoverAllowed"] = false,
                ["deploymentAllowed"] = false,
            },
            ["issuedAtUtc"] = Utc(timeProvider.GetUtcNow()),
        };
        byte[] payload = AppHostMigrationEvidenceV2Canonicalizer.CreatePayload(root);
        root["attestation"] = new JsonObject
        {
            ["algorithm"] = "ECDSA_P256_SHA256",
            ["keyId"] = signer.KeyId,
            ["payloadSha256"] = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant(),
            ["signatureBase64"] = Convert.ToBase64String(signer.Sign(payload)),
        };
        JsonObject baseline = new()
        {
            ["schemaVersion"] = 2,
            ["planSha256"] = planSha256,
            ["databaseInventorySha256"] = DatabaseInventory.InventorySha256,
            ["targetAuthority"] = "local-aspire",
            ["targetMode"] = "incremental",
        };
        return new(root.ToJsonString(OutputJson), baseline.ToJsonString(OutputJson));
    }

    private static string Utc(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static bool Fixed(string left, string right)
    {
        return left.Length == 64 && right.Length == 64 && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}
