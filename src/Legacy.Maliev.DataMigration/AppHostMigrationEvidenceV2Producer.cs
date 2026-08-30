using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record AppHostMigrationEvidenceV2Configuration(
    string SourceSnapshotId,
    string BackupUri,
    string BackupObjectGeneration,
    string RestoreId,
    Guid EvidenceId,
    Guid LeaseId,
    DateTimeOffset LeaseAcquiredAtUtc,
    DateTimeOffset LeaseExpiresAtUtc);

public sealed record MigrationEvidenceProvenanceReceipt(
    string SchemaVersion,
    string SourceSnapshotId,
    string BackupUri,
    string BackupObjectGeneration,
    string RestoreId,
    Guid EvidenceId,
    Guid LeaseId,
    DateTimeOffset LeaseAcquiredAtUtc,
    DateTimeOffset LeaseExpiresAtUtc,
    Guid RunId,
    string SourceCommitSha,
    string SchemaPlanSha256,
    string BackupManifestSha256,
    string RunnerDigestSha256,
    string TargetGeneration,
    DateTimeOffset IssuedAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

public static class MigrationEvidenceProvenanceAttestation
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.EvidenceProvenance.v1";

    public static bool TryCreatePayload(MigrationEvidenceProvenanceReceipt receipt, out byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        payload = [];
        if (string.IsNullOrWhiteSpace(receipt.SchemaVersion) || string.IsNullOrWhiteSpace(receipt.SourceSnapshotId) ||
            string.IsNullOrWhiteSpace(receipt.BackupUri) || string.IsNullOrWhiteSpace(receipt.BackupObjectGeneration) ||
            string.IsNullOrWhiteSpace(receipt.RestoreId) || receipt.EvidenceId == Guid.Empty || receipt.LeaseId == Guid.Empty ||
            receipt.RunId == Guid.Empty || string.IsNullOrWhiteSpace(receipt.SourceCommitSha) ||
            string.IsNullOrWhiteSpace(receipt.SchemaPlanSha256) || string.IsNullOrWhiteSpace(receipt.BackupManifestSha256) ||
            string.IsNullOrWhiteSpace(receipt.RunnerDigestSha256) || string.IsNullOrWhiteSpace(receipt.TargetGeneration) ||
            string.IsNullOrWhiteSpace(receipt.AttestationKeyId))
        {
            return false;
        }

        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            Write(writer, DomainSeparator);
            Write(writer, receipt.SchemaVersion);
            Write(writer, receipt.SourceSnapshotId);
            Write(writer, receipt.BackupUri);
            Write(writer, receipt.BackupObjectGeneration);
            Write(writer, receipt.RestoreId);
            Write(writer, receipt.EvidenceId.ToString("D"));
            Write(writer, receipt.LeaseId.ToString("D"));
            Write(writer, Utc(receipt.LeaseAcquiredAtUtc));
            Write(writer, Utc(receipt.LeaseExpiresAtUtc));
            Write(writer, receipt.RunId.ToString("D"));
            Write(writer, receipt.SourceCommitSha);
            Write(writer, receipt.SchemaPlanSha256);
            Write(writer, receipt.BackupManifestSha256);
            Write(writer, receipt.RunnerDigestSha256);
            Write(writer, receipt.TargetGeneration);
            Write(writer, Utc(receipt.IssuedAtUtc));
            Write(writer, receipt.AttestationKeyId);
        }

        payload = stream.ToArray();
        return true;
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static string Utc(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    }
}

public sealed record AppHostMigrationEvidenceV2Request(
    MigrationExecutionResult ExecutionResult,
    BackupReceipt BackupReceipt,
    FreshSchemaPlan SchemaPlan,
    ExecutionAuthorizationReceipt Authorization,
    AppHostMigrationEvidenceV2Configuration Configuration,
    MigrationEvidenceProvenanceReceipt Provenance)
{
    public VerifiedRestoreReceipt? VerifiedRestoreReceipt { get; init; }
}

public sealed record AppHostMigrationEvidenceV2Document(
    string EvidenceJson,
    string ApprovedBaselineJson);

public sealed class MigrationEvidenceProductionException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static partial class AppHostMigrationEvidenceV2Producer
{
    private static readonly JsonSerializerOptions OutputJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = true,
    };

    public static AppHostMigrationEvidenceV2Document Produce(
        AppHostMigrationEvidenceV2Request request,
        IReceiptAttestationTrustStore backupTrust,
        IReceiptAttestationTrustStore authorizationTrust,
        IReceiptAttestationTrustStore executionTrust,
        IReceiptAttestationTrustStore provenanceTrust,
        IMigrationEvidenceSigner evidenceSigner,
        TimeProvider timeProvider)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(backupTrust);
        ArgumentNullException.ThrowIfNull(authorizationTrust);
        ArgumentNullException.ThrowIfNull(executionTrust);
        ArgumentNullException.ThrowIfNull(provenanceTrust);
        ArgumentNullException.ThrowIfNull(evidenceSigner);
        ArgumentNullException.ThrowIfNull(timeProvider);

        Validate(request, backupTrust, authorizationTrust, executionTrust, provenanceTrust, evidenceSigner, timeProvider.GetUtcNow());
        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan);
        JsonArray mappingDatabases = BuildMapping(request.SchemaPlan);
        JsonArray databaseEvidence = BuildDatabaseEvidence(request, planSha256);
        JsonObject root = new()
        {
            ["schemaVersion"] = 2,
            ["source"] = new JsonObject
            {
                ["system"] = "sqlserver",
                ["snapshotId"] = request.Configuration.SourceSnapshotId,
                ["capturedAtUtc"] = Utc(request.BackupReceipt.CapturedAtUtc),
                ["observedAtUtc"] = Utc(request.BackupReceipt.SourceObservedAtUtc!.Value),
                ["backup"] = new JsonObject
                {
                    ["uri"] = request.Configuration.BackupUri,
                    ["manifestSha256"] = request.BackupReceipt.ManifestSha256,
                    ["databaseInventorySha256"] = request.BackupReceipt.DatabaseInventorySha256,
                    ["objectGeneration"] = request.Configuration.BackupObjectGeneration,
                    ["immutable"] = true,
                },
                ["artifacts"] = new JsonArray(request.BackupReceipt.Artifacts!
                    .Select(artifact => (JsonNode)new JsonObject
                    {
                        ["database"] = artifact!.Database,
                        ["completedAtUtc"] = Utc(artifact.CompletedAtUtc!.Value),
                        ["object"] = artifact.GcsObject,
                        ["generation"] = artifact.GcsGeneration,
                        ["sha256"] = artifact.GcsSha256,
                    }).ToArray()),
            },
            ["mapping"] = new JsonObject
            {
                ["schemaPlanVersion"] = request.SchemaPlan.SchemaVersion,
                ["planSha256"] = planSha256,
                ["sourceCommitSha"] = request.SchemaPlan.SourceCommitSha,
                ["runnerDigestSha256"] = request.ExecutionResult.Receipt.RunnerDigestSha256,
                ["databases"] = mappingDatabases,
            },
            ["target"] = new JsonObject
            {
                ["system"] = "postgresql",
                ["cluster"] = "legacy-postgres-main",
                ["namespace"] = "maliev-legacy",
                ["mode"] = "shadow",
                ["generation"] = request.ExecutionResult.Receipt.TargetGeneration,
                ["capturedAtUtc"] = Utc(request.ExecutionResult.Receipt.CompletedAtUtc),
                ["restoreId"] = request.Configuration.RestoreId,
            },
            ["execution"] = new JsonObject
            {
                ["runId"] = request.ExecutionResult.Receipt.RunId.ToString("D"),
                ["evidenceId"] = request.Configuration.EvidenceId.ToString("D"),
                ["issuedAtUtc"] = Utc(request.Authorization.IssuedAtUtc),
                ["expiresAtUtc"] = Utc(request.Authorization.ExpiresAtUtc),
                ["leaseId"] = request.Configuration.LeaseId.ToString("D"),
                ["leaseAcquiredAtUtc"] = Utc(request.Configuration.LeaseAcquiredAtUtc),
                ["leaseExpiresAtUtc"] = Utc(request.Configuration.LeaseExpiresAtUtc),
                ["targetGeneration"] = request.ExecutionResult.Receipt.TargetGeneration,
                ["restoreId"] = request.Configuration.RestoreId,
                ["state"] = "completed",
            },
            ["verifiedRestore"] = BuildVerifiedRestoreEvidence(request.VerifiedRestoreReceipt!),
            ["inventory"] = BuildInventory(),
            ["archives"] = new JsonArray(),
            ["databases"] = databaseEvidence,
            ["parity"] = "exact",
            ["constraints"] = new JsonObject
            {
                ["productionDataWritesAllowed"] = false,
                ["canonicalTargetMutationAllowed"] = false,
                ["cutoverPercent"] = 0,
                ["newNodePoolAllowed"] = false,
                ["cloudSqlAllowed"] = false,
                ["additionalInfrastructureCostAllowed"] = false,
            },
        };

        byte[] payload = AppHostMigrationEvidenceV2Canonicalizer.CreatePayload(root);
        root["attestation"] = new JsonObject
        {
            ["algorithm"] = "ECDSA_P256_SHA256",
            ["keyId"] = evidenceSigner.KeyId,
            ["payloadSha256"] = Sha256(payload),
            ["signatureBase64"] = Convert.ToBase64String(evidenceSigner.Sign(payload)),
        };

        JsonObject baseline = BuildApprovedBaseline(request.SchemaPlan, planSha256, mappingDatabases);
        return new(root.ToJsonString(OutputJson), baseline.ToJsonString(OutputJson));
    }

    private static void Validate(
        AppHostMigrationEvidenceV2Request request,
        IReceiptAttestationTrustStore backupTrust,
        IReceiptAttestationTrustStore authorizationTrust,
        IReceiptAttestationTrustStore executionTrust,
        IReceiptAttestationTrustStore provenanceTrust,
        IMigrationEvidenceSigner evidenceSigner,
        DateTimeOffset nowUtc)
    {
        MigrationExecutionReceipt execution = request.ExecutionResult.Receipt;
        if (request.ExecutionResult.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            execution.RunId == Guid.Empty || request.Configuration.EvidenceId == Guid.Empty || request.Configuration.LeaseId == Guid.Empty ||
            execution.RunId == request.Configuration.EvidenceId || execution.RunId == request.Configuration.LeaseId ||
            request.Configuration.EvidenceId == request.Configuration.LeaseId)
        {
            throw Error("execution_result_invalid", "Completed execution with unique run, evidence, and lease identities is required.");
        }

        VerifyBackup(request.BackupReceipt, backupTrust);
        VerifyAuthorization(request.Authorization, authorizationTrust);
        VerifyExecution(execution, executionTrust);
        VerifyProvenance(request.Provenance, provenanceTrust);
        if (request.VerifiedRestoreReceipt is null ||
            request.VerifiedRestoreReceipt.CleanupDisposition != RestoreCleanupDisposition.Removed ||
            !VerifiedRestoreReceiptAttestation.Verify(request.VerifiedRestoreReceipt, provenanceTrust) ||
            !FixedHashEquals(request.VerifiedRestoreReceipt.BackupManifestSha256, request.BackupReceipt.ManifestSha256) ||
            !ExactNames(request.VerifiedRestoreReceipt.Artifacts.Select(item => item.Database), DatabaseInventory.ActiveDatabases))
        {
            throw Error("verified_restore_receipt_invalid", "Signed evidence requires the completed exact-25 verified restore receipt.");
        }
        ValidateDistinctAttestationRoles(request, backupTrust, authorizationTrust, executionTrust, provenanceTrust, evidenceSigner);

        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(request.SchemaPlan);
        if (!string.Equals(request.SchemaPlan.SchemaVersion, "2.0", StringComparison.Ordinal) ||
            !CommitSha().IsMatch(request.SchemaPlan.SourceCommitSha) ||
            !FixedHashEquals(planSha256, execution.SchemaPlanSha256) ||
            !FixedHashEquals(planSha256, request.Authorization.SchemaPlanSha256) ||
            !FixedHashEquals(request.BackupReceipt.ManifestSha256, execution.BackupManifestSha256) ||
            !FixedHashEquals(request.BackupReceipt.ManifestSha256, request.Authorization.BackupManifestSha256) ||
            !string.Equals(request.SchemaPlan.SourceCommitSha, execution.SourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(request.SchemaPlan.SourceCommitSha, request.Authorization.SourceCommitSha, StringComparison.Ordinal) ||
            execution.RunId != request.Authorization.RunId ||
            !string.Equals(execution.RunnerDigestSha256, request.Authorization.RunnerDigestSha256, StringComparison.Ordinal) ||
            !string.Equals(execution.TargetGeneration, request.Authorization.TargetGeneration, StringComparison.Ordinal))
        {
            throw Error("evidence_binding_invalid", "Execution, receipt, plan, and authorization bindings do not match.");
        }

        MigrationEvidenceProvenanceReceipt provenance = request.Provenance;
        AppHostMigrationEvidenceV2Configuration configuration = request.Configuration;
        if (!string.Equals(provenance.SchemaVersion, "1.0", StringComparison.Ordinal) ||
            !string.Equals(provenance.SourceSnapshotId, configuration.SourceSnapshotId, StringComparison.Ordinal) ||
            !string.Equals(provenance.BackupUri, configuration.BackupUri, StringComparison.Ordinal) ||
            !string.Equals(provenance.BackupObjectGeneration, configuration.BackupObjectGeneration, StringComparison.Ordinal) ||
            !string.Equals(provenance.RestoreId, configuration.RestoreId, StringComparison.Ordinal) ||
            provenance.EvidenceId != configuration.EvidenceId || provenance.LeaseId != configuration.LeaseId ||
            provenance.LeaseAcquiredAtUtc != configuration.LeaseAcquiredAtUtc ||
            provenance.LeaseExpiresAtUtc != configuration.LeaseExpiresAtUtc ||
            provenance.RunId != execution.RunId ||
            !string.Equals(provenance.SourceCommitSha, execution.SourceCommitSha, StringComparison.Ordinal) ||
            !FixedHashEquals(provenance.SchemaPlanSha256, planSha256) ||
            !FixedHashEquals(provenance.BackupManifestSha256, request.BackupReceipt.ManifestSha256) ||
            !FixedHashEquals(provenance.RunnerDigestSha256, execution.RunnerDigestSha256) ||
            !string.Equals(provenance.TargetGeneration, execution.TargetGeneration, StringComparison.Ordinal))
        {
            throw Error("provenance_binding_invalid", "Signed evidence provenance does not match the migration artifacts and configuration.");
        }

        string[] expected = [.. DatabaseInventory.ActiveDatabases];
        if (!ExactNames(request.SchemaPlan.Databases.Select(item => item.Database), expected) ||
            !ExactNames(execution.Databases.Select(item => item.Database), expected) ||
            !ExactNames(execution.Reconciliation.Select(item => item.Database), expected))
        {
            throw Error("database_inventory_invalid", "Evidence must cover the exact 25 migrated databases.");
        }

        if (request.BackupReceipt.CapturedAtUtc > execution.CompletedAtUtc ||
            request.Authorization.IssuedAtUtc > execution.CompletedAtUtc ||
            request.Authorization.ExpiresAtUtc <= nowUtc ||
            request.Authorization.ExpiresAtUtc - request.Authorization.IssuedAtUtc > TimeSpan.FromHours(1) ||
            request.Configuration.LeaseAcquiredAtUtc < request.Authorization.IssuedAtUtc ||
            request.Configuration.LeaseAcquiredAtUtc > execution.CompletedAtUtc ||
            request.Configuration.LeaseExpiresAtUtc < execution.CompletedAtUtc ||
            request.Configuration.LeaseExpiresAtUtc > request.Authorization.ExpiresAtUtc ||
            request.Configuration.LeaseExpiresAtUtc <= nowUtc)
        {
            throw Error("evidence_window_invalid", "Evidence timing is outside the signed one-hour shadow authorization window.");
        }


        if (provenance.IssuedAtUtc < request.Authorization.IssuedAtUtc ||
            provenance.IssuedAtUtc > execution.CompletedAtUtc ||
            !BackupArtifactsMatchSignedProvenance(request.BackupReceipt, provenance.BackupUri))
        {
            throw Error("provenance_binding_invalid", "Signed evidence provenance is outside the execution window or backup receipt scope.");
        }

        if (!SafeIdentifier().IsMatch(request.Configuration.SourceSnapshotId) ||
            !SafeIdentifier().IsMatch(request.Configuration.BackupObjectGeneration) ||
            !SafeIdentifier().IsMatch(request.Configuration.RestoreId) ||
            !BackupUri().IsMatch(request.Configuration.BackupUri))
        {
            throw Error("evidence_provenance_invalid", "Evidence provenance identifiers or backup URI are invalid.");
        }

        foreach (DatabaseSchemaPlan databasePlan in request.SchemaPlan.Databases)
        {
            DatabaseReconciliationEvidence database = execution.Reconciliation.Single(item => item.Database == databasePlan.Database);
            MigratedShadowDatabase migrated = execution.Databases.Single(item => item.Database == databasePlan.Database);
            if (!FixedHashEquals(database.SourceSchemaSha256, databasePlan.SourceSchemaSha256) ||
                !FixedHashEquals(database.TargetSchemaSha256, databasePlan.TargetSchemaSha256) ||
                database.Tables.Sum(item => item.RowCount) != migrated.TotalRows ||
                !Sha256Value().IsMatch(migrated.ContentSha256) ||
                !FixedHashEquals(migrated.ContentSha256, DatabaseContentHash(database.Tables)) ||
                !ExactNames(database.Tables.Select(item => item.Table), databasePlan.Tables.Select(TableName)))
            {
                throw Error("database_evidence_invalid", $"{databasePlan.Database} evidence does not match its signed plan and result.");
            }

            foreach (TableCopyPlan tablePlan in databasePlan.Tables)
            {
                TableReconciliationEvidence table = database.Tables.Single(item => item.Table == TableName(tablePlan));
                if (!Sha256Value().IsMatch(table.ContentSha256) || table.RowCount < 0 ||
                    !ExactNames(table.NullCounts.Keys, tablePlan.OrderedColumns) ||
                    table.NullCounts.Values.Any(value => value < 0 || value > table.RowCount) ||
                    !ExactNames(table.ForeignKeyOrphanCounts.Keys, tablePlan.ForeignKeys.Select(item => item.Name)) ||
                    table.ForeignKeyOrphanCounts.Values.Any(value => value != 0))
                {
                    throw Error("table_evidence_invalid", $"{databasePlan.Database}.{TableName(tablePlan)} evidence is incomplete.");
                }

                if (!ExactNames(table.ForeignKeyRelationshipCounts.Keys, tablePlan.ForeignKeys.Select(item => item.Name)) ||
                    table.ForeignKeyRelationshipCounts.Values.Any(value => value < 0 || value > table.RowCount))
                {
                    throw Error("relationship_evidence_missing", $"{databasePlan.Database}.{TableName(tablePlan)} relationship evidence is incomplete.");
                }
            }

            string[] sequences = [.. databasePlan.Tables.SelectMany(table => table.Identities.Select(identity => SequenceName(table, identity)))];
            if (!ExactNames(database.SequenceNextValues.Keys, sequences))
            {
                throw Error("sequence_evidence_missing", $"{databasePlan.Database} sequence evidence is incomplete.");
            }
        }
    }

    private static JsonArray BuildMapping(FreshSchemaPlan plan)
    {
        return [.. plan.Databases
        .OrderBy(database => database.Database, StringComparer.Ordinal)
        .Select(database =>
        {
            string[] tableNames = [.. database.Tables.Select(TableName).Order(StringComparer.Ordinal)];
            string[] foreignKeys = [.. database.Tables.SelectMany(table => table.ForeignKeys.Select(foreignKey => ForeignKeyName(table, foreignKey))).Order(StringComparer.Ordinal)];
            string[] sequences = [.. database.Tables.SelectMany(table => table.Identities.Select(identity => SequenceName(table, identity))).Order(StringComparer.Ordinal)];
            return (JsonNode)new JsonObject
            {
                ["name"] = database.Database,
                ["tableInventorySha256"] = InventoryHash(tableNames),
                ["foreignKeyInventorySha256"] = InventoryHash(foreignKeys),
                ["sequenceInventorySha256"] = InventoryHash(sequences),
                ["expectedTableCount"] = tableNames.Length,
                ["expectedForeignKeyCount"] = foreignKeys.Length,
                ["expectedSequenceCount"] = sequences.Length,
                ["tables"] = new JsonArray(database.Tables.OrderBy(TableName, StringComparer.Ordinal).Select(table => (JsonNode)new JsonObject
                {
                    ["name"] = TableName(table),
                    ["columns"] = Strings(table.OrderedColumns),
                    ["approvedAggregates"] = new JsonArray(),
                    ["expectedColumnCount"] = table.OrderedColumns.Count,
                    ["expectedAggregateCount"] = 0,
                    ["expectedBatchCount"] = 1,
                    ["batchInventorySha256"] = InventoryHash(["0"]),
                }).ToArray()),
                ["foreignKeys"] = Strings(foreignKeys),
                ["sequences"] = Strings(sequences),
            };
        }).ToArray()];
    }

    private static JsonArray BuildDatabaseEvidence(AppHostMigrationEvidenceV2Request request, string planSha256)
    {
        return [.. request.SchemaPlan.Databases.OrderBy(database => database.Database, StringComparer.Ordinal).Select(databasePlan =>
        {
            DatabaseReconciliationEvidence database = request.ExecutionResult.Receipt.Reconciliation.Single(item => item.Database == databasePlan.Database);
            MigratedShadowDatabase migrated = request.ExecutionResult.Receipt.Databases.Single(item => item.Database == databasePlan.Database);
            string[] tableNames = [.. databasePlan.Tables.Select(TableName).Order(StringComparer.Ordinal)];
            string[] foreignKeys = [.. databasePlan.Tables.SelectMany(table => table.ForeignKeys.Select(foreignKey => ForeignKeyName(table, foreignKey))).Order(StringComparer.Ordinal)];
            string[] sequences = [.. databasePlan.Tables.SelectMany(table => table.Identities.Select(identity => SequenceName(table, identity))).Order(StringComparer.Ordinal)];
            return (JsonNode)new JsonObject
            {
                ["name"] = databasePlan.Database,
                ["sourceSchemaSha256"] = database.SourceSchemaSha256.ToLowerInvariant(),
                ["mappingPlanSha256"] = planSha256,
                ["targetSchemaSha256"] = database.TargetSchemaSha256.ToLowerInvariant(),
                ["sourceRowCount"] = migrated.TotalRows,
                ["targetRowCount"] = migrated.TotalRows,
                ["sourceContentSha256"] = migrated.ContentSha256.ToLowerInvariant(),
                ["targetContentSha256"] = migrated.ContentSha256.ToLowerInvariant(),
                ["tableInventorySha256"] = InventoryHash(tableNames),
                ["foreignKeyInventorySha256"] = InventoryHash(foreignKeys),
                ["sequenceInventorySha256"] = InventoryHash(sequences),
                ["tableCount"] = tableNames.Length,
                ["foreignKeyCount"] = foreignKeys.Length,
                ["sequenceCount"] = sequences.Length,
                ["tables"] = new JsonArray(databasePlan.Tables.OrderBy(TableName, StringComparer.Ordinal).Select(tablePlan =>
                {
                    TableReconciliationEvidence table = database.Tables.Single(item => item.Table == TableName(tablePlan));
                    return (JsonNode)new JsonObject
                    {
                        ["name"] = TableName(tablePlan),
                        ["sourceRowCount"] = table.RowCount,
                        ["targetRowCount"] = table.RowCount,
                        ["columnCount"] = tablePlan.OrderedColumns.Count,
                        ["aggregateCount"] = 0,
                        ["batchCount"] = 1,
                        ["columns"] = new JsonArray(tablePlan.OrderedColumns.Select(column => (JsonNode)new JsonObject
                        {
                            ["name"] = column,
                            ["sourceNullCount"] = table.NullCounts[column],
                            ["targetNullCount"] = table.NullCounts[column],
                        }).ToArray()),
                        ["aggregates"] = new JsonArray(),
                        ["batchInventorySha256"] = InventoryHash(["0"]),
                        ["batches"] = new JsonArray(new JsonObject
                        {
                            ["ordinal"] = 0,
                            ["sourceRowCount"] = table.RowCount,
                            ["targetRowCount"] = table.RowCount,
                            ["sourceContentSha256"] = table.ContentSha256.ToLowerInvariant(),
                            ["targetContentSha256"] = table.ContentSha256.ToLowerInvariant(),
                        }),
                        ["parity"] = "exact",
                    };
                }).ToArray()),
                ["foreignKeys"] = new JsonArray(databasePlan.Tables.SelectMany(tablePlan =>
                {
                    TableReconciliationEvidence table = database.Tables.Single(item => item.Table == TableName(tablePlan));
                    return tablePlan.ForeignKeys.Select(foreignKey => (JsonNode)new JsonObject
                    {
                        ["name"] = ForeignKeyName(tablePlan, foreignKey),
                        ["sourceRelationshipCount"] = table.ForeignKeyRelationshipCounts[foreignKey.Name],
                        ["targetRelationshipCount"] = table.ForeignKeyRelationshipCounts[foreignKey.Name],
                        ["orphanCount"] = table.ForeignKeyOrphanCounts[foreignKey.Name],
                    });
                }).OrderBy(node => node!["name"]!.GetValue<string>(), StringComparer.Ordinal).ToArray()),
                ["sequences"] = new JsonArray(database.SequenceNextValues.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item => (JsonNode)new JsonObject
                {
                    ["name"] = item.Key,
                    ["sourceNextValue"] = item.Value,
                    ["targetNextValue"] = item.Value,
                }).ToArray()),
                ["parity"] = "exact",
            };
        }).ToArray()];
    }

    private static JsonObject BuildApprovedBaseline(FreshSchemaPlan plan, string planSha256, JsonArray mappingDatabases)
    {
        return new()
        {
            ["schemaVersion"] = 2,
            ["sourceCommitSha"] = plan.SourceCommitSha,
            ["planSha256"] = planSha256,
            ["databases"] = new JsonArray(mappingDatabases.Select(databaseNode =>
            {
                JsonObject database = (JsonObject)databaseNode!;
                JsonArray tables = (JsonArray)database["tables"]!;
                return (JsonNode)new JsonObject
                {
                    ["name"] = database["name"]!.DeepClone(),
                    ["tableInventorySha256"] = database["tableInventorySha256"]!.DeepClone(),
                    ["foreignKeyInventorySha256"] = database["foreignKeyInventorySha256"]!.DeepClone(),
                    ["sequenceInventorySha256"] = database["sequenceInventorySha256"]!.DeepClone(),
                    ["tables"] = new JsonArray(tables.Select(tableNode =>
                    {
                        JsonObject table = (JsonObject)tableNode!;
                        return (JsonNode)new JsonObject
                        {
                            ["name"] = table["name"]!.DeepClone(),
                            ["columns"] = table["columns"]!.DeepClone(),
                            ["approvedAggregates"] = table["approvedAggregates"]!.DeepClone(),
                            ["expectedBatchCount"] = table["expectedBatchCount"]!.DeepClone(),
                            ["batchInventorySha256"] = table["batchInventorySha256"]!.DeepClone(),
                            ["tablePlanSha256"] = TablePlanHash(table),
                        };
                    }).ToArray()),
                    ["foreignKeys"] = database["foreignKeys"]!.DeepClone(),
                    ["sequences"] = database["sequences"]!.DeepClone(),
                };
            }).ToArray()),
        };
    }

    private static JsonArray BuildInventory()
    {
        return [.. DatabaseInventory.Entries.OrderBy(item => item.Key, StringComparer.Ordinal).Select(item => (JsonNode)new JsonObject
        {
            ["name"] = item.Key,
            ["owner"] = item.Value.Owner,
            ["disposition"] = item.Value.Disposition == DatabaseDisposition.Migrate ? "migrate" : "excluded",
        }).ToArray()];
    }

    private static JsonObject BuildVerifiedRestoreEvidence(VerifiedRestoreReceipt receipt)
    {
        return new()
        {
            ["schemaVersion"] = receipt.SchemaVersion,
            ["restoredAtUtc"] = Utc(receipt.RestoredAtUtc),
            ["cleanedAtUtc"] = Utc(receipt.CleanedAtUtc!.Value),
            ["cleanupDisposition"] = "removed",
            ["backupManifestSha256"] = receipt.BackupManifestSha256,
            ["databaseInventorySha256"] = receipt.DatabaseInventorySha256,
            ["resources"] = new JsonObject
            {
                ["sqlServerImage"] = receipt.Resources.SqlServerImage,
                ["sqlServerImageId"] = receipt.Resources.SqlServerImageId,
                ["containerId"] = receipt.Resources.ContainerId,
                ["containerName"] = receipt.Resources.ContainerName,
                ["runBinding"] = receipt.Resources.RunBinding,
                ["volumeId"] = receipt.Resources.VolumeId,
                ["volumeName"] = receipt.Resources.VolumeName,
                ["mountPath"] = receipt.Resources.MountPath,
                ["mountReadOnly"] = receipt.Resources.MountReadOnly,
                ["stagingImage"] = receipt.Resources.StagingImage,
            },
            ["artifacts"] = new JsonArray(receipt.Artifacts.OrderBy(item => item.Database, StringComparer.Ordinal)
                .Select(item => (JsonNode)new JsonObject
                {
                    ["database"] = item.Database,
                    ["retainedByteLength"] = item.RetainedByteLength,
                    ["retainedSha256"] = item.RetainedSha256,
                    ["stagedByteLength"] = item.StagedByteLength,
                    ["stagedSha256"] = item.StagedSha256,
                    ["verifyOnlyWithChecksum"] = item.VerifyOnlyWithChecksum,
                    ["snapshotIsolationEnabled"] = item.SnapshotIsolationEnabled,
                    ["readOnly"] = item.ReadOnly,
                }).ToArray()),
            ["attestationKeyId"] = receipt.AttestationKeyId,
            ["attestationSignature"] = receipt.AttestationSignature,
        };
    }

    private static void VerifyBackup(BackupReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        if (!string.Equals(receipt.SchemaVersion, PreflightService.ReceiptSchemaVersion, StringComparison.Ordinal) ||
            !ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload) ||
            !Verify(receipt.AttestationKeyId, receipt.AttestationSignature, payload, trust) ||
            !FixedHashEquals(receipt.DatabaseInventorySha256, DatabaseInventory.InventorySha256) ||
            receipt.Artifacts is null || !ExactNames(receipt.Artifacts.Where(item => item is not null).Select(item => item!.Database!), DatabaseInventory.ActiveDatabases))
        {
            throw Error("backup_receipt_invalid", "The signed backup receipt is invalid or incomplete.");
        }
    }

    private static void VerifyAuthorization(ExecutionAuthorizationReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        if (!ExecutionAuthorizationAttestation.TryCreatePayload(receipt, out byte[] payload) ||
            !Verify(receipt.AttestationKeyId, receipt.AttestationSignature, payload, trust))
        {
            throw Error("authorization_receipt_invalid", "The signed execution authorization is invalid.");
        }
    }

    private static void VerifyExecution(MigrationExecutionReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        if (!Verify(receipt.AttestationKeyId, receipt.AttestationSignature, MigrationEvidenceAttestation.CreatePayload(receipt), trust))
        {
            throw Error("execution_receipt_invalid", "The signed migration execution receipt is invalid.");
        }
    }

    private static void VerifyProvenance(MigrationEvidenceProvenanceReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        if (!MigrationEvidenceProvenanceAttestation.TryCreatePayload(receipt, out byte[] payload) ||
            !Verify(receipt.AttestationKeyId, receipt.AttestationSignature, payload, trust))
        {
            throw Error("provenance_receipt_invalid", "The signed migration evidence provenance receipt is invalid.");
        }
    }

    private static void ValidateDistinctAttestationRoles(
        AppHostMigrationEvidenceV2Request request,
        IReceiptAttestationTrustStore backupTrust,
        IReceiptAttestationTrustStore authorizationTrust,
        IReceiptAttestationTrustStore executionTrust,
        IReceiptAttestationTrustStore provenanceTrust,
        IMigrationEvidenceSigner evidenceSigner)
    {
        var roles = new (string? KeyId, IReceiptAttestationTrustStore Trust)[]
        {
            (request.BackupReceipt.AttestationKeyId, backupTrust),
            (request.Authorization.AttestationKeyId, authorizationTrust),
            (request.ExecutionResult.Receipt.AttestationKeyId, executionTrust),
            (request.Provenance.AttestationKeyId, provenanceTrust),
        };
        List<string> fingerprints = [evidenceSigner.PublicKeyFingerprintSha256];
        foreach ((string? keyId, IReceiptAttestationTrustStore trust) in roles)
        {
            if (keyId is null || !trust.TryGetPublicKeyFingerprintSha256(keyId, out string fingerprint))
            {
                throw Error("attestation_key_fingerprint_missing", "An attestation role does not expose its trusted public-key fingerprint.");
            }

            fingerprints.Add(fingerprint);
        }

        if (fingerprints.Any(fingerprint => !Sha256Value().IsMatch(fingerprint)) ||
            fingerprints.Distinct(StringComparer.OrdinalIgnoreCase).Count() != fingerprints.Count)
        {
            throw Error("attestation_key_role_reuse", "Backup, authorization, execution, provenance, and evidence roles require distinct P-256 keys.");
        }
    }

    private static bool BackupArtifactsMatchSignedProvenance(BackupReceipt receipt, string backupUri)
    {
        Match match = BackupUriParts().Match(backupUri);
        if (!match.Success || receipt.Artifacts is null)
        {
            return false;
        }

        string prefix = match.Groups["prefix"].Value;
        return receipt.Artifacts.All(artifact => artifact is not null && artifact.GcsGeneration > 0 &&
            !string.IsNullOrWhiteSpace(artifact.GcsObject) && artifact.GcsObject.StartsWith(prefix, StringComparison.Ordinal));
    }

    private static bool Verify(string? keyId, string? signatureBase64, byte[] payload, IReceiptAttestationTrustStore trust)
    {
        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(signatureBase64) || !trust.ContainsKey(keyId))
        {
            return false;
        }

        try { return trust.Verify(keyId, payload, Convert.FromBase64String(signatureBase64)); }
        catch (FormatException) { return false; }
    }

    private static bool ExactNames(IEnumerable<string> actual, IEnumerable<string> expected)
    {
        return actual.Order(StringComparer.Ordinal).SequenceEqual(expected.Order(StringComparer.Ordinal), StringComparer.Ordinal) &&
        actual.Distinct(StringComparer.Ordinal).Count() == actual.Count();
    }

    private static bool FixedHashEquals(string? left, string? right)
    {
        return left is not null && right is not null &&
        Sha256Value().IsMatch(left) && Sha256Value().IsMatch(right) && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static string InventoryHash(IEnumerable<string> names)
    {
        return Sha256(Encoding.UTF8.GetBytes(string.Join('\n', names.Order(StringComparer.Ordinal))));
    }

    private static string DatabaseContentHash(IEnumerable<TableReconciliationEvidence> tables)
    {
        string canonical = string.Join('\n', tables.OrderBy(item => item.Table, StringComparer.Ordinal)
            .Select(item => $"{item.Table}|{item.RowCount}|{item.ContentSha256}|{item.AggregateSha256}"));
        return Sha256(Encoding.UTF8.GetBytes(canonical));
    }

    private static string TablePlanHash(JsonObject table)
    {
        string name = table["name"]!.GetValue<string>();
        string[] columns = ((JsonArray)table["columns"]!).Select(item => item!.GetValue<string>()).ToArray();
        string[] aggregates = ((JsonArray)table["approvedAggregates"]!).Select(item => item!.GetValue<string>()).ToArray();
        string canonical = string.Join('\n',
            $"name={name}",
            $"columnsSha256={InventoryHash(columns)}",
            $"approvedAggregatesSha256={InventoryHash(aggregates)}",
            $"expectedBatchCount={table["expectedBatchCount"]!.GetValue<int>()}",
            $"batchInventorySha256={table["batchInventorySha256"]!.GetValue<string>()}");
        return Sha256(Encoding.UTF8.GetBytes(canonical));
    }

    private static JsonArray Strings(IEnumerable<string> values)
    {
        return [.. values.Select(value => (JsonNode)JsonValue.Create(value)).ToArray()];
    }

    private static string TableName(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }

    private static string ForeignKeyName(TableCopyPlan table, ForeignKeyCopyPlan foreignKey)
    {
        return $"{TableName(table)}.{foreignKey.Name}";
    }

    private static string SequenceName(TableCopyPlan table, IdentityCopyPlan identity)
    {
        return $"{TableName(table)}.{identity.Column}";
    }

    private static string Utc(DateTimeOffset value)
    {
        return value.ToUniversalTime().ToString("O", System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string Sha256(ReadOnlySpan<byte> value)
    {
        return Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    }

    private static MigrationEvidenceProductionException Error(string code, string message)
    {
        return new(code, message);
    }

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)] private static partial Regex CommitSha();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256Value();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex SafeIdentifier();
    [GeneratedRegex("^gs://[A-Za-z0-9._-]+(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)*$", RegexOptions.CultureInvariant)] private static partial Regex BackupUri();
    [GeneratedRegex("^gs://(?<bucket>[A-Za-z0-9._-]+)/(?<prefix>[A-Za-z0-9._~!$&'()*+,;=:@%/-]*/)$", RegexOptions.CultureInvariant)] private static partial Regex BackupUriParts();
}

public static class AppHostMigrationEvidenceV2Canonicalizer
{
    private static readonly JsonSerializerOptions CanonicalJson = new()
    {
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        WriteIndented = false,
    };

    public static byte[] CreatePayload(JsonElement root)
    {
        JsonNode node = JsonNode.Parse(root.GetRawText()) ?? throw new JsonException("Migration evidence is empty.");
        return CreatePayload(node);
    }

    internal static byte[] CreatePayload(JsonNode root)
    {
        JsonNode copy = root.DeepClone();
        if (copy is JsonObject objectRoot)
        {
            _ = objectRoot.Remove("attestation");
        }

        return Encoding.UTF8.GetBytes(Sort(copy).ToJsonString(CanonicalJson));
    }

    private static JsonNode Sort(JsonNode node)
    {
        return node switch
        {
            JsonObject value => new JsonObject(value.OrderBy(item => item.Key, StringComparer.Ordinal)
                .Select(item => KeyValuePair.Create(item.Key, item.Value is null ? null : Sort(item.Value))).ToArray()),
            JsonArray value => new JsonArray(value.Select(item => item is null ? null : Sort(item)).ToArray()),
            _ => node.DeepClone(),
        };
    }
}
