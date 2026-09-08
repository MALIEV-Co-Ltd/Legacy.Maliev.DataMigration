using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public static class DeltaTargetAuthorityKind
{
    public const string ProductionCloudNativePg = "production-cloudnativepg";
    public const string LocalAspire = "local-aspire";
}

public sealed record DeltaTargetAuthority(string Kind, string AuthorityId, string SystemIdentifierSha256);

public sealed record DeltaTablePlan(
    string Table,
    long InsertCount,
    long UpdateCount,
    long DeleteCount,
    long UnchangedCount,
    string OperationsSha256,
    IReadOnlyList<CanonicalDeltaOperation> Operations);

public sealed record DeltaDatabasePlan(string Database, IReadOnlyList<DeltaTablePlan> Tables);

public sealed record DeltaPlanSigningRequest(
    string SourceCommitSha,
    DateTimeOffset SourceCutoffUtc,
    string BackupManifestSha256,
    string SchemaPlanSha256,
    string RunnerDigestSha256,
    string TargetNamespace,
    string TargetCluster,
    string TargetGeneration,
    string TargetObservationSha256,
    string BackupKeyFingerprintSha256,
    string ExecutionAuthorizationKeyFingerprintSha256,
    IReadOnlyList<DeltaDatabasePlan> Databases)
{
    public DeltaTargetAuthority? TargetAuthority { get; init; }
}

public sealed record DeltaSynchronizationPlan(
    string SchemaVersion,
    Guid PlanId,
    string SourceCommitSha,
    DateTimeOffset SourceCutoffUtc,
    string BackupManifestSha256,
    string SchemaPlanSha256,
    string RunnerDigestSha256,
    string TargetNamespace,
    string TargetCluster,
    string TargetGeneration,
    string TargetObservationSha256,
    string BackupKeyFingerprintSha256,
    string ExecutionAuthorizationKeyFingerprintSha256,
    DateTimeOffset CreatedAtUtc,
    IReadOnlyList<DeltaDatabasePlan> Databases,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public DeltaTargetAuthority? TargetAuthority { get; init; }
}

public sealed class DeltaPlanException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public static class DeltaSynchronizationPlanCanonicalizer
{
    private static ReadOnlySpan<byte> Domain => "legacy-maliev-exact23-delta-plan-v1.1\0"u8;

    public static byte[] CreatePayload(DeltaSynchronizationPlan plan)
    {
        ArgumentNullException.ThrowIfNull(plan);
        JsonElement element = JsonSerializer.SerializeToElement(plan with { AttestationSignature = null });
        using var stream = new MemoryStream();
        stream.Write(Domain);
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(writer, element);
        }

        return stream.ToArray();
    }

    public static string ComputeSha256(DeltaSynchronizationPlan plan)
    {
        return Convert.ToHexString(SHA256.HashData(CreatePayload(plan))).ToLowerInvariant();
    }

    public static string ComputeOperationsSha256(IReadOnlyList<CanonicalDeltaOperation> operations)
    {
        ArgumentNullException.ThrowIfNull(operations);
        JsonElement element = JsonSerializer.SerializeToElement(operations);
        using var stream = new MemoryStream();
        stream.Write("legacy-maliev-exact23-delta-operations-v1\0"u8);
        using (var writer = new Utf8JsonWriter(stream))
        {
            WriteCanonical(writer, element);
        }

        return Convert.ToHexString(SHA256.HashData(stream.ToArray())).ToLowerInvariant();
    }

    private static void WriteCanonical(Utf8JsonWriter writer, JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            writer.WriteStartObject();
            foreach (JsonProperty property in element.EnumerateObject().OrderBy(item => item.Name, StringComparer.Ordinal))
            {
                writer.WritePropertyName(property.Name);
                WriteCanonical(writer, property.Value);
            }
            writer.WriteEndObject();
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            writer.WriteStartArray();
            foreach (JsonElement item in element.EnumerateArray())
            {
                WriteCanonical(writer, item);
            }
            writer.WriteEndArray();
        }
        else
        {
            element.WriteTo(writer);
        }
    }
}

public static partial class DeltaSynchronizationPlanProducer
{
    public static DeltaSynchronizationPlan Produce(
        DeltaPlanSigningRequest request,
        P256MigrationEvidenceSigner signer,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(signer);
        ValidateRequest(request, signer, nowUtc);
        var unsigned = new DeltaSynchronizationPlan(
            "1.1",
            Guid.NewGuid(),
            request.SourceCommitSha,
            request.SourceCutoffUtc,
            request.BackupManifestSha256.ToLowerInvariant(),
            request.SchemaPlanSha256.ToLowerInvariant(),
            request.RunnerDigestSha256.ToLowerInvariant(),
            request.TargetNamespace,
            request.TargetCluster,
            request.TargetGeneration,
            request.TargetObservationSha256.ToLowerInvariant(),
            request.BackupKeyFingerprintSha256.ToLowerInvariant(),
            request.ExecutionAuthorizationKeyFingerprintSha256.ToLowerInvariant(),
            nowUtc,
            request.Databases,
            signer.KeyId,
            null)
        {
            TargetAuthority = request.TargetAuthority,
        };
        return unsigned with
        {
            AttestationSignature = Convert.ToBase64String(signer.Sign(
                DeltaSynchronizationPlanCanonicalizer.CreatePayload(unsigned))),
        };
    }

    private static void ValidateRequest(
        DeltaPlanSigningRequest request,
        P256MigrationEvidenceSigner signer,
        DateTimeOffset nowUtc)
    {
        if (nowUtc.Offset != TimeSpan.Zero || request.SourceCutoffUtc.Offset != TimeSpan.Zero ||
            request.SourceCutoffUtc > nowUtc || nowUtc - request.SourceCutoffUtc > GuardedRunnerPolicy.MaximumBackupReceiptAge)
        {
            throw Error("delta_plan_source_cutoff_invalid", "The source cutoff must be current, bounded, and expressed in UTC.");
        }

        if (!CommitSha().IsMatch(request.SourceCommitSha) ||
            !Hashes(request.BackupManifestSha256, request.SchemaPlanSha256, request.RunnerDigestSha256,
                request.TargetObservationSha256, request.BackupKeyFingerprintSha256,
                request.ExecutionAuthorizationKeyFingerprintSha256))
        {
            throw Error("delta_plan_binding_invalid", "A required immutable plan binding is invalid.");
        }

        if (string.IsNullOrWhiteSpace(request.TargetGeneration) ||
            !ValidAuthority(request.TargetAuthority, request.TargetNamespace, request.TargetCluster))
        {
            throw Error("delta_plan_target_invalid", "The reviewed target identity or generation is invalid.");
        }

        if (FixedHashEquals(signer.PublicKeyFingerprintSha256, request.BackupKeyFingerprintSha256) ||
            FixedHashEquals(signer.PublicKeyFingerprintSha256, request.ExecutionAuthorizationKeyFingerprintSha256))
        {
            throw Error("delta_plan_signing_role_reused", "Backup, delta-plan, and execution-authorization roles require distinct keys.");
        }

        ValidateDatabases(request.Databases);
    }

    internal static bool ValidAuthority(
        DeltaTargetAuthority? authority,
        string targetNamespace,
        string targetCluster)
    {
        return authority is not null && Sha256().IsMatch(authority.SystemIdentifierSha256) &&
            !string.IsNullOrWhiteSpace(authority.AuthorityId) && authority.AuthorityId.Length <= 512 && authority.Kind switch
            {
                DeltaTargetAuthorityKind.ProductionCloudNativePg =>
                    targetNamespace == "maliev-legacy" && targetCluster == "legacy-postgres-main" &&
                    authority.AuthorityId.StartsWith("gke://maliev-website/", StringComparison.Ordinal),
                DeltaTargetAuthorityKind.LocalAspire =>
                    targetNamespace == "local-aspire" && targetCluster == "legacy-postgres-main-local" &&
                    authority.AuthorityId.StartsWith("aspire://legacy-postgres-main-local/", StringComparison.Ordinal),
                _ => false,
            };
    }

    internal static void ValidateDatabases(IReadOnlyList<DeltaDatabasePlan> databases)
    {
        if (!databases.Select(database => database.Database)
            .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            throw Error("delta_plan_inventory_invalid", "The delta plan must contain the exact ordered active database inventory.");
        }

        foreach (DeltaDatabasePlan database in databases)
        {
            if (database.Tables.Count == 0 ||
                database.Tables.Select(table => table.Table).Distinct(StringComparer.Ordinal).Count() != database.Tables.Count)
            {
                throw Error("delta_plan_table_inventory_invalid", "Each database requires a unique non-empty table inventory.");
            }

            foreach (DeltaTablePlan table in database.Tables)
            {
                if (string.IsNullOrWhiteSpace(table.Table) ||
                    table.InsertCount < 0 || table.UpdateCount < 0 || table.DeleteCount < 0 || table.UnchangedCount < 0 ||
                    !Sha256().IsMatch(table.OperationsSha256) ||
                    table.InsertCount != table.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Insert) ||
                    table.UpdateCount != table.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Update) ||
                    table.DeleteCount != table.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Delete) ||
                    !FixedHashEquals(table.OperationsSha256,
                        DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(table.Operations)) ||
                    table.Operations.Any(InvalidOperation))
                {
                    throw Error("delta_plan_table_invalid", "A table delta contains invalid counts, hashes, or operation evidence.");
                }
            }
        }
    }

    private static bool InvalidOperation(CanonicalDeltaOperation operation)
    {
        return !Sha256().IsMatch(operation.KeySha256) || operation.Kind switch
        {
            DeltaOperationKind.Insert => !Sha256().IsMatch(operation.SourceRowSha256 ?? string.Empty) || operation.TargetRowSha256 is not null,
            DeltaOperationKind.Update => !Sha256().IsMatch(operation.SourceRowSha256 ?? string.Empty) || !Sha256().IsMatch(operation.TargetRowSha256 ?? string.Empty),
            DeltaOperationKind.Delete => operation.SourceRowSha256 is not null || !Sha256().IsMatch(operation.TargetRowSha256 ?? string.Empty),
            _ => true,
        };
    }

    private static bool Hashes(params string[] values)
    {
        return values.All(value => Sha256().IsMatch(value));
    }

    internal static bool FixedHashEquals(string left, string right)
    {
        return Sha256().IsMatch(left) && Sha256().IsMatch(right) && CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
            System.Text.Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static DeltaPlanException Error(string code, string message)
    {
        return new(code, message);
    }

    [GeneratedRegex("^[0-9a-f]{40}$", RegexOptions.CultureInvariant)]
    private static partial Regex CommitSha();

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();
}

public static class DeltaSynchronizationPlanVerifier
{
    public static bool Verify(
        DeltaSynchronizationPlan plan,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(trust);
        try
        {
            if (!string.Equals(plan.SchemaVersion, "1.1", StringComparison.Ordinal) ||
                plan.PlanId == Guid.Empty || nowUtc.Offset != TimeSpan.Zero || plan.CreatedAtUtc.Offset != TimeSpan.Zero ||
                plan.CreatedAtUtc > nowUtc || plan.SourceCutoffUtc > plan.CreatedAtUtc ||
                nowUtc - plan.SourceCutoffUtc > GuardedRunnerPolicy.MaximumBackupReceiptAge ||
                plan.SourceCommitSha.Length != 40 || plan.SourceCommitSha.Any(character => !char.IsAsciiHexDigit(character) || char.IsUpper(character)) ||
                !Hashes(plan.BackupManifestSha256, plan.SchemaPlanSha256, plan.RunnerDigestSha256,
                    plan.TargetObservationSha256, plan.BackupKeyFingerprintSha256,
                    plan.ExecutionAuthorizationKeyFingerprintSha256) ||
                !DeltaSynchronizationPlanProducer.ValidAuthority(plan.TargetAuthority, plan.TargetNamespace, plan.TargetCluster) ||
                string.IsNullOrWhiteSpace(plan.TargetGeneration) ||
                string.IsNullOrWhiteSpace(plan.AttestationKeyId) || string.IsNullOrWhiteSpace(plan.AttestationSignature))
            {
                return false;
            }

            DeltaSynchronizationPlanProducer.ValidateDatabases(plan.Databases);
            if (!trust.TryGetPublicKeyFingerprintSha256(plan.AttestationKeyId, out string planKeyFingerprint) ||
                DeltaSynchronizationPlanProducer.FixedHashEquals(planKeyFingerprint, plan.BackupKeyFingerprintSha256) ||
                DeltaSynchronizationPlanProducer.FixedHashEquals(planKeyFingerprint, plan.ExecutionAuthorizationKeyFingerprintSha256))
            {
                return false;
            }

            byte[] signature = Convert.FromBase64String(plan.AttestationSignature);
            return trust.Verify(
                plan.AttestationKeyId,
                DeltaSynchronizationPlanCanonicalizer.CreatePayload(plan),
                signature);
        }
        catch (Exception exception) when (exception is DeltaPlanException or FormatException or CryptographicException)
        {
            return false;
        }
    }

    private static bool Hashes(params string[] values)
    {
        return values.All(value => value.Length == 64 && value.All(char.IsAsciiHexDigit));
    }
}
