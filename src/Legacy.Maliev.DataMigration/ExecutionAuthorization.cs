using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record ExecutionAuthorizationReceipt(
    string? SchemaVersion,
    Guid RunId,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    string? SourceCommitSha,
    string? SchemaPlanSha256,
    string? BackupManifestSha256,
    string? RunnerDigestSha256,
    string? TargetGeneration,
    IReadOnlyList<string>? AuthorizedDatabases,
    string? Mode,
    string? AttestationKeyId,
    string? AttestationSignature)
{
    public CloudNativePgTargetObservation? TargetObservation { get; init; }
}

public static class ExecutionAuthorizationAttestation
{
    private const string DomainSeparator = "Legacy.Maliev.DataMigration.ExecutionAuthorization.v2";

    public static bool TryCreatePayload(ExecutionAuthorizationReceipt receipt, out byte[] payload)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        payload = [];
        if (receipt.SchemaVersion is null ||
            receipt.RunId == Guid.Empty ||
            receipt.SourceCommitSha is null ||
            receipt.SchemaPlanSha256 is null ||
            receipt.BackupManifestSha256 is null ||
            receipt.RunnerDigestSha256 is null ||
            receipt.TargetGeneration is null ||
            receipt.AuthorizedDatabases is null ||
            receipt.Mode is null ||
            receipt.AttestationKeyId is null ||
            (string.Equals(receipt.SchemaVersion, "2.1", StringComparison.Ordinal) && receipt.TargetObservation is null))
        {
            return false;
        }

        using MemoryStream stream = new();
        using (BinaryWriter writer = new(stream, new UTF8Encoding(false), leaveOpen: true))
        {
            WriteString(writer, DomainSeparator);
            WriteString(writer, receipt.SchemaVersion);
            WriteString(writer, receipt.RunId.ToString("D"));
            WriteString(writer, receipt.IssuedAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            WriteString(writer, receipt.ExpiresAtUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture));
            WriteString(writer, receipt.SourceCommitSha);
            WriteString(writer, receipt.SchemaPlanSha256);
            WriteString(writer, receipt.BackupManifestSha256);
            WriteString(writer, receipt.RunnerDigestSha256);
            WriteString(writer, receipt.TargetGeneration);
            if (string.Equals(receipt.SchemaVersion, "2.1", StringComparison.Ordinal))
            {
                CloudNativePgTargetObservation target = receipt.TargetObservation!;
                WriteString(writer, target.Namespace);
                WriteString(writer, target.Cluster);
                WriteString(writer, target.Uid);
                WriteString(writer, target.ResourceVersion);
                writer.Write(target.Generation);
                writer.Write(target.ObservedGeneration);
                WriteString(writer, target.Phase);
                writer.Write(target.Instances);
                writer.Write(target.ReadyInstances);
                WriteString(writer, target.CurrentPrimary);
                WriteString(writer, target.TargetPrimary);
                writer.Write(target.Ready);
                writer.Write(target.ConsistentSystemId);
                writer.Write(target.ContinuousArchiving);
                writer.Write(target.LastBackupSucceeded);
                WriteString(writer, target.ReconciliationEvidence);
                writer.Write(target.ObservationReadCount);
                writer.Write(target.StatusInstances);
                WriteString(writer, target.SystemId);
                WriteString(writer, target.InstanceNames);
                WriteString(writer, target.HealthyInstances);
                writer.Write(target.PvcCount);
                WriteString(writer, target.HealthyPvcs);
                WriteString(writer, target.DanglingPvcs);
                WriteString(writer, target.InitializingPvcs);
                WriteString(writer, target.ResizingPvcs);
                WriteString(writer, target.UnusablePvcs);
                WriteString(writer, target.ReadyReason);
                WriteString(writer, target.ConsistentSystemIdReason);
                WriteString(writer, target.ContinuousArchivingReason);
                WriteString(writer, target.LastBackupSucceededReason);
            }
            WriteString(writer, receipt.Mode);
            WriteString(writer, receipt.AttestationKeyId);
            string[] databases = [.. receipt.AuthorizedDatabases.OrderBy(database => database, StringComparer.Ordinal)];
            writer.Write(databases.Length);
            foreach (string database in databases)
            {
                WriteString(writer, database);
            }
        }

        payload = stream.ToArray();
        return true;
    }

    private static void WriteString(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }
}

internal static partial class ExecutionAuthorizationValidator
{
    public static IReadOnlyList<PreflightError> Validate(
        ExecutionAuthorizationReceipt receipt,
        FreshSchemaPlan plan,
        BackupReceipt backupReceipt,
        GuardedRunnerPolicy policy,
        DateTimeOffset nowUtc,
        IReceiptAttestationTrustStore trustStore)
    {
        List<PreflightError> errors = [];
        if (receipt.SchemaVersion is not ("2.0" or "2.1"))
        {
            errors.Add(new("execution_authorization_version_unknown", "The execution authorization version is not approved."));
        }

        if (receipt.RunId == Guid.Empty)
        {
            errors.Add(new("execution_run_id_invalid", "The execution run identifier is required."));
        }

        if (receipt.IssuedAtUtc > nowUtc || receipt.ExpiresAtUtc <= nowUtc || receipt.ExpiresAtUtc <= receipt.IssuedAtUtc)
        {
            errors.Add(new("execution_authorization_expired", "The execution authorization is not currently valid."));
        }

        if (receipt.ExpiresAtUtc - receipt.IssuedAtUtc > GuardedRunnerPolicy.MaximumAuthorizationLifetime)
        {
            errors.Add(new("execution_authorization_lifetime_invalid", "The execution authorization lifetime exceeds policy."));
        }

        if (!string.Equals(receipt.Mode, "shadow-only", StringComparison.Ordinal))
        {
            errors.Add(new("execution_mode_forbidden", "Only shadow-only execution is authorized."));
        }

        if (!string.Equals(receipt.SourceCommitSha, policy.ExpectedSourceCommitSha, StringComparison.Ordinal) ||
            !string.Equals(receipt.SourceCommitSha, plan.SourceCommitSha, StringComparison.Ordinal))
        {
            errors.Add(new("execution_source_commit_mismatch", "The authorization source commit does not match the runner and schema plan."));
        }

        if (!FixedHashEquals(receipt.SchemaPlanSha256, SchemaPlanCanonicalizer.ComputeSha256(plan)))
        {
            errors.Add(new("execution_schema_plan_hash_mismatch", "The authorization does not bind the supplied schema plan."));
        }

        if (!FixedHashEquals(receipt.BackupManifestSha256, backupReceipt.ManifestSha256))
        {
            errors.Add(new("execution_backup_manifest_mismatch", "The authorization does not bind the supplied backup receipt."));
        }

        if (!FixedHashEquals(receipt.RunnerDigestSha256, policy.ExpectedRunnerDigestSha256))
        {
            errors.Add(new("execution_runner_digest_mismatch", "The authorization does not bind the approved runner digest."));
        }

        if (receipt.TargetGeneration is null ||
            (receipt.SchemaVersion == "2.1" ? !NumericGeneration().IsMatch(receipt.TargetGeneration) : !TargetGeneration().IsMatch(receipt.TargetGeneration)))
        {
            errors.Add(new("execution_target_generation_invalid", "The target generation identifier is invalid."));
        }

        if (receipt.SchemaVersion == "2.1" && (receipt.TargetObservation is null || !receipt.TargetObservation.IsHealthy ||
            !string.Equals(receipt.TargetObservation.Namespace, "maliev-legacy", StringComparison.Ordinal) ||
            !string.Equals(receipt.TargetObservation.Cluster, "legacy-postgres-main", StringComparison.Ordinal) ||
            !string.Equals(receipt.TargetGeneration, receipt.TargetObservation.Generation.ToString(CultureInfo.InvariantCulture), StringComparison.Ordinal)))
        {
            errors.Add(new("execution_target_observation_invalid", "The authorization must bind the exact observed CloudNativePG target."));
        }

        IReadOnlyList<string> databases = receipt.AuthorizedDatabases ?? [];
        if (databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            databases.Distinct(StringComparer.Ordinal).Count() != databases.Count ||
            !databases.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new("execution_database_scope_invalid", "The authorization must cover exactly the approved migrate disposition."));
        }

        if (string.IsNullOrWhiteSpace(receipt.AttestationKeyId) || !trustStore.ContainsKey(receipt.AttestationKeyId))
        {
            errors.Add(new("execution_authorization_key_unknown", "The execution authorization key is not trusted."));
        }

        byte[]? signature = null;
        if (string.IsNullOrWhiteSpace(receipt.AttestationSignature) || receipt.AttestationSignature.Length > 4096)
        {
            errors.Add(new("execution_authorization_signature_invalid", "The execution authorization signature is invalid."));
        }
        else
        {
            try
            {
                signature = Convert.FromBase64String(receipt.AttestationSignature);
            }
            catch (FormatException)
            {
                errors.Add(new("execution_authorization_signature_invalid", "The execution authorization signature is invalid."));
            }
        }

        if (!ExecutionAuthorizationAttestation.TryCreatePayload(receipt, out byte[] payload))
        {
            errors.Add(new("execution_authorization_payload_invalid", "The execution authorization cannot be canonicalized."));
        }
        else if (signature is not null &&
            receipt.AttestationKeyId is not null &&
            trustStore.ContainsKey(receipt.AttestationKeyId) &&
            !trustStore.Verify(receipt.AttestationKeyId, payload, signature))
        {
            errors.Add(new("execution_authorization_signature_invalid", "The execution authorization signature is invalid."));
        }

        return errors;
    }

    private static bool FixedHashEquals(string? left, string? right)
    {
        return left is not null &&
            right is not null &&
            Sha256().IsMatch(left) &&
            Sha256().IsMatch(right) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();

    [GeneratedRegex("^[a-z0-9][a-z0-9-]{2,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex TargetGeneration();

    [GeneratedRegex("^[1-9][0-9]{0,18}$", RegexOptions.CultureInvariant)]
    private static partial Regex NumericGeneration();
}
