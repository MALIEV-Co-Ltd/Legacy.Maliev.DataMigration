using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed partial class PreflightService
{
    private readonly IExternalCommandExecutor _externalCommandExecutor;
    private readonly IReceiptAttestationTrustStore _attestationTrustStore;

    public const string ReceiptSchemaVersion = "1.1";
    public const string TargetSchemaVersion = "1.0";

    public PreflightService(
        IExternalCommandExecutor externalCommandExecutor,
        IReceiptAttestationTrustStore attestationTrustStore)
    {
        ArgumentNullException.ThrowIfNull(externalCommandExecutor);
        ArgumentNullException.ThrowIfNull(attestationTrustStore);
        _externalCommandExecutor = externalCommandExecutor;
        _attestationTrustStore = attestationTrustStore;
    }

    public PreflightResult Validate(
        BackupReceipt receipt,
        MigrationPlan plan,
        DateTimeOffset nowUtc,
        TimeSpan maximumReceiptAge)
    {
        ArgumentNullException.ThrowIfNull(receipt);
        ArgumentNullException.ThrowIfNull(plan);
        _ = _externalCommandExecutor;

        List<PreflightError> errors = [];
        ValidateReceipt(receipt, nowUtc, maximumReceiptAge, errors);
        ValidatePlan(plan, errors);
        ValidateAttestation(receipt, errors);
        return new PreflightResult(errors);
    }

    internal static void ValidateReceipt(
        BackupReceipt receipt,
        DateTimeOffset nowUtc,
        TimeSpan maximumReceiptAge,
        List<PreflightError> errors)
    {
        if (maximumReceiptAge <= TimeSpan.Zero)
        {
            errors.Add(new("receipt_age_invalid", "The maximum receipt age must be positive."));
        }

        if (!string.Equals(receipt.SchemaVersion, ReceiptSchemaVersion, StringComparison.Ordinal))
        {
            errors.Add(new("receipt_schema_version_unknown", "The backup receipt schema version is not approved."));
        }

        if (receipt.CapturedAtUtc > nowUtc || nowUtc - receipt.CapturedAtUtc > maximumReceiptAge)
        {
            errors.Add(new("receipt_stale", "The backup receipt is stale or dated in the future."));
        }

        if (receipt.SourceObservedAtUtc is null || receipt.SourceObservedAtUtc.Value.Offset != TimeSpan.Zero ||
            receipt.SourceObservedAtUtc.Value > receipt.CapturedAtUtc)
        {
            errors.Add(new("receipt_capture_provenance_invalid", "The backup receipt source observation is missing or invalid."));
        }

        if (!FixedTimeEquals(receipt.DatabaseInventorySha256, DatabaseInventory.InventorySha256))
        {
            errors.Add(new("inventory_hash_mismatch", "The database disposition inventory differs from the approved contract."));
        }

        IReadOnlyList<BackupArtifact?> artifacts = receipt.Artifacts ?? [];
        string?[] actualDatabases = artifacts.Select(artifact => artifact?.Database).ToArray();
        if (actualDatabases.Length != DatabaseInventory.ActiveDatabases.Count ||
            actualDatabases.Any(string.IsNullOrWhiteSpace) ||
            actualDatabases.Distinct(StringComparer.Ordinal).Count() != actualDatabases.Length ||
            !actualDatabases.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new(
                "database_coverage_mismatch",
                $"The receipt must cover each of the {DatabaseInventory.ActiveDatabases.Count} active databases exactly once."));
        }

        foreach (BackupArtifact? artifact in artifacts)
        {
            if (artifact is null)
            {
                errors.Add(new("backup_artifact_missing", "The receipt contains a null backup artifact."));
                continue;
            }

            if (!string.Equals(artifact.BackupType, "Full", StringComparison.Ordinal))
            {
                errors.Add(new("backup_type_not_full", $"{artifact.Database} is not a full backup."));
            }

            bool hashesAreValid = artifact.Sha256 is not null &&
                artifact.ObservedSha256 is not null &&
                Sha256().IsMatch(artifact.Sha256) &&
                Sha256().IsMatch(artifact.ObservedSha256);
            if (string.IsNullOrWhiteSpace(artifact.Database) ||
                artifact.FileName is null ||
                !FullBackupFileName().IsMatch(artifact.FileName) ||
                artifact.ByteLength <= 0 ||
                !hashesAreValid)
            {
                errors.Add(new("backup_artifact_invalid", $"{artifact.Database} backup evidence is malformed."));
            }

            if (artifact.CompletedAtUtc is null || artifact.CompletedAtUtc.Value.Offset != TimeSpan.Zero ||
                receipt.SourceObservedAtUtc is null || artifact.CompletedAtUtc.Value < receipt.SourceObservedAtUtc.Value ||
                artifact.CompletedAtUtc.Value > receipt.CapturedAtUtc || string.IsNullOrWhiteSpace(artifact.GcsObject) ||
                artifact.GcsGeneration is null or <= 0 || artifact.GcsSha256 is null || !Sha256().IsMatch(artifact.GcsSha256) ||
                !FixedTimeEquals(artifact.GcsSha256, artifact.Sha256))
            {
                errors.Add(new("backup_artifact_provenance_invalid", $"{artifact.Database} immutable capture provenance is incomplete."));
            }

            if (hashesAreValid && !FixedTimeEquals(artifact.ObservedSha256, artifact.Sha256))
            {
                errors.Add(new("backup_hash_mismatch", $"{artifact.Database} observed SHA-256 does not match its receipt."));
            }
        }

        if (!TryComputeManifestSha256(artifacts, out string computedManifestHash))
        {
            errors.Add(new("manifest_payload_invalid", "The backup artifact manifest cannot be canonicalized."));
        }
        else if (!FixedTimeEquals(receipt.ManifestSha256, computedManifestHash))
        {
            errors.Add(new("manifest_hash_mismatch", "The backup artifact manifest SHA-256 does not match its contents."));
        }

        DateTimeOffset? latestCompletion = artifacts.Where(item => item?.CompletedAtUtc is not null)
            .Max(item => item!.CompletedAtUtc);
        if (latestCompletion is null || latestCompletion.Value != receipt.CapturedAtUtc)
        {
            errors.Add(new("receipt_capture_provenance_invalid", "The receipt capture time must equal the latest artifact completion."));
        }
    }

    private static void ValidatePlan(MigrationPlan plan, List<PreflightError> errors)
    {
        if (!string.Equals(plan.Mode, "plan-only", StringComparison.Ordinal))
        {
            errors.Add(new("mode_not_plan_only", "Only plan-only preflight is permitted."));
        }

        if (plan.AllowTargetWrites)
        {
            errors.Add(new("target_writes_forbidden", "Target writes are forbidden during preflight."));
        }

        if (plan.RequestedExternalActions is null)
        {
            errors.Add(new("external_actions_missing", "The external action list is required and must be empty."));
        }
        else if (plan.RequestedExternalActions.Count > 0)
        {
            errors.Add(new("external_actions_forbidden", "External actions are forbidden during preflight."));
        }

        Dictionary<string, string?> versions = plan.TargetSchemaVersions ?? new(StringComparer.Ordinal);
        IOrderedEnumerable<string> databases = versions.Keys.OrderBy(database => database, StringComparer.Ordinal);
        if (!databases.SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new(
                "target_schema_coverage_mismatch",
                $"Target schema versions must cover all {DatabaseInventory.ActiveDatabases.Count} active databases exactly."));
        }

        if (versions.Values.Any(version => !string.Equals(version, TargetSchemaVersion, StringComparison.Ordinal)))
        {
            errors.Add(new("target_schema_version_unknown", "The plan contains an unapproved target schema version."));
        }
    }

    private void ValidateAttestation(BackupReceipt receipt, List<PreflightError> errors)
    {
        bool hasKnownKey = false;
        if (string.IsNullOrWhiteSpace(receipt.AttestationKeyId))
        {
            errors.Add(new("attestation_key_missing", "The producer attestation key identifier is required."));
        }
        else if (!_attestationTrustStore.ContainsKey(receipt.AttestationKeyId))
        {
            errors.Add(new("attestation_key_unknown", "The producer attestation key is not trusted."));
        }
        else
        {
            hasKnownKey = true;
        }

        byte[]? signature = null;
        if (string.IsNullOrWhiteSpace(receipt.AttestationSignature))
        {
            errors.Add(new("attestation_signature_missing", "The producer attestation signature is required."));
        }
        else if (receipt.AttestationSignature.Length > 4096)
        {
            errors.Add(new("attestation_signature_invalid", "The producer attestation signature is invalid."));
        }
        else
        {
            try
            {
                signature = Convert.FromBase64String(receipt.AttestationSignature);
            }
            catch (FormatException)
            {
                errors.Add(new("attestation_signature_invalid", "The producer attestation signature is invalid."));
            }
        }

        if (!ReceiptAttestation.TryCreatePayload(receipt, out byte[] payload))
        {
            errors.Add(new("attestation_payload_invalid", "The receipt cannot be canonicalized for producer attestation."));
            return;
        }

        if (hasKnownKey && signature is not null &&
            !_attestationTrustStore.Verify(receipt.AttestationKeyId!, payload, signature))
        {
            errors.Add(new("attestation_signature_invalid", "The producer attestation signature is invalid."));
        }
    }

    private static bool TryComputeManifestSha256(
        IEnumerable<BackupArtifact?> artifacts,
        out string manifestSha256)
    {
        manifestSha256 = string.Empty;
        BackupArtifact?[] artifactArray = artifacts.ToArray();
        if (artifactArray.Any(artifact => artifact is null ||
            artifact.Database is null ||
            artifact.BackupType is null ||
            artifact.FileName is null ||
            artifact.Sha256 is null ||
            artifact.ObservedSha256 is null))
        {
            return false;
        }

        string canonical = string.Join(
            '\n',
            artifactArray
                .Select(artifact => artifact!)
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .Select(artifact => string.Join(
                    '|',
                    artifact.Database,
                    artifact.BackupType,
                    artifact.FileName,
                    artifact.ByteLength,
                    artifact.Sha256!.ToLowerInvariant(),
                    artifact.ObservedSha256!.ToLowerInvariant())));
        manifestSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
        return true;
    }

    private static bool FixedTimeEquals(string? actual, string? expected)
    {
        return actual is not null &&
            expected is not null &&
            Sha256().IsMatch(actual) &&
            Sha256().IsMatch(expected) &&
            CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(actual.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(expected.ToLowerInvariant()));
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)]
    private static partial Regex Sha256();

    [GeneratedRegex("^Full_[A-Za-z][A-Za-z0-9]*_[A-Za-z0-9][A-Za-z0-9._-]{0,127}\\.bak$", RegexOptions.CultureInvariant)]
    private static partial Regex FullBackupFileName();
}
