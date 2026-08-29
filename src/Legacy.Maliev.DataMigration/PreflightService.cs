using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed partial class PreflightService
{
    private readonly IExternalCommandExecutor _externalCommandExecutor;

    public const string ReceiptSchemaVersion = "1.0";
    public const string TargetSchemaVersion = "1.0";

    public PreflightService(IExternalCommandExecutor externalCommandExecutor)
    {
        ArgumentNullException.ThrowIfNull(externalCommandExecutor);
        _externalCommandExecutor = externalCommandExecutor;
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
        return new PreflightResult(errors);
    }

    private static void ValidateReceipt(
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

        if (!FixedTimeEquals(receipt.DatabaseInventorySha256, DatabaseInventory.InventorySha256))
        {
            errors.Add(new("inventory_hash_mismatch", "The database disposition inventory differs from the approved contract."));
        }

        IReadOnlyList<BackupArtifact> artifacts = receipt.Artifacts ?? [];
        string[] actualDatabases = artifacts.Select(artifact => artifact.Database).ToArray();
        if (actualDatabases.Length != DatabaseInventory.ActiveDatabases.Count ||
            actualDatabases.Distinct(StringComparer.Ordinal).Count() != actualDatabases.Length ||
            !actualDatabases.OrderBy(database => database, StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new("database_coverage_mismatch", "The receipt must cover each of the 21 active databases exactly once."));
        }

        foreach (BackupArtifact artifact in artifacts)
        {
            if (!string.Equals(artifact.BackupType, "Full", StringComparison.Ordinal))
            {
                errors.Add(new("backup_type_not_full", $"{artifact.Database} is not a full backup."));
            }

            if (!FullBackupFileName().IsMatch(artifact.FileName) ||
                artifact.ByteLength <= 0 ||
                !Sha256().IsMatch(artifact.Sha256) ||
                !Sha256().IsMatch(artifact.ObservedSha256))
            {
                errors.Add(new("backup_artifact_invalid", $"{artifact.Database} backup evidence is malformed."));
            }

            if (!FixedTimeEquals(artifact.ObservedSha256, artifact.Sha256))
            {
                errors.Add(new("backup_hash_mismatch", $"{artifact.Database} observed SHA-256 does not match its receipt."));
            }
        }

        string computedManifestHash = ComputeManifestSha256(artifacts);
        if (!FixedTimeEquals(receipt.ManifestSha256, computedManifestHash))
        {
            errors.Add(new("manifest_hash_mismatch", "The backup artifact manifest SHA-256 does not match its contents."));
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

        if (plan.RequestedExternalActions is { Count: > 0 })
        {
            errors.Add(new("external_actions_forbidden", "External actions are forbidden during preflight."));
        }

        Dictionary<string, string> versions = plan.TargetSchemaVersions ?? new(StringComparer.Ordinal);
        IOrderedEnumerable<string> databases = versions.Keys.OrderBy(database => database, StringComparer.Ordinal);
        if (!databases.SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        {
            errors.Add(new("target_schema_coverage_mismatch", "Target schema versions must cover all 21 active databases exactly."));
        }

        if (versions.Values.Any(version => !string.Equals(version, TargetSchemaVersion, StringComparison.Ordinal)))
        {
            errors.Add(new("target_schema_version_unknown", "The plan contains an unapproved target schema version."));
        }
    }

    public static string ComputeManifestSha256(IEnumerable<BackupArtifact> artifacts)
    {
        ArgumentNullException.ThrowIfNull(artifacts);

        string canonical = string.Join(
            '\n',
            artifacts
                .OrderBy(artifact => artifact.Database, StringComparer.Ordinal)
                .Select(artifact => string.Join(
                    '|',
                    artifact.Database,
                    artifact.BackupType,
                    artifact.FileName,
                    artifact.ByteLength,
                    artifact.Sha256.ToLowerInvariant(),
                    artifact.ObservedSha256.ToLowerInvariant())));
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
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

    [GeneratedRegex("^Full_[A-Za-z][A-Za-z0-9]*_\\d{4}-\\d{2}-\\d{2}_\\d{6}\\.bak$", RegexOptions.CultureInvariant)]
    private static partial Regex FullBackupFileName();
}
