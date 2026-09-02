using System.Globalization;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

public sealed record DatabaseMigrationCheckpoint(
    MigrationRunIdentity Identity,
    ShadowDatabase Shadow,
    MigratedShadowDatabase Database,
    DatabaseReconciliationEvidence Reconciliation,
    DateTimeOffset CommittedAtUtc,
    string AttestationKeyId,
    string? AttestationSignature);

public sealed record DatabaseMigrationCheckpointVerificationOptions(
    MigrationRunIdentity Identity,
    FreshSchemaPlan SchemaPlan,
    IReceiptAttestationTrustStore TrustStore);

public sealed class DatabaseMigrationCheckpointVerifier
{
    private readonly MigrationRunIdentity _identity;
    private readonly FreshSchemaPlan _plan;
    private readonly IReceiptAttestationTrustStore _trustStore;

    public DatabaseMigrationCheckpointVerifier(DatabaseMigrationCheckpointVerificationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _identity = options.Identity ?? throw new ArgumentException("The original run identity is required.", nameof(options));
        ArgumentNullException.ThrowIfNull(options.SchemaPlan);
        // Detach caller-owned lists/dictionaries so later mutations cannot change the verification policy.
        _plan = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(options.SchemaPlan))!;
        _trustStore = options.TrustStore ?? throw new ArgumentException("Checkpoint trust is required.", nameof(options));
    }

    public void Validate(DatabaseMigrationCheckpoint checkpoint, ShadowDatabase registeredShadow)
    {
        ArgumentNullException.ThrowIfNull(checkpoint);
        ArgumentNullException.ThrowIfNull(registeredShadow);
        Require(checkpoint.Identity == _identity && _identity.RunId != Guid.Empty &&
            IsHex(_identity.SourceCommitSha, 40) && IsHex(_identity.SchemaPlanSha256, 64) &&
            IsHex(_identity.BackupManifestSha256, 64) && IsHex(_identity.RunnerDigestSha256, 64) &&
            !string.IsNullOrWhiteSpace(_identity.TargetGeneration) &&
            string.Equals(_plan.SourceCommitSha, _identity.SourceCommitSha, StringComparison.Ordinal) &&
            string.Equals(SchemaPlanCanonicalizer.ComputeSha256(_plan), _identity.SchemaPlanSha256, StringComparison.Ordinal),
            "The checkpoint does not match the original immutable run and schema plan.");
        Require(!string.IsNullOrWhiteSpace(checkpoint.AttestationKeyId) && !string.IsNullOrWhiteSpace(checkpoint.AttestationSignature),
            "Checkpoint attestation is required.");
        byte[] signature;
        try
        {
            signature = Convert.FromBase64String(checkpoint.AttestationSignature);
        }
        catch (FormatException exception)
        {
            throw new MigrationExecutionException("checkpoint_invalid", "Checkpoint attestation is malformed.", exception);
        }
        Require(_trustStore.Verify(checkpoint.AttestationKeyId, MigrationEvidenceAttestation.CreatePayload(checkpoint), signature),
            "Checkpoint attestation is not trusted.");

        ShadowDatabase shadow = checkpoint.Shadow;
        MigratedShadowDatabase database = checkpoint.Database;
        DatabaseReconciliationEvidence evidence = checkpoint.Reconciliation;
        Require(shadow is not null && database is not null && evidence is not null, "Checkpoint evidence is incomplete.");
        Require(shadow == registeredShadow && shadow.OwnerRunId == _identity.RunId.ToString("D") &&
            shadow.OwnerAttempt > 0 && shadow.FencingToken != Guid.Empty &&
            shadow.Name == GuardedShadowMigrationRunner.CreateShadowName(shadow.Database, _identity.RunId) &&
            database.Database == shadow.Database && database.ShadowName == shadow.Name &&
            database.OwnerAttempt == shadow.OwnerAttempt && database.FencingToken == shadow.FencingToken &&
            evidence.Database == shadow.Database,
            "The checkpoint does not match the original registered shadow ownership.");
        DatabaseSchemaPlan[] matches = [.. _plan.Databases.Where(item => item.Database == shadow.Database)];
        Require(matches.Length == 1, "The checkpoint database is absent or duplicated in the original plan.");
        DatabaseSchemaPlan plan = matches[0];
        Require(checkpoint.CommittedAtUtc >= _plan.CapturedAtUtc && checkpoint.CommittedAtUtc.Offset == TimeSpan.Zero &&
            evidence.SourceSchemaSha256 == plan.SourceSchemaSha256 && evidence.TargetSchemaSha256 == plan.TargetSchemaSha256 &&
            IsHex(evidence.SourceSchemaSha256, 64) && IsHex(evidence.TargetSchemaSha256, 64),
            "The checkpoint schema or commit time does not match the original plan.");
        Require(evidence.Tables is not null && evidence.Tables.All(item => item is not null) &&
            ExactKeys(plan.Tables.Select(item => $"{item.TargetSchema}.{item.TargetTable}"), evidence.Tables.Select(item => item.Table)),
            "Checkpoint table coverage is incomplete or duplicated.");
        long totalRows = 0;
        foreach (TableCopyPlan tablePlan in plan.Tables)
        {
            TableReconciliationEvidence table = evidence.Tables.Single(item => item.Table == $"{tablePlan.TargetSchema}.{tablePlan.TargetTable}");
            Require(table.RowCount >= 0 && (!tablePlan.SourceKnownEmpty || table.RowCount == 0) &&
                IsHex(table.ContentSha256, 64) && IsHex(table.AggregateSha256, 64), "Checkpoint table evidence is invalid.");
            ValidateCounts(tablePlan.OrderedColumns, table.NullCounts, table.RowCount);
            ValidateCounts(tablePlan.ForeignKeys.Select(item => item.Name), table.ForeignKeyOrphanCounts, table.RowCount);
            Require(table.ForeignKeyOrphanCounts.Values.All(value => value == 0),
                "A committed checkpoint cannot contain orphan rows after foreign-key validation.");
            ValidateCounts(tablePlan.ForeignKeys.Select(item => item.Name), table.ForeignKeyRelationshipCounts, table.RowCount);
            Require(totalRows <= long.MaxValue - table.RowCount, "Checkpoint row totals overflow.");
            totalRows += table.RowCount;
        }
        Require(evidence.SequenceNextValues is not null && ExactKeys(
            plan.Tables.SelectMany(table => table.Identities.Select(identity => $"{table.TargetSchema}.{table.TargetTable}.{identity.Column}")),
            evidence.SequenceNextValues.Keys), "Checkpoint sequence coverage is incomplete or duplicated.");
        string content = string.Join('\n', evidence.Tables.OrderBy(item => item.Table, StringComparer.Ordinal)
            .Select(item => string.Create(CultureInfo.InvariantCulture, $"{item.Table}|{item.RowCount}|{item.ContentSha256}|{item.AggregateSha256}")));
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(content))).ToLowerInvariant();
        Require(database.TotalRows == totalRows && database.ContentSha256 == hash,
            "Checkpoint database totals do not match its table evidence.");
    }

    private static void ValidateCounts(IEnumerable<string> expectedKeys, IReadOnlyDictionary<string, long>? counts, long rows)
    {
        Require(counts is not null && ExactKeys(expectedKeys, counts.Keys) && counts.Values.All(value => value >= 0 && value <= rows),
            "Checkpoint count evidence is incomplete or outside its row bounds.");
    }

    private static bool ExactKeys(IEnumerable<string> expected, IEnumerable<string> actual)
    {
        string[] expectedKeys = [.. expected.Order(StringComparer.Ordinal)];
        string[] actualKeys = [.. actual.Order(StringComparer.Ordinal)];
        return expectedKeys.Distinct(StringComparer.Ordinal).Count() == expectedKeys.Length &&
            actualKeys.Distinct(StringComparer.Ordinal).Count() == actualKeys.Length && expectedKeys.SequenceEqual(actualKeys, StringComparer.Ordinal);
    }

    private static bool IsHex(string? value, int length)
    {
        return value is not null && value.Length == length && value.All(char.IsAsciiHexDigit);
    }

    private static void Require([DoesNotReturnIf(false)] bool condition, string message)
    {
        if (!condition)
        {
            throw new MigrationExecutionException("checkpoint_invalid", message);
        }
    }
}
