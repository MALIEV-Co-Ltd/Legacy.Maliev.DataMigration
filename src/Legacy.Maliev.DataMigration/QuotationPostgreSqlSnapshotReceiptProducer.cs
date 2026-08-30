using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record ImmutablePostgreSqlSnapshotObservation(
    string SnapshotId,
    string BackupObjectUri,
    long BackupObjectGeneration,
    long BackupObjectByteLength,
    string BackupObjectSha256,
    DateTimeOffset RecoveryPointUtc);

public sealed record QuotationPostgreSqlSnapshotReceiptRequest(
    string Workload,
    Guid RunId,
    string SourceSnapshotId,
    string CopyPlanId,
    string SchemaHash,
    string Host,
    int Port,
    string Database,
    string SnapshotId,
    string BackupObjectUri,
    long BackupObjectGeneration,
    string ClusterNamespace,
    string ClusterName,
    DateTimeOffset ExpiresUtc,
    IReadOnlyList<string> ForbiddenSignerFingerprints);

public interface IImmutablePostgreSqlSnapshotObserver
{
    Task<ImmutablePostgreSqlSnapshotObservation> ObserveAsync(
        string backupObjectUri,
        long backupObjectGeneration,
        CancellationToken cancellationToken);
}

public sealed record QuotationPostgreSqlSnapshotReceiptPayload(
    string SchemaVersion, string Workload, string RunId, string SourceSnapshotId, string CopyPlanId,
    string SchemaHash, string SnapshotId, DateTimeOffset RecoveryPointUtc, string SnapshotChecksumSha256,
    string BackupObjectUri, long BackupObjectGeneration, long BackupObjectByteLength, string AttestationKeyId,
    string Host, int Port, string Database, string ClusterNamespace, string ClusterName, string ClusterUid,
    long ClusterGeneration, long ClusterObservedGeneration, DateTimeOffset ExpiresUtc);

public sealed record QuotationPostgreSqlSnapshotReceipt(string EnvelopeJson);

public static partial class QuotationPostgreSqlSnapshotReceiptProducer
{
    public static async Task<QuotationPostgreSqlSnapshotReceipt> ProduceAsync(
        QuotationPostgreSqlSnapshotReceiptRequest request,
        P256MigrationEvidenceSigner signer,
        IImmutablePostgreSqlSnapshotObserver snapshotObserver,
        ICloudNativePgTargetObserver targetObserver,
        TimeProvider timeProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request); ArgumentNullException.ThrowIfNull(signer);
        ArgumentNullException.ThrowIfNull(snapshotObserver); ArgumentNullException.ThrowIfNull(targetObserver); ArgumentNullException.ThrowIfNull(timeProvider);
        ImmutablePostgreSqlSnapshotObservation snapshot = await snapshotObserver.ObserveAsync(
            request.BackupObjectUri, request.BackupObjectGeneration, cancellationToken).ConfigureAwait(false);
        ImmutablePostgreSqlSnapshotObservation snapshotRecheck = await snapshotObserver.ObserveAsync(
            request.BackupObjectUri, request.BackupObjectGeneration, cancellationToken).ConfigureAwait(false);
        CloudNativePgTargetObservation target = await targetObserver.ObserveAsync(
            request.ClusterNamespace, request.ClusterName, cancellationToken).ConfigureAwait(false);
        CloudNativePgTargetObservation targetRecheck = await targetObserver.ObserveAsync(
            request.ClusterNamespace, request.ClusterName, cancellationToken).ConfigureAwait(false);
        string database = request.Workload switch { "quotation" => "Quotation", "quotation-request" => "QuotationRequest", _ => string.Empty };
        DateTimeOffset now = timeProvider.GetUtcNow();
        if (request.RunId == Guid.Empty || request.Database != database || !Identifier().IsMatch(request.SourceSnapshotId) ||
            !Identifier().IsMatch(request.CopyPlanId) || !Sha256().IsMatch(request.SchemaHash) || !Identifier().IsMatch(signer.KeyId) ||
            string.IsNullOrWhiteSpace(request.Host) || request.Port is < 1 or > 65535 || snapshot != snapshotRecheck || target != targetRecheck || !target.IsHealthy ||
            target.Namespace != "maliev-legacy" || target.Cluster != "legacy-postgres-main" ||
            request.ClusterNamespace != target.Namespace || request.ClusterName != target.Cluster ||
            !Identifier().IsMatch(target.Uid) || target.Generation <= 0 || target.ObservedGeneration != target.Generation ||
            snapshot.SnapshotId != request.SnapshotId || snapshot.BackupObjectUri != request.BackupObjectUri ||
            snapshot.BackupObjectGeneration != request.BackupObjectGeneration || !Identifier().IsMatch(snapshot.SnapshotId) ||
            !BackupUri().IsMatch(snapshot.BackupObjectUri) || snapshot.BackupObjectGeneration <= 0 || snapshot.BackupObjectByteLength <= 0 ||
            !Sha256().IsMatch(snapshot.BackupObjectSha256) || snapshot.RecoveryPointUtc.Offset != TimeSpan.Zero ||
            snapshot.RecoveryPointUtc > now || now - snapshot.RecoveryPointUtc > TimeSpan.FromHours(24) ||
            request.ExpiresUtc.Offset != TimeSpan.Zero || request.ExpiresUtc <= now || request.ExpiresUtc > now.AddHours(1) ||
            request.ForbiddenSignerFingerprints.Any(value => FixedEquals(value, signer.PublicKeyFingerprintSha256)))
        {
            throw new MigrationExecutionException("quotation_snapshot_receipt_invalid", "Quotation PostgreSQL snapshot evidence is invalid, stale, or ambiguously trusted.");
        }

        var payload = new QuotationPostgreSqlSnapshotReceiptPayload(
            "1.0", request.Workload, request.RunId.ToString("D"), request.SourceSnapshotId, request.CopyPlanId,
            request.SchemaHash.ToLowerInvariant(), snapshot.SnapshotId, snapshot.RecoveryPointUtc,
            snapshot.BackupObjectSha256.ToLowerInvariant(), snapshot.BackupObjectUri,
            snapshot.BackupObjectGeneration, snapshot.BackupObjectByteLength, signer.KeyId, request.Host,
            request.Port, request.Database, target.Namespace, target.Cluster, target.Uid,
            target.Generation, target.ObservedGeneration, request.ExpiresUtc);
        string json = JsonSerializer.Serialize(payload);
        string signature = Convert.ToBase64String(signer.Sign(QuotationPostgreSqlSnapshotReceiptCanonicalizer.CreatePayload(payload)));
        return new(JsonSerializer.Serialize(new { Payload = json, Signature = signature }));
    }

    private static bool FixedEquals(string left, string right)
    {
        return left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", RegexOptions.CultureInvariant)] private static partial Regex Identifier();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256();
    [GeneratedRegex("^gs://[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+$", RegexOptions.CultureInvariant)] private static partial Regex BackupUri();
}

public static class QuotationPostgreSqlSnapshotReceiptCanonicalizer
{
    private const string Domain = "Legacy.Maliev.QuotationService.PostgreSqlSnapshotReceipt.v1";
    public static byte[] CreatePayload(QuotationPostgreSqlSnapshotReceiptPayload value)
    {
        using var stream = new MemoryStream(); using var writer = new BinaryWriter(stream, new UTF8Encoding(false), true);
        Write(writer, Domain); Write(writer, value.SchemaVersion); Write(writer, value.Workload); Write(writer, value.RunId);
        Write(writer, value.SourceSnapshotId); Write(writer, value.CopyPlanId); Write(writer, value.SchemaHash); Write(writer, value.SnapshotId);
        Write(writer, value.RecoveryPointUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)); Write(writer, value.SnapshotChecksumSha256);
        Write(writer, value.BackupObjectUri); writer.Write(value.BackupObjectGeneration); writer.Write(value.BackupObjectByteLength);
        Write(writer, value.AttestationKeyId); Write(writer, value.Host); writer.Write(value.Port); Write(writer, value.Database);
        Write(writer, value.ClusterNamespace); Write(writer, value.ClusterName); Write(writer, value.ClusterUid);
        writer.Write(value.ClusterGeneration); writer.Write(value.ClusterObservedGeneration);
        Write(writer, value.ExpiresUtc.ToUniversalTime().ToString("O", CultureInfo.InvariantCulture)); return stream.ToArray();
    }
    private static void Write(BinaryWriter writer, string value) { byte[] bytes = Encoding.UTF8.GetBytes(value); writer.Write(bytes.Length); writer.Write(bytes); }
}
