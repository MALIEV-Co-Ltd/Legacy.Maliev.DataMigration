using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

/// <summary>PII-free identity and hashes for one encrypted, immutable source-table capture.</summary>
public sealed record DeltaCapturedTableArtifact(
    string Database,
    string Table,
    Guid CaptureId,
    string SchemaPlanSha256,
    string EncryptedSha256,
    string PlaintextSha256,
    long RowCount);

/// <summary>Writes and replays only run-owned encrypted table artifacts in an existing protected directory.</summary>
public sealed class DeltaCapturedTableArchive(string protectedDirectory)
{
    private readonly string _directory = ValidateDirectory(protectedDirectory);

    public async Task<DeltaCapturedTableArtifact> CaptureAsync(
        string database,
        TableCopyPlan table,
        string schemaPlanSha256,
        IAsyncEnumerable<MigrationRow> sourceRows,
        ReadOnlyMemory<byte> rootKey,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(sourceRows);
        ValidateKey(rootKey);
        ValidateHash(schemaPlanSha256);
        var captureId = Guid.NewGuid();
        string path = PathFor(captureId);
        string qualifiedTable = Qualified(table);
        var context = SnapshotArchiveContext.Create(captureId.ToString("N"), database, schemaPlanSha256);
        long rowCount = 0;
        try
        {
            SnapshotEncryptionResult result;
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
                bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.WriteThrough))
            {
                result = await DeltaCapturedRowCodec.EncryptAsync(table,
                    CountRows(sourceRows, cancellationToken), output, rootKey, context, cancellationToken).ConfigureAwait(false);
                await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            }
            await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None,
                bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            string encryptedSha256 = Convert.ToHexString(await SHA256.HashDataAsync(input, cancellationToken)
                .ConfigureAwait(false)).ToLowerInvariant();
            return new(database, qualifiedTable, captureId, schemaPlanSha256.ToLowerInvariant(),
                encryptedSha256, result.PlaintextSha256, rowCount);
        }
        catch
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
            throw;
        }

        async IAsyncEnumerable<MigrationRow> CountRows(
            IAsyncEnumerable<MigrationRow> rows,
            [EnumeratorCancellation] CancellationToken token = default)
        {
            await foreach (MigrationRow row in rows.WithCancellation(token).ConfigureAwait(false))
            {
                rowCount = checked(rowCount + 1);
                yield return row;
            }
        }
    }

    public async IAsyncEnumerable<MigrationRow> ReplayAsync(
        DeltaCapturedTableArtifact artifact,
        string expectedDatabase,
        TableCopyPlan table,
        string expectedSchemaPlanSha256,
        ReadOnlyMemory<byte> rootKey,
        [EnumeratorCancellation] CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(artifact);
        ArgumentException.ThrowIfNullOrWhiteSpace(expectedDatabase);
        ArgumentNullException.ThrowIfNull(table);
        ValidateKey(rootKey);
        ValidateHash(expectedSchemaPlanSha256);
        ValidateHash(artifact.SchemaPlanSha256);
        ValidateHash(artifact.EncryptedSha256);
        ValidateHash(artifact.PlaintextSha256);
        if (artifact.CaptureId == Guid.Empty || artifact.RowCount < 0 ||
            !string.Equals(artifact.Database, expectedDatabase, StringComparison.Ordinal) ||
            !FixedHashEquals(artifact.SchemaPlanSha256, expectedSchemaPlanSha256) ||
            !string.Equals(artifact.Table, Qualified(table), StringComparison.Ordinal))
        {
            throw Invalid();
        }

        string path = PathFor(artifact.CaptureId);
        await using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None,
            bufferSize: 64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
        string observed = Convert.ToHexString(await SHA256.HashDataAsync(input, cancellationToken)
            .ConfigureAwait(false)).ToLowerInvariant();
        if (!FixedHashEquals(observed, artifact.EncryptedSha256))
        {
            throw Invalid();
        }
        var context = SnapshotArchiveContext.Create(artifact.CaptureId.ToString("N"), artifact.Database,
            artifact.SchemaPlanSha256);
        input.Position = 0;
        using (var plaintextDigest = new Sha256Sink())
        {
            await SnapshotEncryption.DecryptAsync(input, plaintextDigest, rootKey, context, cancellationToken)
                .ConfigureAwait(false);
            if (!FixedHashEquals(plaintextDigest.Finish(), artifact.PlaintextSha256))
            {
                throw Invalid();
            }
        }
        input.Position = 0;
        long rows = 0;
        await foreach (MigrationRow row in DeltaCapturedRowCodec.DecryptAsync(
            table, input, rootKey, context, cancellationToken).WithCancellation(cancellationToken).ConfigureAwait(false))
        {
            rows = checked(rows + 1);
            yield return row;
        }
        if (rows != artifact.RowCount)
        {
            throw Invalid();
        }
    }

    public async Task<DeltaCapturedTableArtifact> CapturePlannedRowsAsync(
        DeltaCapturedTableArtifact fullCapture,
        string database,
        TableCopyPlan table,
        string schemaPlanSha256,
        DeltaTablePlan plan,
        ReadOnlyMemory<byte> rootKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(fullCapture);
        ArgumentNullException.ThrowIfNull(table);
        ArgumentNullException.ThrowIfNull(plan);
        if (!string.Equals(plan.Table, Qualified(table), StringComparison.Ordinal) ||
            !DeltaSynchronizationPlanProducer.FixedHashEquals(plan.OperationsSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeOperationsSha256(plan.Operations)) ||
            plan.InsertCount != plan.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Insert) ||
            plan.UpdateCount != plan.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Update) ||
            plan.DeleteCount != plan.Operations.LongCount(operation => operation.Kind == DeltaOperationKind.Delete) ||
            plan.UnchangedCount < 0 ||
            fullCapture.RowCount != checked(plan.InsertCount + plan.UpdateCount + plan.UnchangedCount) ||
            plan.Operations.Select(operation => operation.KeySha256)
                .Distinct(StringComparer.Ordinal).Count() != plan.Operations.Count)
        {
            throw new DeltaPlanException("delta_capture_operation_invalid", "The selected capture operation set is invalid.");
        }

        CanonicalDeltaOperation[] changed = [.. plan.Operations.Where(operation =>
            operation.Kind is DeltaOperationKind.Insert or DeltaOperationKind.Update)];
        var remaining = changed.ToDictionary(operation => operation.KeySha256, StringComparer.Ordinal);
        DeltaCapturedTableArtifact selected = await CaptureAsync(database, table, schemaPlanSha256,
            SelectRows(cancellationToken), rootKey, cancellationToken).ConfigureAwait(false);
        return selected.RowCount != changed.LongLength
            ? throw new DeltaPlanException("delta_capture_operation_mismatch", "The selected source capture is incomplete.")
            : selected;

        async IAsyncEnumerable<MigrationRow> SelectRows(
            [EnumeratorCancellation] CancellationToken token = default)
        {
            await foreach (MigrationRow row in ReplayAsync(fullCapture, database, table,
                schemaPlanSha256, rootKey, token).WithCancellation(token).ConfigureAwait(false))
            {
                string key = CanonicalDeltaPlanner.ComputeKeySha256(table, row);
                if (remaining.Remove(key, out CanonicalDeltaOperation? operation))
                {
                    yield return row;
                    string observed = CanonicalRowFingerprint.Compute(table, [row]);
                    if (!DeltaSynchronizationPlanProducer.FixedHashEquals(
                        observed, operation.SourceRowSha256 ?? string.Empty))
                    {
                        throw new DeltaPlanException("delta_capture_operation_mismatch",
                            "A selected source row no longer matches its planned fingerprint.");
                    }
                }
                else
                {
                    foreach (StreamingLob lob in row.Values.Values.OfType<StreamingLob>())
                    {
                        await lob.ConsumeAsync(Stream.Null, token).ConfigureAwait(false);
                    }
                }
            }
            if (remaining.Count != 0)
            {
                throw new DeltaPlanException("delta_capture_operation_mismatch",
                    "A planned source row is missing from the immutable capture.");
            }
        }
    }

    private static string ValidateDirectory(string protectedDirectory)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(protectedDirectory);
        var directory = new DirectoryInfo(Path.GetFullPath(protectedDirectory));
        return !directory.Exists || directory.Attributes.HasFlag(FileAttributes.ReparsePoint)
            ? throw new DeltaPlanException("delta_capture_directory_invalid",
                "An existing non-linked protected capture directory is required.")
            : directory.FullName;
    }

    private string PathFor(Guid captureId)
    {
        return Path.Combine(_directory, $"{captureId:N}.enc");
    }

    private static string Qualified(TableCopyPlan table)
    {
        return $"{table.TargetSchema}.{table.TargetTable}";
    }

    private static void ValidateKey(ReadOnlyMemory<byte> rootKey)
    {
        if (rootKey.Length != 32)
        {
            throw new DeltaPlanException("delta_capture_key_invalid", "An independent 256-bit capture key is required.");
        }
    }

    private static void ValidateHash(string value)
    {
        if (value is null || value.Length != 64 || !value.All(char.IsAsciiHexDigit))
        {
            throw Invalid();
        }
    }

    private static bool FixedHashEquals(string left, string right)
    {
        return CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
            System.Text.Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static DeltaPlanException Invalid()
    {
        return new("delta_capture_artifact_invalid",
            "The encrypted captured table artifact is missing, changed, or bound to a different table or schema.");
    }

}

/// <summary>Replays signed-source candidates from encrypted artifacts instead of mutable SQL Server rows.</summary>
public sealed class DeltaCapturedTableRowSource : IDeltaOrderedRowSource, IDisposable
{
    private readonly DeltaCapturedTableArchive _archive;
    private readonly Dictionary<(string Database, string Table), DeltaCapturedTableArtifact> _artifacts;
    private readonly string _schemaPlanSha256;
    private readonly byte[] _rootKey;
    private bool _disposed;

    public DeltaCapturedTableRowSource(DeltaCapturedTableArchive archive,
        IReadOnlyList<DeltaCapturedTableArtifact> artifacts, string schemaPlanSha256, ReadOnlySpan<byte> rootKey)
    {
        ArgumentNullException.ThrowIfNull(archive);
        ArgumentNullException.ThrowIfNull(artifacts);
        if (schemaPlanSha256.Length != 64 || !schemaPlanSha256.All(char.IsAsciiHexDigit) || rootKey.Length != 32)
        {
            throw new DeltaPlanException("delta_capture_source_invalid", "Captured source bindings or key are invalid.");
        }
        _archive = archive;
        _artifacts = artifacts.ToDictionary(artifact => (artifact.Database, artifact.Table));
        _schemaPlanSha256 = schemaPlanSha256;
        _rootKey = rootKey.ToArray();
    }

    public static DeltaCapturedTableRowSource FromSignedPlan(
        DeltaCapturedTableArchive archive,
        DeltaSynchronizationPlan plan,
        IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc,
        ReadOnlySpan<byte> rootKey)
    {
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(trust);
        DeltaSourceCaptureManifest? manifest = plan.SourceCaptureManifest;
        if (plan.SchemaVersion != "1.3" || manifest is null || rootKey.Length != 32 ||
            !DeltaSynchronizationPlanVerifier.Verify(plan, trust, nowUtc))
        {
            throw new DeltaPlanException("delta_capture_plan_invalid", "A current trusted captured-source plan is required.");
        }
        string fingerprint = Convert.ToHexString(SHA256.HashData(rootKey)).ToLowerInvariant();
        if (!CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.ASCII.GetBytes(fingerprint),
            System.Text.Encoding.ASCII.GetBytes(manifest.EncryptionKeyFingerprintSha256.ToLowerInvariant())))
        {
            throw new DeltaPlanException("delta_capture_key_mismatch", "The captured-source key does not match the signed plan.");
        }
        DeltaCapturedTableArtifact[] artifacts = [.. manifest.Databases.SelectMany(database =>
            database.Tables.Select(table => new DeltaCapturedTableArtifact(
                database.Database, table.Table, table.CaptureId, plan.SchemaPlanSha256,
                table.EncryptedSha256, table.PlaintextSha256, table.CapturedRowCount)))];
        return new(archive, artifacts, plan.SchemaPlanSha256, rootKey);
    }

    public IAsyncEnumerable<MigrationRow> ReadOrderedAsync(
        string database, TableCopyPlan table, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ArgumentException.ThrowIfNullOrWhiteSpace(database);
        ArgumentNullException.ThrowIfNull(table);
        string qualified = $"{table.TargetSchema}.{table.TargetTable}";
        return !_artifacts.TryGetValue((database, qualified), out DeltaCapturedTableArtifact? artifact)
            ? throw new DeltaPlanException("delta_capture_table_missing", "The captured source table is not available.")
            : _archive.ReplayAsync(artifact, database, table, _schemaPlanSha256, _rootKey, cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }
        _disposed = true;
        CryptographicOperations.ZeroMemory(_rootKey);
    }
}

internal sealed class Sha256Sink : Stream
{
    private readonly IncrementalHash _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();
    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public string Finish()
    {
        return Convert.ToHexString(_hash.GetHashAndReset()).ToLowerInvariant();
    }

    public override void Flush() { }
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }
    public override void Write(byte[] buffer, int offset, int count)
    {
        _hash.AppendData(buffer, offset, count);
    }
    public override void Write(ReadOnlySpan<byte> buffer)
    {
        _hash.AppendData(buffer);
    }
    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _hash.AppendData(buffer.Span);
        return ValueTask.CompletedTask;
    }
    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _hash.Dispose();
        }
        base.Dispose(disposing);
    }
}
