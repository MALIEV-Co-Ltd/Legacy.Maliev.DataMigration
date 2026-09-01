using System.Collections.ObjectModel;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration;

public sealed record PostExportShadowCleanupReceipt(
    string SchemaVersion,
    Guid RunId,
    string ExecutionReceiptSha256,
    string SnapshotManifestDigestSha256,
    DateTimeOffset CleanedAtUtc,
    IReadOnlyList<ShadowCleanupOutcome> Cleanup,
    string AttestationKeyId,
    string? AttestationSignature)
{
    public bool IsComplete => Cleanup.Count == DatabaseInventory.ActiveDatabases.Count && Cleanup.All(item => item.Deleted);
}

public static class PostExportShadowCleanupAttestation
{
    public static bool Verify(PostExportShadowCleanupReceipt receipt, IReceiptAttestationTrustStore trust)
    {
        try
        {
            return !string.IsNullOrWhiteSpace(receipt.AttestationSignature) &&
                trust.Verify(receipt.AttestationKeyId, MigrationEvidenceAttestation.CreatePayload(receipt),
                    Convert.FromBase64String(receipt.AttestationSignature));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    public static string Digest(PostExportShadowCleanupReceipt receipt)
    {
        return Convert.ToHexString(SHA256.HashData(System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(receipt))).ToLowerInvariant();
    }
}

public sealed class PostExportShadowCleanupService(
    IPostgreSqlShadowTarget target,
    IReceiptAttestationTrustStore backupTrust,
    IReceiptAttestationTrustStore executionTrust,
    IReceiptAttestationTrustStore authorizationTrust,
    IMigrationEvidenceSigner signer,
    ICleanupTargetVerifier targetVerifier,
    TimeProvider timeProvider)
{
    public async Task<PostExportShadowCleanupReceipt> CleanupAsync(
        MigrationExecutionResult execution,
        BackupReceipt backup,
        FreshSchemaPlan plan,
        CleanupAuthorizationReceipt authorization,
        LocalSnapshotManifest snapshot,
        ReadOnlyMemory<byte> snapshotRootKey,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(execution);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(snapshot);
        ValidateExecution(execution);
        ValidateSourceArtifacts(backup, plan, execution.Receipt);
        ValidateAuthorization(authorization, execution.Receipt, snapshot, timeProvider.GetUtcNow());
        CleanupContract.ValidateSnapshot(snapshot, execution.Receipt, snapshotRootKey.Span);

        var outcomes = new List<ShadowCleanupOutcome>(execution.Receipt.Databases.Count);
        foreach (MigratedShadowDatabase migrated in execution.Receipt.Databases.OrderBy(item => item.Database, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            ValidateAuthorization(authorization, execution.Receipt, snapshot, timeProvider.GetUtcNow());
            await targetVerifier.VerifyAsync(authorization, cancellationToken).ConfigureAwait(false);
            var shadow = new ShadowDatabase(migrated.ShadowName, execution.Receipt.RunId.ToString("D"), migrated.Database)
            {
                OwnerAttempt = migrated.OwnerAttempt,
                FencingToken = migrated.FencingToken,
            };
            try
            {
                await target.DeleteRunOwnedShadowAsync(shadow, cancellationToken).ConfigureAwait(false);
                outcomes.Add(new(shadow.Name, true, null)
                {
                    OwnerAttempt = shadow.OwnerAttempt,
                    FencingToken = shadow.FencingToken,
                });
            }
            catch (Exception exception) when (exception is not OperationCanceledException and not OutOfMemoryException and not AccessViolationException)
            {
                outcomes.Add(new(shadow.Name, false, exception is MigrationExecutionException migration ? migration.Code : "shadow_delete_failed")
                {
                    OwnerAttempt = shadow.OwnerAttempt,
                    FencingToken = shadow.FencingToken,
                });
            }
        }

        var unsigned = new PostExportShadowCleanupReceipt(
            "1.0",
            execution.Receipt.RunId,
            CleanupContract.ExecutionDigest(execution.Receipt),
            snapshot.ManifestDigestSha256,
            timeProvider.GetUtcNow(),
            new ReadOnlyCollection<ShadowCleanupOutcome>(outcomes),
            signer.KeyId,
            null);
        byte[] payload = MigrationEvidenceAttestation.CreatePayload(unsigned);
        byte[] signature = signer.Sign(payload);
        return !executionTrust.Verify(signer.KeyId, payload, signature)
            ? throw new MigrationExecutionException("cleanup_evidence_signature_invalid", "Post-export cleanup evidence signer is not trusted.")
            : unsigned with { AttestationSignature = Convert.ToBase64String(signature) };
    }

    private void ValidateSourceArtifacts(BackupReceipt backup, FreshSchemaPlan plan, MigrationExecutionReceipt execution)
    {
        ArgumentNullException.ThrowIfNull(backup);
        ArgumentNullException.ThrowIfNull(plan);
        if (!ReceiptAttestation.TryCreatePayload(backup, out byte[] payload) ||
            !TryDecodeSignature(backup.AttestationSignature, out byte[] signature) ||
            !backupTrust.Verify(backup.AttestationKeyId!, payload, signature) ||
            !CleanupContract.FixedHash(backup.ManifestSha256 ?? string.Empty, execution.BackupManifestSha256) ||
            !CleanupContract.FixedHash(SchemaPlanCanonicalizer.ComputeSha256(plan), execution.SchemaPlanSha256) ||
            !string.Equals(plan.SourceCommitSha, execution.SourceCommitSha, StringComparison.Ordinal))
        {
            throw new MigrationExecutionException("cleanup_source_artifact_invalid", "Cleanup source artifacts do not bind the successful execution.");
        }
    }

    private void ValidateExecution(MigrationExecutionResult execution)
    {
        MigrationExecutionReceipt receipt = execution.Receipt;
        if (execution.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            receipt.RunId == Guid.Empty || receipt.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !receipt.Databases.Select(item => item.Database).Order(StringComparer.Ordinal)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            receipt.Databases.Any(item => item.OwnerAttempt <= 0 || item.FencingToken == Guid.Empty ||
                !string.Equals(item.ShadowName, GuardedShadowMigrationRunner.CreateShadowName(item.Database, receipt.RunId), StringComparison.Ordinal)))
        {
            throw new MigrationExecutionException("cleanup_execution_receipt_invalid", "Cleanup requires the signed, fenced exact-24 successful execution receipt.");
        }

        byte[] signature = DecodeSignature(receipt.AttestationSignature, "cleanup_execution_receipt_invalid");
        if (!executionTrust.Verify(receipt.AttestationKeyId, MigrationEvidenceAttestation.CreatePayload(receipt), signature))
        {
            throw new MigrationExecutionException("cleanup_execution_receipt_invalid", "Cleanup execution evidence signature is not trusted.");
        }
    }

    private void ValidateAuthorization(
        CleanupAuthorizationReceipt authorization,
        MigrationExecutionReceipt execution,
        LocalSnapshotManifest snapshot,
        DateTimeOffset nowUtc)
    {
        byte[] payload = CleanupAuthorizationAttestation.CreatePayload(authorization);
        bool distinctAuthorizationRole = authorizationTrust.TryGetPublicKeyFingerprintSha256(
            authorization.AttestationKeyId, out string authorizationFingerprint) &&
            executionTrust.TryGetPublicKeyFingerprintSha256(execution.AttestationKeyId, out string executionFingerprint) &&
            !string.Equals(authorizationFingerprint, executionFingerprint, StringComparison.OrdinalIgnoreCase);
        if (authorization.SchemaVersion != "1.0" || authorization.RunId != execution.RunId ||
            !CleanupContract.FixedHash(authorization.ExecutionReceiptSha256, CleanupContract.ExecutionDigest(execution)) ||
            !CleanupContract.FixedHash(authorization.SnapshotManifestDigestSha256, snapshot.ManifestDigestSha256) ||
            authorization.Mode != "cleanup-run-owned-shadows" || !authorization.TargetObservation.IsHealthy ||
            !authorization.OwnerApproved ||
            authorization.TargetObservation.Namespace != "maliev-legacy" ||
            authorization.TargetObservation.Cluster != "legacy-postgres-main" ||
            authorization.IssuedAtUtc.Offset != TimeSpan.Zero || authorization.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            authorization.IssuedAtUtc > nowUtc || authorization.ExpiresAtUtc <= nowUtc ||
            authorization.ExpiresAtUtc <= authorization.IssuedAtUtc ||
            authorization.ExpiresAtUtc - authorization.IssuedAtUtc > TimeSpan.FromHours(1) ||
            !distinctAuthorizationRole)
        {
            throw new MigrationExecutionException("cleanup_authorization_invalid", "Cleanup authorization does not bind the successful execution.");
        }

        byte[] signature = DecodeSignature(authorization.AttestationSignature, "cleanup_authorization_invalid");
        if (!authorizationTrust.Verify(authorization.AttestationKeyId, payload, signature))
        {
            throw new MigrationExecutionException("cleanup_authorization_invalid", "Cleanup authorization signature is not trusted.");
        }
    }

    private static byte[] DecodeSignature(string? value, string code)
    {
        try
        {
            return string.IsNullOrWhiteSpace(value) || value.Length > 4096
                ? throw new FormatException()
                : Convert.FromBase64String(value);
        }
        catch (FormatException)
        {
            throw new MigrationExecutionException(code, "A required cleanup input signature is invalid.");
        }
    }

    private static bool TryDecodeSignature(string? value, out byte[] signature)
    {
        try
        {
            signature = string.IsNullOrWhiteSpace(value) || value.Length > 4096
                ? []
                : Convert.FromBase64String(value);
            return signature.Length > 0;
        }
        catch (FormatException)
        {
            signature = [];
            return false;
        }
    }

}
