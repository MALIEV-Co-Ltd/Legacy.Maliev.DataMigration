using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed class OperatorAttestationException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record ReviewedExecutionAuthorizationRequest(
    string ExpectedSourceCommitSha,
    string ReviewedSchemaPlanSha256,
    RunnerArtifactManifest RunnerManifest,
    CloudNativePgTargetObservation TargetObservation,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    bool AllowShadowAuthorization,
    double MaximumReceiptAgeMinutes);

public static partial class ReviewedExecutionAuthorizationProducer
{
    public static ExecutionAuthorizationReceipt Produce(
        ReviewedExecutionAuthorizationRequest request,
        BackupReceipt backupReceipt,
        FreshSchemaPlan plan,
        IReceiptAttestationTrustStore backupTrust,
        P256MigrationEvidenceSigner authorizationSigner,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(backupReceipt);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(backupTrust);
        ArgumentNullException.ThrowIfNull(authorizationSigner);
        if (!request.AllowShadowAuthorization)
        {
            throw Error("authorization_owner_review_required", "Explicit owner review is required before shadow authorization can be signed.");
        }
        if (!CommitSha().IsMatch(request.ExpectedSourceCommitSha) ||
            !Sha256().IsMatch(request.ReviewedSchemaPlanSha256) ||
            request.RunnerManifest is null ||
            request.TargetObservation is null ||
            !Sha256().IsMatch(request.RunnerManifest.ManifestSha256) ||
            request.RunnerManifest.Files.Count == 0 ||
            !request.TargetObservation.IsHealthy ||
            !string.Equals(request.TargetObservation.Namespace, "maliev-legacy", StringComparison.Ordinal) ||
            !string.Equals(request.TargetObservation.Cluster, "legacy-postgres-main", StringComparison.Ordinal))
        {
            throw Error("authorization_review_binding_invalid", "The reviewed execution binding is invalid.");
        }
        if (request.IssuedAtUtc.Offset != TimeSpan.Zero || request.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            request.IssuedAtUtc > nowUtc || request.ExpiresAtUtc <= nowUtc ||
            request.ExpiresAtUtc <= request.IssuedAtUtc ||
            request.ExpiresAtUtc - request.IssuedAtUtc > GuardedRunnerPolicy.MaximumAuthorizationLifetime)
        {
            throw Error("authorization_time_window_invalid", "Authorization must use a current UTC approval window no longer than one hour.");
        }

        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan);
        if (!FixedHashEquals(planSha256, request.ReviewedSchemaPlanSha256))
        {
            throw Error("authorization_reviewed_plan_mismatch", "The fresh plan does not match the independently reviewed digest.");
        }

        var policy = new GuardedRunnerPolicy(request.ExpectedSourceCommitSha, request.RunnerManifest.ManifestSha256);
        if (SchemaPlanCanonicalizer.Validate(plan, policy, nowUtc, GuardedRunnerPolicy.MaximumSchemaPlanAge).Count > 0)
        {
            throw Error("authorization_plan_invalid", "The fresh exact-24 schema plan is invalid or stale.");
        }
        try
        {
            VerifiedBackupRestorer.ValidateReceipt(
                backupReceipt, backupTrust, nowUtc, TimeSpan.FromMinutes(request.MaximumReceiptAgeMinutes));
        }
        catch (Exact25FullBackupException)
        {
            throw Error("authorization_backup_receipt_invalid", "The signed exact-24 backup receipt is invalid or stale.");
        }

        if (backupReceipt.AttestationKeyId is null ||
            !backupTrust.TryGetPublicKeyFingerprintSha256(backupReceipt.AttestationKeyId, out string backupFingerprint) ||
            FixedHashEquals(backupFingerprint, authorizationSigner.PublicKeyFingerprintSha256))
        {
            throw Error("authorization_key_role_reuse", "Backup and authorization roles require distinct P-256 keys.");
        }

        var unsigned = new ExecutionAuthorizationReceipt(
            "2.1",
            Guid.NewGuid(),
            request.IssuedAtUtc.ToUniversalTime(),
            request.ExpiresAtUtc.ToUniversalTime(),
            plan.SourceCommitSha,
            planSha256,
            backupReceipt.ManifestSha256,
            request.RunnerManifest.ManifestSha256.ToLowerInvariant(),
            request.TargetObservation.Generation.ToString(System.Globalization.CultureInfo.InvariantCulture),
            DatabaseInventory.ActiveDatabases,
            "shadow-only",
            authorizationSigner.KeyId,
            null)
        {
            TargetObservation = request.TargetObservation,
        };
        var authorizationTrust = new ReceiptAttestationTrustStore(
        [
            new(authorizationSigner.KeyId, authorizationSigner.ExportSubjectPublicKeyInfo()),
        ]);
        if (ExecutionAuthorizationValidator.Validate(unsigned, plan, backupReceipt, policy, nowUtc, authorizationTrust).Count is not 1)
        {
            // The unsigned signature is the sole expected pre-sign validation error.
            throw Error("authorization_contract_invalid", "The reviewed authorization contract is invalid.");
        }
        if (!ExecutionAuthorizationAttestation.TryCreatePayload(unsigned, out byte[] payload))
        {
            throw Error("authorization_contract_invalid", "The reviewed authorization cannot be canonicalized.");
        }
        ExecutionAuthorizationReceipt signed = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(authorizationSigner.Sign(payload)),
        };
        return ExecutionAuthorizationValidator.Validate(signed, plan, backupReceipt, policy, nowUtc, authorizationTrust).Count > 0
            ? throw Error("authorization_contract_invalid", "The signed reviewed authorization failed self-verification.")
            : signed;
    }

    private static bool FixedHashEquals(string left, string right)
    {
        return Sha256().IsMatch(left) && Sha256().IsMatch(right) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static OperatorAttestationException Error(string code, string message)
    {
        return new(code, message);
    }

    [GeneratedRegex("^[0-9a-fA-F]{40}$", RegexOptions.CultureInvariant)] private static partial Regex CommitSha();
    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256();
}

public sealed record ReviewedMigrationProvenanceRequest(
    AppHostMigrationEvidenceV2Configuration Evidence,
    string ReviewedSchemaPlanSha256,
    DateTimeOffset IssuedAtUtc,
    bool AllowProvenanceSigning);

public static partial class ReviewedMigrationProvenanceProducer
{
    public static MigrationEvidenceProvenanceReceipt Produce(
        ReviewedMigrationProvenanceRequest request,
        MigrationExecutionResult result,
        BackupReceipt backupReceipt,
        FreshSchemaPlan plan,
        ExecutionAuthorizationReceipt authorization,
        VerifiedRestoreReceipt verifiedRestore,
        PostExportShadowCleanupReceipt cleanupReceipt,
        IReceiptAttestationTrustStore backupTrust,
        IReceiptAttestationTrustStore authorizationTrust,
        IReceiptAttestationTrustStore executionTrust,
        P256MigrationEvidenceSigner provenanceSigner,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!request.AllowProvenanceSigning)
        {
            throw Error("provenance_owner_review_required", "Explicit owner review is required before provenance can be signed.");
        }
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(backupReceipt);
        ArgumentNullException.ThrowIfNull(plan);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(verifiedRestore);
        ArgumentNullException.ThrowIfNull(cleanupReceipt);
        ArgumentNullException.ThrowIfNull(backupTrust);
        ArgumentNullException.ThrowIfNull(authorizationTrust);
        ArgumentNullException.ThrowIfNull(executionTrust);
        ArgumentNullException.ThrowIfNull(provenanceSigner);

        string planSha256 = SchemaPlanCanonicalizer.ComputeSha256(plan);
        if (!Sha256().IsMatch(request.ReviewedSchemaPlanSha256) ||
            !FixedHashEquals(planSha256, request.ReviewedSchemaPlanSha256))
        {
            throw Error("provenance_reviewed_plan_mismatch", "The completed execution does not match the reviewed schema plan digest.");
        }
        if (request.IssuedAtUtc.Offset != TimeSpan.Zero || request.IssuedAtUtc > nowUtc ||
            nowUtc - request.IssuedAtUtc > TimeSpan.FromHours(1))
        {
            throw Error("provenance_time_window_invalid", "Provenance approval must be current and expressed in UTC.");
        }
        if (result.Status is not (MigrationExecutionStatus.Completed or MigrationExecutionStatus.AlreadyCompleted) ||
            result.Receipt.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !ExactNames(result.Receipt.Databases.Select(item => item.Database)) ||
            !ExactNames(result.Receipt.Reconciliation.Select(item => item.Database)))
        {
            throw Error("provenance_execution_invalid", "A completed exact-24 migration result is required.");
        }
        MigrationExecutionReceipt execution = result.Receipt;
        if (!Verify(execution.AttestationKeyId, execution.AttestationSignature,
                MigrationEvidenceAttestation.CreatePayload(execution), executionTrust))
        {
            throw Error("provenance_execution_invalid", "The migration execution receipt signature is invalid.");
        }
        try
        {
            VerifiedBackupRestorer.ValidateReceipt(backupReceipt, backupTrust, nowUtc, TimeSpan.FromHours(6));
        }
        catch (Exact25FullBackupException)
        {
            throw Error("provenance_backup_receipt_invalid", "The signed exact-24 backup receipt is invalid or stale.");
        }
        var policy = new GuardedRunnerPolicy(execution.SourceCommitSha, execution.RunnerDigestSha256);
        if (ExecutionAuthorizationValidator.Validate(authorization, plan, backupReceipt, policy, nowUtc, authorizationTrust).Count > 0)
        {
            throw Error("provenance_authorization_invalid", "The signed execution authorization is invalid or stale.");
        }
        var provenanceTrust = new ReceiptAttestationTrustStore(
        [
            new(provenanceSigner.KeyId, provenanceSigner.ExportSubjectPublicKeyInfo()),
        ]);
        if (verifiedRestore.CleanupDisposition != RestoreCleanupDisposition.Removed ||
            !VerifiedRestoreReceiptAttestation.Verify(verifiedRestore, provenanceTrust) ||
            !FixedHashEquals(verifiedRestore.BackupManifestSha256, backupReceipt.ManifestSha256!) ||
            !ExactNames(verifiedRestore.Artifacts.Select(item => item.Database)))
        {
            throw Error("provenance_cleanup_receipt_invalid", "Completed signed restore cleanup evidence is required before provenance signing.");
        }
        if (!BindingsMatch(execution, authorization, planSha256, backupReceipt.ManifestSha256!))
        {
            throw Error("provenance_binding_invalid", "Execution, authorization, plan, and backup bindings do not match.");
        }
        if (!cleanupReceipt.IsComplete || cleanupReceipt.RunId != execution.RunId ||
            !PostExportShadowCleanupAttestation.Verify(cleanupReceipt, executionTrust) ||
            request.IssuedAtUtc < cleanupReceipt.CleanedAtUtc)
        {
            throw Error("provenance_shadow_cleanup_invalid", "Complete signed post-export shadow cleanup is required before provenance signing.");
        }
        EnsureDistinctRole(provenanceSigner, backupReceipt.AttestationKeyId, backupTrust);
        EnsureDistinctRole(provenanceSigner, authorization.AttestationKeyId, authorizationTrust);
        EnsureDistinctRole(provenanceSigner, execution.AttestationKeyId, executionTrust);

        AppHostMigrationEvidenceV2Configuration evidence = request.Evidence;
        var unsigned = new MigrationEvidenceProvenanceReceipt(
            "1.0",
            evidence.SourceSnapshotId,
            evidence.BackupUri,
            evidence.BackupObjectGeneration,
            evidence.RestoreId,
            evidence.EvidenceId,
            evidence.LeaseId,
            evidence.LeaseAcquiredAtUtc,
            evidence.LeaseExpiresAtUtc,
            execution.RunId,
            execution.SourceCommitSha,
            planSha256,
            execution.BackupManifestSha256,
            execution.RunnerDigestSha256,
            execution.TargetGeneration,
            request.IssuedAtUtc,
            provenanceSigner.KeyId,
            null)
        {
            CleanupReceiptSha256 = PostExportShadowCleanupAttestation.Digest(cleanupReceipt),
        };
        if (!MigrationEvidenceProvenanceAttestation.TryCreatePayload(unsigned, out byte[] payload))
        {
            throw Error("provenance_contract_invalid", "The migration provenance cannot be canonicalized.");
        }
        MigrationEvidenceProvenanceReceipt signed = unsigned with
        {
            AttestationSignature = Convert.ToBase64String(provenanceSigner.Sign(payload)),
        };
        return !Verify(signed.AttestationKeyId, signed.AttestationSignature, payload, provenanceTrust)
            ? throw Error("provenance_contract_invalid", "The signed migration provenance failed self-verification.")
            : signed;
    }

    private static void EnsureDistinctRole(
        P256MigrationEvidenceSigner signer,
        string? keyId,
        IReceiptAttestationTrustStore trust)
    {
        if (keyId is null || !trust.TryGetPublicKeyFingerprintSha256(keyId, out string fingerprint) ||
            FixedHashEquals(fingerprint, signer.PublicKeyFingerprintSha256))
        {
            throw Error("provenance_key_role_reuse", "Backup, authorization, execution, and provenance roles require distinct P-256 keys.");
        }
    }

    private static bool BindingsMatch(
        MigrationExecutionReceipt execution,
        ExecutionAuthorizationReceipt authorization,
        string planSha256,
        string backupManifestSha256)
    {
        return execution.RunId == authorization.RunId &&
        string.Equals(execution.SourceCommitSha, authorization.SourceCommitSha, StringComparison.Ordinal) &&
        FixedHashEquals(execution.SchemaPlanSha256, planSha256) &&
        FixedHashEquals(authorization.SchemaPlanSha256!, planSha256) &&
        FixedHashEquals(execution.BackupManifestSha256, backupManifestSha256) &&
        FixedHashEquals(authorization.BackupManifestSha256!, backupManifestSha256) &&
        FixedHashEquals(execution.RunnerDigestSha256, authorization.RunnerDigestSha256!) &&
        string.Equals(execution.TargetGeneration, authorization.TargetGeneration, StringComparison.Ordinal);
    }

    private static bool ExactNames(IEnumerable<string> names)
    {
        string[] actual = [.. names];
        return actual.Length == DatabaseInventory.ActiveDatabases.Count &&
            actual.Distinct(StringComparer.Ordinal).Count() == actual.Length &&
            actual.Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal);
    }

    private static bool Verify(string? keyId, string? signature, byte[] payload, IReceiptAttestationTrustStore trust)
    {
        if (string.IsNullOrWhiteSpace(keyId) || string.IsNullOrWhiteSpace(signature))
        {
            return false;
        }

        try { return trust.Verify(keyId, payload, Convert.FromBase64String(signature)); }
        catch (FormatException) { return false; }
    }

    private static bool FixedHashEquals(string left, string right)
    {
        return Sha256().IsMatch(left) && Sha256().IsMatch(right) &&
        CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left.ToLowerInvariant()), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static OperatorAttestationException Error(string code, string message)
    {
        return new(code, message);
    }

    [GeneratedRegex("^[0-9a-fA-F]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Sha256();
}
