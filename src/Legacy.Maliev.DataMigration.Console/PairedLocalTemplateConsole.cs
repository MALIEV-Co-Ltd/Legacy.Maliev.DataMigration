using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

public static partial class MigrationConsole
{
    internal static async Task ProjectPairedLocalTemplateAsync(
        PairedLocalTemplateCommandConfiguration candidate,
        Func<string, string?> environment,
        IPairedLocalTemplateObserver observer,
        CancellationToken cancellationToken)
    {
        if (candidate.Disposable is null || candidate.Persistent is null ||
            string.IsNullOrWhiteSpace(candidate.SchemaPlanPath) ||
            string.IsNullOrWhiteSpace(candidate.SourceConnectionFile) ||
            string.IsNullOrWhiteSpace(candidate.RunnerAssemblyPath) ||
            string.IsNullOrWhiteSpace(candidate.OutputPath))
        {
            throw DeltaInvalid("delta_paired_template_input_invalid");
        }
        PairedLocalTemplateProjection.ValidateRoleClaims(candidate);
        if (!string.Equals(environment(DeployEnabledEnvironmentVariable), "false", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(environment("LEGACY_MIGRATION_CALLER"), "owner", StringComparison.Ordinal))
        {
            throw DeltaInvalid("delta_paired_template_caller_invalid");
        }
        if (string.IsNullOrWhiteSpace(candidate.OutputPath) || File.Exists(candidate.OutputPath) ||
            Directory.Exists(candidate.OutputPath))
        {
            throw DeltaInvalid("delta_output_exists");
        }
        OwnerProtectedFilePolicy.ValidatePublicationParent(candidate.OutputPath);
        FreshSchemaPlan schema = await ReadProtectedJsonAsync<FreshSchemaPlan>(candidate.SchemaPlanPath,
            "delta_schema_plan_unprotected", cancellationToken).ConfigureAwait(false);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (schema.SchemaVersion != "2.0" || schema.Databases is null ||
            schema.CapturedAtUtc.Offset != TimeSpan.Zero ||
            schema.CapturedAtUtc > now || now - schema.CapturedAtUtc > TimeSpan.FromHours(24) ||
            schema.Databases.Count != DatabaseInventory.ActiveDatabases.Count ||
            !schema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            schema.Databases.Single(database => database.Database == "Quotation").SourceDispositionProfile !=
                "quotation-outboxes-v1")
        {
            throw DeltaInvalid("delta_paired_template_schema_invalid");
        }
        if (!IsSha256(candidate.BackupManifestSha256) || !IsSha256(candidate.BackupKeyFingerprintSha256))
        {
            throw DeltaInvalid("delta_paired_template_baseline_invalid");
        }
        string source = await ReadProtectedTextAsync(candidate.SourceConnectionFile,
            "delta_source_connection_unprotected", cancellationToken).ConfigureAwait(false);
        if (string.IsNullOrWhiteSpace(source) || !File.Exists(candidate.RunnerAssemblyPath) ||
            !string.Equals(Path.GetFullPath(candidate.RunnerAssemblyPath),
                Path.GetFullPath(typeof(MigrationConsole).Assembly.Location), StringComparison.OrdinalIgnoreCase))
        {
            throw DeltaInvalid("delta_paired_template_input_invalid");
        }
        string runnerDigest = Convert.ToHexString(SHA256.HashData(
            await File.ReadAllBytesAsync(candidate.RunnerAssemblyPath, cancellationToken).ConfigureAwait(false)))
            .ToLowerInvariant();

        PairedLocalTemplateTarget[] targets = [candidate.Disposable, candidate.Persistent];
        string[] connections = new string[2];
        var fingerprints = new List<string> { candidate.BackupKeyFingerprintSha256 };
        var keyIds = new HashSet<string>(StringComparer.Ordinal);
        var privatePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        for (var index = 0; index < targets.Length; index++)
        {
            PairedLocalTemplateTarget target = targets[index];
            if (target.PlanKey is null || target.AuthorizationKey is null || target.EvidenceKey is null ||
                string.IsNullOrWhiteSpace(target.TargetConnectionFile) ||
                string.IsNullOrWhiteSpace(target.DockerContainerId) ||
                string.IsNullOrWhiteSpace(target.DockerVolumeName))
            {
                throw DeltaInvalid("delta_paired_template_input_invalid");
            }
            connections[index] = await ReadProtectedTextAsync(target.TargetConnectionFile,
                "delta_target_connection_unprotected", cancellationToken).ConfigureAwait(false);
            foreach ((DeltaTrustedKeyReference reference, string variable) in SigningRoles(target, index == 1))
            {
                if (string.IsNullOrWhiteSpace(reference.KeyId) || !keyIds.Add(reference.KeyId))
                {
                    throw DeltaInvalid("delta_paired_template_key_reuse");
                }
                string publicText = await ReadProtectedTextAsync(reference.SubjectPublicKeyInfoPath,
                    "delta_paired_template_key_unprotected", cancellationToken).ConfigureAwait(false);
                var trust = new ReceiptAttestationTrustStore(
                    [new TrustedAttestationKey(reference.KeyId, Convert.FromBase64String(publicText))]);
                if (!trust.TryGetPublicKeyFingerprintSha256(reference.KeyId, out string fingerprint) ||
                    !IsSha256(fingerprint) || fingerprints.Contains(fingerprint, StringComparer.OrdinalIgnoreCase))
                {
                    throw DeltaInvalid("delta_paired_template_key_reuse");
                }
                fingerprints.Add(fingerprint);
                string privatePath = environment(variable) ?? string.Empty;
                if (string.IsNullOrWhiteSpace(privatePath) || !privatePaths.Add(Path.GetFullPath(privatePath)))
                {
                    throw DeltaInvalid("delta_paired_template_private_key_missing_or_reused");
                }
                using P256MigrationEvidenceSigner signer = await ReadDeltaSignerAsync(environment, variable,
                    reference.KeyId, fingerprint, "delta_paired_template_private_key_unprotected",
                    cancellationToken).ConfigureAwait(false);
            }
        }
        if (string.Equals(Path.GetFullPath(targets[0].TargetConnectionFile),
                Path.GetFullPath(targets[1].TargetConnectionFile), StringComparison.OrdinalIgnoreCase))
        {
            throw DeltaInvalid("delta_paired_template_connection_reuse");
        }

        ObservedPairedLocalTarget disposable = await observer.ObserveAsync(candidate.Disposable,
            connections[0], schema, cancellationToken).ConfigureAwait(false);
        ObservedPairedLocalTarget persistent = await observer.ObserveAsync(candidate.Persistent,
            connections[1], schema, cancellationToken).ConfigureAwait(false);
        PairedLocalTemplateProjection.ValidateObservations(candidate, disposable, persistent, DateTimeOffset.UtcNow);
        DeltaCommandConfiguration delta = new(candidate.SchemaPlanPath, candidate.OutputPath,
            candidate.SourceConnectionFile, candidate.Disposable.TargetConnectionFile,
            candidate.Disposable.PlanKey, candidate.Disposable.AuthorizationKey, candidate.Disposable.EvidenceKey,
            candidate.BackupKeyFingerprintSha256, now, candidate.BackupManifestSha256, runnerDigest,
            "local-aspire", "legacy-postgres-main-local", disposable.Generation,
            disposable.ObservationSha256, disposable.Authority,
            AllowPlanSigning: true, AllowAuthorizationSigning: true, AllowExecution: true,
            SourceMode: DeltaSourceMode.LiveReadOnly, UseCapturedSource: true,
            UseQuotationPhysicalTransition: true,
            PairedPersistentTarget: new(candidate.Persistent.TargetConnectionFile,
                candidate.Persistent.PlanKey, candidate.Persistent.AuthorizationKey, candidate.Persistent.EvidenceKey,
                "local-aspire", "legacy-postgres-main-local", persistent.Generation,
                persistent.ObservationSha256, persistent.Authority));
        await WriteNewJsonAsync(candidate.OutputPath, new { delta }, cancellationToken).ConfigureAwait(false);
    }

    private static IEnumerable<(DeltaTrustedKeyReference Reference, string Variable)> SigningRoles(
        PairedLocalTemplateTarget target, bool persistent)
    {
        yield return (target.PlanKey, persistent ? PairedPlanSigningKeyEnvironmentVariable : DeltaPlanSigningKeyEnvironmentVariable);
        yield return (target.AuthorizationKey, persistent ?
            "LEGACY_MIGRATION_PERSISTENT_DELTA_AUTHORIZATION_SIGNING_KEY_FILE" : DeltaAuthorizationSigningKeyEnvironmentVariable);
        yield return (target.EvidenceKey, persistent ?
            "LEGACY_MIGRATION_PERSISTENT_DELTA_EVIDENCE_SIGNING_KEY_FILE" : DeltaEvidenceSigningKeyEnvironmentVariable);
    }
}

internal sealed record PairedLocalTemplateCommandConfiguration(
    string SchemaPlanPath,
    string OutputPath,
    string SourceConnectionFile,
    string RunnerAssemblyPath,
    string BackupManifestSha256,
    string BackupKeyFingerprintSha256,
    PairedLocalTemplateTarget Disposable,
    PairedLocalTemplateTarget Persistent);

internal sealed record PairedLocalTemplateTarget(
    string TargetConnectionFile,
    string DockerContainerId,
    string DockerVolumeName,
    DeltaTrustedKeyReference PlanKey,
    DeltaTrustedKeyReference AuthorizationKey,
    DeltaTrustedKeyReference EvidenceKey);

internal sealed record ObservedPairedLocalTarget(
    string ContainerId,
    string VolumeName,
    int LoopbackPort,
    string Generation,
    string ObservationSha256,
    DeltaTargetAuthority Authority,
    DateTimeOffset ObservedAtUtc);

internal interface IPairedLocalTemplateObserver
{
    Task<ObservedPairedLocalTarget> ObserveAsync(PairedLocalTemplateTarget candidate,
        string connectionString, FreshSchemaPlan schema, CancellationToken cancellationToken);
}

internal static class PairedLocalTemplateProjection
{
    internal static void ValidateRoleClaims(PairedLocalTemplateCommandConfiguration candidate)
    {
        if (candidate.Disposable.DockerVolumeName is null ||
            !candidate.Disposable.DockerVolumeName.StartsWith("legacy-delta-proof-", StringComparison.Ordinal) ||
            candidate.Disposable.DockerVolumeName.Length <= "legacy-delta-proof-".Length ||
            candidate.Persistent.DockerVolumeName != "legacy-maliev-exact23-postgres-data")
        {
            throw new MigrationConsoleException("delta_paired_template_role_invalid",
                "The disposable proof volume and persistent LOCAL volume are not interchangeable.");
        }
    }

    internal static void ValidateObservations(PairedLocalTemplateCommandConfiguration candidate,
        ObservedPairedLocalTarget disposable, ObservedPairedLocalTarget persistent, DateTimeOffset now)
    {
        ValidateRoleClaims(candidate);
        ValidateTarget(candidate.Disposable, disposable, "disposable-", now);
        ValidateTarget(candidate.Persistent, persistent, "persistent-", now);
        if (disposable.ContainerId == persistent.ContainerId ||
            disposable.VolumeName == persistent.VolumeName ||
            disposable.LoopbackPort == persistent.LoopbackPort ||
            disposable.Authority.SystemIdentifierSha256 == persistent.Authority.SystemIdentifierSha256 ||
            disposable.ObservationSha256 == persistent.ObservationSha256)
        {
            throw new MigrationConsoleException("delta_paired_template_target_reuse",
                "The disposable and persistent LOCAL targets must be independent.");
        }
    }

    private static void ValidateTarget(PairedLocalTemplateTarget claimed, ObservedPairedLocalTarget observed,
        string label, DateTimeOffset now)
    {
        if (!string.Equals(claimed.DockerContainerId, observed.ContainerId, StringComparison.Ordinal) ||
            !string.Equals(claimed.DockerVolumeName, observed.VolumeName, StringComparison.Ordinal) ||
            observed.ContainerId.Length != 64 || !observed.ContainerId.All(char.IsAsciiHexDigit) ||
            observed.LoopbackPort is < 1 or > 65535 ||
            !LocalDockerGenerationGuard.IsGenerationFor(observed.Generation, observed.ContainerId) ||
            observed.ObservationSha256.Length != 64 || !observed.ObservationSha256.All(char.IsAsciiHexDigit) ||
            observed.Authority.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            observed.Authority.AuthorityId !=
                "aspire://legacy-postgres-main-local/" + label + observed.ContainerId[..12] ||
            observed.Authority.SystemIdentifierSha256.Length != 64 ||
            !observed.Authority.SystemIdentifierSha256.All(char.IsAsciiHexDigit) ||
            observed.ObservedAtUtc.Offset != TimeSpan.Zero || observed.ObservedAtUtc > now.AddMinutes(1) ||
            now - observed.ObservedAtUtc > TimeSpan.FromMinutes(15))
        {
            throw new MigrationConsoleException("delta_paired_template_observation_invalid",
                "A fresh, independently observed LOCAL target is required.");
        }
    }
}
