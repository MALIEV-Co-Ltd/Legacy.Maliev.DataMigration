using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerSeedTrustKey(string KeyId, string FingerprintSha256, string PublicKeyPath);
internal sealed record CustomerClosedSeedEvidence(string PrecursorBindingPath, string IntendedSubjectPath,
    CustomerDefinitionArtifact Definition, CustomerDefinitionArtifact NativeComponent, CustomerDefinitionArtifact MaintenanceComponent,
    CustomerSeedTrustKey DefinitionKey, CustomerSeedTrustKey NativeKey, CustomerSeedTrustKey MaintenanceKey,
    IReadOnlyList<CustomerSeedTrustKey> PrecursorTrustKeys);

internal static class CurrentCustomerSequenceClosedSeedReadback
{
    internal static Task RequireAsync(CustomerClosedSeedEvidence evidence, CurrentCustomerSequenceRepairScope namedScope,
        FreshSchemaPlan source, IReceiptAttestationTrustStore seedTrust, CurrentCustomerSequenceRepairSigningPins pins,
        CancellationToken ct)
    {
        return RequireCoreAsync(evidence, namedScope, source, seedTrust, pins, true, ct);
    }

    // Producer observation only; no public admission route calls this unsigned entry.
    internal static Task RequireUnsignedForProducerAsync(CustomerClosedSeedEvidence evidence, CurrentCustomerSequenceRepairScope namedScope,
        FreshSchemaPlan source, IReceiptAttestationTrustStore seedTrust, CurrentCustomerSequenceRepairSigningPins pins,
        CancellationToken ct)
    {
        return RequireCoreAsync(evidence, namedScope, source, seedTrust, pins, false, ct);
    }

    private static Task RequireCoreAsync(CustomerClosedSeedEvidence evidence, CurrentCustomerSequenceRepairScope namedScope,
        FreshSchemaPlan source, IReceiptAttestationTrustStore seedTrust, CurrentCustomerSequenceRepairSigningPins pins, bool signed, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false); ct.ThrowIfCancellationRequested();
        var seed = namedScope.ClosedConsoleSeed ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        CurrentCustomerSequenceClosedBootstrap.Require(seed, namedScope, seedTrust, pins.ReviewKeyId, pins.ReviewFingerprint, DateTimeOffset.UtcNow, signed);
        using var input = SecureLocalFile.OpenReadShared(evidence.PrecursorBindingPath);
        if (input.Length is < 1 or > 65536) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        byte[] bindingBytes = new byte[checked((int)input.Length)]; input.ReadExactly(bindingBytes);
        var binding = Decode<LocalExecutionBinding>(bindingBytes);
        if (binding.ComputeSha256() == namedScope.RunBindingSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        // Separate genuine predecessor root; never reacquire the active named case's lock.
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        if (!files.Read(evidence.PrecursorBindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bindingBytes))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        T Read<T>(string path)
        {
            return Decode<T>(files.Read(path, sharedReader: true, maximumBytes: 8_000_000));
        }

        var intended = Read<CustomerDefinitionSubject>(evidence.IntendedSubjectPath);
        if (seed.PrecursorSubjectSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(intended) ||
            intended.Source.CommitSha != namedScope.SourceCommitSha || intended.Source.CatalogReportSha256 != namedScope.CatalogReportSha256 ||
            intended.SourceSchemaPlanSha256 != namedScope.SourceSchemaPlanSha256 || SchemaPlanCanonicalizer.ComputeSha256(source) != namedScope.SourceSchemaPlanSha256 ||
            intended.DefinitionSha256 != namedScope.DefinitionSha256 || intended.Owner.Head != seed.OwnerHead ||
            intended.Owner.ContextSha256 != seed.OwnerContextSha256 || intended.Owner.SnapshotSha256 != seed.OwnerSnapshotSha256 ||
            intended.CoreAssemblySha256 != seed.CoreAssemblySha256 || intended.ConsoleAssemblySha256 != seed.ConsoleAssemblySha256 ||
            HashFile(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location) != seed.CoreAssemblySha256 ||
            HashFile(typeof(MigrationConsole).Assembly.Location) != seed.ConsoleAssemblySha256 ||
            evidence.Definition.Sha256 != seed.DefinitionPrecursorSha256 || evidence.NativeComponent.Sha256 != seed.NativeComponentSha256 ||
            evidence.MaintenanceComponent.Sha256 != seed.MaintenanceComponentSha256 || evidence.PrecursorTrustKeys.Count is < 1 or > 16 ||
            evidence.PrecursorTrustKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != evidence.PrecursorTrustKeys.Count)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var trust = new ReceiptAttestationTrustStore(evidence.PrecursorTrustKeys.Select(key =>
        {
            byte[] bytes = files.Read(key.PublicKeyPath, sharedReader: true, maximumBytes: 65536);
            return Convert.ToHexStringLower(SHA256.HashData(bytes)) != key.FingerprintSha256
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : new TrustedAttestationKey(key.KeyId, bytes);
        }).ToArray());
        byte[] ReadArtifact(CustomerDefinitionArtifact artifact)
        {
            ct.ThrowIfCancellationRequested(); CurrentCustomerSequenceCapacity.Require(admission: false); files.Require();
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000);
            return CurrentCustomerSequenceRepairPermit.Hash(bytes) != artifact.Sha256
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : bytes;
        }
        CustomerDefinitionPrecursorReader.Require(files, Decode<CustomerDefinitionProof>(ReadArtifact(evidence.Definition)), intended,
            trust, evidence.DefinitionKey.KeyId, evidence.DefinitionKey.FingerprintSha256, DateTimeOffset.UtcNow);
        foreach (var (artifact, key, kind, count) in new[] {
            (evidence.NativeComponent, evidence.NativeKey, "current-customer-sequence-native-bootstrap-precursor-v1", 6),
            (evidence.MaintenanceComponent, evidence.MaintenanceKey, "current-customer-sequence-maintenance-bootstrap-precursor-v1", 4) })
        {
            var report = Decode<CustomerGuardedBootstrapProof>(ReadArtifact(artifact));
            if (report.Kind != kind || report.Cases.Count != count || report.DefinitionPrecursor.Sha256 != evidence.Definition.Sha256 ||
                report.Cases.Any(x => x.TestAssembly.Sha256 != seed.TestAssemblySha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CustomerGuardedBootstrapProofReader.Require(files, report, intended, trust, key.KeyId, key.FingerprintSha256, DateTimeOffset.UtcNow);
        }
        var definition = Read<CustomerDefinitionProof>(evidence.Definition.Path);
        if (definition.Cases.Any(x => x.TestAssembly.Sha256 != seed.TestAssemblySha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        files.Require(); CurrentCustomerSequenceCapacity.Require(admission: false); return Task.CompletedTask;
    }
    private static T Decode<T>(byte[] bytes)
    {
        return JsonSerializer.Deserialize<T>(bytes) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
    }

    private static string HashFile(string path) { using var stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
}
