using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerClosedLaneInput(string InputBindingPath, string InputBindingSha256,
    string SourceSchemaPath, string SourceSchemaSha256, CurrentCustomerSequenceRepairSourceInputs SourceInputs,
    string MaintenanceValidatorSourcePath, CustomerClosedSeedEvidence Completed,
    string TestAssemblyPath, string TestAssemblySha256, string ConsoleAssemblySha256, string CoreAssemblySha256,
    string TestBundleBindingPath, string TestBundleBindingSha256);

internal static class CustomerClosedCompletedReadback
{
    // Authentication of original 13/6/4 evidence only, independent of any future
    // case target/operation or result. This creates no repair scope or permission.
    internal static CustomerDefinitionSubject Require(CustomerClosedLaneInput input, DateTimeOffset now)
    {
        RequireTestBundle(input);
        if (!CurrentCustomerSequenceRepairPermit.HashShape(input.TestAssemblySha256) ||
            Image(typeof(MigrationConsole).Assembly.Location) != input.ConsoleAssemblySha256 ||
            Image(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location) != input.CoreAssemblySha256 ||
            Image(input.TestAssemblyPath) != input.TestAssemblySha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        LocalExecutionBinding binding = ReadProtected<LocalExecutionBinding>(input.Completed.PrecursorBindingPath, 65536);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        var e = input.Completed;
        RequireExactBinding(files, e.PrecursorBindingPath, binding);
        var subject = Read<CustomerDefinitionSubject>(e.IntendedSubjectPath);
        if (subject.ConsoleAssemblySha256 != input.ConsoleAssemblySha256 || subject.CoreAssemblySha256 != input.CoreAssemblySha256 ||
            subject.SourceSchemaPlanSha256 != input.SourceSchemaSha256 || e.PrecursorTrustKeys.Count is < 1 or > 16 ||
            e.PrecursorTrustKeys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != e.PrecursorTrustKeys.Count)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var trust = new ReceiptAttestationTrustStore(e.PrecursorTrustKeys.Select(key =>
        {
            byte[] der = files.Read(key.PublicKeyPath, sharedReader: true, maximumBytes: 65536);
            return CurrentCustomerSequenceRepairPermit.Hash(der) != key.FingerprintSha256
                ? throw CurrentCustomerSequenceRepairPermit.Invalid()
                : new TrustedAttestationKey(key.KeyId, der);
        }).ToArray());
        var definition = Decode<CustomerDefinitionProof>(Artifact(e.Definition));
        CustomerDefinitionPrecursorReader.Require(files, definition, subject, trust, e.DefinitionKey.KeyId, e.DefinitionKey.FingerprintSha256, now);
        if (definition.Cases.Any(x => x.TestAssembly.Sha256 != input.TestAssemblySha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (var pair in new[] {(e.NativeComponent,e.NativeKey,"current-customer-sequence-native-bootstrap-precursor-v1",6),
            (e.MaintenanceComponent,e.MaintenanceKey,"current-customer-sequence-maintenance-bootstrap-precursor-v1",4)})
        {
            var report = Decode<CustomerGuardedBootstrapProof>(Artifact(pair.Item1));
            if (report.Kind != pair.Item3 || report.Cases.Count != pair.Item4 || report.DefinitionPrecursor.Sha256 != e.Definition.Sha256 ||
                report.DefinitionKeyId != e.DefinitionKey.KeyId || report.DefinitionFingerprint != e.DefinitionKey.FingerprintSha256 ||
                report.Cases.Any(x => x.TestAssembly.Sha256 != input.TestAssemblySha256)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            CustomerGuardedBootstrapProofReader.Require(files, report, subject, trust, pair.Item2.KeyId, pair.Item2.FingerprintSha256, now);
        }
        files.Require(); return subject;
        T Read<T>(string path)
        {
            return Decode<T>(files.Read(path, sharedReader: true, maximumBytes: 8_000_000));
        }

        byte[] Artifact(CustomerDefinitionArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000);
            return CurrentCustomerSequenceRepairPermit.Hash(bytes) == artifact.Sha256 ? bytes : throw CurrentCustomerSequenceRepairPermit.Invalid();
        }
    }
    internal static void RequireTestBundle(CustomerClosedLaneInput input)
    {
        var binding = ReadProtected<LocalExecutionBinding>(input.TestBundleBindingPath, 65536);
        if (binding.ComputeSha256() != input.TestBundleBindingSha256 ||
            Path.GetDirectoryName(Path.GetFullPath(input.TestAssemblyPath)) != binding.ArtifactRootCanonicalPath ||
            binding.ArtifactRootCanonicalPath == Path.GetDirectoryName(Path.GetFullPath(input.Completed.PrecursorBindingPath)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        RequireExactBinding(files, input.TestBundleBindingPath, binding);
        var image = files.BorrowReadStream(input.TestAssemblyPath, 128 * 1024 * 1024); image.Position = 0;
        if (Convert.ToHexStringLower(SHA256.HashData(image)) != input.TestAssemblySha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        files.Require();
    }
    internal static DateTimeOffset MaximumExpires(CustomerClosedLaneInput input)
    {
        var binding = ReadProtected<LocalExecutionBinding>(input.Completed.PrecursorBindingPath, 65536);
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        RequireExactBinding(files, input.Completed.PrecursorBindingPath, binding);
        DateTimeOffset? expires = null;
        foreach (var a in new[] { input.Completed.Definition, input.Completed.NativeComponent, input.Completed.MaintenanceComponent })
        {
            byte[] bytes = files.Read(a.Path, sharedReader: true, maximumBytes: 8_000_000);
            if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != a.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            using var document = JsonDocument.Parse(bytes); var observed = document.RootElement.GetProperty("ExpiresAtUtc").GetDateTimeOffset();
            if (observed.Offset != TimeSpan.Zero) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            if (expires is null || observed < expires.Value) { expires = observed; }
        }
        files.Require(); return expires ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
    }
    internal static void RequireExactBinding(CurrentAppOwnedRepairCustody files, string path, LocalExecutionBinding binding)
    {
        var actual = Decode<LocalExecutionBinding>(files.Read(path, sharedReader: true, maximumBytes: 65536));
        if (actual != binding) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal static T ReadProtected<T>(string path, int maximum)
    {
        using var stream = SecureLocalFile.OpenReadShared(path);
        if (stream.Length is < 1 || stream.Length > maximum) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return Decode<T>(bytes);
    }
    internal static T Decode<T>(byte[] bytes)
    {
        return JsonSerializer.Deserialize<T>(bytes) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
    }

    internal static string Image(string path)
    {
        using var stream = SecureLocalFile.OpenReadShared(path); return stream.Length is < 1 or > 128 * 1024 * 1024
        ? throw CurrentCustomerSequenceRepairPermit.Invalid()
        : Convert.ToHexStringLower(SHA256.HashData(stream));
    }
}
