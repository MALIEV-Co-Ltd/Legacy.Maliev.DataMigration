using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed class Production181PipelineInputs : IDisposable
{
    private readonly Dictionary<string, (WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files)> _roots = [];
    private readonly Production181PipelineConfiguration _configuration;
    internal CustomerDefinitionSubject Subject { get; }
    internal Production181PipelineInputs(Production181PipelineConfiguration configuration, string originalConfigurationPath)
    {
        _configuration = configuration;
        try
        {
            if (configuration.Roots.Count is < 1 or > 128 || configuration.Roots.Select(x => x.Id).Distinct(StringComparer.Ordinal).Count() != configuration.Roots.Count ||
                configuration.Roots.Select(x => x.Binding.ArtifactRootCanonicalPath).Distinct(StringComparer.OrdinalIgnoreCase).Count() != configuration.Roots.Count) { throw Invalid(); }
            foreach (var root in configuration.Roots)
            {
                var authority = WindowsLocalRunAuthority.AcquireResume(root.Binding.ArtifactRootCanonicalPath, root.Binding);
                try { _roots.Add(root.Id, (authority, new CurrentAppOwnedRepairCustody(authority))); }
                catch { authority.Dispose(); throw; }
            }
            string full = Path.GetFullPath(originalConfigurationPath);
            var owner = configuration.Roots.Single(x => StringComparer.OrdinalIgnoreCase.Equals(x.Binding.ArtifactRootCanonicalPath, Path.GetDirectoryName(full)));
            byte[] actual = _roots[owner.Id].Files.Read(full, sharedReader: true, maximumBytes: 8_000_000);
            if (JsonSerializer.Serialize(MigrationConsole.DecodeCustomerSequence<Production181PipelineConfiguration>(actual)) != JsonSerializer.Serialize(configuration)) { throw Invalid(); }
            Subject = Decode<CustomerDefinitionSubject>(configuration.Subject);
            var schema = Decode<FreshSchemaPlan>(configuration.Schema); var source = Decode<CurrentCustomerSequenceSource>(configuration.Source);
            var ownerObservation = Decode<CurrentCustomerSequenceOwner>(configuration.Owner); var before = Decode<CurrentCustomerSequenceObservation>(configuration.NativeBefore);
            var target = Decode<CurrentAppOwnedRepairTargetPins>(configuration.TargetPins); var intendedBinding = Decode<LocalExecutionBinding>(configuration.IntendedBinding);
            DateTimeOffset now = DateTimeOffset.UtcNow;
            if (!configuration.Roots.Any(x => x.Binding == intendedBinding) || configuration.Catalog.Sha256 != configuration.AcceptedCatalogSha256) { throw Invalid(); }
            var catalog = CurrentCustomerSequenceRepairSourceObservation.ReadCatalog(Read(configuration.Catalog), schema, configuration.Catalog.Sha256, configuration.AcceptedSourceCommitSha, now);
            if (source.ObservedAtUtc < catalog.Source.ObservedAtUtc || source != (catalog.Source with { ObservedAtUtc = source.ObservedAtUtc })) { throw Invalid(); }
            var definition = ApprovedCurrentCustomerSequenceDefinition.Create(source, ownerObservation, configuration.AcceptedSourceCommitSha, configuration.AcceptedCatalogSha256, now);
            ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, configuration.SequenceOwner);
            if (Subject.Source != source || Subject.Owner != ownerObservation || Subject.DefinitionSha256 != definition.ComputeSha256() ||
                Subject.SourceSchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(schema) || Subject.IntendedNativeBeforeStateSha256 != ApprovedCurrentCustomerSequenceDefinition.NativeStateSha256(before.State) ||
                Subject.IntendedTargetObservationSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(target) || Subject.IntendedRunBindingSha256 != intendedBinding.ComputeSha256() ||
                Subject.ConsoleAssemblySha256 != Image(typeof(MigrationConsole).Assembly.Location) || Subject.CoreAssemblySha256 != Image(typeof(CurrentCustomerSequenceRepairPermit).Assembly.Location)) { throw Invalid(); }
            Require();
        }
        catch { Dispose(); throw; }
    }
    private T Decode<T>(Production181Input input)
    {
        return MigrationConsole.DecodeCustomerSequence<T>(Read(input));
    }

    internal byte[] Read(Production181Input input, int maximum = 8_000_000)
    {
        Require(); byte[] bytes = Files(input).Read(PathOf(input), sharedReader: true, maximumBytes: maximum);
        if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != input.Sha256) { throw Invalid(); }
        Require(); return bytes;
    }
    internal CurrentAppOwnedRepairCustody Files(Production181Input input)
    {
        return _roots.TryGetValue(input.RootId, out var root) ? root.Files : throw Invalid();
    }

    internal string PathOf(Production181Input input)
    {
        return Path.GetFileName(input.Name) != input.Name || input.Name is "" or "." or ".." || input.Name == WindowsLocalRunAuthority.RunLockRelativeName || !CurrentCustomerSequenceRepairPermit.HashShape(input.Sha256)
            ? throw Invalid()
            : Path.Combine(_roots[input.RootId].Authority.Binding.ArtifactRootCanonicalPath, input.Name);
    }
    internal void Require() { foreach (var root in _roots.Values) { root.Files.Require(); } }
    internal IReadOnlyList<string> RootPaths => _configuration.Roots.Select(x => x.Binding.ArtifactRootCanonicalPath).ToArray();
    public void Dispose() { foreach (var root in _roots.Values.Reverse()) { root.Files.Dispose(); root.Authority.Dispose(); } _roots.Clear(); }
    internal static string Image(string path) { using var stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
