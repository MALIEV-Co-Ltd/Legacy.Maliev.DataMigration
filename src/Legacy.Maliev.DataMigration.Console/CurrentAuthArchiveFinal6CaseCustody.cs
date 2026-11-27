namespace Legacy.Maliev.DataMigration.Console;

// Fixed generated-family roots only. Each custody still accepts direct children exclusively.
internal sealed class CurrentAuthArchiveFinal6CaseCustody : IDisposable
{
    private readonly CurrentAppOwnedRepairCustody _parent;
    private readonly string _parentRoot;
    private readonly Dictionary<string, (WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files)> _roots = new(StringComparer.OrdinalIgnoreCase);
    private CurrentAuthArchiveFinal6CaseCustody(CurrentAppOwnedRepairCustody parent, string parentRoot) { _parent = parent; _parentRoot = parentRoot; }
    internal static CurrentAuthArchiveFinal6CaseCustody Open(CurrentAppOwnedRepairCustody parent, CurrentAuthArchiveFinal6GeneratedCase generated)
    {
        if (generated.QualifiedInputBinding is null || generated.Definition is null) { throw Invalid(); }
        string root = Path.GetDirectoryName(generated.PreDefinitionIntendedObservation.Path) ?? throw Invalid();
        _ = ReadDirect(parent, generated.PreDefinitionIntendedObservation, 1024 * 1024);
        var result = new CurrentAuthArchiveFinal6CaseCustody(parent, root);
        try
        {
            result.AddChild(generated.QualifiedInputBinding, null);
            string control = Path.Combine(root, "archive-case-host-" + generated.OperationId.ToString("N"));
            if (!SameRoot(Path.GetDirectoryName(generated.HostConfiguration.Path), control)) { throw Invalid(); }
            result.AddChild(BindingArtifact(Path.Combine(control, "fixture-binding.json")), control);
            // The separate Final6 definition reader acquires/releases its exact anchor root itself.
            return result;
        }
        catch { result.Dispose(); throw; }
    }
    internal static (WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files) OpenQualified(
        CurrentAuthArchiveProofArtifact artifact, string parentRoot)
    {
        var (Binding, _) = ReadBinding(artifact);
        RequireChild(parentRoot, Binding.ArtifactRootCanonicalPath);
        return OpenBound(artifact, Binding);
    }
    internal CurrentAppOwnedRepairCustody For(string path)
    {
        string root = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw Invalid();
        return SameRoot(root, _parentRoot) ? _parent : _roots.TryGetValue(root, out var value) ? value.Files : throw Invalid();
    }
    internal void AddFixture(CurrentAuthArchiveGenuineArtifact artifact, string expectedBinding)
    {
        var reference = new CurrentAuthArchiveProofArtifact(artifact.Path, artifact.Sha256);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(Read(reference, 65536));
        if (binding.ComputeSha256() != expectedBinding || _roots.ContainsKey(binding.ArtifactRootCanonicalPath) ||
            SameRoot(_parentRoot, binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        var original = new CurrentAuthArchiveProofArtifact(Path.Combine(binding.ArtifactRootCanonicalPath, "fixture-binding.json"), artifact.Sha256);
        var held = OpenBound(original, binding);
        _roots.Add(binding.ArtifactRootCanonicalPath, held);
    }
    internal byte[] Read(CurrentAuthArchiveProofArtifact artifact, int maximum)
    {
        return ReadDirect(For(artifact.Path), artifact, maximum);
    }

    private void AddChild(CurrentAuthArchiveProofArtifact artifact, string? expected)
    {
        var (Binding, _) = ReadBinding(artifact); RequireChild(_parentRoot, Binding.ArtifactRootCanonicalPath);
        if (expected is not null && !SameRoot(expected, Binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        _roots.Add(Binding.ArtifactRootCanonicalPath, OpenBound(artifact, Binding));
    }
    private static (WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files) OpenBound(CurrentAuthArchiveProofArtifact artifact, LocalExecutionBinding binding)
    {
        var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        var files = new CurrentAppOwnedRepairCustody(authority);
        try { _ = ReadDirect(files, artifact, 65536); return (authority, files); }
        catch { files.Dispose(); authority.Dispose(); throw; }
    }
    private static (LocalExecutionBinding Binding, byte[] Bytes) ReadBinding(CurrentAuthArchiveProofArtifact artifact)
    {
        using var held = SecureLocalFile.OpenReadShared(artifact.Path);
        if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, artifact.Path)) { throw Invalid(); }
        byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256) { throw Invalid(); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(bytes);
        return !SameRoot(Path.GetDirectoryName(artifact.Path), binding.ArtifactRootCanonicalPath) ? throw Invalid() : ((LocalExecutionBinding Binding, byte[] Bytes))(binding, bytes);
    }
    private static CurrentAuthArchiveProofArtifact BindingArtifact(string path)
    {
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536) { throw Invalid(); }
        byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes);
        return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
    }
    internal static void RequireChild(string parent, string child)
    {
        if (!Path.IsPathFullyQualified(parent) || !Path.IsPathFullyQualified(child) || !SameRoot(Path.GetDirectoryName(Path.TrimEndingDirectorySeparator(child)), parent)) { throw Invalid(); }
    }
    private static bool SameRoot(string? left, string right)
    {
        return left is not null && StringComparer.OrdinalIgnoreCase.Equals(Path.TrimEndingDirectorySeparator(left), Path.TrimEndingDirectorySeparator(right));
    }

    private static byte[] ReadDirect(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact, int maximum)
    { byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: maximum); return CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) == artifact.Sha256 ? bytes : throw Invalid(); }
    public void Dispose()
    {
        var failures = new List<Exception>();
        foreach (var (Authority, Files) in _roots.Values.Reverse())
        {
            try { Files.Dispose(); } catch (Exception failure) { failures.Add(failure); }
            try { Authority.Dispose(); } catch (Exception failure) { failures.Add(failure); }
        }
        _roots.Clear();
        if (failures.Count != 0) { throw new AggregateException("Generated evidence custody cleanup failed.", failures); }
    }
    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
