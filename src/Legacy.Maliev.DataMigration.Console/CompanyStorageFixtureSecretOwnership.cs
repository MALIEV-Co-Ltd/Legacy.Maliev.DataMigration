namespace Legacy.Maliev.DataMigration.Console;

// Cleanup custody only: this object grants no database or fixture execution authority.
internal sealed class CompanyStorageFixtureSecretOwnership
{
    private static readonly string[] Names = ["operator.txt", "ordinary.txt"];
    private readonly string _root;
    private readonly LocalExecutionBinding _binding;
    private readonly DateTimeOffset _created;
    private readonly IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> _identities;
    private CompanyStorageFixtureSecretOwnership(string root, LocalExecutionBinding binding, DateTimeOffset created,
        IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> identities)
    { _root = root; _binding = binding; _created = created; _identities = identities; }

    internal static CompanyStorageFixtureSecretOwnership FromCreatedFiles(string root, LocalExecutionBinding binding, DateTimeOffset created,
        IReadOnlyDictionary<string, WindowsRunFileIdentity.Identity> identities)
    {
        if (!OperatingSystem.IsWindows()) { throw CompanyStorageRepairProtocol.Invalid(); }
        if (identities.Count > 2 || !Path.IsPathFullyQualified(root) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(root), binding.ArtifactRootCanonicalPath) ||
            identities.Keys.Any(path => !Path.IsPathFullyQualified(path) ||
                !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), binding.ArtifactRootCanonicalPath) ||
                Path.GetFileName(path) is not ("operator.txt" or "ordinary.txt")))
        { throw CompanyStorageRepairProtocol.Invalid(); }
        var copied = new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal);
        foreach (var identity in identities) { copied.Add(identity.Key, identity.Value); }
        return new(root, binding, created, copied);
    }

    internal void RequireBinding(string root, LocalExecutionBinding binding)
    {
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(root), _root) || binding.ComputeSha256() != _binding.ComputeSha256())
        { throw CompanyStorageRepairProtocol.Invalid(); }
    }

    internal static bool OwnsPairMember(string name)
    {
        return name is "operator.txt" or "ordinary.txt";
    }

    internal void Remove()
    {
        if (!OperatingSystem.IsWindows()) { throw CompanyStorageRepairProtocol.Invalid(); }
        List<Exception>? failures = null;
        foreach (var identity in _identities)
        {
            try
            {
                CompanyStorageSecretCustody.Remove(_root, _binding, _created,
                    new Dictionary<string, WindowsRunFileIdentity.Identity>(StringComparer.Ordinal) { [identity.Key] = identity.Value });
            }
            catch (Exception failure) { (failures ??= []).Add(failure); }
        }
        // Preparation can fail before every ID is captured. Unknown objects are never adopted for cleanup.
        try
        {
            using var authority = WindowsLocalRunAuthority.AcquireResume(_root, _binding);
            authority.ValidateHeld();
            foreach (string name in Names)
            {
                if (_identities.Keys.Any(path => Path.GetFileName(path) == name)) { continue; }
                try
                {
                    _ = File.GetAttributes(Path.Combine(_root, name));
                    (failures ??= []).Add(new IOException("company_untracked_fixture_secret_preserved"));
                }
                catch (FileNotFoundException) { }
                catch (DirectoryNotFoundException) { }
                catch (Exception failure) { (failures ??= []).Add(failure); }
            }
            authority.ValidateHeld();
        }
        catch (Exception failure) { (failures ??= []).Add(failure); }
        if (failures is not null) { throw new AggregateException("Company fixture secret ownership cleanup failed.", failures); }
    }
}
