using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class Production181ProtectedBundle : IDisposable
{
    private readonly List<(WindowsLocalRunAuthority Authority, CurrentAppOwnedRepairCustody Files)> _folders = [];
    internal string TestAssembly { get; private set; } = string.Empty;
    internal string TestSha256 { get; private set; } = string.Empty;
    internal static async Task<Production181ProtectedBundle> CreateAsync(Production181PipelineInputs inputs, Production181PipelineConfiguration configuration, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        RequireFreshPath(configuration.FreshBundleRoot, inputs.RootPaths);
        var result = new Production181ProtectedBundle();
        try
        {
            if (configuration.Bundle.Count is < 1 or > 4000 || configuration.Bundle.Select(x => Relative(x.RelativePath)).Distinct(StringComparer.OrdinalIgnoreCase).Count() != configuration.Bundle.Count) { throw Invalid(); }
            string root = Path.GetFullPath(configuration.FreshBundleRoot);
            var directories = configuration.Bundle.Select(x => Path.GetDirectoryName(Relative(x.RelativePath)) ?? string.Empty).Append(string.Empty).Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(x => x.Length).ToArray();
            foreach (string directory in directories)
            {
                string path = Path.Combine(root, directory); SecureSnapshotFileCreation.CreateRestrictedDirectory(path);
                var authority = WindowsLocalRunAuthority.AcquireFresh(path); var files = new CurrentAppOwnedRepairCustody(authority); result._folders.Add((authority, files));
                await files.WriteNewAsync(Path.Combine(path, "production181-bundle-binding.json"), JsonSerializer.SerializeToUtf8Bytes(authority.Binding), ct).ConfigureAwait(false);
            }
            long total = 0;
            foreach (var item in configuration.Bundle)
            {
                CurrentCustomerSequenceCapacity.Require(admission: false); inputs.Require(); result.Require();
                string path = Path.Combine(root, Relative(item.RelativePath)); var destination = result._folders.Single(x => StringComparer.OrdinalIgnoreCase.Equals(x.Authority.Binding.ArtifactRootCanonicalPath, Path.GetDirectoryName(path))).Files;
                FileStream source = inputs.Files(item.Input).BorrowReadStream(inputs.PathOf(item.Input), 128L * 1024 * 1024); // Borrowed; only its custody may dispose it.
                source.Position = 0; string sourceHash = Convert.ToHexStringLower(await SHA256.HashDataAsync(source, ct).ConfigureAwait(false));
                if (sourceHash != item.Input.Sha256 || (total = checked(total + source.Length)) > 1024L * 1024 * 1024) { throw Invalid(); }
                source.Position = 0;
                await using (var copy = new FileStream(path, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
                {
                    if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) || !SecureLocalFile.HandleResolvesToApprovedPath(copy, path)) { throw Invalid(); }
                    await source.CopyToAsync(copy, 65536, ct).ConfigureAwait(false); await copy.FlushAsync(ct).ConfigureAwait(false); copy.Flush(true);
                    if (copy.Length != source.Length) { throw Invalid(); }
                }
                FileStream readback = destination.BorrowReadStream(path, 128L * 1024 * 1024); readback.Position = 0;
                if (Convert.ToHexStringLower(await SHA256.HashDataAsync(readback, ct).ConfigureAwait(false)) != sourceHash) { throw Invalid(); }
                inputs.Require(); result.Require();
            }
            result.TestAssembly = Path.Combine(root, "Legacy.Maliev.DataMigration.Tests.dll"); result.TestSha256 = Production181PipelineInputs.Image(result.TestAssembly);
            if (result.TestSha256 != configuration.TestAssemblySha256 ||
                Production181PipelineInputs.Image(Path.Combine(root, "Legacy.Maliev.DataMigration.Console.dll")) != inputs.Subject.ConsoleAssemblySha256 ||
                Production181PipelineInputs.Image(Path.Combine(root, "Legacy.Maliev.DataMigration.dll")) != inputs.Subject.CoreAssemblySha256) { throw Invalid(); }
            result.Require(); return result;
        }
        catch { result.Dispose(); throw; }
    }
    internal void Require() { foreach (var (_, Files) in _folders) { Files.Require(); } }
    internal CurrentAppOwnedRepairCustody FilesFor(string path)
    {
        Require(); string parent = Path.GetDirectoryName(Path.GetFullPath(path)) ?? throw Invalid();
        return _folders.Single(x => StringComparer.OrdinalIgnoreCase.Equals(x.Authority.Binding.ArtifactRootCanonicalPath, parent)).Files;
    }
    public void Dispose() { foreach (var (Authority, Files) in _folders.AsEnumerable().Reverse()) { Files.Dispose(); Authority.Dispose(); } _folders.Clear(); }
    internal static string Relative(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || Path.IsPathFullyQualified(path) || path.Contains(':')) { throw Invalid(); }
        string[] parts = path.Split(['/', '\\']);
        return parts.Any(x => x is "" or "." or ".." || x == WindowsLocalRunAuthority.RunLockRelativeName || x == "production181-bundle-binding.json" ||
            x.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 || x.EndsWith('.') || x.EndsWith(' ') ||
            ReservedDeviceName().IsMatch(x))
            ? throw Invalid()
            : Path.Combine(parts);
    }
    internal static void RequireFreshPath(string path, IReadOnlyList<string> protectedRoots)
    {
        if (!Path.IsPathFullyQualified(path) || (Directory.Exists(path) && Directory.EnumerateFileSystemEntries(path).Any())) { throw Invalid(); }
        string full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
        foreach (string existing in protectedRoots)
        {
            string other = Path.TrimEndingDirectorySeparator(Path.GetFullPath(existing));
            if (StringComparer.OrdinalIgnoreCase.Equals(full, other) || full.StartsWith(other + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) || other.StartsWith(full + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) { throw Invalid(); }
        }
    }
    [System.Text.RegularExpressions.GeneratedRegex("^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\\.|$)", System.Text.RegularExpressions.RegexOptions.IgnoreCase | System.Text.RegularExpressions.RegexOptions.CultureInvariant)]
    private static partial System.Text.RegularExpressions.Regex ReservedDeviceName();
    private static MigrationExecutionException Invalid()
    {
        return CurrentCustomerSequenceRepairPermit.Invalid();
    }
}
