using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoComponentArtifactImport
{
    internal static async Task<IReadOnlyDictionary<string, IsoDefinitionArtifact>> ImportActualAsync(CurrentAppOwnedRepairCustody sourceFiles,
        CurrentAppOwnedRepairCustody destinationFiles, string sourceRoot, string destinationRoot, IReadOnlyList<string> sourcePaths, CancellationToken ct)
    {
        if (!Path.IsPathFullyQualified(sourceRoot) || !Path.IsPathFullyQualified(destinationRoot) || StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(sourceRoot), Path.GetFullPath(destinationRoot)) ||
            sourcePaths.Select(Path.GetFileName).Distinct(StringComparer.OrdinalIgnoreCase).Count() != sourcePaths.Count) { throw Invalid(); }
        var imported = new Dictionary<string, IsoDefinitionArtifact>(StringComparer.OrdinalIgnoreCase);
        foreach (string path in sourcePaths)
        {
            ct.ThrowIfCancellationRequested(); sourceFiles.Require(); destinationFiles.Require();
            if (!Path.IsPathFullyQualified(path) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), Path.GetFullPath(sourceRoot))) { throw Invalid(); }
            string output = Path.Combine(destinationRoot, Path.GetFileName(path)); string hash; long length;
            using (var held = SecureLocalFile.OpenReadShared(path)) { length = held.Length; if (length is < 1 or > 512L * 1024 * 1024) { throw Invalid(); } hash = Convert.ToHexStringLower(SHA256.HashData(held)); }
            bool baseline = Path.GetFileName(path).Contains("-fleet-", StringComparison.Ordinal);
            if (baseline)
            {
                // Both writes use the same existing canonical streaming baseline writer. Require
                // exact raw-byte hash equality afterward; no adoption or silent normalization.
                var snapshots = await sourceFiles.ReadBaselineAsync(path, ct);
                await destinationFiles.WriteBaselineNewAsync(output, snapshots, ct);
            }
            else
            {
                if (length > 8_000_000) { throw Invalid(); }
                byte[] bytes = sourceFiles.Read(path, maximumBytes: 8_000_000, sharedReader: true);
                if (CurrentAppOwnedRepairPermit.Hash(bytes) != hash) { throw Invalid(); }
                await destinationFiles.WriteNewAsync(output, bytes, ct);
            }
            using (var copied = SecureLocalFile.OpenReadShared(output)) { if (copied.Length != length || Convert.ToHexStringLower(SHA256.HashData(copied)) != hash) { throw Invalid(); } }
            sourceFiles.Require(); destinationFiles.Require(); imported.Add(path, new(output, hash, path));
        }
        return imported;
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_component_import_invalid", "Actual protected flat source artifacts must be imported without overwrite or byte changes.");
    }
}
