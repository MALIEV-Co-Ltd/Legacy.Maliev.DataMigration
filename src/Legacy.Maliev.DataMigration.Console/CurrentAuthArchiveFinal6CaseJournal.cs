using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed partial class CurrentAuthArchiveFinal6CaseReadback
{
    private void RequireNativeOriginalJournalV2(IReadOnlyList<string> slots, bool setup)
    {
        if (!OperatingSystem.IsWindows()) { throw Invalid(); }
        foreach (bool comparison in new[] { false, true })
        {
            var cleanup = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineCleanupArtifacts>(JsonSerializer.SerializeToUtf8Bytes(_candidate.GetProperty(comparison ? "ComparisonCleanup" : "LocalCleanup")));
            var binding = Artifact<LocalExecutionBinding>(cleanup.Binding);
            var files = _roots.For(Path.Combine(binding.ArtifactRootCanonicalPath, "fixture-binding.json"));
            string prefix = Scope.OperationId.ToString("D") + "-Auth-session-archive-";
            string[] actual = Directory.EnumerateFileSystemEntries(binding.ArtifactRootCanonicalPath, "*", SearchOption.TopDirectoryOnly)
                .Select(Path.GetFileName).Where(name => name is not null && name.StartsWith(Scope.OperationId.ToString("D") + "-", StringComparison.OrdinalIgnoreCase))
                .Select(name => name!).Order(StringComparer.Ordinal).ToArray();
            string[] expected = comparison ? [] : slots.Select(slot => prefix + slot + ".json").Order(StringComparer.Ordinal).ToArray();
            if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) { throw Invalid(); }
            if (comparison) { continue; }
            foreach (string slot in slots)
            {
                string name = (setup ? "setup-" : string.Empty) + slot;
                string path = Path.Combine(binding.ArtifactRootCanonicalPath, prefix + slot + ".json");
                using var recorded = JsonDocument.Parse(Bytes(name + "-native-file", 65536));
                if (recorded.RootElement.GetProperty("OriginalPath").GetString() != path ||
                    recorded.RootElement.GetProperty("Sha256").GetString() != _artifacts[name].Sha256) { throw Invalid(); }
                byte[] original = files.Read(path, sharedReader: true, maximumBytes: 65536);
                if (CurrentAuthLocalSessionArchivePolicy.HashBytes(original) != _artifacts[name].Sha256) { throw Invalid(); }
                using var held = SecureLocalFile.OpenReadShared(path);
                if (!SecureLocalFile.HandleResolvesToApprovedPath(held, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) ||
                    Convert.ToHexStringLower(SHA256.HashData(held)) != _artifacts[name].Sha256 ||
                    CurrentAuthLocalSessionArchivePolicy.Hash(WindowsRunFileIdentity.Observe(held.SafeFileHandle)) !=
                    CurrentAuthLocalSessionArchivePolicy.Hash(recorded.RootElement.GetProperty("Identity"))) { throw Invalid(); }
            }
            files.Require();
        }
    }
}
