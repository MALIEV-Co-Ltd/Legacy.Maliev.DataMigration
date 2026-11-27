using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.Console;

// Only complete snapshot arrays use this existing 512MiB contract. Ciphertext, keys and small artifact limits are unchanged.
internal static class CurrentAuthArchiveStreamedBaselineV2
{
    internal static async Task<CurrentAuthArchiveGenuineArtifact> RetainAsync(CurrentAppOwnedRepairCustody files, string path,
        IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> snapshots, CancellationToken ct)
    {
        files.Require(); CurrentAuthRepairCapacity.Require(admission: false);
        await files.WriteBaselineNewAsync(path, snapshots.ToArray(), ct);
        FileStream held = files.BorrowReadStream(path); held.Position = 0;
        string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(held, ct));
        var observed = await files.ReadBaselineAsync(path, ct, sharedReader: true);
        if (observed.Length != snapshots.Count || observed.Where((snapshot, index) => snapshot.Database != snapshots[index].Database || snapshot.Sha256 != snapshots[index].Sha256).Any())
        { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        files.Require(); return new(path, hash);
    }
    internal static async Task<CurrentAppOwnedDatabaseSnapshot[]> ReadAsync(CurrentAppOwnedRepairCustody files,
        CurrentAuthArchiveGenuineArtifact artifact, CancellationToken ct)
    {
        files.Require(); CurrentAuthRepairCapacity.Require(admission: false);
        FileStream held = files.BorrowReadStream(artifact.Path); held.Position = 0;
        string hash = Convert.ToHexStringLower(await SHA256.HashDataAsync(held, ct));
        if (hash != artifact.Sha256) { throw CurrentAuthArchiveRecoveryV2.Invalid(); }
        var baseline = await files.ReadBaselineAsync(artifact.Path, ct, sharedReader: true);
        files.Require(); return baseline;
    }
}
