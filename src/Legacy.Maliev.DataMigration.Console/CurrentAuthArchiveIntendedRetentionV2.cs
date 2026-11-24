using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveIntendedRetainedFleetV2(CurrentAuthArchiveGenuineArtifact Native,
    CurrentAuthArchiveGenuineArtifact Databases, CurrentAuthArchiveFleetCatalogs Catalogs, DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveIntendedRetainedEvidenceV2(string Kind, string SourceFullSha256,
    string SourceIdentitySha256, string SourceDefinitionSha256, string LocalIdentitySha256, string ComparisonIdentitySha256,
    string LocalAuthRowsSha256, int LocalAuthRows, CurrentAuthRepairScope LocalPolicy, CurrentAuthRepairScope ComparisonPolicy,
    CurrentAuthArchiveIntendedRetainedFleetV2 Local, CurrentAuthArchiveIntendedRetainedFleetV2 Comparison, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc);

internal static class CurrentAuthArchiveIntendedRetentionV2
{
    internal static async Task<CurrentAuthArchiveProofArtifact> RetainAsync(CurrentAppOwnedRepairCustody files, string path,
        CurrentAuthArchiveIntendedObservationEvidenceV2 observation, CancellationToken ct)
    {
        string prefix = Path.Combine(Path.GetDirectoryName(path)!, Path.GetFileNameWithoutExtension(path));
        var local = await FleetAsync("local", observation.Local); var comparison = await FleetAsync("comparison", observation.Comparison);
        var manifest = new CurrentAuthArchiveIntendedRetainedEvidenceV2(observation.Kind, observation.SourceFullSha256, observation.SourceIdentitySha256,
            observation.SourceDefinitionSha256, observation.LocalIdentitySha256, observation.ComparisonIdentitySha256, observation.LocalAuthRowsSha256,
            observation.LocalAuthRows, observation.LocalPolicy, observation.ComparisonPolicy, local, comparison, observation.BeganAtUtc, observation.CompletedAtUtc);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(manifest); await files.WriteNewAsync(path, bytes, ct);
        return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
        async Task<CurrentAuthArchiveIntendedRetainedFleetV2> FleetAsync(string name, CurrentAuthArchiveIntendedFleetV2 value)
        {
            var databases = await CurrentAuthArchiveStreamedBaselineV2.RetainAsync(files, prefix + "-" + name + "-databases.json", value.Databases, ct);
            byte[] native = JsonSerializer.SerializeToUtf8Bytes(value.Auth);
            string nativePath = prefix + "-" + name + "-native.json"; await files.WriteNewAsync(nativePath, native, ct);
            return new(new(nativePath, CurrentAuthLocalSessionArchivePolicy.HashBytes(native)), databases, value.Catalogs, value.BeganAtUtc, value.EndedAtUtc);
        }
    }
}
