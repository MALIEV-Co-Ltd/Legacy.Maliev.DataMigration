using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedRepairHostConstructionTests
{
    [WindowsLocalRunFact]
    public async Task Production_composition_accepts_protected_host_trust_under_the_held_Windows_run_root()
    {
        await using var tls = new HostTlsTestServer();
        using WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireFresh(Path.Combine(tls.Root, "repair-custody"));
        string root = authority.Binding.ArtifactRootCanonicalPath;
        string token = Path.Combine(root, "kubernetes-token.txt"), ca = Path.Combine(root, "kubernetes-ca.pem");
        File.Copy(tls.TokenPath, token);
        File.Copy(tls.CaPath, ca);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        CurrentAppOwnedDatabaseSnapshot[] baseline = [.. DatabaseInventory.ActiveDatabases.Select(database =>
            new CurrentAppOwnedDatabaseSnapshot(database, [], [], []))];
        DateTimeOffset now = DateTimeOffset.UtcNow;
        string binding = authority.Binding.ComputeSha256();
        var scope = new CurrentAppOwnedRepairScope(Guid.NewGuid(), CurrentAppOwnedRepairOperation.CreateEightTables,
            new string('a', 40), new string('b', 64), new string('c', 64),
            CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables),
            new(DeltaTargetAuthorityKind.ProductionCloudNativePg, "gke://maliev-website/native-construction-fixture", new string('d', 64)),
            "maliev-legacy", "legacy-postgres-main", "native-construction-fixture", new string('e', 64), binding,
            CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables)
                .ToDictionary(database => database, _ => new string('f', 64), StringComparer.Ordinal),
            CurrentAppOwnedRepairPermit.Hash(JsonSerializer.SerializeToUtf8Bytes(baseline)), new string('a', 64),
            new string('b', 64), new string('c', 64),
            new("fixture", "legacy-maliev-current-app-owned-eight-v1:" + binding, now, now.AddMinutes(30),
                now, now, new string('d', 64), new string('e', 64), "/fixture/pg_hba.conf"));
        foreach (Uri address in new[] { tls.Address, new Uri($"https://127.0.0.1:{tls.Address.Port}") })
        {
            var target = new CurrentAppOwnedRepairTargetPins(null, null, null, null, "/fixture/pg_hba.conf", null,
                new(address, token, ca), null);
            using var environment = new CurrentAppOwnedRepairConsoleEnvironment(authority, files, target, string.Empty, string.Empty,
                baseline, CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1),
                CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2), scope);
            files.Require();
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => environment.RequireResourceAndCustodyAsync(scope, default));
            Assert.Equal(0, tls.Requests);
        }
        // Construction is not target admission: no live cluster, source, HBA or database write is asserted.
    }
}
