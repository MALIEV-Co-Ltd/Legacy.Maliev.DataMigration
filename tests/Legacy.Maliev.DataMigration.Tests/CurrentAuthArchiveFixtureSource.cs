using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Validates a host-supplied input artifact. Acquisition provenance remains the owning host's responsibility.
internal static class CurrentAuthArchiveFixtureSource
{
    private const int MaximumBytes = 32 * 1024 * 1024;

    internal static FreshSchemaPlan Read(CurrentAppOwnedRepairCustody files, CurrentAuthArchiveProofArtifact artifact,
        string acceptedCommit, DateTimeOffset now)
    {
        return DecodeHeld(files.Read(artifact.Path, sharedReader: true, maximumBytes: MaximumBytes), artifact.Sha256, acceptedCommit, now);
    }

    internal static FreshSchemaPlan DecodeHeld(byte[] bytes, string expectedSha256, string acceptedCommit, DateTimeOffset now)
    {
        if (bytes.Length is < 1 or > MaximumBytes ||
            !CurrentAuthRepairPermit.HashShape(expectedSha256) ||
            Convert.ToHexStringLower(SHA256.HashData(bytes)) != expectedSha256 ||
            acceptedCommit.Length != 40 || !acceptedCommit.All(char.IsAsciiHexDigitLower))
        {
            throw Invalid();
        }

        FreshSchemaPlan plan = MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(bytes);
        ProductionSchemaCatalogInspector.ValidatePlan(plan, now);
        return plan.SourceCommitSha != acceptedCommit || !ApprovedConsumerOverlaySelection.IsApproved(plan) ||
            plan.Databases.Sum(database => database.Tables.Count) != 100
            ? throw Invalid()
            : plan;
    }

    private static MigrationExecutionException Invalid()
    {
        return new("current_auth_archive_fixture_source_invalid", "The archive fixture requires an unchanged host-supplied current source plan.");
    }
}
