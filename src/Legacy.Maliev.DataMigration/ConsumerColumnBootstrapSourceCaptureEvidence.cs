namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapSourceWindow(string Database, DateTimeOffset BeginRequestedAtUtc,
    DateTimeOffset SnapshotOpenedAtUtc, DateTimeOffset SnapshotClosedAtUtc);
internal sealed record ConsumerColumnBootstrapSourceCapture(FreshSchemaPlan Plan, string SourceIdentitySha256,
    string FullPlanSha256, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc,
    IReadOnlyList<ConsumerColumnBootstrapSourceWindow> Windows)
{
    internal void Require(string expectedCommit, string expectedSourceIdentity, DateTimeOffset actualInvocationUtc)
    {
        if (SourceIdentitySha256 != expectedSourceIdentity || !ConsumerColumnBootstrapOperationalContract.IsHash(SourceIdentitySha256) ||
            FullPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(Plan) || Plan.SourceCommitSha != expectedCommit ||
            Plan.Databases.Any(database => database.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(database.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3)) ||
            BeganAtUtc.Offset != TimeSpan.Zero || CompletedAtUtc.Offset != TimeSpan.Zero || actualInvocationUtc.Offset != TimeSpan.Zero ||
            BeganAtUtc > Plan.CapturedAtUtc || Plan.CapturedAtUtc > CompletedAtUtc || CompletedAtUtc > actualInvocationUtc ||
            actualInvocationUtc - BeganAtUtc > TimeSpan.FromHours(2) || Windows.Count != 23 ||
            !Windows.Select(window => window.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        DateTimeOffset previous = Plan.CapturedAtUtc;
        foreach (var window in Windows)
        {
            if (window.BeginRequestedAtUtc.Offset != TimeSpan.Zero || window.SnapshotOpenedAtUtc.Offset != TimeSpan.Zero || window.SnapshotClosedAtUtc.Offset != TimeSpan.Zero ||
                window.BeginRequestedAtUtc < previous || window.SnapshotOpenedAtUtc < window.BeginRequestedAtUtc ||
                window.SnapshotClosedAtUtc < window.SnapshotOpenedAtUtc || window.SnapshotClosedAtUtc > CompletedAtUtc)
            { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
            previous = window.SnapshotClosedAtUtc;
        }
        _ = ConsumerColumnBootstrapContract.Create(Plan, expectedCommit, actualInvocationUtc);
    }
}
