using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Explicit protected-host fixture component; no provider, installed maintenance policy or closed proof.
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveFixtureSeedNativeTests
{
    [WindowsLocalRunFact]
    public async Task Genuine_source23_seed_has_exact_fleets_C_Auth_and_stable_complete_private_captures()
    {
        string config = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_FIXTURE_INPUT") ??
            throw new InvalidOperationException("archive_fixture_protected_host_input_required");
        byte[] initial = ReadProtected(config);
        var input = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFixtureHostInput>(initial);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.ParentRunBindingPath));
        string parent = binding.ArtifactRootCanonicalPath;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(config)), parent) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(input.ParentRunBindingPath)), parent))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(parent, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        Assert.Equal(initial, files.Read(config, maximumBytes: 65536));
        FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(files, input.SourcePlan, input.AcceptedCommit, DateTimeOffset.UtcNow);
        Guid operation = Guid.NewGuid();
        var captures = new List<CurrentAuthArchiveFixtureSeedCapture>();
        foreach (bool comparison in new[] { false, true })
        {
            string root;
            await using (var fixture = await CurrentAuthArchiveFixtureTarget.CreateAsync(parent, files, input.SourcePlan, input.AcceptedCommit,
                operation, comparison, CancellationToken.None))
            {
                root = fixture.Root;
                CurrentAuthArchiveFixtureSeedCapture capture = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(fixture, files,
                    input.SourcePlan, input.AcceptedCommit, fixture.Token);
                captures.Add(capture);
                Assert.Equal(comparison ? 49 : 26, capture.Databases.Count);
                Assert.Equal(comparison ? 51 : 28, capture.Before.Databases.Count);
                Assert.Equal(capture.Before.Databases, capture.After.Databases);
                Assert.True(capture.Before.ReadOnly); Assert.True(capture.After.ReadOnly);
                Assert.Equal(capture.Before.SystemIdentifierSha256, capture.After.SystemIdentifierSha256);
                Assert.Equal(23, capture.PhysicalSha256.Count);
                foreach (DatabaseSchemaPlan plan in source.Databases)
                { Assert.Equal(plan.TargetSchemaSha256, capture.PhysicalSha256[plan.Database]); }
                Assert.Equal(comparison ? 0 : 2, capture.Auth.Sessions.Count);
                CurrentAuthNativePreservation.RequireCurrentExplicitCShape(capture.Auth.Native);
                foreach (CurrentAppOwnedDatabaseSnapshot snapshot in capture.Databases)
                {
                    Assert.NotEmpty(snapshot.Catalog);
                    if (source.Databases.Any(x => x.Database == snapshot.Database))
                    {
                        Assert.All(snapshot.Relations.Where(x => x.Schema == "public"), x => Assert.Equal(0, x.Rows));
                        Assert.DoesNotContain(snapshot.Relations, x => x.Schema == "private");
                        Assert.DoesNotContain(snapshot.Sequences, x => x.Schema == "private");
                    }
                    else
                    {
                        Assert.Equal(2, snapshot.Relations.Single(x => x.Schema == "private" && x.Name == "journal").Rows);
                        _ = Assert.Single(snapshot.Sequences, x => x.Schema == "private" && x.Name == "allocation");
                    }
                }
                await RequireHistoryAndSentinelsAsync(fixture, comparison);
                // The create-new seed marker rejects reuse, then disposes the entire owned target.
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(
                    fixture, files, input.SourcePlan, input.AcceptedCommit, fixture.Token));
            }
            RequireVerifiedAbsence(root);
        }
        Assert.NotEqual(captures[0].Before.SystemIdentifierSha256, captures[1].Before.SystemIdentifierSha256);
        _ = CurrentAuthLocalSessionArchivePolicy.RequireComparison(captures[0].Auth, captures[1].Auth);
        Assert.NotEqual(captures[0].Auth.Native.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "__EFMigrationsHistory").RowSha256,
            captures[1].Auth.Native.Snapshot.Relations.Single(x => x.Schema == "public" && x.Name == "__EFMigrationsHistory").RowSha256);
    }

    private static async Task RequireHistoryAndSentinelsAsync(CurrentAuthArchiveFixtureTarget fixture, bool comparison)
    {
        foreach (string database in CurrentAuthArchiveFixtureSeed.PrivateSentinelDatabases(fixture.Source, comparison))
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = database }.ConnectionString);
            await connection.OpenAsync(fixture.Token);
            await using var tx = await connection.BeginTransactionAsync(System.Data.IsolationLevel.RepeatableRead, fixture.Token);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
            { _ = await readOnly.ExecuteNonQueryAsync(fixture.Token); }
            await using (var sequence = new NpgsqlCommand("SELECT last_value,is_called FROM private.allocation;", connection, tx))
            await using (var reader = await sequence.ExecuteReaderAsync(fixture.Token))
            { Assert.True(await reader.ReadAsync(fixture.Token)); Assert.Equal(comparison ? 211 : 113, reader.GetInt64(0)); Assert.True(reader.GetBoolean(1)); }
            if (database == "Auth")
            {
                await using var history = new NpgsqlCommand("SELECT count(*),min(\"ProductVersion\"),max(\"ProductVersion\") FROM public.\"__EFMigrationsHistory\";", connection, tx);
                await using var reader = await history.ExecuteReaderAsync(fixture.Token);
                Assert.True(await reader.ReadAsync(fixture.Token)); Assert.Equal(5, reader.GetInt64(0));
                Assert.Equal(comparison ? "10.0.10" : "10.0.12", reader.GetString(1)); Assert.Equal(reader.GetString(1), reader.GetString(2));
            }
            await tx.RollbackAsync(fixture.Token);
        }
    }

    private static void RequireVerifiedAbsence(string root)
    {
        string[] paths = Directory.GetFiles(root, "*-disposed.json"); _ = Assert.Single(paths);
        using var final = JsonDocument.Parse(ReadProtected(paths[0]));
        Assert.False(final.RootElement.GetProperty("cleanupFailed").GetBoolean());
        Assert.True(final.RootElement.GetProperty("verifiedAbsence").GetBoolean());
        _ = Assert.Single(Directory.GetFiles(root, "*-absent.json"));
    }
    private static byte[] ReadProtected(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw CurrentAuthRepairPermit.Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
}
