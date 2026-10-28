using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Explicit host-configured resource component. No source capture, archive provider or closed proof is emitted.
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveFixtureTargetNativeTests
{
    [WindowsLocalRunFact]
    public async Task Genuine_archive_targets_use_fresh_owned_volumes_and_verify_final_absence()
    {
        string configPath = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_FIXTURE_INPUT") ??
            throw new InvalidOperationException("archive_fixture_protected_host_input_required");
        byte[] initial = ReadProtected(configPath);
        var input = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFixtureHostInput>(initial);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.ParentRunBindingPath));
        string parent = binding.ArtifactRootCanonicalPath;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(configPath)), parent) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(input.ParentRunBindingPath)), parent))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(parent, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        Assert.Equal(initial, files.Read(configPath, maximumBytes: 65536));
        FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(files, input.SourcePlan, input.AcceptedCommit, DateTimeOffset.UtcNow);
        Guid operation = Guid.NewGuid();
        string localRoot, comparisonRoot;
        await using (var local = await CurrentAuthArchiveFixtureTarget.CreateAsync(parent, files, input.SourcePlan, input.AcceptedCommit, operation, false, CancellationToken.None))
        {
            localRoot = local.Root;
            await using var comparison = await CurrentAuthArchiveFixtureTarget.CreateAsync(parent, files, input.SourcePlan, input.AcceptedCommit, operation, true, local.Token);
            comparisonRoot = comparison.Root;
            Assert.NotEqual(local.ContainerId, comparison.ContainerId);
            Assert.NotEqual(local.Binding.ComputeSha256(), comparison.Binding.ComputeSha256());
            Assert.NotEqual(local.Name, comparison.Name);
            Assert.Equal(26, local.Configuration.Databases.Count);
            Assert.Equal(49, comparison.Configuration.Databases.Count);
            Assert.Equal(SchemaPlanCanonicalizer.ComputeSha256(source), SchemaPlanCanonicalizer.ComputeSha256(local.Source));
            Assert.Equal(SchemaPlanCanonicalizer.ComputeSha256(source), SchemaPlanCanonicalizer.ComputeSha256(comparison.Source));
            await RequireUnseededServerAsync(local);
            await RequireUnseededServerAsync(comparison);
        }
        RequireVerifiedAbsence(localRoot);
        RequireVerifiedAbsence(comparisonRoot);
    }

    [WindowsLocalRunFact]
    public async Task Cancellation_after_actual_start_before_return_recovers_port_and_verifies_absence()
    {
        string configPath = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_FIXTURE_INPUT") ??
            throw new InvalidOperationException("archive_fixture_protected_host_input_required");
        var input = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFixtureHostInput>(ReadProtected(configPath));
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.ParentRunBindingPath));
        string parent = binding.ArtifactRootCanonicalPath;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(configPath)), parent) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(input.ParentRunBindingPath)), parent))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(parent, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        Guid operation = Guid.NewGuid();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => CurrentAuthArchiveFixtureTarget.CreateAsync(
            parent, files, input.SourcePlan, input.AcceptedCommit, operation, false, CancellationToken.None,
            CurrentAuthArchiveFixtureFault.CancelAfterStarted));
        string root = Path.Combine(parent, "auth-archive-target-" + operation.ToString("N"));
        RequireVerifiedAbsence(root);
        using var absent = JsonDocument.Parse(ReadProtected(Directory.GetFiles(root, "*-absent.json").Single()));
        Assert.InRange(absent.RootElement.GetProperty("observedPort").GetInt32(), 1, 65535);
    }
    private static async Task RequireUnseededServerAsync(CurrentAuthArchiveFixtureTarget fixture)
    {
        await using var connection = new NpgsqlConnection(fixture.AdminConnection);
        await connection.OpenAsync(fixture.Token);
        await using var command = new NpgsqlCommand("SELECT count(*) FROM pg_database WHERE NOT datistemplate;", connection);
        Assert.Equal(1L, await command.ExecuteScalarAsync(fixture.Token));
        // Expected profile names are not an assertion that this resource-only helper seeded them.
    }

    private static void RequireVerifiedAbsence(string root)
    {
        string[] files = Directory.GetFiles(root, "*-disposed.json");
        _ = Assert.Single(files);
        using var final = JsonDocument.Parse(ReadProtected(files[0]));
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

internal sealed record CurrentAuthArchiveFixtureHostInput(string ParentRunBindingPath,
    CurrentAuthArchiveProofArtifact SourcePlan, string AcceptedCommit);
