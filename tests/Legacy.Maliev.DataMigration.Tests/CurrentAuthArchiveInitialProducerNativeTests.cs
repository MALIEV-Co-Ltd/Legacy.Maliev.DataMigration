using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveInitialProducerFactAttribute : FactAttribute
{
    public CurrentAuthArchiveInitialProducerFactAttribute()
    {
        if (!OperatingSystem.IsWindows()) { Skip = "The initial paired observer requires the protected Windows native host."; }
        else if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable(CurrentAuthArchiveInitialProducerNativeTests.InputVariable)))
        { Skip = "The initial paired observer requires an explicitly supplied protected input configuration."; }
    }
}

[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveInitialProducerNativeTests
{
    internal const string InputVariable = "MALIEV_AUTH_ARCHIVE_INITIAL_PRODUCER_INPUT";

    [CurrentAuthArchiveInitialProducerFact]
    public async Task Actual_initial_observer_captures_both_fleets_before_held_custody_and_verifies_cleanup()
    {
        string path = Environment.GetEnvironmentVariable(InputVariable) ??
            throw new InvalidOperationException("archive_initial_protected_input_required");
        byte[] bytes = ReadProtected(path);
        var config = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveInitialProducerConfiguration>(bytes);
        CurrentAuthArchiveInitialProducer.RequireInput(config);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(config.Inputs.ParentBinding.Path));
        Assert.Equal(binding.ArtifactRootCanonicalPath, Path.GetDirectoryName(path), StringComparer.OrdinalIgnoreCase);
        // Release the parent authority before the producer independently authenticates and holds it.
        using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { Assert.Equal(bytes, files.Read(path, maximumBytes: 65536)); }

        using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        CurrentAuthArchiveComponentBootstrapSubject subject = await CurrentAuthArchiveInitialNativeProducer.ObserveAsync(config, deadline.Token);
        Assert.Equal("current-auth-actual-paired-archive-component-subject-v1", subject.Kind);
        Assert.Equal(2, subject.DeleteCount);
        Assert.NotEqual(subject.Local.ContainerId, subject.Comparison.ContainerId);
        Assert.NotEqual(subject.Local.SystemIdentifierSha256, subject.Comparison.SystemIdentifierSha256);
        using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            var scope = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveScope>(files.Read(
                Path.Combine(binding.ArtifactRootCanonicalPath, "archive-pair-candidate-scope.json"), maximumBytes: 1024 * 1024));
            Assert.Equal(subject.Seed.OperationId, scope.OperationId);
            Assert.Equal(26, scope.LocalObservationPolicy.BeforeDatabaseSha256.Count);
            Assert.Equal(49, scope.ProductionObservationPolicy.BeforeDatabaseSha256.Count);
            Assert.Equal(JsonSerializer.Serialize(subject), JsonSerializer.Serialize(scope.ComponentSubject));
            var retained = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveComponentBootstrapSubject>(files.Read(
                Path.Combine(binding.ArtifactRootCanonicalPath, "archive-pair-observed-after-cleanup.json"), maximumBytes: 1024 * 1024));
            Assert.Equal(JsonSerializer.Serialize(subject), JsonSerializer.Serialize(retained));
        }
        string suffix = "auth-archive-target-" + subject.Seed.OperationId.ToString("N");
        RequireCleanup(Path.Combine(config.FirstFixtureParent, suffix), subject.Local);
        RequireCleanup(Path.Combine(config.SecondFixtureParent, suffix + "-comparison"), subject.Comparison);
    }

    private static void RequireCleanup(string root, CurrentAuthArchiveComponentTargetSubject target)
    {
        using var final = JsonDocument.Parse(ReadProtected(Assert.Single(Directory.GetFiles(root, "*-disposed.json"))));
        Assert.True(final.RootElement.GetProperty("removed").GetBoolean());
        Assert.True(final.RootElement.GetProperty("sdkDisposed").GetBoolean());
        Assert.True(final.RootElement.GetProperty("verifiedAbsence").GetBoolean());
        Assert.False(final.RootElement.GetProperty("cleanupFailed").GetBoolean());
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-operator.txt")));
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-ordinary.txt")));
        using var absence = JsonDocument.Parse(ReadProtected(Assert.Single(Directory.GetFiles(root, "*-absent.json"))));
        Assert.Equal(target.ContainerId, absence.RootElement.GetProperty("_id").GetString());
        Assert.Equal(target.VolumeName, absence.RootElement.GetProperty("volume").GetString());
        Assert.DoesNotContain(absence.RootElement.GetProperty("containerIds").EnumerateArray(), x => x.GetString() == target.ContainerId);
        Assert.DoesNotContain(absence.RootElement.GetProperty("containerNames").EnumerateArray(), x => x.GetString() == "/" + target.ContainerName);
        Assert.DoesNotContain(absence.RootElement.GetProperty("volumeNames").EnumerateArray(), x => x.GetString() == target.VolumeName);
        Assert.DoesNotContain(absence.RootElement.GetProperty("listeningPorts").EnumerateArray(),
            x => x.GetInt32() == absence.RootElement.GetProperty("observedPort").GetInt32());
    }

    private static byte[] ReadProtected(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw CurrentAuthRepairPermit.Invalid(); }
        using var input = SecureLocalFile.OpenReadShared(path);
        if (input.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        string identity = SecureLocalFile.GetHandleIdentity(input);
        byte[] bytes = new byte[checked((int)input.Length)];
        input.ReadExactly(bytes);
        return input.Position != input.Length || SecureLocalFile.GetHandleIdentity(input) != identity ||
            !SecureLocalFile.HandleResolvesToApprovedPath(input, path) ? throw CurrentAuthRepairPermit.Invalid() : bytes;
    }
}
