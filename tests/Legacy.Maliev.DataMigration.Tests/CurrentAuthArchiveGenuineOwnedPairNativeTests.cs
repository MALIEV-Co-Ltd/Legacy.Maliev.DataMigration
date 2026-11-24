using System.Diagnostics;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineOwnedPairFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuineOwnedPairFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_GENUINE_INPUT")))
        { Skip = "Requires Windows NTFS and fresh owner-protected authenticated archive inputs for a disposable paired lifecycle."; }
    }
}

// Component characterization only: never counted as any of the 18 archive cases.
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveGenuineOwnedPairNativeTests(ITestOutputHelper output)
{
    [CurrentAuthArchiveGenuineOwnedPairFact]
    public async Task Owned_live_pair_holds_authenticated_inputs_and_reobserves_before_verified_cleanup()
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_GENUINE_INPUT") ??
            throw new InvalidOperationException("archive_genuine_protected_host_input_required");
        byte[] original = ReadProtected(path);
        var request = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineHostConfiguration>(original);
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        if (!Path.IsPathFullyQualified(path) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(path), root))
        { throw CurrentAuthArchiveGenuineHost.Invalid("component_configuration_origin"); }
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(request.Inputs.ParentBinding.Path));
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { Assert.Equal(original, files.Read(path, maximumBytes: 65536)); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        var clock = Stopwatch.StartNew();
        Guid operation;
        string firstBinding, secondBinding;
        await using (var pair = await CurrentAuthArchiveGenuineOwnedPair.CreateAsync(request, timeout.Token))
        {
            operation = pair.Subject.Seed.OperationId;
            firstBinding = pair.Subject.Local.RunBindingSha256;
            secondBinding = pair.Subject.Comparison.RunBindingSha256;
            Assert.NotEqual(pair.Subject.Local.ContainerId, pair.Subject.Comparison.ContainerId);
            Assert.NotEqual(pair.Subject.Local.SystemIdentifierSha256, pair.Subject.Comparison.SystemIdentifierSha256);
            Assert.Equal(26, pair.Scope.LocalObservationPolicy.BeforeDatabaseSha256.Count);
            Assert.Equal(49, pair.Scope.ProductionObservationPolicy.BeforeDatabaseSha256.Count);
            await pair.RequireAsync(timeout.Token);
            output.WriteLine("owned_pair_component_live_elapsed_ms=" + clock.ElapsedMilliseconds);
        }
        RequireVerifiedAbsence(Path.Combine(request.FirstFixtureParent, "auth-archive-target-" + operation.ToString("N")), firstBinding);
        RequireVerifiedAbsence(Path.Combine(request.SecondFixtureParent, "auth-archive-target-" + operation.ToString("N") + "-comparison"), secondBinding);
        output.WriteLine("owned_pair_component_cleanup_elapsed_ms=" + clock.ElapsedMilliseconds);
    }

    private static void RequireVerifiedAbsence(string root, string expectedBinding)
    {
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(Path.Combine(root, "fixture-binding.json")));
        Assert.Equal(expectedBinding, binding.ComputeSha256());
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        string path = Assert.Single(Directory.GetFiles(root, "*-disposed.json"));
        using var final = JsonDocument.Parse(files.Read(path, maximumBytes: 65536));
        Assert.False(final.RootElement.GetProperty("cleanupFailed").GetBoolean());
        Assert.True(final.RootElement.GetProperty("verifiedAbsence").GetBoolean());
        _ = Assert.Single(Directory.GetFiles(root, "*-absent.json"));
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-operator.txt")));
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-ordinary.txt")));
    }

    private static byte[] ReadProtected(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw CurrentAuthArchiveGenuineHost.Invalid("component_configuration_origin"); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, path))
        { throw CurrentAuthArchiveGenuineHost.Invalid("component_configuration_origin"); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
}
