using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineIssuerFactAttribute : FactAttribute
{
    public CurrentAuthArchiveGenuineIssuerFactAttribute()
    {
        if (!OperatingSystem.IsWindows() || string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_GENUINE_ISSUER_INPUT")))
        { Skip = "Requires a distinct fresh protected issuer input and the accepted qualified bundle for an owned disposable pair."; }
    }
}

// A component proof of issuer identity/lifetime only, never an Archive_18 case.
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveGenuineIssuerNativeTests
{
    [CurrentAuthArchiveGenuineIssuerFact]
    public async Task Actual_owned_issuer_allows_only_one_capability_and_one_reservation()
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_GENUINE_ISSUER_INPUT") ??
            throw new InvalidOperationException("archive_genuine_issuer_protected_host_input_required");
        if (!Path.IsPathFullyQualified(path)) { throw CurrentAuthArchiveGenuineHost.Invalid("issuer_configuration_origin"); }
        byte[] bytes;
        using (var held = SecureLocalFile.OpenReadShared(path))
        {
            if (held.Length is < 1 or > 65536 || !SecureLocalFile.HandleResolvesToApprovedPath(held, path))
            { throw CurrentAuthArchiveGenuineHost.Invalid("issuer_configuration_origin"); }
            bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes);
        }
        var request = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveGenuineHostConfiguration>(bytes);
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        if (!StringComparer.OrdinalIgnoreCase.Equals(root, Path.GetDirectoryName(path)))
        { throw CurrentAuthArchiveGenuineHost.Invalid("issuer_configuration_origin"); }
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        await using var issuer = await CurrentAuthArchiveGenuineIssuer.CreateAsync(request, timeout.Token);
        var capability = await CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(issuer, timeout.Token);
        try
        {
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() =>
                CurrentAuthArchiveGenuineCapability.AuthenticateConsoleOwnedIssuerAsync(issuer, timeout.Token));
            await capability.ReserveOnceAsync(timeout.Token);
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => capability.ReserveOnceAsync(timeout.Token));
            await capability.RequireAsync(timeout.Token);
            capability.Stop();
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => capability.RequireAsync(timeout.Token));
        }
        finally { capability.Stop(); }
        // Actual owned-pair removal/absence is performed by issuer disposal before
        // this test can pass. This method publishes no archive execution report.
    }
}
