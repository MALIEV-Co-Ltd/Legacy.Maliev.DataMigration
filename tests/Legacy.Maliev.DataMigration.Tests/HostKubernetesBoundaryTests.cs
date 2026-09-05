namespace Legacy.Maliev.DataMigration.Tests;

public sealed class HostKubernetesBoundaryTests
{
    [Theory]
    [InlineData(false, "trusted")]
    [InlineData(true, "trusted")]
    [InlineData(false, "hostname")]
    [InlineData(true, "hostname")]
    [InlineData(false, "ca")]
    [InlineData(true, "ca")]
    public async Task HostFactories_AuthenticateRealTlsBeforeSendingToken(bool provision, string fault)
    {
        await using var server = new HostTlsTestServer(fault == "hostname" ? "wrong.example" : "localhost");
        await using var other = new HostTlsTestServer();
        string ca = fault == "ca" ? other.CaPath : server.CaPath;
        if (provision)
        {
            using var target = CloudNativePgShadowDatabaseProvisioner.CreateForHost(new(server.Address, "maliev-legacy", "legacy-postgres-main",
                "legacy_migration_shadow_test", server.TokenPath, ca, TimeSpan.FromSeconds(10)));
            _ = await Assert.ThrowsAsync<HttpRequestException>(() => target.ProvisionWithConnectionsDisabledAsync(Shadow(), "legacy_migration_shadow_test", default));
        }
        else
        {
            using var observer = CloudNativePgTargetObserver.CreateForHost(new(server.Address, server.TokenPath, ca));
            _ = await Assert.ThrowsAsync<RuntimeAttestationException>(() => observer.ObserveAsync("maliev-legacy", "legacy-postgres-main", default));
        }
        Assert.True(
            server.Requests == (fault == "trusted" ? 1 : 0),
            $"requests={server.Requests}; authorizationObserved={server.Authorization is not null}; lastFailure={server.LastFailure}");
        if (fault == "trusted") { Assert.Contains("synthetic.bound.token", server.Authorization); }
        else { Assert.Null(server.Authorization); }
    }

    [Theory]
    [InlineData("http")]
    [InlineData("userinfo")]
    [InlineData("path")]
    [InlineData("missing")]
    [InlineData("relative")]
    [InlineData("not-ca")]
    [InlineData("unprotected")]
    public async Task HostFactories_UnsafeReferencesRejectBeforeNetwork(string fault)
    {
        await using var server = new HostTlsTestServer();
        Uri address = fault switch
        {
            "http" => new("http://localhost"),
            "userinfo" => new("https://secret@localhost"),
            "path" => new("https://localhost/redirect"),
            _ => server.Address,
        };
        string token = fault switch { "missing" => Path.Combine(server.Root, "missing"), "relative" => "token", _ => server.TokenPath };
        if (fault == "not-ca") { File.WriteAllText(server.CaPath, server.Server.ExportCertificatePem()); }
        if (fault == "unprotected")
        {
            if (OperatingSystem.IsWindows())
            {
                var acl = new System.Security.AccessControl.FileSecurity();
                acl.SetAccessRuleProtection(true, false);
                acl.AddAccessRule(new System.Security.AccessControl.FileSystemAccessRule(
                    new System.Security.Principal.SecurityIdentifier(System.Security.Principal.WellKnownSidType.WorldSid, null),
                    System.Security.AccessControl.FileSystemRights.FullControl, System.Security.AccessControl.AccessControlType.Allow));
                FileSystemAclExtensions.SetAccessControl(new FileInfo(token), acl);
            }
            else { File.SetUnixFileMode(token, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.OtherRead); }
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForHost(new(address, token, server.CaPath)));
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgShadowDatabaseProvisioner.CreateForHost(new(address, "maliev-legacy", "legacy-postgres-main",
            "legacy_migration_shadow_test", token, server.CaPath, TimeSpan.FromSeconds(10))));
        Assert.Equal(0, server.Requests);
    }

    internal static ShadowDatabase Shadow()
    {
        return new($"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), "Order")
        { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };
    }
}
