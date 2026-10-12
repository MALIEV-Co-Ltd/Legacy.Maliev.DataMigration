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
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(new(address, token, server.CaPath)));
        Assert.Equal(0, server.Requests);
    }

    [Theory]
    [InlineData("trusted")]
    [InlineData("wrong-ip")]
    [InlineData("dns-numeric")]
    [InlineData("ca")]
    [InlineData("eku")]
    public async Task RepairIpv4Factory_AuthenticatesIpSanBeforeSendingToken(string fault)
    {
        await using var server = new HostTlsTestServer(fault == "wrong-ip" ? "127.0.0.2" : "127.0.0.1",
            ipSan: fault != "dns-numeric", serverEku: fault != "eku");
        await using var other = new HostTlsTestServer();
        Uri address = new($"https://127.0.0.1:{server.Address.Port}");
        var options = new CloudNativePgTargetObserverOptions(address, server.TokenPath, fault == "ca" ? other.CaPath : server.CaPath);
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForHost(options));
        using var observer = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(options);
        _ = await Assert.ThrowsAsync<RuntimeAttestationException>(() => observer.ObserveAsync("maliev-legacy", "legacy-postgres-main", default));
        Assert.Equal(fault == "trusted" ? 1 : 0, server.Requests);
        if (fault == "trusted") { Assert.Contains("synthetic.bound.token", server.Authorization); }
        else { Assert.Null(server.Authorization); }
    }

    [Theory]
    [InlineData("http://127.0.0.1/")]
    [InlineData("https://user@127.0.0.1/")]
    [InlineData("https://127.0.0.1/path")]
    [InlineData("https://127.0.0.1/?q=1")]
    [InlineData("https://127.0.0.1/#fragment")]
    [InlineData("https://[::1]/")]
    public async Task RepairIpv4Factory_UnsafeAddressRejectsBeforeNetwork(string address)
    {
        await using var server = new HostTlsTestServer();
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(
            new(new Uri(address), server.TokenPath, server.CaPath)));
        Assert.Equal(0, server.Requests);
    }

    [Fact]
    public async Task RepairIpv4Factory_MalformedEndpointAndRedirectCannotForwardToken()
    {
        await using var server = new HostTlsTestServer("127.0.0.1", ipSan: true);
        await using var other = new HostTlsTestServer();
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(
            new(new Uri("relative", UriKind.Relative), server.TokenPath, server.CaPath)));
        _ = Assert.Throws<MigrationExecutionException>(() => CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(
            new(null!, server.TokenPath, server.CaPath)));
        server.ResponseStatusCode = 302;
        server.RedirectLocation = other.Address;
        using var observer = CloudNativePgTargetObserver.CreateForCurrentAppOwnedRepair(
            new(new Uri($"https://127.0.0.1:{server.Address.Port}"), server.TokenPath, server.CaPath));
        _ = await Assert.ThrowsAsync<RuntimeAttestationException>(() => observer.ObserveAsync("maliev-legacy", "legacy-postgres-main", default));
        Assert.Equal(1, server.Requests);
        Assert.Contains("synthetic.bound.token", server.Authorization);
        Assert.Equal(0, other.Requests);
        Assert.Null(other.Authorization);
    }

    [Theory]
    [InlineData("300687047F000001", true)]
    [InlineData("300B87047F0000018703010203", false)]
    [InlineData("300887047F0000010500", false)]
    [InlineData("300687047F00000100", false)]
    [InlineData("300687047F000002", false)]
    public void RepairIpSanParser_RequiresCompleteLegalIpIdentity(string der, bool expected)
    {
        using var key = System.Security.Cryptography.RSA.Create(2048);
        var request = new System.Security.Cryptography.X509Certificates.CertificateRequest("CN=Parser fixture", key,
            System.Security.Cryptography.HashAlgorithmName.SHA256, System.Security.Cryptography.RSASignaturePadding.Pkcs1);
        request.CertificateExtensions.Add(new System.Security.Cryptography.X509Certificates.X509Extension("2.5.29.17", Convert.FromHexString(der), false));
        using var certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddMinutes(1));
        Assert.Equal(expected, HostRuntimeTrust.HasMatchingIpSan(certificate, System.Net.IPAddress.Loopback));
    }

    internal static ShadowDatabase Shadow()
    {
        return new($"legacy_shadow_order_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), "Order")
        { OwnerAttempt = 1, FencingToken = Guid.NewGuid() };
    }
}
