using System.Net;
using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CloudNativePgShadowDatabaseProvisionerTests : IDisposable
{
    private readonly string _tokenFile = Path.Combine(Path.GetTempPath(), $"cnpg-token-{Guid.NewGuid():N}");

    [Fact]
    public async Task Lifecycle_BindsExactDatabaseOwnerClusterAndDisabledBeforeEnable()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();

        await provisioner.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        await provisioner.EnableConnectionsAsync(shadow, CancellationToken.None);
        await provisioner.DeleteAsync(shadow, CancellationToken.None);

        Assert.Equal([false, true, false], handler.ObservedAllowConnections);
        Assert.Equal(["present", "present", "absent"], handler.ObservedEnsure);
        Assert.All(handler.Requests, request => Assert.Equal("Bearer test-token", request.Authorization));
        Assert.Equal("legacy_shadow_order_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", handler.DatabaseName);
        Assert.Equal("legacy_migration_shadow_test", handler.Owner);
        Assert.Equal("legacy-postgres-main", handler.Cluster);
        Assert.Equal(shadow.OwnerRunId, handler.OwnerRunId);
        Assert.Equal(shadow.FencingToken.ToString("D"), handler.FencingToken);
        Assert.Equal("1", handler.OwnerAttempt);
    }

    [Fact]
    public async Task ExistingResourceWithDifferentOwner_IsRejected()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler { OverrideOwner = "attacker" };
        using var provisioner = Create(handler);

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => provisioner.ProvisionWithConnectionsDisabledAsync(
                CreateShadow(), "legacy_migration_shadow_test", CancellationToken.None));

        Assert.Equal("shadow_provisioning_observation_invalid", failure.Code);
    }

    [Fact]
    public async Task ReconciliationWithoutInitialStatus_IsPolledUntilApplied()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler { OmitFirstGetStatus = true };
        using var provisioner = Create(handler);

        await provisioner.ProvisionWithConnectionsDisabledAsync(
            CreateShadow(), "legacy_migration_shadow_test", CancellationToken.None);

        Assert.True(handler.GetCalls >= 2);
    }

    [Fact]
    public async Task ArbitraryDatabaseName_IsRejectedBeforeKubernetesRequest()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase unsafeShadow = CreateShadow() with { Name = "production" };

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => provisioner.ProvisionWithConnectionsDisabledAsync(
                unsafeShadow, "legacy_migration_shadow_test", CancellationToken.None));

        Assert.Equal("shadow_provisioning_request_invalid", failure.Code);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task Enable_RecreatedResourceUid_IsRejectedBeforePatch()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await provisioner.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        handler.ReplaceUid = true;

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => provisioner.EnableConnectionsAsync(shadow, CancellationToken.None));

        Assert.Equal("shadow_provisioning_fence_invalid", failure.Code);
        Assert.Equal(0, handler.PatchCalls);
    }

    [Fact]
    public async Task EveryRequest_RefreshesProjectedServiceAccountToken()
    {
        await File.WriteAllTextAsync(_tokenFile, "first-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await provisioner.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        await File.WriteAllTextAsync(_tokenFile, "second-token");

        await provisioner.EnableConnectionsAsync(shadow, CancellationToken.None);

        Assert.Contains(handler.Requests, request => request.Authorization == "Bearer first-token");
        Assert.Equal("Bearer second-token", handler.Requests[^1].Authorization);
    }

    [Fact]
    public void HttpApiServer_IsRejectedBeforeAnyRequest()
    {
        var handler = new ReconciledDatabaseHandler();
        _ = Assert.Throws<ArgumentException>(() => new CloudNativePgShadowDatabaseProvisioner(new(
            new Uri("http://kubernetes.example"),
            "maliev-legacy",
            "legacy-postgres-main",
            "legacy_migration_shadow_test",
            _tokenFile,
            _tokenFile,
            TimeSpan.FromSeconds(10)), handler));
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public void PublicProvisioner_RejectsSubstitutedApiAndTrustReferences()
    {
        _ = Assert.Throws<ArgumentException>(() => new CloudNativePgShadowDatabaseProvisioner(new(
            new Uri("https://attacker.example"),
            "maliev-legacy",
            "legacy-postgres-main",
            "legacy_migration_shadow_test",
            "C:/caller/token",
            "C:/caller/ca.crt",
            TimeSpan.FromSeconds(10))));
    }

    [Fact]
    public async Task Delete_RecreatedResourceUid_IsRejectedBeforeMutation()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await provisioner.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        handler.ReplaceUid = true;

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => provisioner.DeleteAsync(shadow, CancellationToken.None));

        Assert.Equal("shadow_provisioning_fence_invalid", failure.Code);
        Assert.Equal(0, handler.PatchCalls);
    }

    [Fact]
    public async Task AmbiguousCreate_ReconcilesExactResourceForCleanup()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler { ThrowAfterPost = true };
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();

        _ = await Assert.ThrowsAsync<HttpRequestException>(() => provisioner.ProvisionWithConnectionsDisabledAsync(
            shadow, "legacy_migration_shadow_test", CancellationToken.None));
        await provisioner.DeleteAsync(shadow, CancellationToken.None);

        Assert.True(handler.Deleted);
    }

    [Fact]
    public async Task ConditionalPatchConflict_FailsClosed()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var provisioner = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await provisioner.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        handler.ConflictNextPatch = true;

        MigrationExecutionException failure = await Assert.ThrowsAsync<MigrationExecutionException>(
            () => provisioner.EnableConnectionsAsync(shadow, CancellationToken.None));

        Assert.Equal("shadow_provisioning_fence_invalid", failure.Code);
    }

    [Fact]
    public async Task AmbiguousCreate_AppearingAfterInitialNotFound_IsPreservedWithoutMutation()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler
        {
            ThrowAfterPost = true,
            HiddenGetResponsesAfterPost = 1,
        };
        using var provisioner = Create(handler);

        _ = await Assert.ThrowsAsync<HttpRequestException>(() => provisioner.ProvisionWithConnectionsDisabledAsync(
            CreateShadow(), "legacy_migration_shadow_test", CancellationToken.None));

        Assert.False(handler.Deleted);
        Assert.Equal(0, handler.PatchCalls);
    }

    [Fact]
    public async Task CancelledCreate_WaitsForPostAndPreservesLateExactResource()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler { PostCompletionDelay = TimeSpan.FromMilliseconds(150) };
        using var provisioner = Create(handler);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(25));

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provisioner.ProvisionWithConnectionsDisabledAsync(
            CreateShadow(), "legacy_migration_shadow_test", cancellation.Token));

        Assert.True(handler.PostCompleted);
        Assert.False(handler.Deleted);
        Assert.Equal(0, handler.PatchCalls);
    }

    public void Dispose()
    {
        File.Delete(_tokenFile);
    }

    [Fact]
    public async Task CancelledCreate_LaterPostFailureRetainsPrimaryAndSafeSecondary()
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler { PostCompletionDelay = TimeSpan.FromMilliseconds(150), ThrowAfterPost = true };
        using var provisioner = Create(handler);
        using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(25));
        OperationCanceledException primary = await Assert.ThrowsAnyAsync<OperationCanceledException>(() => provisioner.ProvisionWithConnectionsDisabledAsync(
            CreateShadow(), "legacy_migration_shadow_test", cancellation.Token));
        Assert.Equal(nameof(HttpRequestException), primary.Data["shadow_post_completion_failure"]);
        Assert.True(handler.PostCompleted);
        Assert.False(handler.Deleted);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task RecoveryObservation_ExactSettledResource_IsReadOnly(bool enabled)
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var creator = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await creator.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        if (enabled) { await creator.EnableConnectionsAsync(shadow, CancellationToken.None); }
        int before = handler.Requests.Count;
        CloudNativePgShadowSettlement observed = await creator.ObserveSettlementAsync(shadow, CancellationToken.None);
        Assert.Equal(shadow, observed.OriginalShadow);
        Assert.Equal(enabled, observed.AllowConnections);
        Assert.All(handler.Requests.Skip(before), request => Assert.Equal("GET", request.Method));
    }

    [Theory]
    [InlineData("pending")]
    [InlineData("deleting")]
    [InlineData("owner")]
    [InlineData("uid")]
    public async Task RecoveryObservation_UnsettledOrChangedResource_PreservesAndRejects(string fault)
    {
        await File.WriteAllTextAsync(_tokenFile, "test-token");
        var handler = new ReconciledDatabaseHandler();
        using var creator = Create(handler);
        ShadowDatabase shadow = CreateShadow();
        await creator.ProvisionWithConnectionsDisabledAsync(shadow, "legacy_migration_shadow_test", CancellationToken.None);
        handler.Pending = fault == "pending";
        handler.Deleting = fault == "deleting";
        handler.OverrideOwner = fault == "owner" ? "other" : null;
        handler.ReplaceUid = fault == "uid";
        int before = handler.Requests.Count;
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => creator.ObserveSettlementAsync(shadow, CancellationToken.None));
        Assert.All(handler.Requests.Skip(before), request => Assert.Equal("GET", request.Method));
        Assert.False(handler.Deleted);
    }

    private CloudNativePgShadowDatabaseProvisioner Create(HttpMessageHandler handler)
    {
        return new(new(
        new Uri("https://kubernetes.example"),
        "maliev-legacy",
        "legacy-postgres-main",
        "legacy_migration_shadow_test",
        _tokenFile,
        _tokenFile,
        TimeSpan.FromSeconds(10)), handler);
    }

    private static ShadowDatabase CreateShadow()
    {
        return new(
        "legacy_shadow_order_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "Order")
        {
            OwnerAttempt = 1,
            FencingToken = Guid.Parse("22222222-2222-2222-2222-222222222222"),
        };
    }

    private sealed class ReconciledDatabaseHandler : HttpMessageHandler
    {
        private JsonObject? _resource;

        public string? OverrideOwner { get; set; }
        public bool Pending { get; set; }
        public bool Deleting { get; set; }

        public bool OmitFirstGetStatus { get; init; }

        public bool ReplaceUid { get; set; }

        public bool ThrowAfterPost { get; init; }

        public bool Deleted { get; private set; }

        public bool ConflictNextPatch { get; set; }

        public int HiddenGetResponsesAfterPost { get; init; }

        public TimeSpan PostCompletionDelay { get; init; }

        public bool PostCompleted { get; private set; }

        public int PatchCalls { get; private set; }

        public int GetCalls { get; private set; }

        public List<(string Method, string Path, string Authorization)> Requests { get; } = [];

        public List<bool> ObservedAllowConnections { get; } = [];

        public List<string> ObservedEnsure { get; } = [];

        public string? DatabaseName { get; private set; }

        public string? Owner { get; private set; }

        public string? Cluster { get; private set; }

        public string? OwnerRunId { get; private set; }

        public string? FencingToken { get; private set; }

        public string? OwnerAttempt { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Requests.Add((request.Method.Method, request.RequestUri!.AbsolutePath,
                $"{request.Headers.Authorization?.Scheme} {request.Headers.Authorization?.Parameter}"));
            if (request.Method == HttpMethod.Post)
            {
                if (PostCompletionDelay > TimeSpan.Zero)
                {
                    await Task.Delay(PostCompletionDelay, cancellationToken);
                }

                _resource = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsObject();
                _resource["metadata"]!["generation"] = 1;
                _resource["metadata"]!["uid"] = "11111111-aaaa-bbbb-cccc-111111111111";
                _resource["metadata"]!["resourceVersion"] = "1";
                DatabaseName = _resource["spec"]!["name"]!.GetValue<string>();
                Owner = _resource["spec"]!["owner"]!.GetValue<string>();
                Cluster = _resource["spec"]!["cluster"]!["name"]!.GetValue<string>();
                OwnerRunId = _resource["metadata"]!["annotations"]!["maliev.com/owner-run-id"]!.GetValue<string>();
                OwnerAttempt = _resource["metadata"]!["annotations"]!["maliev.com/owner-attempt"]!.GetValue<string>();
                FencingToken = _resource["metadata"]!["annotations"]!["maliev.com/fencing-token"]!.GetValue<string>();
                PostCompleted = true;
                if (ThrowAfterPost)
                {
                    throw new HttpRequestException("Ambiguous create response.");
                }
            }
            else if (request.Method == HttpMethod.Patch)
            {
                PatchCalls++;
                if (ConflictNextPatch)
                {
                    ConflictNextPatch = false;
                    return new HttpResponseMessage(HttpStatusCode.Conflict);
                }

                JsonArray patch = JsonNode.Parse(await request.Content!.ReadAsStringAsync(cancellationToken))!.AsArray();
                foreach (JsonObject operation in patch.Cast<JsonObject>())
                {
                    string op = operation["op"]!.GetValue<string>();
                    string path = operation["path"]!.GetValue<string>();
                    if (op == "test")
                    {
                        string expected = operation["value"]!.GetValue<string>();
                        string actual = path switch
                        {
                            "/metadata/uid" => _resource!["metadata"]!["uid"]!.GetValue<string>(),
                            "/metadata/resourceVersion" => _resource!["metadata"]!["resourceVersion"]!.GetValue<string>(),
                            "/metadata/annotations/maliev.com~1owner-run-id" => OwnerRunId!,
                            "/metadata/annotations/maliev.com~1owner-attempt" => OwnerAttempt!,
                            "/metadata/annotations/maliev.com~1fencing-token" => FencingToken!,
                            _ => throw new InvalidOperationException($"Unexpected test path {path}."),
                        };
                        if (!string.Equals(expected, actual, StringComparison.Ordinal))
                        {
                            return new HttpResponseMessage(HttpStatusCode.Conflict);
                        }
                    }
                    else if (path == "/spec/ensure")
                    {
                        _resource!["spec"]!["ensure"] = operation["value"]!.GetValue<string>();
                    }
                    else if (path == "/spec/allowConnections")
                    {
                        _resource!["spec"]!["allowConnections"] = operation["value"]!.GetValue<bool>();
                    }
                }

                _resource!["metadata"]!["generation"] = _resource["metadata"]!["generation"]!.GetValue<int>() + 1;
                _resource["metadata"]!["resourceVersion"] =
                    (int.Parse(_resource["metadata"]!["resourceVersion"]!.GetValue<string>(), CultureInfo.InvariantCulture) + 1)
                    .ToString(CultureInfo.InvariantCulture);
            }
            else if (request.Method == HttpMethod.Delete)
            {
                Deleted = true;
                _resource = null;
                return new HttpResponseMessage(HttpStatusCode.OK);
            }

            if (_resource is null)
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }

            bool allow = _resource["spec"]!["allowConnections"]!.GetValue<bool>();
            string ensure = _resource["spec"]!["ensure"]!.GetValue<string>();
            if (request.Method != HttpMethod.Get)
            {
                ObservedAllowConnections.Add(allow);
                ObservedEnsure.Add(ensure);
            }

            JsonObject response = (JsonObject)_resource.DeepClone();
            if (Deleting) { response["metadata"]!["deletionTimestamp"] = "2026-09-03T00:00:00Z"; }
            if (ReplaceUid)
            {
                response["metadata"]!["uid"] = "22222222-aaaa-bbbb-cccc-222222222222";
            }
            if (OverrideOwner is not null)
            {
                response["spec"]!["owner"] = OverrideOwner;
            }

            if (request.Method == HttpMethod.Get)
            {
                GetCalls++;
                if (GetCalls <= HiddenGetResponsesAfterPost)
                {
                    return new HttpResponseMessage(HttpStatusCode.NotFound);
                }
            }

            if (OmitFirstGetStatus && request.Method == HttpMethod.Get && GetCalls == 1)
            {
                return new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"),
                };
            }

            response["status"] = new JsonObject
            {
                ["applied"] = !Pending,
                ["observedGeneration"] = response["metadata"]!["generation"]!.GetValue<int>(),
            };
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(response.ToJsonString(), Encoding.UTF8, "application/json"),
            };
        }
    }
}
