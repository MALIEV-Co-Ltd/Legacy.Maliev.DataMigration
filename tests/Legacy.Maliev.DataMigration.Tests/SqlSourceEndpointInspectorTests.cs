using System.Text.Json;
using System.Text.Json.Nodes;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SqlSourceEndpointInspectorTests
{
    private const string Context = "gke_maliev-website_us-central1-a_web-production-cluster";
    private static readonly SqlSourceEndpointConfiguration Valid = new(
        Context, "maliev", "maliev-mssql", "maliev-mssql-0",
        "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "mssql", 15433);
    private const string Service = """
        {"metadata":{"namespace":"maliev","name":"maliev-mssql","uid":"11111111-2222-3333-4444-555555555555"},
         "spec":{"type":"ClusterIP","selector":{"app":"mssql"},"ports":[{"protocol":"TCP","port":1433,"targetPort":1433}]}}
        """;
    private const string Pod = """
        {"metadata":{"namespace":"maliev","name":"maliev-mssql-0","uid":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","labels":{"app":"mssql"}},
         "spec":{"containers":[{"name":"mssql","ports":[{"name":"sql","containerPort":1433,"protocol":"TCP"}]}]},
         "status":{"phase":"Running","conditions":[{"type":"Ready","status":"True"}],
          "containerStatuses":[{"name":"mssql","ready":true,"containerID":"containerd://abc123","imageID":"sha256:abc123","restartCount":0,"state":{"running":{"startedAt":"2026-10-22T00:00:00Z"}}}]}}
        """;

    [Fact]
    public async Task Inspect_ReportsOnlyObservedMetadataAndPlannedLoopback()
    {
        var runner = new MetadataRunner();
        SqlSourceEndpointObservation result = await new SqlSourceEndpointInspector(runner, TimeProvider.System)
            .InspectAsync(Valid, CancellationToken.None);

        Assert.Equal("metadata_observed", result.State);
        Assert.Equal("planned_not_ready", result.TransportState);
        Assert.Equal("127.0.0.1:15433", result.PlannedEndpoint);
        Assert.False(result.ListenerCreated);
        Assert.False(result.SqlAuthenticationVerified);
        Assert.Equal("11111111-2222-3333-4444-555555555555", result.ServiceUid);
        Assert.Equal(Valid.ExpectedPodUid, result.PodUid);
        Assert.Equal("containerd://abc123", result.ContainerId);
        Assert.Equal(1433, result.ForwardParameters.RemotePort);
        Assert.Equal("maliev", result.ForwardParameters.Namespace);
        Assert.Equal("maliev-mssql-0", result.ForwardParameters.PodName);
        Assert.Equal(6, runner.Calls);
        Assert.DoesNotContain("private-native-canary", JsonSerializer.Serialize(result), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_ResolvesNamedPortWithoutClaimingServiceRouting()
    {
        var runner = new MetadataRunner { ServiceJson = Service.Replace("\"targetPort\":1433", "\"targetPort\":\"sql\"", StringComparison.Ordinal) };

        SqlSourceEndpointObservation result = await new SqlSourceEndpointInspector(runner, TimeProvider.System)
            .InspectAsync(Valid, CancellationToken.None);

        Assert.Equal(1433, result.ForwardParameters.RemotePort);
        Assert.Equal("planned_not_ready", result.TransportState);
        Assert.False(result.SqlAuthenticationVerified);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("namespace")]
    [InlineData("service")]
    [InlineData("pod-option")]
    [InlineData("uid")]
    [InlineData("container-option")]
    [InlineData("low-port")]
    [InlineData("high-port")]
    public async Task Inspect_RejectsUnapprovedConfigurationBeforeNativeIo(string mutation)
    {
        SqlSourceEndpointConfiguration invalid = mutation switch
        {
            "context" => Valid with { Context = "other" },
            "namespace" => Valid with { Namespace = "other" },
            "service" => Valid with { ServiceName = "other" },
            "pod-option" => Valid with { ExpectedPodName = "--other" },
            "uid" => Valid with { ExpectedPodUid = "" },
            "container-option" => Valid with { ContainerName = "--other" },
            "low-port" => Valid with { PlannedLocalPort = 1023 },
            _ => Valid with { PlannedLocalPort = 65536 },
        };
        var runner = new MetadataRunner();

        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            new SqlSourceEndpointInspector(runner, TimeProvider.System).InspectAsync(invalid, CancellationToken.None));

        Assert.Equal("sql_source_endpoint_config_invalid", failure.Code);
        Assert.Equal(0, runner.Calls);
    }

    [Theory]
    [InlineData("selector")]
    [InlineData("service-uid")]
    [InlineData("service-port")]
    [InlineData("duplicate-port")]
    [InlineData("target-port")]
    [InlineData("service-namespace")]
    [InlineData("service-name")]
    [InlineData("pod-uid")]
    [InlineData("pod-ready")]
    [InlineData("pod-phase")]
    [InlineData("pod-deletion")]
    [InlineData("container-id")]
    [InlineData("image-id")]
    [InlineData("container-ready")]
    [InlineData("duplicate-container")]
    [InlineData("duplicate-json")]
    [InlineData("empty-selector")]
    [InlineData("pod-namespace")]
    [InlineData("container-name")]
    [InlineData("duplicate-ready")]
    [InlineData("started-at")]
    [InlineData("service-deletion")]
    public async Task Inspect_RejectsMalformedUnreadyOrAmbiguousObservations(string mutation)
    {
        JsonNode service = JsonNode.Parse(Service)!;
        JsonNode pod = JsonNode.Parse(Pod)!;
        switch (mutation)
        {
            case "empty-selector":
                service["spec"]!["selector"] = new JsonObject();
                break;
            case "pod-namespace":
                pod["metadata"]!["namespace"] = "other";
                break;
            case "container-name":
                pod["spec"]!["containers"]![0]!["name"] = "other";
                break;
            case "duplicate-ready":
                pod["status"]!["conditions"]!.AsArray().Add(pod["status"]!["conditions"]![0]!.DeepClone());
                break;
            case "started-at":
                pod["status"]!["containerStatuses"]![0]!["state"]!["running"]!["startedAt"] = new string('x', 65);
                break;
            case "service-deletion":
                service["metadata"]!["deletionTimestamp"] = "2026-10-22T00:00:00Z";
                break;
            case "selector":
                service["spec"]!["selector"]!["app"] = "other";
                break;
            case "service-uid":
                service["metadata"]!["uid"] = "";
                break;
            case "service-port":
                service["spec"]!["ports"]![0]!["port"] = 1434;
                break;
            case "duplicate-port":
                service["spec"]!["ports"]!.AsArray().Add(service["spec"]!["ports"]![0]!.DeepClone());
                break;
            case "target-port":
                service["spec"]!["ports"]![0]!["targetPort"] = 1434;
                break;
            case "service-namespace":
                service["metadata"]!["namespace"] = "other";
                break;
            case "service-name":
                service["metadata"]!["name"] = "other";
                break;
            case "pod-uid":
                pod["metadata"]!["uid"] = "00000000-0000-0000-0000-000000000000";
                break;
            case "pod-ready":
                pod["status"]!["conditions"]![0]!["status"] = "False";
                break;
            case "pod-phase":
                pod["status"]!["phase"] = "Pending";
                break;
            case "pod-deletion":
                pod["metadata"]!["deletionTimestamp"] = "2026-10-22T00:00:00Z";
                break;
            case "container-id":
                pod["status"]!["containerStatuses"]![0]!["containerID"] = "";
                break;
            case "image-id":
                pod["status"]!["containerStatuses"]![0]!["imageID"] = "";
                break;
            case "container-ready":
                pod["status"]!["containerStatuses"]![0]!["ready"] = false;
                break;
            case "duplicate-container":
                pod["status"]!["containerStatuses"]!.AsArray().Add(pod["status"]!["containerStatuses"]![0]!.DeepClone());
                break;
            case "duplicate-json":
            default:
                break;
        }
        var runner = new MetadataRunner
        {
            ServiceJson = mutation == "duplicate-json"
                ? Service.Replace("\"port\":1433", "\"port\":1434,\"port\":1433", StringComparison.Ordinal)
                : service.ToJsonString(),
            PodJson = pod.ToJsonString(),
        };

        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            new SqlSourceEndpointInspector(runner, TimeProvider.System).InspectAsync(Valid, CancellationToken.None));

        Assert.Equal("sql_source_endpoint_observation_invalid", failure.Code);
        Assert.InRange(runner.Calls, 2, 3);
    }

    [Theory]
    [InlineData("service-uid")]
    [InlineData("container-id")]
    [InlineData("image-id")]
    [InlineData("restart")]
    public async Task Inspect_RejectsIdentityDriftInsteadOfRebinding(string mutation)
    {
        var runner = new MetadataRunner
        {
            MutateRepeated = mutation,
        };

        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            new SqlSourceEndpointInspector(runner, TimeProvider.System).InspectAsync(Valid, CancellationToken.None));

        Assert.Equal("sql_source_endpoint_identity_drift", failure.Code);
        Assert.Equal(5, runner.Calls);
    }

    [Theory]
    [InlineData("context")]
    [InlineData("context-final")]
    [InlineData("native")]
    [InlineData("json")]
    [InlineData("oversized")]
    public async Task Inspect_RefusesNativeFailuresWithoutPublishingPrivateDetails(string mode)
    {
        var runner = new MetadataRunner { FailureMode = mode };

        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            new SqlSourceEndpointInspector(runner, TimeProvider.System).InspectAsync(Valid, CancellationToken.None));

        Assert.StartsWith("sql_source_endpoint_", failure.Code, StringComparison.Ordinal);
        Assert.DoesNotContain("private-native-canary", failure.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Inspect_UsesOneOverallDeadlineNotOneDeadlinePerRequest()
    {
        var clock = new DeadlineClock();
        var runner = new MetadataRunner
        {
            BeforeCall = call =>
            {
                if (call == 2)
                {
                    clock.Expire();
                }
            },
        };

        MigrationConsoleException failure = await Assert.ThrowsAsync<MigrationConsoleException>(() =>
            new SqlSourceEndpointInspector(runner, clock).InspectAsync(Valid, CancellationToken.None));

        Assert.Equal("sql_source_endpoint_observation_timeout", failure.Code);
        Assert.Equal(TimeSpan.FromSeconds(60), clock.DueTime);
        Assert.Equal(2, runner.Calls);
        Assert.True(clock.Disposed);
    }

    [Fact]
    public async Task Inspect_PreservesCallerCancellationWithoutRetry()
    {
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        var runner = new MetadataRunner();

        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            new SqlSourceEndpointInspector(runner, TimeProvider.System).InspectAsync(Valid, cancellation.Token));

        Assert.Equal(0, runner.Calls);
    }

    [Fact]
    public async Task Console_DispatchReadsProtectedConfigAndReturnsPlannedMetadata()
    {
        string root = Path.Combine(Path.GetTempPath(), "sql-endpoint-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "inspection.json");
            await MigrationConsole.WriteNewJsonForTestsAsync(path, Valid, CancellationToken.None);
            var runner = new MetadataRunner();
            using var output = new StringWriter();
            using var error = new StringWriter();

            int code = await MigrationConsole.RunSqlSourceEndpointForTestsAsync(
                ["inspect-sql-source-endpoint", "--config", path], output, error,
                name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null,
                runner, TimeProvider.System, CancellationToken.None);

            Assert.Equal(0, code);
            Assert.Equal(string.Empty, error.ToString());
            using JsonDocument result = JsonDocument.Parse(output.ToString());
            Assert.Equal("planned_not_ready", result.RootElement.GetProperty("transportState").GetString());
            Assert.False(result.RootElement.GetProperty("listenerCreated").GetBoolean());
            Assert.Equal(6, runner.Calls);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Theory]
    [InlineData("gate")]
    [InlineData("missing")]
    [InlineData("unknown")]
    [InlineData("oversized")]
    public async Task Console_RejectsAdmissionBeforeNativeIo(string mode)
    {
        string root = Path.Combine(Path.GetTempPath(), "sql-endpoint-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "inspection.json");
            if (mode is "unknown")
            {
                await MigrationConsole.WriteNewJsonForTestsAsync(path, new { unknown = true }, CancellationToken.None);
            }
            else if (mode is "oversized")
            {
                await MigrationConsole.WriteNewJsonForTestsAsync(path, new { unknown = new string('x', 65537) }, CancellationToken.None);
            }
            var runner = new MetadataRunner();
            using var output = new StringWriter();
            using var error = new StringWriter();

            int code = await MigrationConsole.RunSqlSourceEndpointForTestsAsync(
                ["inspect-sql-source-endpoint", "--config", path], output, error,
                name => name == "LEGACY_DEPLOY_ENABLED" && mode != "gate" ? "false" : null,
                runner, TimeProvider.System, CancellationToken.None);

            Assert.Equal(65, code);
            Assert.Equal(string.Empty, output.ToString());
            Assert.Equal(0, runner.Calls);
            Assert.Equal((mode == "gate" ? "sql_source_endpoint_deploy_gate_invalid" :
                mode == "missing" ? "sql_source_endpoint_config_unprotected" : "configuration_invalid") + Environment.NewLine,
                error.ToString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public async Task Console_RejectsNonOwnerOnlyConfigBeforeNativeIoOnUnix()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }
        string root = Path.Combine(Path.GetTempPath(), "sql-endpoint-" + Guid.NewGuid().ToString("N"));
        _ = Directory.CreateDirectory(root);
        try
        {
            string path = Path.Combine(root, "inspection.json");
            await MigrationConsole.WriteNewJsonForTestsAsync(path, Valid, CancellationToken.None);
            File.SetUnixFileMode(path, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            var runner = new MetadataRunner();
            using var error = new StringWriter();

            int code = await MigrationConsole.RunSqlSourceEndpointForTestsAsync(
                ["inspect-sql-source-endpoint", "--config", path], TextWriter.Null, error,
                name => name == "LEGACY_DEPLOY_ENABLED" ? "false" : null,
                runner, TimeProvider.System, CancellationToken.None);

            Assert.Equal(65, code);
            Assert.Equal(0, runner.Calls);
            Assert.Equal("sql_source_endpoint_config_unprotected" + Environment.NewLine, error.ToString());
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    private sealed class MetadataRunner : IBackupProcessRunner
    {
        internal string ServiceJson { get; init; } = Service;
        internal string PodJson { get; init; } = Pod;
        internal string? MutateRepeated { get; init; }
        internal string? FailureMode { get; init; }
        internal Action<int>? BeforeCall { get; init; }
        internal int Calls { get; private set; }

        public Task<BackupProcessResult> RunAsync(SecureBackupProcessInvocation invocation, CancellationToken cancellationToken)
        {
            Calls++;
            BeforeCall?.Invoke(Calls);
            cancellationToken.ThrowIfCancellationRequested();
            Assert.Equal("kubectl", invocation.FileName);
            Assert.Equal(string.Empty, invocation.StandardInput);
            string[] expected = Calls is 1 or 6
                ? ["--context", Context, "config", "current-context"]
                : ["--context", Context, "-n", "maliev", "get", Calls is 2 or 4 ? "service" : "pod",
                    Calls is 2 or 4 ? "maliev-mssql" : "maliev-mssql-0", "-o", "json"];
            Assert.Equal(expected, invocation.Arguments);
            string body = Calls is 1 or 6 ? Context : Calls is 2 or 4 ? ServiceJson : PodJson;
            if (Calls == 4 && MutateRepeated == "service-uid")
            {
                body = body.Replace("11111111-2222-3333-4444-555555555555", "22222222-2222-3333-4444-555555555555", StringComparison.Ordinal);
            }
            if (Calls == 5)
            {
                body = MutateRepeated switch
                {
                    "container-id" => body.Replace("containerd://abc123", "containerd://other", StringComparison.Ordinal),
                    "image-id" => body.Replace("sha256:abc123", "sha256:other", StringComparison.Ordinal),
                    "restart" => body.Replace("\"restartCount\":0", "\"restartCount\":1", StringComparison.Ordinal),
                    _ => body,
                };
            }
            body = FailureMode switch
            {
                "context" when Calls == 1 => "other",
                "context-final" when Calls == 6 => "other",
                "json" when Calls == 2 => "{private-native-canary",
                "oversized" when Calls == 2 => new string('x', (1024 * 1024) + 1),
                _ => body,
            };
            return Task.FromResult(new BackupProcessResult(
                FailureMode == "native" ? 1 : 0, body, "private-native-canary"));
        }
    }

    private sealed class DeadlineClock : TimeProvider
    {
        private TimerCallback? _callback;
        private object? _state;
        internal TimeSpan DueTime { get; private set; }
        internal bool Disposed { get; private set; }

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            _callback = callback;
            _state = state;
            DueTime = dueTime;
            return new ClockTimer(this);
        }

        internal void Expire()
        {
            _callback!(_state);
        }

        private sealed class ClockTimer(DeadlineClock owner) : ITimer
        {
            public bool Change(TimeSpan dueTime, TimeSpan period)
            {
                throw new NotSupportedException();
            }

            public void Dispose()
            {
                owner.Disposed = true;
            }
            public ValueTask DisposeAsync()
            {
                Dispose();
                return ValueTask.CompletedTask;
            }
        }
    }
}
