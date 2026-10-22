using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record SqlSourceEndpointConfiguration(
    string Context,
    string Namespace,
    string ServiceName,
    string ExpectedPodName,
    string ExpectedPodUid,
    string ContainerName,
    int PlannedLocalPort);

internal sealed record SqlSourceEndpointForwardParameters(
    string Context,
    string Namespace,
    string PodName,
    string ExpectedPodUid,
    string ContainerName,
    string LocalAddress,
    int LocalPort,
    int RemotePort);

internal sealed record SqlSourceEndpointObservation(
    int Version,
    DateTimeOffset ObservedAtUtc,
    string State,
    string TransportState,
    string Context,
    string Namespace,
    string ServiceName,
    string ServiceUid,
    string PodName,
    string PodUid,
    string ContainerName,
    string ContainerId,
    string ImageId,
    int RestartCount,
    string StartedAt,
    string PlannedEndpoint,
    bool ListenerCreated,
    bool SqlAuthenticationVerified,
    string Instructions,
    SqlSourceEndpointForwardParameters ForwardParameters);

internal sealed partial class SqlSourceEndpointInspector(IBackupProcessRunner runner, TimeProvider timeProvider)
{
    private const string RequiredContext = "gke_maliev-website_us-central1-a_web-production-cluster";
    private const string SourceNamespace = "maliev";
    private const string SourceService = "maliev-mssql";
    private const int MaximumObservationBytes = 1024 * 1024;

    internal async Task<SqlSourceEndpointObservation> InspectAsync(
        SqlSourceEndpointConfiguration configuration,
        CancellationToken cancellationToken)
    {
        ValidateConfiguration(configuration);
        cancellationToken.ThrowIfCancellationRequested();
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(60), timeProvider);
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, deadline.Token);
        try
        {
            await CheckContextAsync(configuration, linked.Token).ConfigureAwait(false);
            ObservedTarget first = await ObserveAsync(configuration, linked.Token).ConfigureAwait(false);
            ObservedTarget second = await ObserveAsync(configuration, linked.Token).ConfigureAwait(false);
            if (first != second)
            {
                throw Failure("identity_drift");
            }
            await CheckContextAsync(configuration, linked.Token).ConfigureAwait(false);
            linked.Token.ThrowIfCancellationRequested();
            return new(
                1, timeProvider.GetUtcNow(), "metadata_observed", "planned_not_ready",
                configuration.Context, SourceNamespace, SourceService, first.ServiceUid,
                configuration.ExpectedPodName, configuration.ExpectedPodUid, configuration.ContainerName,
                first.ContainerId, first.ImageId, first.RestartCount, first.StartedAt,
                "127.0.0.1:" + configuration.PlannedLocalPort.ToString(CultureInfo.InvariantCulture),
                false, false,
                "Planned parameters only. No listener or SQL session was created. A separately admitted transport must re-observe identity and establish readiness; SQL authentication and data-operation authority remain separate.",
                new(configuration.Context, SourceNamespace, configuration.ExpectedPodName,
                    configuration.ExpectedPodUid, configuration.ContainerName, "127.0.0.1",
                    configuration.PlannedLocalPort, 1433));
        }
        catch (OperationCanceledException) when (deadline.IsCancellationRequested && !cancellationToken.IsCancellationRequested)
        {
            throw Failure("observation_timeout");
        }
        catch (Exception exception) when (exception is Exact25BackupTransportException or IOException or UnauthorizedAccessException)
        {
            throw Failure("observation_failed");
        }
    }

    private static void ValidateConfiguration(SqlSourceEndpointConfiguration configuration)
    {
        if (!string.Equals(configuration.Context, RequiredContext, StringComparison.Ordinal) ||
            !string.Equals(configuration.Namespace, SourceNamespace, StringComparison.Ordinal) ||
            !string.Equals(configuration.ServiceName, SourceService, StringComparison.Ordinal) ||
            !SafeIdentifier(configuration.ExpectedPodName) || !SafeIdentifier(configuration.ContainerName) ||
            !Guid.TryParseExact(configuration.ExpectedPodUid, "D", out Guid uid) || uid == Guid.Empty ||
            configuration.PlannedLocalPort is < 1024 or > 65535)
        {
            throw Failure("config_invalid");
        }
    }

    private async Task CheckContextAsync(SqlSourceEndpointConfiguration configuration, CancellationToken cancellationToken)
    {
        string observed = await ReadAsync(
            ["--context", configuration.Context, "config", "current-context"], cancellationToken).ConfigureAwait(false);
        if (!string.Equals(observed.Trim(), configuration.Context, StringComparison.Ordinal))
        {
            throw Failure("context_drift");
        }
    }

    private async Task<ObservedTarget> ObserveAsync(
        SqlSourceEndpointConfiguration configuration,
        CancellationToken cancellationToken)
    {
        string serviceText = await ReadAsync(
            ["--context", configuration.Context, "-n", SourceNamespace, "get", "service", SourceService, "-o", "json"],
            cancellationToken).ConfigureAwait(false);
        string podText = await ReadAsync(
            ["--context", configuration.Context, "-n", SourceNamespace, "get", "pod", configuration.ExpectedPodName, "-o", "json"],
            cancellationToken).ConfigureAwait(false);
        try
        {
            using JsonDocument service = JsonDocument.Parse(serviceText, new JsonDocumentOptions { MaxDepth = 32 });
            using JsonDocument pod = JsonDocument.Parse(podText, new JsonDocumentOptions { MaxDepth = 32 });
            RejectDuplicateProperties(service.RootElement);
            RejectDuplicateProperties(pod.RootElement);
            JsonElement serviceRoot = service.RootElement;
            JsonElement podRoot = pod.RootElement;
            JsonElement serviceMetadata = serviceRoot.GetProperty("metadata");
            JsonElement podMetadata = podRoot.GetProperty("metadata");
            string serviceUid = serviceMetadata.GetProperty("uid").GetString() ?? string.Empty;
            if (!Guid.TryParseExact(serviceUid, "D", out Guid uid) || uid == Guid.Empty ||
                !Matches(serviceMetadata, "namespace", SourceNamespace) ||
                !Matches(serviceMetadata, "name", SourceService) ||
                !Matches(podMetadata, "namespace", SourceNamespace) ||
                !Matches(podMetadata, "name", configuration.ExpectedPodName) ||
                !Matches(podMetadata, "uid", configuration.ExpectedPodUid) ||
                IsDeleting(serviceMetadata) || IsDeleting(podMetadata))
            {
                throw Failure("observation_invalid");
            }

            JsonElement serviceSpec = serviceRoot.GetProperty("spec");
            if (serviceSpec.TryGetProperty("type", out JsonElement serviceType) &&
                string.Equals(serviceType.GetString(), "ExternalName", StringComparison.Ordinal))
            {
                throw Failure("observation_invalid");
            }
            JsonElement selector = serviceSpec.GetProperty("selector");
            JsonElement labels = podMetadata.GetProperty("labels");
            JsonProperty[] selectors = selector.EnumerateObject().ToArray();
            if (selectors.Length == 0 || selectors.Any(entry =>
                entry.Value.ValueKind != JsonValueKind.String ||
                !labels.TryGetProperty(entry.Name, out JsonElement value) ||
                value.ValueKind != JsonValueKind.String ||
                !string.Equals(value.GetString(), entry.Value.GetString(), StringComparison.Ordinal)))
            {
                throw Failure("observation_invalid");
            }
            JsonElement sqlPort = serviceSpec.GetProperty("ports").EnumerateArray()
                .Single(port => port.GetProperty("port").GetInt32() == 1433 && IsTcp(port));
            JsonElement container = podRoot.GetProperty("spec").GetProperty("containers").EnumerateArray()
                .Single(item => Matches(item, "name", configuration.ContainerName));
            JsonElement targetPort = sqlPort.GetProperty("targetPort");
            bool targetMatches = targetPort.ValueKind == JsonValueKind.Number
                ? targetPort.GetInt32() == 1433
                : targetPort.ValueKind == JsonValueKind.String &&
                    container.GetProperty("ports").EnumerateArray().Count(port =>
                        Matches(port, "name", targetPort.GetString() ?? string.Empty) &&
                        port.GetProperty("containerPort").GetInt32() == 1433 && IsTcp(port)) == 1;
            JsonElement status = podRoot.GetProperty("status");
            JsonElement ready = status.GetProperty("conditions").EnumerateArray()
                .Single(condition => Matches(condition, "type", "Ready"));
            JsonElement containerStatus = status.GetProperty("containerStatuses").EnumerateArray()
                .Single(item => Matches(item, "name", configuration.ContainerName));
            JsonElement running = containerStatus.GetProperty("state").GetProperty("running");
            string containerId = containerStatus.GetProperty("containerID").GetString() ?? string.Empty;
            string imageId = containerStatus.GetProperty("imageID").GetString() ?? string.Empty;
            int restartCount = containerStatus.GetProperty("restartCount").GetInt32();
            string startedAt = running.TryGetProperty("startedAt", out JsonElement started)
                ? started.GetString() ?? string.Empty : string.Empty;
            if (!targetMatches || !Matches(status, "phase", "Running") || !Matches(ready, "status", "True") ||
                !containerStatus.GetProperty("ready").GetBoolean() || running.ValueKind != JsonValueKind.Object ||
                !SafeRuntimeIdentity(containerId) || !SafeRuntimeIdentity(imageId) || restartCount < 0 ||
                startedAt.Length > 64 || (startedAt.Length != 0 && (!DateTimeOffset.TryParse(startedAt, CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out DateTimeOffset timestamp) || timestamp.Offset != TimeSpan.Zero)))
            {
                throw Failure("observation_invalid");
            }
            string selectorIdentity = JsonSerializer.Serialize(selectors.OrderBy(entry => entry.Name, StringComparer.Ordinal)
                .ToDictionary(entry => entry.Name, entry => entry.Value.GetString(), StringComparer.Ordinal));
            return new(serviceUid, containerId, imageId, restartCount, startedAt,
                selectorIdentity, targetPort.GetRawText());
        }
        catch (Exception exception) when (exception is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        {
            throw Failure("observation_invalid");
        }
    }

    private async Task<string> ReadAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        BackupProcessResult result = await runner.RunAsync(
            new SecureBackupProcessInvocation("kubectl", arguments, string.Empty), cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.ExitCode != 0 || Encoding.UTF8.GetByteCount(result.StandardOutput) > MaximumObservationBytes)
        {
            throw Failure("observation_failed");
        }
        return result.StandardOutput;
    }

    private static void RejectDuplicateProperties(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (JsonProperty property in element.EnumerateObject())
            {
                if (!names.Add(property.Name))
                {
                    throw Failure("observation_invalid");
                }
                RejectDuplicateProperties(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement item in element.EnumerateArray())
            {
                RejectDuplicateProperties(item);
            }
        }
    }

    private static bool Matches(JsonElement element, string property, string expected) =>
        string.Equals(element.GetProperty(property).GetString(), expected, StringComparison.Ordinal);

    private static bool IsTcp(JsonElement port) =>
        !port.TryGetProperty("protocol", out JsonElement protocol) ||
        string.Equals(protocol.GetString(), "TCP", StringComparison.Ordinal);

    private static bool IsDeleting(JsonElement metadata) =>
        metadata.TryGetProperty("deletionTimestamp", out JsonElement value) && value.ValueKind != JsonValueKind.Null;

    private static bool SafeIdentifier(string? value) =>
        value is not null && KubernetesIdentifier().IsMatch(value);

    private static bool SafeRuntimeIdentity(string value) =>
        value.Length is > 0 and <= 512 && value.All(character =>
            char.IsAsciiLetterOrDigit(character) || character is ':' or '/' or '.' or '-' or '_' or '@');

    private static MigrationConsoleException Failure(string suffix) =>
        new("sql_source_endpoint_" + suffix, "SQL source endpoint metadata inspection was refused.");

    [GeneratedRegex("^[a-z0-9](?:[-a-z0-9.]{0,61}[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex KubernetesIdentifier();

    private sealed record ObservedTarget(
        string ServiceUid,
        string ContainerId,
        string ImageId,
        int RestartCount,
        string StartedAt,
        string SelectorIdentity,
        string TargetPortIdentity);
}
