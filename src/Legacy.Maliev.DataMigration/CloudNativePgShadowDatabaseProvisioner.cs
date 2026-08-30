using System.Collections.Concurrent;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

public sealed record CloudNativePgShadowDatabaseProvisionerOptions(
    Uri ApiServer,
    string Namespace,
    string Cluster,
    string OwnerRole,
    string ServiceAccountTokenFile,
    string ServiceAccountCaFile,
    TimeSpan ReconciliationTimeout);

public sealed partial class CloudNativePgShadowDatabaseProvisioner : IPostgreSqlShadowDatabaseProvisioner, IDisposable
{
    private static readonly TimeSpan StableTerminalAbsenceWindow = TimeSpan.FromSeconds(1);
    private readonly CloudNativePgShadowDatabaseProvisionerOptions _options;
    private readonly HttpClient _client;
    private readonly ConcurrentDictionary<string, ResourceFence> _fences = new(StringComparer.Ordinal);

    public CloudNativePgShadowDatabaseProvisioner(CloudNativePgShadowDatabaseProvisionerOptions options)
        : this(options, CreatePinnedHandler(options))
    {
    }

    internal CloudNativePgShadowDatabaseProvisioner(CloudNativePgShadowDatabaseProvisionerOptions options, HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(handler);
        if (!NamespaceName().IsMatch(options.Namespace) || !ClusterName().IsMatch(options.Cluster) ||
            !RoleName().IsMatch(options.OwnerRole) || !options.ApiServer.IsAbsoluteUri ||
            !string.Equals(options.ApiServer.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal) ||
            string.IsNullOrWhiteSpace(options.ServiceAccountTokenFile) || string.IsNullOrWhiteSpace(options.ServiceAccountCaFile) ||
            options.ReconciliationTimeout < TimeSpan.FromSeconds(10) || options.ReconciliationTimeout > TimeSpan.FromMinutes(10))
        {
            throw new ArgumentException("The CloudNativePG provisioning boundary is invalid.", nameof(options));
        }

        _options = options;
        _client = new HttpClient(handler, disposeHandler: true) { BaseAddress = options.ApiServer };
    }

    public async Task ProvisionWithConnectionsDisabledAsync(ShadowDatabase shadow, string ownerRole, CancellationToken cancellationToken)
    {
        ValidateRequest(shadow, ownerRole);
        string resourceName = ResourceName(shadow.Name);
        using var postDeadline = new CancellationTokenSource(_options.ReconciliationTimeout);
        using var request = CreateRequest(HttpMethod.Post, CollectionPath(), JsonContent.Create(
            Resource(shadow, resourceName, "present", allowConnections: false)));
        Task<HttpResponseMessage> postTask = SendAsync(request, postDeadline.Token);
        try
        {
            using HttpResponseMessage response = await postTask.WaitAsync(cancellationToken).ConfigureAwait(false);
            if (response.StatusCode != HttpStatusCode.Conflict)
            {
                _ = response.EnsureSuccessStatusCode();
            }

            _fences[shadow.Name] = await WaitForStateAsync(
                shadow, resourceName, allowConnections: false, "present", expectedUid: null, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception primary)
        {
            try
            {
                await AwaitOriginalPostCompletionAsync(postTask).ConfigureAwait(false);
                await ReconcileAmbiguousCreateAndProveAbsenceAsync(shadow, resourceName).ConfigureAwait(false);
            }
            catch (Exception reconciliation)
            {
                if (primary is MigrationExecutionException migration &&
                    migration.Code == "shadow_provisioning_observation_invalid")
                {
                    System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw();
                }

                throw new AggregateException("CloudNativePG provisioning failed and its exact resource could not be reconciled.", primary, reconciliation);
            }

            throw;
        }
    }

    private static async Task AwaitOriginalPostCompletionAsync(Task<HttpResponseMessage> postTask)
    {
        try
        {
            using HttpResponseMessage response = await postTask.ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is not OutOfMemoryException and not AccessViolationException)
        {
            // Completion, including a bounded transport cancellation, is the fence needed before reconciliation.
        }
    }

    private async Task ReconcileAmbiguousCreateAndProveAbsenceAsync(ShadowDatabase shadow, string resourceName)
    {
        using var deadline = new CancellationTokenSource(_options.ReconciliationTimeout);
        long? absenceStarted = null;
        while (true)
        {
            ObservedResource? observed = await ObserveAsync(resourceName, deadline.Token).ConfigureAwait(false);
            if (observed is null)
            {
                absenceStarted ??= System.Diagnostics.Stopwatch.GetTimestamp();
                if (System.Diagnostics.Stopwatch.GetElapsedTime(absenceStarted.Value) >= StableTerminalAbsenceWindow)
                {
                    _ = _fences.TryRemove(shadow.Name, out _);
                    return;
                }
            }
            else
            {
                absenceStarted = null;
                ValidateObservedResource(observed.Root, shadow, resourceName, allowConnections: null, ensure: null);
                _fences[shadow.Name] = observed.Fence;
                await DeleteAsync(shadow, deadline.Token).ConfigureAwait(false);
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), deadline.Token).ConfigureAwait(false);
        }
    }

    public async Task EnableConnectionsAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        ValidateRequest(shadow, _options.OwnerRole);
        ResourceFence fence = await RequireCurrentFenceAsync(shadow, allowConnections: false, "present", cancellationToken).ConfigureAwait(false);
        using var request = CreateJsonPatchRequest(shadow, fence,
            [Patch("replace", "/spec/ensure", "present"), Patch("replace", "/spec/allowConnections", true)]);
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        EnsureConditionalMutationSucceeded(response);
        _fences[shadow.Name] = await WaitForStateAsync(
            shadow, ResourceName(shadow.Name), allowConnections: true, "present", fence.Uid, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(ShadowDatabase shadow, CancellationToken cancellationToken)
    {
        ValidateRequest(shadow, _options.OwnerRole);
        string resourceName = ResourceName(shadow.Name);
        ObservedResource? initial = await ObserveAsync(resourceName, cancellationToken).ConfigureAwait(false);
        if (initial is null)
        {
            _ = _fences.TryRemove(shadow.Name, out _);
            return;
        }

        ValidateObservedResource(initial.Root, shadow, resourceName, allowConnections: null, ensure: null);
        EnsureSameUid(shadow, initial.Fence.Uid);
        using (var patch = CreateJsonPatchRequest(shadow, initial.Fence,
            [Patch("replace", "/spec/allowConnections", false), Patch("replace", "/spec/ensure", "absent")]))
        using (HttpResponseMessage response = await SendAsync(patch, cancellationToken).ConfigureAwait(false))
        {
            EnsureConditionalMutationSucceeded(response);
        }

        ResourceFence absentFence = await WaitForStateAsync(
            shadow, resourceName, allowConnections: false, "absent", initial.Fence.Uid, cancellationToken).ConfigureAwait(false);
        using var delete = CreateRequest(HttpMethod.Delete, $"{CollectionPath()}/{resourceName}", JsonContent.Create(new
        {
            apiVersion = "v1",
            kind = "DeleteOptions",
            preconditions = new { uid = absentFence.Uid, resourceVersion = absentFence.ResourceVersion },
        }));
        using HttpResponseMessage deleteResponse = await SendAsync(delete, cancellationToken).ConfigureAwait(false);
        EnsureConditionalMutationSucceeded(deleteResponse);
        await WaitForDeletionAsync(resourceName, absentFence.Uid, cancellationToken).ConfigureAwait(false);
        _ = _fences.TryRemove(shadow.Name, out _);
    }

    public void Dispose()
    {
        _client.Dispose();
    }

    private async Task<ResourceFence> RequireCurrentFenceAsync(
        ShadowDatabase shadow, bool allowConnections, string ensure, CancellationToken cancellationToken)
    {
        string resourceName = ResourceName(shadow.Name);
        ObservedResource observed = await ObserveAsync(resourceName, cancellationToken).ConfigureAwait(false) ??
            throw FenceError("The fenced CloudNativePG Database resource no longer exists.");
        ValidateObservedResource(observed.Root, shadow, resourceName, allowConnections, ensure);
        EnsureSameUid(shadow, observed.Fence.Uid);
        _fences[shadow.Name] = observed.Fence;
        return observed.Fence;
    }

    private async Task<ResourceFence> WaitForStateAsync(
        ShadowDatabase shadow,
        string resourceName,
        bool allowConnections,
        string ensure,
        string? expectedUid,
        CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ReconciliationTimeout);
        while (true)
        {
            ObservedResource observed = await ObserveAsync(resourceName, timeout.Token).ConfigureAwait(false) ??
                throw FenceError("The CloudNativePG Database resource disappeared during reconciliation.");
            ValidateObservedResource(observed.Root, shadow, resourceName, allowConnections, ensure);
            if (expectedUid is not null && !string.Equals(expectedUid, observed.Fence.Uid, StringComparison.Ordinal))
            {
                throw FenceError("The CloudNativePG Database resource was replaced during reconciliation.");
            }

            long generation = observed.Root.GetProperty("metadata").GetProperty("generation").GetInt64();
            if (observed.Root.TryGetProperty("status", out JsonElement status) &&
                status.TryGetProperty("applied", out JsonElement applied) && applied.GetBoolean() &&
                status.TryGetProperty("observedGeneration", out JsonElement observedGeneration) && observedGeneration.GetInt64() == generation)
            {
                return observed.Fence;
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), timeout.Token).ConfigureAwait(false);
        }
    }

    private async Task WaitForDeletionAsync(string resourceName, string expectedUid, CancellationToken cancellationToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(_options.ReconciliationTimeout);
        while (true)
        {
            ObservedResource? observed = await ObserveAsync(resourceName, timeout.Token).ConfigureAwait(false);
            if (observed is null)
            {
                return;
            }

            if (!string.Equals(observed.Fence.Uid, expectedUid, StringComparison.Ordinal))
            {
                throw FenceError("A replacement CloudNativePG Database resource occupied the deleted name.");
            }

            await Task.Delay(TimeSpan.FromMilliseconds(250), timeout.Token).ConfigureAwait(false);
        }
    }

    private async Task<ObservedResource?> ObserveAsync(string resourceName, CancellationToken cancellationToken)
    {
        using var request = CreateRequest(HttpMethod.Get, $"{CollectionPath()}/{resourceName}");
        using HttpResponseMessage response = await SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == HttpStatusCode.NotFound)
        {
            return null;
        }

        _ = response.EnsureSuccessStatusCode();
        using JsonDocument document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        JsonElement root = document.RootElement.Clone();
        JsonElement metadata = root.GetProperty("metadata");
        string uid = metadata.GetProperty("uid").GetString() ?? string.Empty;
        string resourceVersion = metadata.GetProperty("resourceVersion").GetString() ?? string.Empty;
        return !Guid.TryParse(uid, out _) || string.IsNullOrWhiteSpace(resourceVersion)
            ? throw FenceError("The CloudNativePG Database resource lacks an immutable UID/resourceVersion fence.")
            : new(root, new(uid, resourceVersion));
    }

    private HttpRequestMessage CreateJsonPatchRequest(ShadowDatabase shadow, ResourceFence fence, IReadOnlyList<object> mutations)
    {
        var operations = new List<object>
        {
            Patch("test", "/metadata/uid", fence.Uid),
            Patch("test", "/metadata/resourceVersion", fence.ResourceVersion),
            Patch("test", "/metadata/annotations/maliev.com~1owner-run-id", shadow.OwnerRunId),
            Patch("test", "/metadata/annotations/maliev.com~1owner-attempt", shadow.OwnerAttempt.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            Patch("test", "/metadata/annotations/maliev.com~1fencing-token", shadow.FencingToken.ToString("D")),
        };
        operations.AddRange(mutations);
        return CreateRequest(HttpMethod.Patch, $"{CollectionPath()}/{ResourceName(shadow.Name)}",
            JsonContent.Create(operations, mediaType: new MediaTypeHeaderValue("application/json-patch+json")));
    }

    private static HttpRequestMessage CreateRequest(HttpMethod method, string path, HttpContent? content = null)
    {
        return new(method, path) { Content = content };
    }

    private async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        string token = (await File.ReadAllTextAsync(_options.ServiceAccountTokenFile, cancellationToken).ConfigureAwait(false)).Trim();
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new MigrationExecutionException("shadow_provisioning_token_invalid", "The projected Kubernetes service-account token is empty.");
        }

        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
    }

    private static void EnsureConditionalMutationSucceeded(HttpResponseMessage response)
    {
        if (response.StatusCode is HttpStatusCode.Conflict or HttpStatusCode.UnprocessableEntity or HttpStatusCode.NotFound)
        {
            throw FenceError("The CloudNativePG Database conditional mutation fence failed.");
        }

        _ = response.EnsureSuccessStatusCode();
    }

    private void EnsureSameUid(ShadowDatabase shadow, string observedUid)
    {
        if (_fences.TryGetValue(shadow.Name, out ResourceFence? expected) &&
            !string.Equals(expected.Uid, observedUid, StringComparison.Ordinal))
        {
            throw FenceError("The CloudNativePG Database resource UID changed.");
        }
    }

    private void ValidateRequest(ShadowDatabase shadow, string ownerRole)
    {
        ArgumentNullException.ThrowIfNull(shadow);
        if (shadow.Name.Length > 63 || !ShadowName().IsMatch(shadow.Name) || !Guid.TryParseExact(shadow.OwnerRunId, "D", out _) ||
            shadow.OwnerAttempt < 1 || shadow.FencingToken == Guid.Empty ||
            !string.Equals(ownerRole, _options.OwnerRole, StringComparison.Ordinal))
        {
            throw new MigrationExecutionException("shadow_provisioning_request_invalid", "The CloudNativePG shadow request is outside the reviewed boundary.");
        }
    }

    private void ValidateObservedResource(
        JsonElement root, ShadowDatabase shadow, string resourceName, bool? allowConnections, string? ensure)
    {
        JsonElement metadata = root.GetProperty("metadata");
        JsonElement spec = root.GetProperty("spec");
        JsonElement annotations = metadata.GetProperty("annotations");
        JsonElement labels = metadata.GetProperty("labels");
        if (!string.Equals(root.GetProperty("apiVersion").GetString(), "postgresql.cnpg.io/v1", StringComparison.Ordinal) ||
            !string.Equals(root.GetProperty("kind").GetString(), "Database", StringComparison.Ordinal) ||
            !string.Equals(metadata.GetProperty("name").GetString(), resourceName, StringComparison.Ordinal) ||
            !string.Equals(metadata.GetProperty("namespace").GetString(), _options.Namespace, StringComparison.Ordinal) ||
            !string.Equals(labels.GetProperty("app.kubernetes.io/managed-by").GetString(), "legacy-maliev-data-migration", StringComparison.Ordinal) ||
            !string.Equals(labels.GetProperty("maliev.com/database-purpose").GetString(), "legacy-shadow", StringComparison.Ordinal) ||
            !string.Equals(spec.GetProperty("name").GetString(), shadow.Name, StringComparison.Ordinal) ||
            !string.Equals(spec.GetProperty("owner").GetString(), _options.OwnerRole, StringComparison.Ordinal) ||
            !string.Equals(spec.GetProperty("cluster").GetProperty("name").GetString(), _options.Cluster, StringComparison.Ordinal) ||
            (allowConnections.HasValue && spec.GetProperty("allowConnections").GetBoolean() != allowConnections.Value) ||
            (ensure is not null && !string.Equals(spec.GetProperty("ensure").GetString(), ensure, StringComparison.Ordinal)) ||
            !string.Equals(spec.GetProperty("databaseReclaimPolicy").GetString(), "delete", StringComparison.Ordinal) ||
            !string.Equals(annotations.GetProperty("maliev.com/owner-run-id").GetString(), shadow.OwnerRunId, StringComparison.Ordinal) ||
            !string.Equals(annotations.GetProperty("maliev.com/owner-attempt").GetString(), shadow.OwnerAttempt.ToString(System.Globalization.CultureInfo.InvariantCulture), StringComparison.Ordinal) ||
            !string.Equals(annotations.GetProperty("maliev.com/fencing-token").GetString(), shadow.FencingToken.ToString("D"), StringComparison.Ordinal))
        {
            throw new MigrationExecutionException("shadow_provisioning_observation_invalid", "The observed CloudNativePG Database resource does not match the exact request.");
        }
    }

    private object Resource(ShadowDatabase shadow, string resourceName, string ensure, bool allowConnections)
    {
        return new
        {
            apiVersion = "postgresql.cnpg.io/v1",
            kind = "Database",
            metadata = new
            {
                name = resourceName,
                @namespace = _options.Namespace,
                labels = new Dictionary<string, string>
                {
                    ["app.kubernetes.io/managed-by"] = "legacy-maliev-data-migration",
                    ["maliev.com/database-purpose"] = "legacy-shadow",
                },
                annotations = new Dictionary<string, string>
                {
                    ["maliev.com/owner-run-id"] = shadow.OwnerRunId,
                    ["maliev.com/owner-attempt"] = shadow.OwnerAttempt.ToString(System.Globalization.CultureInfo.InvariantCulture),
                    ["maliev.com/fencing-token"] = shadow.FencingToken.ToString("D"),
                },
            },
            spec = new
            {
                name = shadow.Name,
                owner = _options.OwnerRole,
                cluster = new { name = _options.Cluster },
                ensure,
                allowConnections,
                databaseReclaimPolicy = "delete",
            },
        };
    }

    private static object Patch(string op, string path, object value)
    {
        return new { op, path, value };
    }

    private string CollectionPath()
    {
        return $"/apis/postgresql.cnpg.io/v1/namespaces/{_options.Namespace}/databases";
    }

    private static string ResourceName(string database)
    {
        return database.Replace('_', '-');
    }

    private static MigrationExecutionException FenceError(string message)
    {
        return new("shadow_provisioning_fence_invalid", message);
    }

    private static SocketsHttpHandler CreatePinnedHandler(CloudNativePgShadowDatabaseProvisionerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.ApiServer.IsAbsoluteUri ||
            !string.Equals(options.ApiServer.Scheme, Uri.UriSchemeHttps, StringComparison.Ordinal))
        {
            throw new ArgumentException("The Kubernetes API server must use HTTPS.", nameof(options));
        }

        X509Certificate2 root = X509CertificateLoader.LoadCertificateFromFile(options.ServiceAccountCaFile);
        return new SocketsHttpHandler
        {
            SslOptions = new()
            {
                RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
                    ValidateApiServerCertificate(certificate, chain, errors, root),
            },
        };
    }

    private static bool ValidateApiServerCertificate(
        X509Certificate? certificate, X509Chain? chain, SslPolicyErrors errors, X509Certificate2 root)
    {
        if (certificate is null || chain is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
        {
            return false;
        }

        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        _ = chain.ChainPolicy.CustomTrustStore.Add(root);
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return chain.Build(certificate is X509Certificate2 typed ? typed : new X509Certificate2(certificate));
    }

    private sealed record ResourceFence(string Uid, string ResourceVersion);

    private sealed record ObservedResource(JsonElement Root, ResourceFence Fence);

    [GeneratedRegex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex NamespaceName();

    [GeneratedRegex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", RegexOptions.CultureInvariant)]
    private static partial Regex ClusterName();

    [GeneratedRegex("^[a-z][a-z0-9_]{0,62}$", RegexOptions.CultureInvariant)]
    private static partial Regex RoleName();

    [GeneratedRegex("^legacy_shadow_[a-z0-9_]+_[0-9a-f]{32}$", RegexOptions.CultureInvariant)]
    private static partial Regex ShadowName();
}
