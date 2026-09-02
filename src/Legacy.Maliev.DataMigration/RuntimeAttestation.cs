using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Net.Security;

namespace Legacy.Maliev.DataMigration;

public sealed class RuntimeAttestationException(string code, string message) : Exception(message)
{
    public string Code { get; } = code;
}

public sealed record RunnerArtifactFile(string RelativePath, long Length, string Sha256);

public sealed record RunnerArtifactManifest(string ManifestSha256, IReadOnlyList<RunnerArtifactFile> Files);

public static class RunnerArtifactManifestMeasurer
{
    public static Task<RunnerArtifactManifest> MeasureAsync(string publishDirectory, CancellationToken cancellationToken)
    {
        return MeasureAsync(publishDirectory, afterInitialMeasurement: null, cancellationToken);
    }

    internal static async Task<RunnerArtifactManifest> MeasureAsync(
        string publishDirectory,
        Func<CancellationToken, Task>? afterInitialMeasurement,
        CancellationToken cancellationToken)
    {
        try
        {
            return await MeasureCoreAsync(publishDirectory, afterInitialMeasurement, cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeAttestationException)
        {
            throw;
        }
        catch (Exact25FullBackupException)
        {
            throw Error("runtime_runner_boundary_invalid", "The Release publication is not owner-only or stable.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw Error("runtime_runner_measurement_failed", "The Release publication could not be measured securely.");
        }
    }

    private static async Task<RunnerArtifactManifest> MeasureCoreAsync(
        string publishDirectory,
        Func<CancellationToken, Task>? afterInitialMeasurement,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(publishDirectory))
        {
            throw Error("runtime_runner_path_invalid", "A Release publish directory is required.");
        }

        string root = Path.GetFullPath(publishDirectory);
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        ValidateDirectoryTree(root);
        string[] paths = EnumerateFiles(root);
        if (paths.Length == 0)
        {
            throw Error("runtime_runner_manifest_empty", "The Release publish directory is empty.");
        }

        var opened = new List<OpenedArtifact>(paths.Length);
        try
        {
            foreach (string path in paths)
            {
                cancellationToken.ThrowIfCancellationRequested();
                EnsureNoLinks(root, path);
                var info = new FileInfo(path);
                info.Refresh();
                if (!info.Exists || IsLink(info))
                {
                    throw Error("runtime_runner_manifest_invalid", "A published runner artifact is not a regular file.");
                }

                FileStream stream = SecureLocalFile.OpenRead(path);
                try
                {
                    string sha = await SecureLocalFile.ComputeSha256Async(stream, cancellationToken).ConfigureAwait(false);
                    opened.Add(new(path, NormalizeRelative(root, path), info.Length, info.LastWriteTimeUtc,
                        SecureLocalFile.GetHandleIdentity(stream), sha, stream));
                }
                catch
                {
                    await stream.DisposeAsync().ConfigureAwait(false);
                    throw;
                }
            }

            if (afterInitialMeasurement is not null)
            {
                await afterInitialMeasurement(cancellationToken).ConfigureAwait(false);
            }

            SecureLocalFile.EnsureOwnerOnlyDirectory(root);
            ValidateDirectoryTree(root);
            string[] afterPaths = EnumerateFiles(root).Select(path => NormalizeRelative(root, path)).ToArray();
            if (!afterPaths.SequenceEqual(opened.Select(file => file.RelativePath), StringComparer.Ordinal))
            {
                throw Error("runtime_runner_manifest_mutated", "The published runner file set changed while it was measured.");
            }

            foreach (OpenedArtifact artifact in opened)
            {
                var current = new FileInfo(artifact.FullPath);
                current.Refresh();
                if (!current.Exists || IsLink(current) || current.Length != artifact.Length ||
                    current.LastWriteTimeUtc != artifact.LastWriteUtc ||
                    !SecureLocalFile.HandleResolvesToApprovedPath(artifact.Stream, artifact.FullPath))
                {
                    throw Error("runtime_runner_manifest_mutated", "A published runner artifact was replaced while it was measured.");
                }

                artifact.Stream.Position = 0;
                string secondHash = await SecureLocalFile.ComputeSha256Async(artifact.Stream, cancellationToken).ConfigureAwait(false);
                if (!FixedHashEquals(artifact.Sha256, secondHash))
                {
                    throw Error("runtime_runner_manifest_mutated", "A published runner artifact changed while it was measured.");
                }

                if (OperatingSystem.IsLinux())
                {
                    // The original handle deliberately remains exclusive. Compare the live path via statx;
                    // reopening it would conflict with FileShare.None on Linux before identity can be checked.
                    if (!string.Equals(artifact.Identity, SecureLocalFile.GetPathIdentity(artifact.FullPath), StringComparison.Ordinal))
                    {
                        throw Error("runtime_runner_manifest_mutated", "A published runner artifact identity changed while it was measured.");
                    }
                }
                else if (!OperatingSystem.IsWindows())
                {
                    await using FileStream reopened = SecureLocalFile.OpenRead(artifact.FullPath);
                    if (!string.Equals(artifact.Identity, SecureLocalFile.GetHandleIdentity(reopened), StringComparison.Ordinal))
                    {
                        throw Error("runtime_runner_manifest_mutated", "A published runner artifact identity changed while it was measured.");
                    }
                }
            }

            RunnerArtifactFile[] files = [.. opened.Select(file => new RunnerArtifactFile(file.RelativePath, file.Length, file.Sha256))];
            using var buffer = new MemoryStream();
            using (var writer = new BinaryWriter(buffer, new UTF8Encoding(false), leaveOpen: true))
            {
                Write(writer, "Legacy.Maliev.DataMigration.RunnerArtifactManifest.v1");
                writer.Write(files.Length);
                foreach (RunnerArtifactFile file in files)
                {
                    Write(writer, file.RelativePath);
                    writer.Write(file.Length);
                    Write(writer, file.Sha256);
                }
            }

            return new(Convert.ToHexString(SHA256.HashData(buffer.ToArray())).ToLowerInvariant(), files);
        }
        finally
        {
            foreach (OpenedArtifact artifact in opened)
            {
                await artifact.Stream.DisposeAsync().ConfigureAwait(false);
            }
        }
    }

    private static void ValidateDirectoryTree(string root)
    {
        var rootInfo = new DirectoryInfo(root);
        rootInfo.Refresh();
        if (!rootInfo.Exists || IsLink(rootInfo))
        {
            throw Error("runtime_runner_path_invalid", "The Release publish directory must be a regular non-link directory.");
        }

        foreach (string directory in Directory.EnumerateDirectories(root, "*", SearchOption.AllDirectories))
        {
            if (IsLink(new DirectoryInfo(directory)))
            {
                throw Error("runtime_runner_link_forbidden", "Published runner links and reparse points are forbidden.");
            }

            SecureLocalFile.EnsureOwnerOnlyDirectory(directory);
        }
    }

    private static string[] EnumerateFiles(string root)
    {
        return [.. Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(Path.GetFullPath)
            .OrderBy(path => NormalizeRelative(root, path), StringComparer.Ordinal)];
    }

    private static string NormalizeRelative(string root, string path)
    {
        string relative = Path.GetRelativePath(root, path);
        return relative == ".." || relative.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal) || Path.IsPathRooted(relative)
            ? throw Error("runtime_runner_path_escape", "A published runner artifact escaped the approved directory.")
            : relative.Replace(Path.DirectorySeparatorChar, '/');
    }

    private static void EnsureNoLinks(string root, string path)
    {
        for (DirectoryInfo? current = new(Path.GetDirectoryName(path)!); current is not null; current = current.Parent)
        {
            if (IsLink(current))
            {
                throw Error("runtime_runner_link_forbidden", "Published runner links and reparse points are forbidden.");
            }

            if (string.Equals(current.FullName.TrimEnd(Path.DirectorySeparatorChar), root.TrimEnd(Path.DirectorySeparatorChar),
                OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
            {
                return;
            }
        }

        throw Error("runtime_runner_path_escape", "A published runner artifact escaped the approved directory.");
    }

    private static bool IsLink(FileSystemInfo info)
    {
        info.Refresh();
        return info.LinkTarget is not null || (info.Attributes & FileAttributes.ReparsePoint) != 0;
    }

    private static void Write(BinaryWriter writer, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static bool FixedHashEquals(string left, string right)
    {
        return left.Length == right.Length && CryptographicOperations.FixedTimeEquals(
            Encoding.ASCII.GetBytes(left), Encoding.ASCII.GetBytes(right));
    }

    private static RuntimeAttestationException Error(string code, string message)
    {
        return new(code, message);
    }

    private sealed record OpenedArtifact(
        string FullPath,
        string RelativePath,
        long Length,
        DateTime LastWriteUtc,
        string Identity,
        string Sha256,
        FileStream Stream);
}

public sealed record CloudNativePgTargetObservation(
    string Namespace,
    string Cluster,
    string Uid,
    string ResourceVersion,
    long Generation,
    long ObservedGeneration,
    string Phase,
    int Instances,
    int ReadyInstances,
    string CurrentPrimary,
    string TargetPrimary,
    bool Ready,
    bool ConsistentSystemId,
    bool ContinuousArchiving,
    bool LastBackupSucceeded)
{
    public string ReconciliationEvidence { get; init; } = string.Empty;
    public int ObservationReadCount { get; init; }
    public int StatusInstances { get; init; }
    public string SystemId { get; init; } = string.Empty;
    public string InstanceNames { get; init; } = string.Empty;
    public string HealthyInstances { get; init; } = string.Empty;
    public int PvcCount { get; init; }
    public string HealthyPvcs { get; init; } = string.Empty;
    public string DanglingPvcs { get; init; } = string.Empty;
    public string InitializingPvcs { get; init; } = string.Empty;
    public string ResizingPvcs { get; init; } = string.Empty;
    public string UnusablePvcs { get; init; } = string.Empty;
    public string ReadyReason { get; init; } = string.Empty;
    public string ConsistentSystemIdReason { get; init; } = string.Empty;
    public string ContinuousArchivingReason { get; init; } = string.Empty;
    public string LastBackupSucceededReason { get; init; } = string.Empty;

    public bool IsHealthy => HasHealthyTargetState && HasReconciliationEvidence;

    internal bool HasHealthyTargetState => Generation > 0 && Instances > 0 && StatusInstances == Instances &&
        ReadyInstances == Instances && Count(InstanceNames) == Instances &&
        string.Equals(InstanceNames, HealthyInstances, StringComparison.Ordinal) &&
        PvcCount == Instances && Count(HealthyPvcs) == PvcCount &&
        string.IsNullOrEmpty(DanglingPvcs) && string.IsNullOrEmpty(InitializingPvcs) &&
        string.IsNullOrEmpty(ResizingPvcs) && string.IsNullOrEmpty(UnusablePvcs) &&
        !string.IsNullOrWhiteSpace(SystemId) &&
        string.Equals(Phase, "Cluster in healthy state", StringComparison.Ordinal) &&
        !string.IsNullOrWhiteSpace(CurrentPrimary) && string.Equals(CurrentPrimary, TargetPrimary, StringComparison.Ordinal) &&
        Ready && string.Equals(ReadyReason, "ClusterIsReady", StringComparison.Ordinal) &&
        ConsistentSystemId && string.Equals(ConsistentSystemIdReason, "Unique", StringComparison.Ordinal) &&
        ContinuousArchiving && string.Equals(ContinuousArchivingReason, "ContinuousArchivingSuccess", StringComparison.Ordinal) &&
        LastBackupSucceeded && string.Equals(LastBackupSucceededReason, "LastBackupSucceeded", StringComparison.Ordinal);

    private bool HasReconciliationEvidence =>
        (string.Equals(ReconciliationEvidence, "observed-generation", StringComparison.Ordinal) &&
        ObservationReadCount == 1 && ObservedGeneration == Generation) ||
        (string.Equals(ReconciliationEvidence, "stable-resource-version-double-read", StringComparison.Ordinal) &&
        ObservationReadCount == 2 && ObservedGeneration == 0);

    private static int Count(string canonicalSet)
    {
        return string.IsNullOrEmpty(canonicalSet) ? 0 : canonicalSet.Count(character => character == '\n') + 1;
    }
}

public static class CloudNativePgTargetObservationParser
{
    public static CloudNativePgTargetObservation Parse(JsonElement root, string expectedNamespace, string expectedCluster)
    {
        CloudNativePgTargetObservation result = ParseSnapshot(root, expectedNamespace, expectedCluster);
        return !result.HasHealthyTargetState
            ? throw Error("runtime_target_unhealthy", "The CloudNativePG target is not fully healthy and reconciled.")
            : !result.IsHealthy
            ? throw Error("runtime_target_reconciliation_unproven", "The CloudNativePG target does not expose current reconciliation evidence.")
            : result;
    }

    public static CloudNativePgTargetObservation ParseStableDoubleRead(
        JsonElement firstRoot,
        JsonElement secondRoot,
        string expectedNamespace,
        string expectedCluster)
    {
        CloudNativePgTargetObservation first = ParseSnapshot(firstRoot, expectedNamespace, expectedCluster);
        CloudNativePgTargetObservation second = ParseSnapshot(secondRoot, expectedNamespace, expectedCluster);
        if (!string.IsNullOrEmpty(first.ReconciliationEvidence) || !string.IsNullOrEmpty(second.ReconciliationEvidence) ||
            first != second)
        {
            throw Error("runtime_target_drift", "The CloudNativePG target changed between stable observation reads.");
        }

        if (!first.HasHealthyTargetState)
        {
            throw Error("runtime_target_unhealthy", "The CloudNativePG target is not fully healthy and reconciled.");
        }

        CloudNativePgTargetObservation result = second with
        {
            ReconciliationEvidence = "stable-resource-version-double-read",
            ObservationReadCount = 2,
        };
        return !result.IsHealthy
            ? throw Error("runtime_target_unhealthy", "The CloudNativePG target is not fully healthy and reconciled.")
            : result;
    }

    private static CloudNativePgTargetObservation ParseSnapshot(JsonElement root, string expectedNamespace, string expectedCluster)
    {
        try
        {
            JsonElement metadata = root.GetProperty("metadata");
            JsonElement spec = root.GetProperty("spec");
            JsonElement status = root.GetProperty("status");
            string name = metadata.GetProperty("name").GetString() ?? "";
            string ns = metadata.GetProperty("namespace").GetString() ?? "";
            string uid = metadata.GetProperty("uid").GetString() ?? "";
            string resourceVersion = metadata.GetProperty("resourceVersion").GetString() ?? "";
            long generation = metadata.GetProperty("generation").GetInt64();
            string phase = status.GetProperty("phase").GetString() ?? "";
            int instances = spec.GetProperty("instances").GetInt32();
            int statusInstances = status.GetProperty("instances").GetInt32();
            int readyInstances = status.GetProperty("readyInstances").GetInt32();
            string currentPrimary = status.GetProperty("currentPrimary").GetString() ?? "";
            string targetPrimary = status.GetProperty("targetPrimary").GetString() ?? "";
            var observedGenerations = new List<long>();
            if (status.TryGetProperty("observedGeneration", out JsonElement topLevelObservedGeneration))
            {
                observedGenerations.Add(topLevelObservedGeneration.GetInt64());
            }

            ConditionEvidence Condition(string type)
            {
                JsonElement[] matches = [.. status.GetProperty("conditions").EnumerateArray().Where(condition =>
                    string.Equals(condition.GetProperty("type").GetString(), type, StringComparison.Ordinal))];
                if (matches.Length != 1)
                {
                    return new(false, string.Empty);
                }

                JsonElement condition = matches[0];
                if (condition.TryGetProperty("observedGeneration", out JsonElement conditionObservedGeneration))
                {
                    observedGenerations.Add(conditionObservedGeneration.GetInt64());
                }

                return new(
                    string.Equals(condition.GetProperty("status").GetString(), "True", StringComparison.Ordinal),
                    condition.TryGetProperty("reason", out JsonElement reason) ? reason.GetString() ?? string.Empty : string.Empty);
            }

            ConditionEvidence ready = Condition("Ready");
            ConditionEvidence consistentSystemId = Condition("ConsistentSystemID");
            ConditionEvidence continuousArchiving = Condition("ContinuousArchiving");
            ConditionEvidence lastBackupSucceeded = Condition("LastBackupSucceeded");

            return !string.Equals(ns, expectedNamespace, StringComparison.Ordinal) || !string.Equals(name, expectedCluster, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(resourceVersion) || generation <= 0
                ? throw Error("runtime_target_identity_invalid", "The observed CloudNativePG target identity is invalid.")
                : observedGenerations.Any(value => value != generation)
                ? throw Error("runtime_target_unhealthy", "The CloudNativePG target reports a stale observed generation.")
                : new CloudNativePgTargetObservation(
                ns, name, uid, resourceVersion, generation, observedGenerations.Count == 0 ? 0 : generation, phase,
                instances, readyInstances, currentPrimary, targetPrimary, ready.Status, consistentSystemId.Status,
                continuousArchiving.Status, lastBackupSucceeded.Status)
                {
                    ReconciliationEvidence = observedGenerations.Count == 0 ? string.Empty : "observed-generation",
                    ObservationReadCount = 1,
                    StatusInstances = statusInstances,
                    SystemId = status.GetProperty("systemID").GetString() ?? string.Empty,
                    InstanceNames = CanonicalSet(status.GetProperty("instanceNames")),
                    HealthyInstances = CanonicalSet(status.GetProperty("instancesStatus").GetProperty("healthy")),
                    PvcCount = status.GetProperty("pvcCount").GetInt32(),
                    HealthyPvcs = CanonicalSet(status.GetProperty("healthyPVC")),
                    DanglingPvcs = OptionalCanonicalSet(status, "danglingPVC"),
                    InitializingPvcs = OptionalCanonicalSet(status, "initializingPVC"),
                    ResizingPvcs = OptionalCanonicalSet(status, "resizingPVC"),
                    UnusablePvcs = OptionalCanonicalSet(status, "unusablePVC"),
                    ReadyReason = ready.Reason,
                    ConsistentSystemIdReason = consistentSystemId.Reason,
                    ContinuousArchivingReason = continuousArchiving.Reason,
                    LastBackupSucceededReason = lastBackupSucceeded.Reason,
                };
        }
        catch (RuntimeAttestationException) { throw; }
        catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        {
            throw Error("runtime_target_observation_invalid", "The CloudNativePG observation is incomplete or malformed.");
        }
    }

    private static string OptionalCanonicalSet(JsonElement parent, string propertyName)
    {
        return parent.TryGetProperty(propertyName, out JsonElement value) && value.ValueKind == JsonValueKind.Array
            ? CanonicalSet(value)
            : string.Empty;
    }

    private static string CanonicalSet(JsonElement array)
    {
        return string.Join('\n', array.EnumerateArray()
            .Select(value => value.GetString() ?? string.Empty)
            .Where(value => value.Length > 0)
            .Distinct(StringComparer.Ordinal)
            .Order(StringComparer.Ordinal));
    }

    private static RuntimeAttestationException Error(string code, string message)
    {
        return new(code, message);
    }

    private sealed record ConditionEvidence(bool Status, string Reason);
}

public interface ICloudNativePgTargetObserver
{
    Task<CloudNativePgTargetObservation> ObserveAsync(string namespaceName, string cluster, CancellationToken cancellationToken);
}

public interface IRuntimeAttestationVerifier
{
    Task VerifyAsync(ExecutionAuthorizationReceipt authorization, CancellationToken cancellationToken);
}

public sealed class RuntimeAttestationVerifier(
    string runnerPublishDirectory,
    ICloudNativePgTargetObserver targetObserver,
    string targetNamespace,
    string targetCluster) : IRuntimeAttestationVerifier
{
    public async Task VerifyAsync(ExecutionAuthorizationReceipt authorization, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        RunnerArtifactManifest manifest = await RunnerArtifactManifestMeasurer.MeasureAsync(runnerPublishDirectory, cancellationToken).ConfigureAwait(false);
        if (!FixedEquals(manifest.ManifestSha256, authorization.RunnerDigestSha256))
        {
            throw new RuntimeAttestationException("runtime_runner_drift", "The running Release publication no longer matches its signed authorization.");
        }

        CloudNativePgTargetObservation expected = authorization.TargetObservation ??
            throw new RuntimeAttestationException("runtime_target_binding_missing", "The authorization does not bind a CloudNativePG target observation.");
        CloudNativePgTargetObservation observed = await targetObserver.ObserveAsync(targetNamespace, targetCluster, cancellationToken).ConfigureAwait(false);
        if (observed != expected)
        {
            throw new RuntimeAttestationException("runtime_target_drift", "The CloudNativePG target was replaced, changed, or became unhealthy after authorization.");
        }
    }

    private static bool FixedEquals(string left, string? right)
    {
        return right is not null && left.Length == right.Length &&
        CryptographicOperations.FixedTimeEquals(Encoding.ASCII.GetBytes(left), Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }
}

public sealed record CloudNativePgTargetObserverOptions(Uri ApiServer, string ServiceAccountTokenFile, string ServiceAccountCaFile);

public sealed class CloudNativePgTargetObserver : ICloudNativePgTargetObserver, IDisposable
{
    public static CloudNativePgTargetObserver CreateForHost(CloudNativePgTargetObserverOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        HttpMessageHandler handler = HostRuntimeTrust.CreateKubernetesHandler(options.ApiServer, options.ServiceAccountTokenFile, options.ServiceAccountCaFile);
        return new(new HttpClient(handler) { BaseAddress = options.ApiServer }, options.ServiceAccountTokenFile, Task.Delay) { _protectedHost = true };
    }
    private bool _protectedHost;
    private static readonly TimeSpan StableReadDelay = TimeSpan.FromSeconds(2);
    private readonly HttpClient _client;
    private readonly string _tokenFile;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public CloudNativePgTargetObserver(CloudNativePgTargetObserverOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.ApiServer.IsAbsoluteUri ||
            !string.Equals(options.ApiServer.AbsoluteUri.TrimEnd('/'), "https://kubernetes.default.svc", StringComparison.Ordinal) ||
            !string.Equals(options.ServiceAccountTokenFile, "/var/run/secrets/kubernetes.io/serviceaccount/token", StringComparison.Ordinal) ||
            !string.Equals(options.ServiceAccountCaFile, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", StringComparison.Ordinal))
        {
            throw new ArgumentException("Only fixed in-cluster Kubernetes trust references are permitted.", nameof(options));
        }

        _tokenFile = options.ServiceAccountTokenFile;
        var handler = new SocketsHttpHandler();
        var ca = new X509Certificate2Collection(); ca.ImportFromPemFile(options.ServiceAccountCaFile);
        handler.SslOptions.RemoteCertificateValidationCallback = (_, certificate, chain, errors) =>
        {
            if (certificate is null || (errors & SslPolicyErrors.RemoteCertificateNameMismatch) != 0)
            {
                return false;
            }

            using var customChain = new X509Chain();
            customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            customChain.ChainPolicy.CustomTrustStore.AddRange(ca);
            return customChain.Build(new X509Certificate2(certificate));
        };
        _client = new HttpClient(handler) { BaseAddress = options.ApiServer };
        _delay = Task.Delay;
    }

    internal CloudNativePgTargetObserver(
        HttpClient client,
        string tokenFile,
        Func<TimeSpan, CancellationToken, Task> delay)
    {
        _client = client;
        _tokenFile = tokenFile;
        _delay = delay;
    }

    public async Task<CloudNativePgTargetObservation> ObserveAsync(string namespaceName, string cluster, CancellationToken cancellationToken)
    {
        try
        {
            return await ObserveWithStableFallbackAsync(
                (_, observedNamespace, observedCluster) => ObserveSnapshotAsync(
                    observedNamespace, observedCluster, cancellationToken),
                _delay,
                namespaceName,
                cluster,
                cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeAttestationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or HttpRequestException or JsonException)
        {
            throw new RuntimeAttestationException("runtime_target_observation_failed", "The exact CloudNativePG target could not be observed securely.");
        }
    }

    internal static async Task<CloudNativePgTargetObservation> ObserveWithStableFallbackAsync(
        Func<CancellationToken, string, string, Task<JsonElement>> observe,
        Func<TimeSpan, CancellationToken, Task> delay,
        string namespaceName,
        string cluster,
        CancellationToken cancellationToken)
    {
        JsonElement first = await observe(cancellationToken, namespaceName, cluster).ConfigureAwait(false);
        try
        {
            return CloudNativePgTargetObservationParser.Parse(first, namespaceName, cluster);
        }
        catch (RuntimeAttestationException exception) when (exception.Code == "runtime_target_reconciliation_unproven")
        {
            await delay(StableReadDelay, cancellationToken).ConfigureAwait(false);
            JsonElement second = await observe(cancellationToken, namespaceName, cluster).ConfigureAwait(false);
            return CloudNativePgTargetObservationParser.ParseStableDoubleRead(
                first, second, namespaceName, cluster);
        }
    }

    private async Task<JsonElement> ObserveSnapshotAsync(
        string namespaceName,
        string cluster,
        CancellationToken cancellationToken)
    {
        string token = (_protectedHost ? HostRuntimeTrust.ReadText(_tokenFile) :
            await File.ReadAllTextAsync(_tokenFile, cancellationToken).ConfigureAwait(false)).Trim();
        if (!IsValidBoundToken(token))
        {
            throw new RuntimeAttestationException("runtime_target_token_invalid", "The projected Kubernetes bound token is empty or invalid.");
        }

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"/apis/postgresql.cnpg.io/v1/namespaces/{Uri.EscapeDataString(namespaceName)}/clusters/{Uri.EscapeDataString(cluster)}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using HttpResponseMessage response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new RuntimeAttestationException("runtime_target_observation_failed", "The exact CloudNativePG target could not be observed.");
        }

        using JsonDocument document = await JsonDocument.ParseAsync(
            await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false),
            cancellationToken: cancellationToken).ConfigureAwait(false);
        return document.RootElement.Clone();
    }

    private static bool IsValidBoundToken(string token)
    {
        string[] segments = token.Split('.');
        return segments.Length == 3 && segments.All(segment => segment.Length > 0 &&
            segment.All(character => char.IsAsciiLetterOrDigit(character) || character is '-' or '_'));
    }

    public void Dispose()
    {
        _client.Dispose();
    }
}
