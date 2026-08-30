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
    public static async Task<RunnerArtifactManifest> MeasureAsync(string publishDirectory, CancellationToken cancellationToken)
    {
        try
        {
            return await MeasureCoreAsync(publishDirectory, cancellationToken).ConfigureAwait(false);
        }
        catch (RuntimeAttestationException)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            throw Error("runtime_runner_measurement_failed", "The Release publication could not be measured securely.");
        }
    }

    private static async Task<RunnerArtifactManifest> MeasureCoreAsync(string publishDirectory, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(publishDirectory))
        {
            throw Error("runtime_runner_path_invalid", "A Release publish directory is required.");
        }

        string root = Path.GetFullPath(publishDirectory);
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
        }

        string[] paths = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(Path.GetFullPath)
            .OrderBy(path => NormalizeRelative(root, path), StringComparer.Ordinal)
            .ToArray();
        if (paths.Length == 0)
        {
            throw Error("runtime_runner_manifest_empty", "The Release publish directory is empty.");
        }

        var files = new List<RunnerArtifactFile>(paths.Length);
        foreach (string path in paths)
        {
            cancellationToken.ThrowIfCancellationRequested();
            EnsureNoLinks(root, path);
            string relative = NormalizeRelative(root, path);
            var before = new FileInfo(path);
            before.Refresh();
            if (!before.Exists || IsLink(before))
            {
                throw Error("runtime_runner_manifest_invalid", "A published runner artifact is not a regular file.");
            }

            long length = before.Length;
            DateTime lastWriteUtc = before.LastWriteTimeUtc;
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            string sha = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false)).ToLowerInvariant();
            before.Refresh();
            if (!before.Exists || before.Length != length || before.LastWriteTimeUtc != lastWriteUtc || IsLink(before))
            {
                throw Error("runtime_runner_manifest_mutated", "The published runner changed while it was measured.");
            }

            files.Add(new(relative, length, sha));
        }

        string[] afterPaths = Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories)
            .Select(path => NormalizeRelative(root, Path.GetFullPath(path))).Order(StringComparer.Ordinal).ToArray();
        if (!afterPaths.SequenceEqual(files.Select(file => file.RelativePath), StringComparer.Ordinal))
        {
            throw Error("runtime_runner_manifest_mutated", "The published runner file set changed while it was measured.");
        }

        using var buffer = new MemoryStream();
        using (var writer = new BinaryWriter(buffer, new UTF8Encoding(false), leaveOpen: true))
        {
            Write(writer, "Legacy.Maliev.DataMigration.RunnerArtifactManifest.v1");
            writer.Write(files.Count);
            foreach (RunnerArtifactFile file in files)
            {
                Write(writer, file.RelativePath); writer.Write(file.Length); Write(writer, file.Sha256);
            }
        }
        return new(Convert.ToHexString(SHA256.HashData(buffer.ToArray())).ToLowerInvariant(), files);
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
        byte[] bytes = Encoding.UTF8.GetBytes(value); writer.Write(bytes.Length); writer.Write(bytes);
    }

    private static RuntimeAttestationException Error(string code, string message)
    {
        return new(code, message);
    }
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
    public bool IsHealthy => Generation > 0 && ObservedGeneration == Generation && Instances > 0 && ReadyInstances == Instances &&
        string.Equals(Phase, "Cluster in healthy state", StringComparison.Ordinal) && !string.IsNullOrWhiteSpace(CurrentPrimary) &&
        string.Equals(CurrentPrimary, TargetPrimary, StringComparison.Ordinal) && Ready && ConsistentSystemId && ContinuousArchiving && LastBackupSucceeded;
}

public static class CloudNativePgTargetObservationParser
{
    public static CloudNativePgTargetObservation Parse(JsonElement root, string expectedNamespace, string expectedCluster)
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
            long observedGeneration = status.GetProperty("observedGeneration").GetInt64();
            string phase = status.GetProperty("phase").GetString() ?? "";
            int instances = spec.GetProperty("instances").GetInt32();
            int readyInstances = status.GetProperty("readyInstances").GetInt32();
            string currentPrimary = status.GetProperty("currentPrimary").GetString() ?? "";
            string targetPrimary = status.GetProperty("targetPrimary").GetString() ?? "";
            bool Condition(string type)
            {
                return status.GetProperty("conditions").EnumerateArray().Any(condition =>
                string.Equals(condition.GetProperty("type").GetString(), type, StringComparison.Ordinal) &&
                string.Equals(condition.GetProperty("status").GetString(), "True", StringComparison.Ordinal));
            }

            if (!string.Equals(ns, expectedNamespace, StringComparison.Ordinal) || !string.Equals(name, expectedCluster, StringComparison.Ordinal) ||
                string.IsNullOrWhiteSpace(uid) || string.IsNullOrWhiteSpace(resourceVersion) || generation <= 0)
            {
                throw Error("runtime_target_identity_invalid", "The observed CloudNativePG target identity is invalid.");
            }

            var result = new CloudNativePgTargetObservation(ns, name, uid, resourceVersion, generation, observedGeneration, phase,
                instances, readyInstances, currentPrimary, targetPrimary, Condition("Ready"), Condition("ConsistentSystemID"),
                Condition("ContinuousArchiving"), Condition("LastBackupSucceeded"));
            return !result.IsHealthy
                ? throw Error("runtime_target_unhealthy", "The CloudNativePG target is not fully healthy and reconciled.")
                : result;
        }
        catch (RuntimeAttestationException) { throw; }
        catch (Exception exception) when (exception is KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        {
            throw Error("runtime_target_observation_invalid", "The CloudNativePG observation is incomplete or malformed.");
        }
    }

    private static RuntimeAttestationException Error(string code, string message)
    {
        return new(code, message);
    }
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
    private readonly HttpClient _client;
    private readonly string _tokenFile;

    public CloudNativePgTargetObserver(CloudNativePgTargetObserverOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        if (!options.ApiServer.IsAbsoluteUri || options.ApiServer.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException("A HTTPS API server is required.", nameof(options));
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
    }

    public async Task<CloudNativePgTargetObservation> ObserveAsync(string namespaceName, string cluster, CancellationToken cancellationToken)
    {
        try
        {
            string token = (await File.ReadAllTextAsync(_tokenFile, cancellationToken).ConfigureAwait(false)).Trim();
            if (token.Length == 0)
            {
                throw new RuntimeAttestationException("runtime_target_token_invalid", "The read-only Kubernetes token is empty.");
            }

            using var request = new HttpRequestMessage(HttpMethod.Get,
                $"/apis/postgresql.cnpg.io/v1/namespaces/{Uri.EscapeDataString(namespaceName)}/clusters/{Uri.EscapeDataString(cluster)}");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using HttpResponseMessage response = await _client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new RuntimeAttestationException("runtime_target_observation_failed", "The exact CloudNativePG target could not be observed.");
            }

            using JsonDocument document = await JsonDocument.ParseAsync(await response.Content.ReadAsStreamAsync(cancellationToken).ConfigureAwait(false), cancellationToken: cancellationToken).ConfigureAwait(false);
            return CloudNativePgTargetObservationParser.Parse(document.RootElement, namespaceName, cluster);
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

    public void Dispose()
    {
        _client.Dispose();
    }
}
