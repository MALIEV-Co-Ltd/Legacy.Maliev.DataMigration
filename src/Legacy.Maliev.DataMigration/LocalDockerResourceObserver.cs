using System.Collections.Immutable;
using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Legacy.Maliev.DataMigration;

internal interface IReadOnlyDockerProcess
{
    Task<BackupProcessResult> RunAsync(IReadOnlyList<string> arguments, CancellationToken cancellationToken);
}

/// <summary>Read-only operator-host inspection. Supports local named pipes/unix sockets, Linux overlay2 and ordinary local volumes only.</summary>
public sealed partial class LocalDockerResourceObserver
{
    private readonly IReadOnlyDockerProcess _process;
    public LocalDockerResourceObserver() : this(new ReadOnlyDockerProcess()) { }
    internal LocalDockerResourceObserver(IReadOnlyDockerProcess process)
    {
        _process = process;
    }

    /// <summary>When supplied, the trusted immutable image ID is checked before any in-container read-only process.</summary>
    public async Task<LocalDockerResourceState> ObserveAsync(string containerId, CancellationToken cancellationToken, string? expectedImageId = null)
    {
        Require(Hash().IsMatch(containerId), "container_id");
        string context = await RunAsync(["context", "show"], cancellationToken).ConfigureAwait(false);
        Require(SafeName().IsMatch(context), "context");
        string host = await RunAsync(["context", "inspect", "--format", "{{.Endpoints.docker.Host}}", context], cancellationToken).ConfigureAwait(false);
        Require(IsLocalDockerHost(host), "remote_context");
        try
        {
            using JsonDocument info = await InspectAsync(host, ["info", "--format",
                "{\"ID\":{{json .ID}},\"DockerRootDir\":{{json .DockerRootDir}},\"OSType\":{{json .OSType}},\"Driver\":{{json .Driver}}}"], cancellationToken).ConfigureAwait(false);
            JsonElement daemon = info.RootElement;
            Require(Text(daemon, "OSType") == "linux" && Text(daemon, "Driver") == "overlay2", "storage_backend");
            string root = PathValue(daemon, "DockerRootDir");
            using JsonDocument inspect = await InspectAsync(host, ["container", "inspect", "--format", ContainerFormat, containerId], cancellationToken).ConfigureAwait(false);
            JsonElement container = inspect.RootElement;
            Require(Text(container, "Id") == containerId && container.GetProperty("Running").GetBoolean() &&
                !container.GetProperty("Paused").GetBoolean() && !container.GetProperty("Restarting").GetBoolean(), "container_state");
            string mode = Text(container, "NetworkMode");
            Require(mode != "host" && mode != "none" && !mode.StartsWith("container:", StringComparison.Ordinal), "network_mode");
            JsonElement graph = container.GetProperty("GraphDriver");
            JsonElement data = graph.GetProperty("Data");
            Require(Text(graph, "Name") == "overlay2" && Text(data, "ID") == containerId, "writable_layer");
            var layer = new DockerObservedLayer("overlay2", containerId, Text(data, "LowerDir"),
                PathValue(data, "MergedDir"), PathValue(data, "UpperDir"), PathValue(data, "WorkDir"), CanonicalJson(graph));
            Require(layer.LowerDir.Split(':').All(IsAbsoluteLinuxPath) &&
                new[] { layer.MergedDir, layer.UpperDir, layer.WorkDir }.All(path => path.StartsWith(root + "/overlay2/", StringComparison.Ordinal)), "writable_layer");
            string imageId = Text(container, "Image");
            Require(imageId.StartsWith("sha256:", StringComparison.Ordinal) && Hash().IsMatch(imageId[7..]), "image");
            Require(expectedImageId is null || imageId == expectedImageId, "expected_image");
            using JsonDocument imageInspect = await InspectAsync(host, ["image", "inspect", "--format", ImageFormat, imageId], cancellationToken).ConfigureAwait(false);
            JsonElement image = imageInspect.RootElement;
            Require(Text(image, "Id") == imageId && Text(image, "Os") == "linux" && Text(image.GetProperty("RootFS"), "Type") == "layers", "image");
            var observedImage = new DockerObservedImage(imageId, Text(image, "Created"), Text(image, "Os"), Text(image, "Architecture"),
                Strings(image.GetProperty("RepoDigests")).Order(StringComparer.Ordinal).ToImmutableArray(), Strings(image.GetProperty("RootFS").GetProperty("Layers")));
            Require(!observedImage.RepoDigests.IsEmpty && !observedImage.Layers.IsEmpty, "image");
            var mounts = ImmutableArray.CreateBuilder<DockerObservedMount>();
            foreach (JsonElement mount in container.GetProperty("Mounts").EnumerateArray())
            {
                Require(Text(mount, "Type") == "volume" && Text(mount, "Driver") == "local", "mount_type");
                string name = Text(mount, "Name");
                Require(SafeName().IsMatch(name), "volume");
                using JsonDocument volumeInspect = await InspectAsync(host, ["volume", "inspect", "--format", VolumeFormat, name], cancellationToken).ConfigureAwait(false);
                JsonElement volume = volumeInspect.RootElement;
                Require(Text(volume, "Name") == name && Text(volume, "Driver") == "local" && Text(volume, "Scope") == "local" &&
                    IsEmptyOptions(volume.GetProperty("Options")), "volume");
                string source = PathValue(mount, "Source");
                Require(source == PathValue(volume, "Mountpoint") && source.StartsWith(root + "/volumes/", StringComparison.Ordinal), "volume_source");
                var observedVolume = new DockerObservedVolume(name, "local", Text(volume, "CreatedAt"), source, "local",
                    OptionalText(volume, "RunBinding"), OptionalText(volume, "VolumeBinding"), OptionalText(volume, "Fingerprint"));
                string destination = PathValue(mount, "Destination");
                FileSystemObjectIdentity identity = await StatAsync(host, containerId, destination, "directory", cancellationToken).ConfigureAwait(false);
                mounts.Add(new("volume", name, source, destination, "local", OptionalText(mount, "Mode"), mount.GetProperty("RW").GetBoolean(),
                    OptionalText(mount, "Propagation"), CanonicalJson(mount), observedVolume, identity));
            }
            Require(mounts.Select(mount => mount.Destination).Distinct(StringComparer.Ordinal).Count() == mounts.Count, "mount_duplicate");
            var networks = ImmutableArray.CreateBuilder<DockerObservedNetwork>();
            foreach (JsonProperty network in container.GetProperty("Networks").EnumerateObject())
            {
                networks.Add(new(network.Name, Text(network.Value, "NetworkID"), Text(network.Value, "EndpointID"),
                    Text(network.Value, "IPAddress"), CanonicalJson(network.Value)));
            }
            Require(networks.Count > 0, "network");
            var ports = ImmutableArray.CreateBuilder<DockerObservedPort>();
            foreach (JsonProperty port in container.GetProperty("Ports").EnumerateObject())
            {
                if (port.Value.ValueKind == JsonValueKind.Null) { continue; }
                Require(port.Name.EndsWith("/tcp", StringComparison.Ordinal) && int.TryParse(port.Name.AsSpan(0, port.Name.Length - 4), out _), "port");
                int containerPort = int.Parse(port.Name.AsSpan(0, port.Name.Length - 4), CultureInfo.InvariantCulture);
                foreach (JsonElement binding in port.Value.EnumerateArray())
                {
                    ports.Add(new(Text(binding, "HostIp"), int.Parse(Text(binding, "HostPort"), CultureInfo.InvariantCulture), containerPort));
                }
            }
            return new(context, host, Text(daemon, "ID"), root, containerId, Text(container, "Name").TrimStart('/'),
                Text(container, "Created"), Text(container, "StartedAt"), Text(container, "Hostname"), OptionalText(container, "RunBinding"),
                container.GetProperty("ReadonlyRootfs").GetBoolean(), mode, observedImage, layer,
                await StatAsync(host, containerId, "/", "directory", cancellationToken).ConfigureAwait(false),
                mounts.OrderBy(mount => mount.Destination, StringComparer.Ordinal).ToImmutableArray(),
                networks.OrderBy(network => network.Name, StringComparer.Ordinal).ToImmutableArray(),
                ports.OrderBy(port => port.HostAddress, StringComparer.Ordinal).ThenBy(port => port.HostPort).ThenBy(port => port.ContainerPort).ToImmutableArray());
        }
        catch (Exception error) when (error is JsonException or KeyNotFoundException or InvalidOperationException or FormatException or OverflowException)
        {
            throw Reject("metadata_invalid");
        }
    }

    internal async Task<FileSystemObjectIdentity> StatAsync(string host, string containerId, string path, string expectedType, CancellationToken token)
    {
        Require(IsLocalDockerHost(host) && Hash().IsMatch(containerId) && IsAbsoluteLinuxPath(path), "stat_path");
        string resolved = await RunAsync(["--host", host, "exec", containerId, "readlink", "-e", "--", path], token).ConfigureAwait(false);
        Require(resolved == path, "filesystem_path_alias");
        string output = await RunAsync(["--host", host, "exec", containerId, "stat", "--printf=%d|%i|%F", "--", path], token).ConfigureAwait(false);
        string[] fields = output.Split('|');
        Require(fields.Length == 3 && ulong.TryParse(fields[0], out ulong device) && device > 0 &&
            ulong.TryParse(fields[1], out ulong inode) && inode > 0 && fields[2] == expectedType, "filesystem_identity");
        return new(fields[0], fields[1], fields[2]);
    }

    internal static bool IsAbsoluteLinuxPath(string path)
    {
        return path.StartsWith('/') && !path.Contains("//", StringComparison.Ordinal) &&
        !path.Split('/').Any(part => part is "." or "..") && !path.Any(char.IsControl);
    }

    internal static void Require(bool condition, string boundary) { if (!condition) { throw Reject(boundary); } }
    internal static MigrationExecutionException Reject(string boundary)
    {
        return new("source_observation_" + boundary, "Read-only source identity observation could not verify the required " + boundary + " boundary.");
    }

    private static bool IsLocalDockerHost(string host)
    {
        return LocalPipe().IsMatch(host) ||
            (host.StartsWith("unix:///", StringComparison.Ordinal) && IsAbsoluteLinuxPath(host[7..]));
    }

    private static bool IsEmptyOptions(JsonElement options)
    {
        return options.ValueKind == JsonValueKind.Null || (options.ValueKind == JsonValueKind.Object && !options.EnumerateObject().Any());
    }

    private static string Text(JsonElement item, string name) { string value = OptionalText(item, name); Require(!string.IsNullOrWhiteSpace(value), "missing_identity"); return value; }
    private static string OptionalText(JsonElement item, string name)
    {
        return item.GetProperty(name).ValueKind == JsonValueKind.Null ? "" : item.GetProperty(name).GetString() ?? "";
    }

    private static string PathValue(JsonElement item, string name) { string path = Text(item, name); Require(IsAbsoluteLinuxPath(path), "resource_path"); return path; }
    private static ImmutableArray<string> Strings(JsonElement value)
    {
        return value.EnumerateArray().Select(item => item.GetString() ?? "").ToImmutableArray();
    }

    private static string CanonicalJson(JsonElement value)
    {
        return JsonSerializer.Serialize(CanonicalValue(value));
    }

    private static object? CanonicalValue(JsonElement value)
    {
        return value.ValueKind == JsonValueKind.Object
            ? value.EnumerateObject().OrderBy(property => property.Name, StringComparer.Ordinal)
                .ToDictionary(property => property.Name, property => CanonicalValue(property.Value), StringComparer.Ordinal)
            : value.ValueKind == JsonValueKind.Array ? value.EnumerateArray().Select(CanonicalValue).ToArray() : value;
    }

    private async Task<JsonDocument> InspectAsync(string host, string[] args, CancellationToken token)
    {
        return JsonDocument.Parse(await RunAsync(["--host", host, .. args], token).ConfigureAwait(false));
    }

    private async Task<string> RunAsync(string[] args, CancellationToken token)
    {
        BackupProcessResult result = await _process.RunAsync(args, token).ConfigureAwait(false);
        Require(result.ExitCode == 0, "docker_process");
        return result.StandardOutput.Trim();
    }
    [GeneratedRegex("^[0-9a-f]{64}$", RegexOptions.CultureInvariant)] private static partial Regex Hash();
    [GeneratedRegex("^npipe:/+\\./pipe/[A-Za-z0-9_.-]+$", RegexOptions.CultureInvariant)] private static partial Regex LocalPipe();
    [GeneratedRegex("^[A-Za-z0-9][A-Za-z0-9_.-]*$", RegexOptions.CultureInvariant)] private static partial Regex SafeName();
    private const string ContainerFormat = "{\"Id\":{{json .Id}},\"Name\":{{json .Name}},\"Image\":{{json .Image}},\"Created\":{{json .Created}},\"Hostname\":{{json .Config.Hostname}},\"RunBinding\":{{json (index .Config.Labels \"com.maliev.legacy.restore-run\")}},\"Running\":{{json .State.Running}},\"Paused\":{{json .State.Paused}},\"Restarting\":{{json .State.Restarting}},\"StartedAt\":{{json .State.StartedAt}},\"ReadonlyRootfs\":{{json .HostConfig.ReadonlyRootfs}},\"NetworkMode\":{{json .HostConfig.NetworkMode}},\"GraphDriver\":{{json .GraphDriver}},\"Mounts\":{{json .Mounts}},\"Networks\":{{json .NetworkSettings.Networks}},\"Ports\":{{json .NetworkSettings.Ports}}}";
    private const string ImageFormat = "{\"Id\":{{json .Id}},\"Created\":{{json .Created}},\"Os\":{{json .Os}},\"Architecture\":{{json .Architecture}},\"RepoDigests\":{{json .RepoDigests}},\"RootFS\":{{json .RootFS}}}";
    private const string VolumeFormat = "{\"Name\":{{json .Name}},\"Driver\":{{json .Driver}},\"CreatedAt\":{{json .CreatedAt}},\"Mountpoint\":{{json .Mountpoint}},\"Scope\":{{json .Scope}},\"Options\":{{json .Options}},\"RunBinding\":{{json (index .Labels \"com.maliev.legacy.restore-run\")}},\"VolumeBinding\":{{json (index .Labels \"com.maliev.legacy.restore-volume-binding\")}},\"Fingerprint\":{{json (index .Labels \"com.maliev.legacy.restore-volume-fingerprint\")}}}";
}
