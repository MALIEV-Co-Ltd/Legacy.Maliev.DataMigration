using System.Net.NetworkInformation;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentAuthArchiveDefinitionAnchorIntent(string Kind, Guid OperationId, string SourceCommitSha,
    string ParentBindingSha256, string Root, LocalExecutionBinding Binding, DateTimeOffset BeganAtUtc,
    DateTimeOffset ExpiresAtUtc, IReadOnlyList<string> BeforeContainers, IReadOnlyList<string> BeforeVolumes);

// A fixed resource handoff, never an execution permission or a configurable cleanup selector.
internal sealed class CurrentAuthArchiveDefinitionAnchorOwner
{
    internal const string ParentLabel = "codex.repair.definition-anchor-parent";
    internal const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    private readonly CurrentAppOwnedRepairCustody _parent;
    private readonly string _prefix;
    private readonly CurrentAuthArchiveDefinitionAnchorIntent _intent;
    private int _created;
    internal Guid Operation => _intent.OperationId;
    internal string Root => _intent.Root;
    internal string Name => "legacy-delta-proof-" + Operation.ToString("N");
    internal LocalExecutionBinding Binding => _intent.Binding;
    internal string ParentBindingSha256 => _intent.ParentBindingSha256;
    internal DateTimeOffset BeganAtUtc => _intent.BeganAtUtc;
    internal DateTimeOffset ExpiresAtUtc => _intent.ExpiresAtUtc;
    private CurrentAuthArchiveDefinitionAnchorOwner(CurrentAppOwnedRepairCustody parent, string prefix, CurrentAuthArchiveDefinitionAnchorIntent intent)
    { _parent = parent; _prefix = prefix; _intent = intent; }

    internal static async Task<CurrentAuthArchiveDefinitionAnchorOwner> BeginAsync(CurrentAppOwnedRepairCustody parent,
        WindowsLocalRunAuthority parentAuthority, CancellationToken ct)
    {
        parentAuthority.ValidateHeld(); parent.Require(); CurrentAuthRepairCapacity.Require(admission: true);
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct);
        LocalExecutionBinding parentBinding = parentAuthority.Binding;
        string parentRoot = parentBinding.ArtifactRootCanonicalPath;
        Guid operation = Guid.NewGuid(); string root = Path.Combine(parentRoot, "auth-definition-anchor-" + operation.ToString("N"));
        string name = "legacy-delta-proof-" + operation.ToString("N");
        string[] containers = Lines(await Docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], ct));
        string[] volumes = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct));
        if (Directory.Exists(root) || File.Exists(root) || volumes.Contains(name, StringComparer.Ordinal) || containers.Any(x => x.Split('|')[^1] == name)) { throw Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        LocalExecutionBinding binding;
        using (var authority = WindowsLocalRunAuthority.AcquireFresh(root))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { binding = authority.Binding; await files.WriteNewAsync(Path.Combine(root, "fixture-binding.json"), JsonSerializer.SerializeToUtf8Bytes(binding), ct); }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        var intent = new CurrentAuthArchiveDefinitionAnchorIntent("current-auth-archive-definition-anchor-intent-v2", operation, accepted,
            parentBinding.ComputeSha256(), root, binding, began, began.AddMinutes(8), containers, volumes);
        string prefix = Path.Combine(parentRoot, "archive-definition-anchor-" + operation.ToString("N"));
        await parent.WriteNewAsync(prefix + "-intent.json", JsonSerializer.SerializeToUtf8Bytes(intent), ct);
        return new(parent, prefix, intent);
    }

    internal void RequireForFixture()
    {
        RequireLive();
        if (Path.GetFileName(Root) != "auth-definition-anchor-" + Operation.ToString("N") ||
            !StringComparer.OrdinalIgnoreCase.Equals(Binding.ArtifactRootCanonicalPath, Root) ||
            Binding.ComputeSha256() == ParentBindingSha256) { throw Invalid(); }
    }

    internal void RequireBeforeCreate()
    {
        RequireForFixture();
        if (Interlocked.CompareExchange(ref _created, 1, 0) != 0)
        { throw Invalid(); }
    }

    internal async Task ObserveVolumeAsync(CancellationToken ct)
    {
        RequireLive();
        using var document = JsonDocument.Parse(await Docker(["volume", "inspect", Name], ct));
        JsonElement volume = document.RootElement.EnumerateArray().Single(); RequireVolume(volume, _intent);
        await _parent.WriteNewAsync(_prefix + "-volume.json", JsonSerializer.SerializeToUtf8Bytes(volume), ct);
    }

    internal async Task ObserveContainerAsync(CancellationToken ct)
    {
        RequireLive();
        using var volumeDocument = JsonDocument.Parse(_parent.Read(_prefix + "-volume.json", sharedReader: true, maximumBytes: 65536));
        using var document = JsonDocument.Parse(await Docker(["inspect", "--type", "container", Name], ct));
        JsonElement container = document.RootElement.EnumerateArray().Single(); RequireContainer(container, volumeDocument.RootElement, _intent);
        // Docker's Config.Env includes the disposable administrator credential. It is never evidence.
        var retained = JsonNode.Parse(container.GetRawText())!.AsObject(); _ = retained["Config"]!.AsObject().Remove("Env");
        await _parent.WriteNewAsync(_prefix + "-container.json", JsonSerializer.SerializeToUtf8Bytes(retained), ct);
    }

    internal Task RequireAbsentAfterOwnerAsync(CancellationToken ct)
    {
        return ObserveAbsenceAsync("absence", ct);
    }

    private async Task ObserveAbsenceAsync(string slot, CancellationToken ct)
    {
        _parent.Require();
        string[] containers = Lines(await Docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], ct));
        string[] volumes = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct));
        if (File.Exists(_prefix + "-container.json"))
        {
            using var record = JsonDocument.Parse(_parent.Read(_prefix + "-container.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            RequireRecordedContainerAbsent(record.RootElement.GetProperty("Id").GetString()!, containers);
        }
        if (containers.Any(x => x.Split('|')[^1] == Name) || volumes.Contains(Name, StringComparer.Ordinal)) { throw Invalid(); }
        int[] listeners = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
        if (File.Exists(_prefix + "-container.json"))
        {
            using var record = JsonDocument.Parse(_parent.Read(_prefix + "-container.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            if (listeners.Contains(Port(record.RootElement))) { throw Invalid(); }
        }
        if (File.Exists(Path.Combine(Root, "operator.txt")) || File.Exists(Path.Combine(Root, "ordinary.txt"))) { throw Invalid(); }
        await _parent.WriteNewAsync(_prefix + "-" + slot + ".json", JsonSerializer.SerializeToUtf8Bytes(new
        { Operation, ObservedAtUtc = DateTimeOffset.UtcNow, Containers = containers, Volumes = volumes, Listeners = listeners, PhaseProofComplete = false }), ct);
    }

    internal static async Task CleanupRecordedAfterSettledJobAsync(CurrentAppOwnedRepairCustody parent,
        WindowsLocalRunAuthority parentAuthority, CurrentAuthArchiveProofArtifact intentArtifact, CurrentAuthTypedHostJob job, CancellationToken ct)
    {
        parent.Require(); parentAuthority.ValidateHeld(); if (!job.Empty) { throw Invalid(); }
        byte[] bytes = parent.Read(intentArtifact.Path, sharedReader: true, maximumBytes: 2 * 1024 * 1024);
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != intentArtifact.Sha256) { throw Invalid(); }
        var intent = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveDefinitionAnchorIntent>(bytes); RequireIntentShape(intent);
        string parentRoot = parentAuthority.Binding.ArtifactRootCanonicalPath;
        string prefix = Path.Combine(parentRoot, "archive-definition-anchor-" + intent.OperationId.ToString("N"));
        if (intentArtifact.Path != prefix + "-intent.json" || intent.ParentBindingSha256 != parentAuthority.Binding.ComputeSha256() ||
            intent.Root != Path.Combine(parentRoot, "auth-definition-anchor-" + intent.OperationId.ToString("N"))) { throw Invalid(); }
        var owner = new CurrentAuthArchiveDefinitionAnchorOwner(parent, prefix, intent);
        try { await owner.CleanupAfterSettledJobAsync(job, ct); }
        catch (Exception failure)
        {
            using var retention = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await parent.WriteNewAsync(prefix + "-supervisor-failure.json", JsonSerializer.SerializeToUtf8Bytes(new
            {
                intent.OperationId,
                ObservedAtUtc = DateTimeOffset.UtcNow,
                FailureType = failure.GetType().Name,
                CleanupFailed = true,
                PreservedUncertainResources = true,
                intent.ExpiresAtUtc,
                PhaseProofComplete = false
            }), retention.Token);
            throw;
        }
    }

    private async Task CleanupAfterSettledJobAsync(CurrentAuthTypedHostJob job, CancellationToken ct)
    {
        _parent.Require(); if (!job.Empty) { throw Invalid(); }
        string[] inventory = Lines(await Docker(["ps", "--all", "--no-trunc", "--format", "{{.ID}}|{{.Names}}"], ct));
        using var recordedContainer = JsonDocument.Parse(_parent.Read(_prefix + "-container.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
        string[] ids = RequireRecordedContainerForCleanup(recordedContainer.RootElement.GetProperty("Id").GetString()!, Name, inventory);
        bool exists = Lines(await Docker(["volume", "ls", "--format", "{{.Name}}"], ct)).Contains(Name, StringComparer.Ordinal);
        if (ids.Length > 1) { throw Invalid(); }
        if (ids.Length != 0 || exists)
        {
            // No recorded identity means uncertain creation. Preserve it instead of adopting it by label/name.
            using var volumeRecord = JsonDocument.Parse(_parent.Read(_prefix + "-volume.json", sharedReader: true, maximumBytes: 65536));
            using var containerRecord = ids.Length == 0 ? null : JsonDocument.Parse(_parent.Read(_prefix + "-container.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024));
            using var authority = WindowsLocalRunAuthority.AcquireResume(Root, Binding);
            if (ids.Length == 1)
            {
                using var actual = JsonDocument.Parse(await Docker(["inspect", "--type", "container", ids[0]], ct));
                JsonElement container = actual.RootElement.EnumerateArray().Single();
                RequireContainer(container, volumeRecord.RootElement, _intent);
                if (containerRecord!.RootElement.GetProperty("Id").GetString() != ids[0] ||
                    container.GetProperty("Created").GetString() != containerRecord.RootElement.GetProperty("Created").GetString() ||
                    container.GetProperty("Image").GetString() != containerRecord.RootElement.GetProperty("Image").GetString()) { throw Invalid(); }
                int port = Port(container);
                if (IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpConnections().Any(x => x.State == TcpState.Established &&
                    (x.LocalEndPoint.Port == port || x.RemoteEndPoint.Port == port))) { throw Invalid(); }
                string[] consumers = Lines(await Docker(["ps", "--all", "--no-trunc", "--filter", "volume=" + Name, "--format", "{{.ID}}"], ct));
                if (!consumers.SequenceEqual(ids, StringComparer.Ordinal)) { throw Invalid(); }
                authority.ValidateHeld(); _ = await Docker(["stop", "--time", "5", ids[0]], ct); _ = await Docker(["rm", ids[0]], ct);
            }
            if (exists)
            {
                if (Lines(await Docker(["ps", "--all", "--no-trunc", "--filter", "volume=" + Name, "--format", "{{.ID}}"], ct)).Length != 0) { throw Invalid(); }
                using var actual = JsonDocument.Parse(await Docker(["volume", "inspect", Name], ct));
                JsonElement volume = actual.RootElement.EnumerateArray().Single(); RequireVolume(volume, _intent);
                if (volume.GetProperty("CreatedAt").GetString() != volumeRecord.RootElement.GetProperty("CreatedAt").GetString()) { throw Invalid(); }
                authority.ValidateHeld(); _ = await Docker(["volume", "rm", Name], ct);
            }
        }
        CurrentAuthClosedSecretCleanup.RequireRemoved(Root, Binding, Operation);
        await ObserveAbsenceAsync("supervisor-absence", ct);
    }

    internal static void RequireVolume(JsonElement volume, CurrentAuthArchiveDefinitionAnchorIntent intent)
    {
        RequireIntentShape(intent);
        string name = "legacy-delta-proof-" + intent.OperationId.ToString("N");
        JsonElement options = volume.GetProperty("Options"); DateTimeOffset created = volume.GetProperty("CreatedAt").GetDateTimeOffset();
        if (intent.OperationId == Guid.Empty || intent.BeforeVolumes.Contains(name, StringComparer.Ordinal) ||
            volume.GetProperty(nameof(Name)).GetString() != name || volume.GetProperty("Driver").GetString() != "local" || volume.GetProperty("Scope").GetString() != "local" ||
            created < intent.BeganAtUtc || created > intent.ExpiresAtUtc ||
            (options.ValueKind != JsonValueKind.Null && (options.ValueKind != JsonValueKind.Object || options.EnumerateObject().Any()))) { throw Invalid(); }
        RequireLabels(volume.GetProperty("Labels"), intent);
    }

    internal static void RequireContainer(JsonElement container, JsonElement volume, CurrentAuthArchiveDefinitionAnchorIntent intent)
    {
        RequireVolume(volume, intent); string name = "legacy-delta-proof-" + intent.OperationId.ToString("N");
        string id = container.GetProperty("Id").GetString()!; DateTimeOffset created = container.GetProperty("Created").GetDateTimeOffset();
        JsonElement config = container.GetProperty("Config"), host = container.GetProperty("HostConfig");
        JsonElement[] mounts = [.. container.GetProperty("Mounts").EnumerateArray()];
        if (!CurrentAuthRepairPermit.HashShape(id) || intent.BeforeContainers.Any(x => x.StartsWith(id + "|", StringComparison.Ordinal)) ||
            container.GetProperty(nameof(Name)).GetString() != "/" + name || config.GetProperty("Image").GetString() != Image ||
            !ImageIdentity(container.GetProperty("Image").GetString()) || created < intent.BeganAtUtc || created > intent.ExpiresAtUtc ||
            host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
            host.GetProperty("NanoCpus").GetInt64() != 750_000_000 || Nonempty(host, "Binds") || Nonempty(host, "VolumesFrom") || Nonempty(host, "Tmpfs") ||
            mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty(nameof(Name)).GetString() != name ||
            mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" || !mounts[0].GetProperty("RW").GetBoolean()) { throw Invalid(); }
        RequireLabels(config.GetProperty("Labels"), intent); _ = Port(container);
    }

    private static bool Nonempty(JsonElement value, string name)
    { JsonElement item = value.GetProperty(name); return item.ValueKind != JsonValueKind.Null && (item.ValueKind == JsonValueKind.Array ? item.GetArrayLength() != 0 : item.EnumerateObject().Any()); }
    private static int Port(JsonElement container)
    {
        JsonElement ports = container.GetProperty("NetworkSettings").GetProperty("Ports");
        if (ports.EnumerateObject().Count() != 1) { throw Invalid(); }
        JsonElement[] maps = [.. ports.GetProperty("5432/tcp").EnumerateArray()];
        return maps.Length != 1 || maps[0].GetProperty("HostIp").GetString() != "127.0.0.1" ||
            !int.TryParse(maps[0].GetProperty("HostPort").GetString(), out int port) || port is < 1 or > 65535 ? throw Invalid() : port;
    }
    private static void RequireLabels(JsonElement labels, CurrentAuthArchiveDefinitionAnchorIntent intent)
    {
        if (labels.EnumerateObject().Count() != 4 || labels.GetProperty("codex.repair.purpose").GetString() != "current-auth-repair-proof" ||
            labels.GetProperty("codex.repair.operation").GetString() != intent.OperationId.ToString("D") ||
            labels.GetProperty("codex.repair.run-binding").GetString() != intent.Binding.ComputeSha256() ||
            labels.GetProperty(ParentLabel).GetString() != intent.ParentBindingSha256) { throw Invalid(); }
    }
    private void RequireLive()
    {
        RequireIntentShape(_intent); _parent.Require(); if (DateTimeOffset.UtcNow >= ExpiresAtUtc ||
            !JsonSerializer.SerializeToUtf8Bytes(_intent).AsSpan().SequenceEqual(_parent.Read(_prefix + "-intent.json", sharedReader: true, maximumBytes: 2 * 1024 * 1024))) { throw Invalid(); }
    }
    private static Task<string> Docker(IReadOnlyList<string> args, CancellationToken ct)
    {
        return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct);
    }

    internal static void RequireRecordedContainerAbsent(string recordedId, IReadOnlyList<string> inventory)
    {
        if (!CurrentAuthRepairPermit.HashShape(recordedId) || inventory.Any(line => InventoryId(line) == recordedId)) { throw Invalid(); }
    }
    internal static string[] RequireRecordedContainerForCleanup(string recordedId, string fixedName, IReadOnlyList<string> inventory)
    {
        if (!CurrentAuthRepairPermit.HashShape(recordedId)) { throw Invalid(); }
        string[] owned = inventory.Where(line => InventoryId(line) == recordedId).ToArray();
        string[] named = inventory.Where(line => { _ = InventoryId(line); return line.Split('|')[1] == fixedName; }).ToArray();
        return owned.Length > 1 || named.Length > 1 || owned.Length != named.Length ||
            (owned.Length == 1 && (owned[0] != named[0] || InventoryId(named[0]) != recordedId))
            ? throw Invalid()
            : owned.Length == 0 ? [] : [recordedId];
    }
    private static string InventoryId(string line)
    {
        string[] parts = line.Split('|');
        return parts.Length != 2 || !CurrentAuthRepairPermit.HashShape(parts[0]) || string.IsNullOrWhiteSpace(parts[1]) ? throw Invalid() : parts[0];
    }
    private static void RequireIntentShape(CurrentAuthArchiveDefinitionAnchorIntent intent)
    {
        if (intent.Kind != "current-auth-archive-definition-anchor-intent-v2" || intent.OperationId == Guid.Empty ||
            intent.SourceCommitSha is not { Length: 40 } || !intent.SourceCommitSha.All(char.IsAsciiHexDigitLower) ||
            !CurrentAuthRepairPermit.HashShape(intent.ParentBindingSha256) || !Path.IsPathFullyQualified(intent.Root) ||
            Path.GetFileName(intent.Root) != "auth-definition-anchor-" + intent.OperationId.ToString("N") ||
            intent.Binding.ArtifactRootCanonicalPath != intent.Root || intent.Binding.ComputeSha256() == intent.ParentBindingSha256 ||
            intent.BeganAtUtc.Offset != TimeSpan.Zero || intent.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            intent.ExpiresAtUtc - intent.BeganAtUtc != TimeSpan.FromMinutes(8)) { throw Invalid(); }
    }
    private static bool ImageIdentity(string? value)
    {
        return value is not null && value.StartsWith("sha256:", StringComparison.Ordinal) && CurrentAuthRepairPermit.HashShape(value[7..]);
    }

    private static string[] Lines(string value)
    {
        return value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
    }

    private static MigrationExecutionException Invalid()
    {
        return CurrentAuthArchiveRecoveryV2.Invalid();
    }
}
