using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text;
using System.Data;
using System.Net.NetworkInformation;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed record CurrentAuthRecordedArtifact(string Path, string Sha256);
internal sealed record CurrentAuthRecordedStorage(uint FileNode, long Blocks);
internal sealed record CurrentAuthRecordedNative(CurrentAppOwnedDatabaseSnapshot Snapshot,
    Dictionary<string, string[]> Tuples, Dictionary<string, CurrentAuthRecordedStorage> Storage,
    Dictionary<string, string> Expressions);
internal sealed record CurrentAuthRecordedEvent(Guid RunId, string CaseId, string Phase,
    DateTimeOffset ObservedAtUtc, CurrentAuthRecordedArtifact Artifact);
internal sealed record CurrentAuthRecordedFile(string Name, long Length, string Sha256);
internal sealed record CurrentAuthRecordedSecretAbsence(Guid RunId, DateTimeOffset ObservedAtUtc,
    string Kind, string BindingSha256, string[] CreatedCredentialPaths, string[] RemainingCredentialPaths,
    IReadOnlyList<CurrentAuthRecordedFile> Files);

/// <summary>Records observations only. It never emits a Passed result, manifest signature or execution permit.</summary>
internal sealed class CurrentAuthExecutedProofRecorder : IDisposable
{
    private readonly WindowsLocalRunAuthority _authority;
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly Guid _run;
    private readonly string _case;
    private int _ordinal;
    private bool _disposed;
    private bool _ownsAuthority;
    private readonly Dictionary<string, CurrentAuthRecordedArtifact> _latest = new(StringComparer.Ordinal);
    internal LocalExecutionBinding Binding => _authority.Binding;
    internal CurrentAuthComponentBootstrapSeed? ComponentSeed { get; private set; }
    internal byte[]? ComponentSeedPublicKey { get; private set; }
    internal static async Task<CurrentAuthExecutedProofRecorder?> CreateAsync(Guid run, string caseId, CancellationToken ct)
    {
        string? parent = Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_PROOF_ROOT");
        if (parent is null) { return null; }
        WindowsLocalRunAuthority authority = CreateFreshRootAuthority(parent, run);
        CurrentAuthExecutedProofRecorder? recorder = null;
        try
        {
            recorder = new CurrentAuthExecutedProofRecorder(authority, run, caseId) { _ownsAuthority = true };
            string? seedPath = Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_COMPONENT_SEED");
            if (seedPath is not null)
            {
                string keyPath = Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_COMPONENT_SEED_KEY") ?? throw new InvalidOperationException("auth_component_seed_key_absent");
                byte[] ReadParent(string path)
                {
                    if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), parent)) { throw new InvalidOperationException("auth_component_seed_path_invalid"); }
                    using var input = SecureLocalFile.OpenReadShared(path);
                    if (input.Length is < 1 or > 65536) { throw new InvalidOperationException("auth_component_seed_size_invalid"); }
                    byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes); return bytes;
                }
                recorder.ComponentSeed = MigrationConsole.DecodeAuthRepair<CurrentAuthComponentBootstrapSeed>(ReadParent(seedPath));
                recorder.ComponentSeedPublicKey = ReadParent(keyPath);
                var seedTrust = new ReceiptAttestationTrustStore([new TrustedAttestationKey(recorder.ComponentSeed.KeyId, recorder.ComponentSeedPublicKey)]);
                CurrentAuthComponentBootstrap.RequireSeed(recorder.ComponentSeed, seedTrust, recorder.ComponentSeed.KeyId,
                    Convert.ToHexStringLower(SHA256.HashData(recorder.ComponentSeedPublicKey)), DateTimeOffset.UtcNow);
            }
            _ = await recorder.RecordAsync("run-binding", authority.Binding, ct).ConfigureAwait(false);
            using Process testhost = Process.GetCurrentProcess();
            _ = await recorder.RecordAsync("test-image", new
            {
                TestAssemblyPath = typeof(CurrentAuthExecutedProofRecorder).Assembly.Location,
                TestAssemblySha256 = HashFile(typeof(CurrentAuthExecutedProofRecorder).Assembly.Location),
                ConsoleAssemblyPath = typeof(MigrationConsole).Assembly.Location,
                ConsoleAssemblySha256 = HashFile(typeof(MigrationConsole).Assembly.Location),
                CoreAssemblyPath = typeof(CurrentAuthRepairPermit).Assembly.Location,
                CoreAssemblySha256 = HashFile(typeof(CurrentAuthRepairPermit).Assembly.Location),
                Environment.ProcessId,
                ProcessStartTimeUtc = new DateTimeOffset(testhost.StartTime.ToUniversalTime(), TimeSpan.Zero)
            }, ct).ConfigureAwait(false);
            return recorder;
        }
        catch { recorder?.Dispose(); authority.Dispose(); throw; }
    }

    internal static WindowsLocalRunAuthority CreateFreshRootAuthority(string parent, Guid run)
    {
        if (!OperatingSystem.IsWindows() || run == Guid.Empty || !Path.IsPathFullyQualified(parent) || !Directory.Exists(parent))
        { throw new InvalidOperationException("auth_proof_root_unavailable"); }
        string root = Path.Combine(parent, "auth-executed-" + run.ToString("N"));
        if (Directory.Exists(root) || File.Exists(root)) { throw new InvalidOperationException("auth_proof_root_exists"); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(root);
        return WindowsLocalRunAuthority.AcquireFresh(root);
    }

    internal Task<CurrentAuthRecordedArtifact> ContainerAsync<T>(T metadata, CancellationToken ct)
    {
        JsonObject json = JsonSerializer.SerializeToNode(metadata)!.AsObject();
        CanonicalDockerNames(json);
        JsonObject config = json["Config"]!.AsObject();
        string[] values = config["Env"]!.AsArray().Select(x => x!.GetValue<string>())
            .Where(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)).ToArray();
        if (values.Length != 1 || values[0].Length <= 7) { throw new InvalidOperationException("auth_proof_pgdata_unobserved"); }
        _ = config.Remove("Env"); config["PgData"] = values[0][7..];
        return RecordAsync("container", json, ct);
    }
    private static void CanonicalDockerNames(JsonNode? node)
    {
        if (node is JsonObject value)
        {
            foreach ((string key, JsonNode? child) in value.ToArray())
            {
                CanonicalDockerNames(child);
                string canonical = key switch { "ID" => "Id", "NanoCPUs" => "NanoCpus", "HostIP" => "HostIp", _ => key };
                if (canonical == key) { continue; }
                if (value.ContainsKey(canonical)) { throw new InvalidOperationException("ambiguous_docker_metadata_property"); }
                _ = value.Remove(key); value.Add(canonical, child);
            }
        }
        else if (node is JsonArray array) { foreach (JsonNode? child in array) { CanonicalDockerNames(child); } }
    }

    internal async Task ObserveImageAsync(DockerClient docker, CancellationToken ct)
    {
        var image = await docker.Images.InspectImageAsync("postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382", ct).ConfigureAwait(false);
        _ = await RecordAsync("image-metadata", new { Id = image.ID, image.RepoDigests }, ct).ConfigureAwait(false);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatus
    {
        internal uint Length, Load;
        internal ulong TotalPhysical, AvailablePhysical, TotalPageFile, AvailablePageFile, TotalVirtual, AvailableVirtual, AvailableExtendedVirtual;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool ReadMemory(ref MemoryStatus memory);
    internal async Task CapacityAsync(bool admission, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            var observer = Marshal.GetDelegateForFunctionPointer<ReadMemory>(NativeLibrary.GetExport(library, "GlobalMemoryStatusEx"));
            var memory = new MemoryStatus { Length = (uint)Marshal.SizeOf<MemoryStatus>() };
            if (!observer(ref memory)) { throw new InvalidOperationException("auth_proof_capacity_unobserved"); }
            using var process = Process.GetCurrentProcess(); process.Refresh();
            CurrentAuthRepairCapacity.RequireValues(memory.AvailablePhysical, (ulong)process.WorkingSet64, admission);
            _ = await RecordAsync("capacity", new
            {
                observedAtUtc = DateTimeOffset.UtcNow,
                memory.AvailablePhysical,
                ownedRssBytes = process.WorkingSet64,
                admission,
                processId = process.Id,
                processStartTimeUtc = process.StartTime.ToUniversalTime()
            }, ct).ConfigureAwait(false);
        }
        finally { NativeLibrary.Free(library); }
    }

    internal async Task ObserveAbsenceAsync(DockerClient docker, string ownedId, string? ownedVolume, int port,
        DateTimeOffset removedAtUtc, CancellationToken ct)
    {
        IList<ContainerListResponse> containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, ct).ConfigureAwait(false);
        var volumes = await docker.Volumes.ListAsync(ct).ConfigureAwait(false);
        int[] ports = [.. IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners().Select(x => x.Port).Distinct().Order()];
        string[] ids = [.. containers.Select(x => x.ID).Order(StringComparer.Ordinal)];
        string[] names = [.. containers.SelectMany(x => x.Names).Order(StringComparer.Ordinal)];
        string[] volumeNames = [.. (volumes.Volumes ?? []).Select(x => x.Name).Order(StringComparer.Ordinal)];
        if (ids.Contains(ownedId, StringComparer.Ordinal) || (ownedVolume is not null && volumeNames.Contains(ownedVolume, StringComparer.Ordinal)) || ports.Contains(port))
        { throw new InvalidOperationException("auth_proof_owned_resource_still_present"); }
        _ = await RecordAsync("absence-inventory", new
        {
            run = _run,
            observedAtUtc = DateTimeOffset.UtcNow,
            removedAtUtc,
            containerIds = ids,
            containerNames = names,
            volumeNames,
            listeningPorts = ports
        }, ct).ConfigureAwait(false);
        await ObserveSecretAbsenceAsync(ct).ConfigureAwait(false);
    }

    private async Task ObserveSecretAbsenceAsync(CancellationToken ct)
    {
        _files.Require(); string root = _authority.Binding.ArtifactRootCanonicalPath;
        string[] paths = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly);
        if (paths.Length > 8001 || Directory.EnumerateDirectories(root).Any()) { throw new InvalidOperationException("auth_proof_unknown_case_slot"); }
        var observed = new List<CurrentAuthRecordedFile>();
        foreach (string path in paths.Order(StringComparer.Ordinal))
        {
            ct.ThrowIfCancellationRequested(); string name = Path.GetFileName(path);
            if (name == WindowsLocalRunAuthority.RunLockRelativeName) { continue; }
            if (!name.StartsWith($"auth-observed-{_run:N}-", StringComparison.Ordinal) || !name.EndsWith(".json", StringComparison.Ordinal))
            { throw new InvalidOperationException("auth_proof_unknown_case_slot"); }
            using var input = SecureLocalFile.OpenReadShared(path); string identity = SecureLocalFile.GetHandleIdentity(input); long length = input.Length;
            if (length is < 1 or > 512L * 1024 * 1024) { throw new InvalidOperationException("auth_proof_case_slot_size"); }
            string hash = Convert.ToHexStringLower(SHA256.HashData(input));
            if (input.Position != length || input.Length != length || SecureLocalFile.GetHandleIdentity(input) != identity) { throw new InvalidOperationException("auth_proof_case_slot_changed"); }
            observed.Add(new(name, length, hash));
        }
        _files.Require();
        // These two fixed native fixture producers create credentials and signing keys in memory only.
        // Their accepted test-image hash is separately bound by the executed host/TRX proof; no general Console case uses this inventory contract.
        _ = await RecordAsync("secret-absence", new CurrentAuthRecordedSecretAbsence(_run, DateTimeOffset.UtcNow,
            "auth-native-fixture-no-credential-files-v1", _authority.Binding.ComputeSha256(), [], [], observed), ct).ConfigureAwait(false);
    }

    internal async Task ObservePolicyAsync(string endpoint, CurrentAuthRepairScope scope, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint)
        { Database = "Auth", Pooling = false, Timeout = 5, CommandTimeout = 15, IncludeErrorDetail = false }.ConnectionString);
        await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
        { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),
              current_user,rolvaliduntil,shobj_description(r.oid,'pg_authid'),current_setting('hba_file'),NOT pg_is_in_recovery(),
              rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
              (SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
              (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),(SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
              pg_read_file(current_setting('hba_file')),
              (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h)
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection, tx);
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw new InvalidOperationException("auth_proof_policy_missing"); }
        string identity = reader.GetString(0), role = reader.GetString(3), comment = reader.GetString(5), hbaPath = reader.GetString(6);
        DateTimeOffset postmaster = reader.GetFieldValue<DateTimeOffset>(1), loaded = reader.GetFieldValue<DateTimeOffset>(2), expires = reader.GetFieldValue<DateTimeOffset>(4);
        bool[] flags = Enumerable.Range(7, 8).Select(reader.GetBoolean).ToArray();
        long[] counts = Enumerable.Range(15, 5).Select(reader.GetInt64).ToArray();
        byte[] rawHba = Encoding.UTF8.GetBytes(reader.GetString(20)), rawRules = Encoding.UTF8.GetBytes(reader.GetString(21));
        if (await reader.ReadAsync(ct).ConfigureAwait(false)) { throw new InvalidOperationException("auth_proof_policy_not_unique"); }
        await reader.DisposeAsync().ConfigureAwait(false);
        var hba = await BytesAsync("raw-hba", rawHba, ct).ConfigureAwait(false);
        var rulesArtifact = await BytesAsync("raw-hba-rules", rawRules, ct).ConfigureAwait(false);
        using var parsed = JsonDocument.Parse(rawRules);
        var rules = parsed.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(
            row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!, Strings(row, "database"), Strings(row, "user_name"),
            Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error"))).ToArray();
        var policy = new CurrentAuthProofPolicy(scope, DateTimeOffset.UtcNow, identity, postmaster, loaded, role, expires, comment, hbaPath,
            new(hba.Path, hba.Sha256), new(rulesArtifact.Path, rulesArtifact.Sha256), flags[0], flags[1], flags[2], flags[3], flags[4], flags[5], flags[6], flags[7],
            counts[0], counts[1], counts[2], counts[3], counts[4], rules);
        _ = await RecordAsync("installed-policy", policy, ct).ConfigureAwait(false);
        await tx.RollbackAsync(ct).ConfigureAwait(false);
        static string? Text(JsonElement row, string field)
        {
            return row.GetProperty(field).ValueKind == JsonValueKind.Null ? null : row.GetProperty(field).GetString();
        }

        static string[] Strings(JsonElement row, string field)
        {
            return row.GetProperty(field).ValueKind == JsonValueKind.Null ? [] : [.. row.GetProperty(field).EnumerateArray().Select(x => x.GetString()!)];
        }
    }

    private async Task<CurrentAuthRecordedArtifact> BytesAsync(string phase, byte[] bytes, CancellationToken ct)
    {
        if (bytes.Length is < 1 or > 1024 * 1024) { throw new InvalidOperationException("auth_proof_raw_policy_size"); }
        string path = Next(phase);
        await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        byte[] readback = _files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024);
        if (!readback.AsSpan().SequenceEqual(bytes)) { throw new InvalidOperationException("auth_proof_observation_readback_changed"); }
        var artifact = new CurrentAuthRecordedArtifact(path, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        _latest[phase] = artifact;
        await EventAsync(phase, artifact, ct).ConfigureAwait(false); return artifact;
    }
    internal CurrentAuthComponentBootstrapSubject CreateComponentSubject(FreshSchemaPlan source, CurrentAuthNativeObservation before)
    {
        var seed = ComponentSeed ?? throw new InvalidOperationException("genuine_definition_component_seed_absent");
        if (seed.TestAssemblySha256 != HashFile(typeof(CurrentAuthExecutedProofRecorder).Assembly.Location) ||
            seed.ConsoleAssemblySha256 != HashFile(typeof(MigrationConsole).Assembly.Location) ||
            seed.CoreAssemblySha256 != HashFile(typeof(CurrentAuthRepairPermit).Assembly.Location)) { throw new InvalidOperationException("auth_component_seed_images_changed"); }
        var containerArtifact = _latest["container"]; var volumeArtifact = _latest["volume-metadata"];
        using var container = JsonDocument.Parse(_files.Read(containerArtifact.Path, sharedReader: true, maximumBytes: 4 * 1024 * 1024));
        using var volume = JsonDocument.Parse(_files.Read(volumeArtifact.Path, sharedReader: true, maximumBytes: 65536));
        JsonElement c = container.RootElement, v = volume.RootElement;
        string id = c.GetProperty("Id").GetString()!, name = c.GetProperty("Name").GetString()!, pgData = c.GetProperty("Config").GetProperty("PgData").GetString()!;
        string volumeName = v.GetProperty("Name").GetString()!;
        string generation = LocalDockerGenerationGuard.ComposeGeneration(new DockerLocalTargetObservation(id, name, volumeName,
            "/var/lib/postgresql", pgData, c.GetProperty("Created").GetDateTimeOffset().ToUniversalTime(),
            c.GetProperty("State").GetProperty("StartedAt").GetDateTimeOffset().ToUniversalTime(), v.GetProperty("CreatedAt").GetDateTimeOffset().ToUniversalTime()));
        return new("current-auth-actual-anonymous-component-subject-v1", seed,
            "generated-synthetic-schema-physically-observed-not-accepted-source-capture", SchemaPlanCanonicalizer.ComputeSha256(source),
            Binding.ComputeSha256(), id, name.TrimStart('/'), volumeName, c.GetProperty("Image").GetString()!, pgData, generation,
            before.Snapshot.Sha256, containerArtifact.Sha256, volumeArtifact.Sha256);
    }

    private static string HashFile(string path)
    {
        using var file = SecureLocalFile.OpenReadShared(path);
        return Convert.ToHexStringLower(SHA256.HashData(file));
    }
    internal CurrentAuthExecutedProofRecorder(WindowsLocalRunAuthority authority, Guid run, string caseId)
    {
        ArgumentNullException.ThrowIfNull(authority);
        if (run == Guid.Empty || !AllowedCases.Contains(caseId, StringComparer.Ordinal)) { throw new InvalidOperationException("unsupported_auth_proof_case"); }
        _authority = authority; _files = new(authority); _run = run; _case = caseId;
        _files.Require();
    }
    private static readonly string[] AllowedCases = ["history-10.0.12", "history-10.0.10", "reject-expression",
        "reject-extended-statistics", "reject-statistics", "reject-column", "reject-partial", "success",
        "prepared-publication", "lost-commit-ack", "terminal-publication", "host-unprobed-sdk", "local-ordinary-trust"];

    internal Task<CurrentAuthRecordedArtifact> NativeAsync(string phase, CurrentAuthNativeObservation value, CancellationToken ct)
    {
        return RecordAsync(phase, new CurrentAuthRecordedNative(value.Snapshot, value.CopyTuples(),
            value.CopyStorage().ToDictionary(x => x.Key, x => new CurrentAuthRecordedStorage(x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal),
            value.CopyExpressions()), ct);
    }

    internal async Task<CurrentAuthRecordedArtifact> FleetAsync(string phase, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> fleet, CancellationToken ct)
    {
        if (fleet.Count != 26 || fleet.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26) { throw new InvalidOperationException("auth_proof_fleet_not_26"); }
        string path = Next(phase);
        await _files.WriteBaselineNewAsync(path, [.. fleet], ct).ConfigureAwait(false);
        using var stream = SecureLocalFile.OpenReadShared(path);
        string identity = SecureLocalFile.GetHandleIdentity(stream);
        string hash = Convert.ToHexStringLower(SHA256.HashData(stream));
        if (SecureLocalFile.GetHandleIdentity(stream) != identity || stream.Position != stream.Length)
        { throw new InvalidOperationException("auth_proof_baseline_readback_changed"); }
        _files.Require();
        var artifact = new CurrentAuthRecordedArtifact(path, hash);
        await EventAsync(phase, artifact, ct).ConfigureAwait(false);
        return artifact;
    }

    internal async Task<CurrentAuthRecordedArtifact> RecordAsync<T>(string phase, T observed, CancellationToken ct)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(observed);
        if (bytes.Length > 32 * 1024 * 1024) { throw new InvalidOperationException("auth_proof_observation_too_large"); }
        string path = Next(phase);
        await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        byte[] readback = _files.Read(path, sharedReader: true, maximumBytes: 32 * 1024 * 1024);
        if (!readback.AsSpan().SequenceEqual(bytes)) { throw new InvalidOperationException("auth_proof_observation_readback_changed"); }
        var artifact = new CurrentAuthRecordedArtifact(path, Convert.ToHexStringLower(SHA256.HashData(bytes)));
        await EventAsync(phase, artifact, ct).ConfigureAwait(false);
        return artifact;
    }

    private async Task EventAsync(string phase, CurrentAuthRecordedArtifact artifact, CancellationToken ct)
    {
        string path = Next("event");
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new CurrentAuthRecordedEvent(_run, _case, phase, DateTimeOffset.UtcNow, artifact));
        await _files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        byte[] readback = _files.Read(path, sharedReader: true, maximumBytes: 65536);
        if (!readback.AsSpan().SequenceEqual(bytes)) { throw new InvalidOperationException("auth_proof_event_readback_changed"); }
    }

    private string Next(string phase)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrEmpty(phase) || phase.Length > 64 || phase.Any(x => x is not (>= 'a' and <= 'z') and not '-'))
        { throw new InvalidOperationException("unsupported_auth_proof_phase"); }
        _files.Require();
        int ordinal = Interlocked.Increment(ref _ordinal);
        return Path.Combine(_authority.Binding.ArtifactRootCanonicalPath, $"auth-observed-{_run:N}-{ordinal:D5}-{phase}.json");
    }
    public void Dispose()
    {
        if (_disposed) { return; }
        _files.Dispose(); _disposed = true;
        if (_ownsAuthority) { _authority.Dispose(); }
    }
}
