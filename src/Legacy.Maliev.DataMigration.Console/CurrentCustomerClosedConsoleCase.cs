using System.Data;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CustomerClosedCommand(string Command, DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, int ExitCode);
internal sealed record CustomerClosedCase(string Kind, Guid OperationId, string CaseId, string BindingSha256,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, IReadOnlyList<CustomerClosedCommand> Commands,
    CustomerDefinitionArtifact? Review, CustomerDefinitionArtifact? Authorization,
    CustomerDefinitionArtifact BeforeNative, CustomerDefinitionArtifact AfterNative,
    CustomerDefinitionArtifact BeforeFleet, CustomerDefinitionArtifact AfterFleet,
    IReadOnlyList<CustomerDefinitionArtifact> RetainedReceipts);

// This is the actual public invocation producer, not an admission callback. The
// caller must supply a genuinely initialized, owned named fixture and config.
// It intentionally emits unsigned raw case facts; a completed signed eight-case
// reader/assembler must authenticate these, actual TRX and post-exit cleanup.
internal static class CurrentCustomerClosedConsoleCase
{
    private static readonly string[] Commands = ["review-current-customer-sequence-repair", "authorize-current-customer-sequence-repair",
        "verify-current-customer-sequence-repair", "apply-current-customer-sequence-repair"];
    internal static async Task<CustomerClosedCase> RunAsync(LocalExecutionBinding binding,
        CurrentCustomerSequenceRepairConfiguration config, CurrentCustomerSequenceRepairScope scope,
        string configPath, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        var seed = scope.ClosedConsoleSeed ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        CurrentCustomerSequenceClosedBootstrap.RequireBinding(seed, scope);
        if (scope.RunBindingSha256 != binding.ComputeSha256() || config.ProofAdmission != scope.ProofAdmission ||
            Path.GetDirectoryName(Path.GetFullPath(configPath)) != binding.ArtifactRootCanonicalPath ||
            config.ReviewOutputPath != config.ReviewPath || config.AuthorizationOutputPath != config.AuthorizationPath)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        DateTimeOffset began = DateTimeOffset.UtcNow;
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct);
        TimeSpan remaining = seed.ExpiresAtUtc - began;
        if (remaining <= TimeSpan.Zero || remaining > TimeSpan.FromMinutes(8)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        lease.CancelAfter(remaining);
        CustomerDefinitionArtifact beforeNative, beforeFleet;
        using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            RequireExact(files, configPath, config); RequireExact(files, config.ScopePath, scope);
            if (File.Exists(config.ReviewPath) || File.Exists(config.AuthorizationPath) ||
                Directory.EnumerateFileSystemEntries(binding.ArtifactRootCanonicalPath, scope.OperationId.ToString("D") + "*").Any())
            { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            (beforeNative, beforeFleet) = await CaptureAsync(files, binding, config, "before", lease.Token).ConfigureAwait(false);
        }
        // No root authority/file handles are held while the public route resumes it.
        var commands = new List<CustomerClosedCommand>();
        foreach (string command in Commands)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false);
            DateTimeOffset commandBegan = DateTimeOffset.UtcNow;
            using var output = new StringWriter(); using var error = new StringWriter();
            int exit = await MigrationConsole.RunAsync([command, "--config", configPath], output, error,
                Environment.GetEnvironmentVariable, lease.Token).ConfigureAwait(false);
            commands.Add(new(command, commandBegan, DateTimeOffset.UtcNow, exit));
            // Console output can contain environmental details. Retain only exit/phase;
            // authentic claims/native observations/effect receipts are held separately.
            if (exit != 0) { break; }
        }
        CustomerDefinitionArtifact? replayNative = null, replayFleet = null;
        Dictionary<string, string>? replaySlots = null;
        if (seed.CaseId == "replay" && commands.Count == 4 && commands[^1].ExitCode == 0)
        {
            using (var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                (replayNative, replayFleet) = await CaptureAsync(files, binding, config, "pre-replay", lease.Token).ConfigureAwait(false);
                replaySlots = ReadSlots(files, binding, scope.OperationId);
            }
            DateTimeOffset replayBegan = DateTimeOffset.UtcNow;
            using var output = new StringWriter(); using var error = new StringWriter();
            int exit = await MigrationConsole.RunAsync([Commands[^1], "--config", configPath], output, error,
                Environment.GetEnvironmentVariable, lease.Token).ConfigureAwait(false);
            commands.Add(new(Commands[^1], replayBegan, DateTimeOffset.UtcNow, exit));
        }
        using var finalAuthority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var finalFiles = new CurrentAppOwnedRepairCustody(finalAuthority);
        (CustomerDefinitionArtifact afterNative, CustomerDefinitionArtifact afterFleet) =
            await CaptureAsync(finalFiles, binding, config, "after", lease.Token).ConfigureAwait(false);
        if (replaySlots is not null && (replayNative!.Sha256 != afterNative.Sha256 || replayFleet!.Sha256 != afterFleet.Sha256 ||
            !replaySlots.OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(ReadSlots(finalFiles, binding, scope.OperationId).OrderBy(x => x.Key, StringComparer.Ordinal))))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        CustomerDefinitionArtifact? review = ReadOptional(finalFiles, config.ReviewPath);
        CustomerDefinitionArtifact? authorization = ReadOptional(finalFiles, config.AuthorizationPath);
        var receipts = new List<CustomerDefinitionArtifact>();
        foreach (string path in Directory.EnumerateFileSystemEntries(binding.ArtifactRootCanonicalPath, scope.OperationId.ToString("D") + "*").Order(StringComparer.Ordinal))
        {
            // Reservation is real evidence too, not a receipt. Keep it outside this list.
            if (Path.GetFileName(path) == scope.OperationId.ToString("D") + "-customer-sequence-operation-start.json") { continue; }
            receipts.Add(ReadOptional(finalFiles, path) ?? throw CurrentCustomerSequenceRepairPermit.Invalid());
        }
        var result = new CustomerClosedCase("current-customer-sequence-public-console-case-v1", scope.OperationId,
            seed.CaseId, binding.ComputeSha256(), began, DateTimeOffset.UtcNow, commands, review, authorization,
            beforeNative, afterNative, beforeFleet, afterFleet, receipts);
        RequirePhases(result);
        await finalFiles.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath, "customer-closed-actual-case.json"),
            JsonSerializer.SerializeToUtf8Bytes(result), lease.Token).ConfigureAwait(false);
        return result;
    }
    internal static void RequirePhases(CustomerClosedCase value)
    {
        bool early = value.CaseId is "host-unprobed-sdk" or "local-ordinary-trust";
        int expected = early ? 1 : value.CaseId == "replay" ? 5 : 4;
        string[] expectedCommands = value.CaseId == "replay" ? [.. Commands, Commands[^1]] : [.. Commands.Take(expected)];
        if (value.Kind != "current-customer-sequence-public-console-case-v1" || value.OperationId == Guid.Empty ||
            !CurrentCustomerSequenceClosedBootstrap.Cases.Contains(value.CaseId, StringComparer.Ordinal) ||
            value.BeganAtUtc.Offset != TimeSpan.Zero || value.CompletedAtUtc.Offset != TimeSpan.Zero ||
            value.CompletedAtUtc < value.BeganAtUtc || value.CompletedAtUtc - value.BeganAtUtc > TimeSpan.FromMinutes(8) ||
            value.Commands.Count != expected || !value.Commands.Select(x => x.Command).SequenceEqual(expectedCommands, StringComparer.Ordinal) ||
            value.Commands.Any(x => x.BeganAtUtc.Offset != TimeSpan.Zero || x.CompletedAtUtc.Offset != TimeSpan.Zero ||
                x.BeganAtUtc < value.BeganAtUtc || x.CompletedAtUtc < x.BeganAtUtc || x.CompletedAtUtc > value.CompletedAtUtc) ||
            value.Commands.Zip(value.Commands.Skip(1)).Any(x => x.First.CompletedAtUtc > x.Second.BeganAtUtc) ||
            value.Commands.Take(expected - 1).Any(x => x.ExitCode != 0) ||
            (early && (value.Commands[0].ExitCode == 0 || value.Review is not null || value.Authorization is not null || value.RetainedReceipts.Count != 0)) ||
            (!early && (value.Review is null || value.Authorization is null)) ||
            (!early && value.Commands[^1].ExitCode == 0 != (value.CaseId == "success")))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private static void RequireExact<T>(CurrentAppOwnedRepairCustody files, string path, T value)
    {
        T held = JsonSerializer.Deserialize<T>(files.Read(path, sharedReader: true, maximumBytes: 8 * 1024 * 1024)) ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        if (JsonSerializer.Serialize(held) != JsonSerializer.Serialize(value)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private static CustomerDefinitionArtifact? ReadOptional(CurrentAppOwnedRepairCustody files, string path)
    {
        if (!File.Exists(path)) { return null; }
        byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: 8 * 1024 * 1024);
        return new(path, CurrentCustomerSequenceRepairPermit.Hash(bytes));
    }
    private static Dictionary<string, string> ReadSlots(CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding, Guid operation)
    {
        return Directory.EnumerateFileSystemEntries(binding.ArtifactRootCanonicalPath, operation.ToString("D") + "*")
            .ToDictionary(x => Path.GetFileName(x), x => (ReadOptional(files, x) ?? throw CurrentCustomerSequenceRepairPermit.Invalid()).Sha256, StringComparer.Ordinal);
    }

    private static async Task<(CustomerDefinitionArtifact Native, CustomerDefinitionArtifact Fleet)> CaptureAsync(
        CurrentAppOwnedRepairCustody files, LocalExecutionBinding binding, CurrentCustomerSequenceRepairConfiguration config,
        string phase, CancellationToken ct)
    {
        string text = System.Text.Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536));
        var endpoint = new NpgsqlConnectionStringBuilder(text);
        if (endpoint.Host != "127.0.0.1" || endpoint.Pooling || endpoint.SslMode != SslMode.Disable || !string.IsNullOrEmpty(endpoint.Options))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string[] expected = [.. DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).Order(StringComparer.Ordinal)];
        await using (var inventory = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = "postgres" }.ConnectionString))
        {
            await inventory.OpenAsync(ct).ConfigureAwait(false);
            await using var command = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate ORDER BY datname COLLATE \"C\";", inventory);
            await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false); var actual = new List<string>();
            while (await reader.ReadAsync(ct).ConfigureAwait(false)) { actual.Add(reader.GetString(0)); }
            if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        var pool = new CurrentAppOwnedSnapshotInternPool(); var fleet = new List<CurrentAppOwnedDatabaseSnapshot>();
        CustomerDefinitionArtifact? nativeArtifact = null;
        foreach (string database in expected)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false); files.Require();
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(text) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            CurrentAppOwnedDatabaseSnapshot snapshot;
            if (database == "Customer")
            {
                var native = await CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
                snapshot = native.Snapshot; string path = Path.Combine(binding.ArtifactRootCanonicalPath, "customer-closed-" + phase + "-native.json");
                byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(native);
                if (bytes.Length > 8 * 1024 * 1024) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false); nativeArtifact = ReadOptional(files, path);
            }
            else { snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false); }
            fleet.Add(pool.Intern(snapshot)); await tx.RollbackAsync(ct).ConfigureAwait(false);
        }
        string fleetPath = Path.Combine(binding.ArtifactRootCanonicalPath, "customer-closed-" + phase + "-fleet.json");
        await files.WriteBaselineNewAsync(fleetPath, [.. fleet], ct).ConfigureAwait(false);
        // Stream hash avoids allocating the complete fleet serialization.
        // Custody owns this borrowed stream. Caller must not dispose it.
        Stream stream = files.BorrowReadStream(fleetPath, maximumBytes: 512L * 1024 * 1024);
        string hash = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(stream));
        files.Require(); return (nativeArtifact ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), new(fleetPath, hash));
    }
}
