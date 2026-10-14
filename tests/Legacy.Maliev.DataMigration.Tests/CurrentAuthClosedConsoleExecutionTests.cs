using System.Data;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthClosedConsoleExecutionTests(ITestOutputHelper output)
{
    [WindowsLocalRunTheory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("host-unprobed-sdk")]
    [InlineData("local-ordinary-trust")]
    [InlineData("final-fleet")]
    [InlineData("replay")]
    public async Task Genuine_named_closed_auth_console_preserves_or_stops(string caseId)
    {
        string parent = Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_PROOF_ROOT") ?? throw new InvalidOperationException("auth_closed_parent_root_required");
        string inputPath = Environment.GetEnvironmentVariable("MALIEV_AUTH_CLOSED_LANE_INPUT") ?? throw new InvalidOperationException("auth_closed_lane_input_required");
        if (!Path.IsPathFullyQualified(parent) || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(inputPath)), parent))
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthClosedLaneConfiguration input = MigrationConsole.DecodeAuthRepair<CurrentAuthClosedLaneConfiguration>(ReadProtected(inputPath, 65536));
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(input.ParentRunBindingPath)), parent)) { throw CurrentAuthRepairPermit.Invalid(); }
        var parentBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.ParentRunBindingPath, 65536));
        if (!StringComparer.OrdinalIgnoreCase.Equals(parentBinding.ArtifactRootCanonicalPath, parent) || parentBinding.ComputeSha256() != input.ParentRunBindingSha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        string actualTest = typeof(CurrentAuthClosedConsoleExecutionTests).Assembly.Location;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(actualTest), Path.GetFullPath(input.TestAssemblyPath)) ||
            CurrentAuthTypedHostProducer.ImageHash(actualTest) != input.TestAssemblySha256 ||
            CurrentAuthTypedHostProducer.ImageHash(typeof(MigrationConsole).Assembly.Location) != input.ConsoleAssemblySha256 ||
            CurrentAuthTypedHostProducer.ImageHash(typeof(CurrentAuthRepairPermit).Assembly.Location) != input.CoreAssemblySha256)
        { throw CurrentAuthRepairPermit.Invalid(); }
        var source = MigrationConsole.DecodeAuthRepair<FreshSchemaPlan>(ReadProtected(input.SourceSchemaPath, 32 * 1024 * 1024));
        var precursorBinding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.CompletedComponents.PrecursorRunBindingPath, 65536));
        if (StringComparer.OrdinalIgnoreCase.Equals(precursorBinding.ArtifactRootCanonicalPath, parent)) { throw CurrentAuthRepairPermit.Invalid(); }
        // Actual owner-only fixture resource lifetime is independent of test-host/TRX exit.
        await using var fixture = await CurrentAuthNamedClosedFixture.CreateAsync(parent, CancellationToken.None);
        using (var process = System.Diagnostics.Process.GetCurrentProcess())
        {
            await fixture.RecordAsync("test-image", new
            {
                testAssemblyPath = actualTest,
                input.TestAssemblySha256,
                input.ConsoleAssemblySha256,
                input.CoreAssemblySha256,
                processId = process.Id,
                processStartTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime(), TimeSpan.Zero),
                executable = process.MainModule?.FileName ?? throw CurrentAuthRepairPermit.Invalid()
            }, fixture.Token);
        }
        string configPath; CurrentAuthClosedTemplateCapture captured;
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            var state = await CurrentAuthClosedTemplate.PrepareAsync(files, fixture.Binding, fixture.Operation, fixture.ContainerId,
                source, fixture.AdminConnection, fixture.Token);
            await CurrentAuthClosedTemplate.InstallPolicyAsync(files, fixture.Binding, state, fixture.AdminConnection, caseId, fixture.Token);
            captured = await CurrentAuthClosedTemplate.CaptureAsync(files, fixture.Binding, state, source,
                caseId is "host-unprobed-sdk" or "local-ordinary-trust", fixture.Token);
            configPath = await CurrentAuthClosedConfiguration.WriteAsync(files, fixture.Binding, captured, source, caseId,
                input.CompletedComponents, input.PrecursorReviewPrivateKeyPath, actualTest, fixture.Token);
            var writtenConfig = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairConfiguration>(files.Read(configPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            var writtenScope = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairScope>(files.Read(writtenConfig.ScopePath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            await CurrentAuthClosedPolicyObservation.CaptureAsync(files, writtenConfig, writtenScope, caseId, fixture.Token);
        }
        // Releasing all fixture custody handles before each public route is mandatory:
        // the real Console itself reacquires the original exclusive Windows run lock.
        bool unsafePolicy = caseId is "host-unprobed-sdk" or "local-ordinary-trust";
        var invocations = new List<object>();
        int review = await Invoke("review-current-auth-repair");
        if (unsafePolicy)
        {
            Assert.Equal(1, review);
            Assert.False(File.Exists(Path.Combine(fixture.Root, "closed-review.json")));
            Assert.False(File.Exists(Path.Combine(fixture.Root, "closed-authorization.json")));
            Assert.Empty(Directory.GetFiles(fixture.Root, fixture.Operation.ToString("D") + "-*.json"));
        }
        else
        {
            Assert.Equal(0, review); Assert.Equal(0, await Invoke("authorize-current-auth-repair"));
            Assert.Equal(0, await Invoke("verify-current-auth-repair"));
            int applied = await Invoke("apply-current-auth-repair");
            Assert.Equal(caseId is "success" or "replay" ? 0 : 1, applied);
        }
        var config = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairConfiguration>(ReadProtected(configPath, 32 * 1024 * 1024));
        string op = Encoding.UTF8.GetString(ReadProtected(config.OperatorConnectionPath, 65536));
        var before = MigrationConsole.DecodeAuthRepair<CurrentAuthProofNative>(ReadProtected(captured.NativeBeforePath, 32 * 1024 * 1024)).Observation();
        CurrentAuthNativeObservation after = await Auth(op, fixture.Token);
        if (unsafePolicy || caseId == "prepared-publication")
        { CurrentAuthNativePreservation.RequireBefore(after); Assert.Equal(before.Snapshot.Sha256, after.Snapshot.Sha256); }
        else
        {
            CurrentAuthNativePreservation.RequirePreserved(before, after);
            var prepared = MigrationConsole.DecodeAuthRepair<CurrentAuthRepairReceipt>(ReadProtected(Path.Combine(fixture.Root,
                fixture.Operation.ToString("D") + "-Auth-prepared.json"), 65536));
            Assert.Equal(prepared.AfterSha256, after.Snapshot.Sha256);
        }
        await WriteNative("closed-native-after.json", after);
        if (caseId == "lost-commit-ack")
        {
            using var proxy = JsonDocument.Parse(ReadProtected(Path.Combine(fixture.Root, "auth-closed-proxy-" + fixture.Operation.ToString("N") + "-disposed.json"), 65536));
            Assert.Equal(1, proxy.RootElement.GetProperty("droppedCommits").GetInt32());
            Assert.True(proxy.RootElement.GetProperty("workerCompleted").GetBoolean()); Assert.True(proxy.RootElement.GetProperty("readersSettled").GetBoolean());
            Assert.False(proxy.RootElement.GetProperty("cleanupFailed").GetBoolean());
        }
        if (caseId == "replay")
        {
            var saved = Receipts(); Assert.Equal(1, await Invoke("apply-current-auth-repair"));
            var retained = Receipts(); Assert.Equal(saved.Count, retained.Count);
            foreach (var item in saved) { Assert.Equal(item.Value, retained[item.Key]); }
            Assert.Equal(after.Snapshot.Sha256, (await Auth(op, fixture.Token)).Snapshot.Sha256);
        }
        if (caseId == "final-fleet")
        {
            var mutated = await Database(op, "postgres", fixture.Token);
            Assert.NotEqual(captured.BeforeDatabaseSha256["postgres"], mutated.Sha256);
            await fixture.RecordAsync("final-fleet-before-restore", mutated, fixture.Token);
            await using (var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = "postgres" }.ConnectionString))
            {
                await connection.OpenAsync(fixture.Token); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, fixture.Token);
                await using var command = new NpgsqlCommand("UPDATE private.auth_closed_sentinel SET evidence='unchanged' WHERE id=1 AND evidence='changed-during-candidate';", connection, tx);
                Assert.Equal(1, await command.ExecuteNonQueryAsync(fixture.Token)); await tx.CommitAsync(fixture.Token);
            }
            Assert.Equal(captured.BeforeDatabaseSha256["postgres"], (await Database(op, "postgres", fixture.Token)).Sha256);
        }
        var fleet = new List<CurrentAppOwnedDatabaseSnapshot>(); var pool = new CurrentAppOwnedSnapshotInternPool();
        foreach (string database in captured.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentAuthRepairCapacity.Require(admission: false);
            var snapshot = database == "Auth" ? after.Snapshot : await Database(op, database, fixture.Token);
            if (database != "Auth") { Assert.Equal(captured.BeforeDatabaseSha256[database], snapshot.Sha256); }
            fleet.Add(pool.Intern(snapshot));
        }
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteBaselineNewAsync(Path.Combine(fixture.Root, "closed-fleet-after.json"), [.. fleet], fixture.Token);
            await files.WriteNewAsync(Path.Combine(fixture.Root, "closed-invocations.json"), JsonSerializer.SerializeToUtf8Bytes(invocations), fixture.Token);
            await files.WriteNewAsync(Path.Combine(fixture.Root, "closed-case-return.json"), JsonSerializer.SerializeToUtf8Bytes(new
            {
                caseId,
                fixture.Operation,
                sourceCommitSha = source.SourceCommitSha,
                runBindingSha256 = fixture.Binding.ComputeSha256(),
                returnedAtUtc = DateTimeOffset.UtcNow,
                configurationSha256 = CurrentAuthRepairPermit.Hash(files.Read(configPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024)),
                nativeBeforeSha256 = before.Snapshot.Sha256,
                nativeAfterSha256 = after.Snapshot.Sha256,
                receiptFiles = Receipts().OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { name = x.Key, sha256 = CurrentAuthRepairPermit.Hash(x.Value) }).ToArray()
            }), fixture.Token);
        }
        output.WriteLine(JsonSerializer.Serialize(new
        {
            fixture.Operation,
            caseId,
            fixture.Root,
            actualConsoleInvocations = invocations.Count,
            sourceOnlyCodeStatus = "execution evidence must be assembled from actual TRX and cleanup, never this stdout"
        }));

        async Task<int> Invoke(string command)
        {
            DateTimeOffset started = DateTimeOffset.UtcNow; using var stdout = new StringWriter(); using var stderr = new StringWriter();
            int result = await MigrationConsole.RunAsync([command, "--config", configPath], stdout, stderr, Environment.GetEnvironmentVariable, fixture.Token);
            invocations.Add(new
            {
                command,
                operation = fixture.Operation,
                startedAtUtc = started,
                exitedAtUtc = DateTimeOffset.UtcNow,
                exitCode = result,
                stdoutSha256 = CurrentAuthRepairPermit.Hash(Encoding.UTF8.GetBytes(stdout.ToString())),
                stderrSha256 = CurrentAuthRepairPermit.Hash(Encoding.UTF8.GetBytes(stderr.ToString()))
            });
            return result;
        }
        Dictionary<string, byte[]> Receipts()
        {
            return Directory.GetFiles(fixture.Root, fixture.Operation.ToString("D") + "-*.json")
            .ToDictionary(path => Path.GetFileName(path) ?? throw CurrentAuthRepairPermit.Invalid(), path => ReadProtected(path, 65536), StringComparer.Ordinal);
        }

        async Task WriteNative(string name, CurrentAuthNativeObservation native)
        {
            using var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding); using var files = new CurrentAppOwnedRepairCustody(authority);
            var value = new CurrentAuthProofNative(native.Snapshot, native.CopyTuples(), native.CopyStorage().ToDictionary(x => x.Key,
                x => new CurrentAuthProofStorage(x.Value.FileNode, x.Value.Blocks), StringComparer.Ordinal), native.CopyExpressions());
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value); if (bytes.Length > 32 * 1024 * 1024) { throw CurrentAuthRepairPermit.Invalid(); }
            await files.WriteNewAsync(Path.Combine(fixture.Root, name), bytes, fixture.Token);
        }
    }

    private static byte[] ReadProtected(string path, int maximum)
    {
        using var input = SecureLocalFile.OpenReadShared(path);
        if (input.Length is < 1 || input.Length > maximum) { throw CurrentAuthRepairPermit.Invalid(); }
        string identity = SecureLocalFile.GetHandleIdentity(input); byte[] bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
        return input.Position != input.Length || SecureLocalFile.GetHandleIdentity(input) != identity || !SecureLocalFile.HandleResolvesToApprovedPath(input, path)
            ? throw CurrentAuthRepairPermit.Invalid()
            : bytes;
    }
    private static async Task<CurrentAuthNativeObservation> Auth(string op, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = "Auth" }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await command.ExecuteNonQueryAsync(ct); }
        var native = await CurrentAuthNativePreservation.CaptureAsync(connection, tx, ct); await tx.RollbackAsync(ct); return native;
    }
    private static async Task<CurrentAppOwnedDatabaseSnapshot> Database(string op, string database, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = database }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var command = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await command.ExecuteNonQueryAsync(ct); }
        var snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct); await tx.RollbackAsync(ct); return snapshot;
    }
}
