using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record DualTargetNativeProofPreparationConfiguration(string Kind, string RouteConfigurationPath,
    string ToolPinsPath, string OutputPath);

public static partial class MigrationConsole
{
    // A closed producer: only generated dumps and factory-owned targets reach restore, then the existing fixed proof route.
    internal static async Task<int> PrepareDualTargetNativeProofAsync(string configPath, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("LEGACY_MIGRATION_CALLER") != "owner" ||
            Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw DualTargetNativeProofPreimage.Invalid(); }
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        var request = await ReadProtectedJsonAsync<DualTargetNativeProofPreparationConfiguration>(configPath, "native_proof_configuration_unprotected", ct).ConfigureAwait(false);
        var initial = await ReadProtectedJsonAsync<DualTargetCapturedDeltaConfiguration>(request.RouteConfigurationPath, "native_proof_route_unprotected", ct).ConfigureAwait(false);
        var binding = await ReadProtectedJsonAsync<LocalExecutionBinding>(initial.BindingPath, "native_proof_binding_unprotected", ct).ConfigureAwait(false);
        string root = binding.ArtifactRootCanonicalPath;
        Guid run = Guid.NewGuid();
        if (request.Kind != "dual-target-native-proof-preparer-v1" || Path.GetDirectoryName(Path.GetFullPath(request.OutputPath)) != root ||
            File.Exists(request.OutputPath) || Directory.Exists(request.OutputPath) || initial.ExpiresAtUtc.Offset != TimeSpan.Zero || initial.ExpiresAtUtc <= DateTimeOffset.UtcNow ||
            initial.ExpiresAtUtc - DateTimeOffset.UtcNow > TimeSpan.FromMinutes(8)) { throw DualTargetNativeProofPreimage.Invalid(); }
        string dumpRoot = Path.Combine(root, "native-proof-dumps-" + run.ToString("N"));
        if (Directory.Exists(dumpRoot)) { throw DualTargetNativeProofPreimage.Invalid(); }
        SecureSnapshotFileCreation.CreateRestrictedDirectory(dumpRoot);
        using WindowsLocalRunAuthority dumpAuthority = WindowsLocalRunAuthority.AcquireFresh(dumpRoot);
        using var dumpFiles = new CurrentAppOwnedRepairCustody(dumpAuthority);
        var clones = new List<DualTargetNativeProofClone>();
        var ownedProofs = new Dictionary<DualTargetCapturedDeltaPurpose, DualTargetNativeProofClone.ProofLease>();
        var generated = new List<DualTargetNativeProofGeneratedSecret>();
        var retained = new List<object>();
        string[] phases = ["plan-dual-target-captured-delta", "prove-dual-target-captured-delta", "prove-dual-target-captured-delta"];
        var phaseInputs = new List<string>();
        Exception? primary = null;
        bool completed = false, cleanupComplete = false;
        try
        {
            using (WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                var config = DecodeV3<DualTargetCapturedDeltaConfiguration>(files.Read(request.RouteConfigurationPath, maximumBytes: 1024 * 1024));
                if (JsonSerializer.Serialize(config) != JsonSerializer.Serialize(initial) ||
                    JsonSerializer.Serialize(DecodeV3<DualTargetNativeProofPreparationConfiguration>(files.Read(configPath, maximumBytes: 65536))) != JsonSerializer.Serialize(request))
                { throw DualTargetNativeProofPreimage.Invalid(); }
                FreshSchemaPlan schema = DecodeV3<FreshSchemaPlan>(files.Read(config.SchemaPath, maximumBytes: 32 * 1024 * 1024));
                RequireDualSchema(schema, accepted);
                if (config.Targets.Count != 4 || !config.Targets.Select(x => x.Endpoint.Purpose).Order().SequenceEqual(Enum.GetValues<DualTargetCapturedDeltaPurpose>().Order()))
                { throw DualTargetNativeProofPreimage.Invalid(); }
                using DualTargetNativeProofTools tools = DualTargetNativeProofTools.Acquire(files, request.ToolPinsPath, accepted);
                await tools.RequireVersionsAsync(ct).ConfigureAwait(false);
                DualTargetCapturedDeltaObservation observers = await DualTargetCapturedDeltaObservation.OpenAsync(files, root,
                    config.TunnelPath, accepted, config.ExpiresAtUtc, ct).ConfigureAwait(false);
                Exception? sourceFailure = null;
                try
                {
                    using var life = CancellationTokenSource.CreateLinkedTokenSource(ct, observers.OperationToken);
                    life.CancelAfter(config.ExpiresAtUtc - DateTimeOffset.UtcNow);
                    CancellationToken token = life.Token;
                    var replacements = config.Targets.ToDictionary(x => x.Endpoint.Purpose);
                    foreach (DualTargetCapturedDeltaPurpose purpose in new[] { DualTargetCapturedDeltaPurpose.Production, DualTargetCapturedDeltaPurpose.PersistentLocal })
                    {
                        DualTargetCapturedEndpointKeys source = replacements[purpose];
                        string sourceConnection = ReadConnection(files, source.Endpoint.ConnectionFile);
                        DualTargetCapturedTargetObservation before = await observers.ObserveAsync(source.Endpoint, sourceConnection, schema, token).ConfigureAwait(false);
                        string[] names = before.NativeBeforeSha256.Keys.Order(StringComparer.Ordinal).ToArray();
                        DualTargetNativeProofPreimage.RequireInventory(purpose, names);
                        string[] roles = await ReadSourceRolesAsync(sourceConnection, token).ConfigureAwait(false);
                        DualTargetNativeProofClone clone = await DualTargetNativeProofClone.CreateAsync(root, token).ConfigureAwait(false); clones.Add(clone);
                        using var cloneLife = CancellationTokenSource.CreateLinkedTokenSource(token, clone.Token); token = cloneLife.Token;
                        DualTargetNativeProofPreimage.RequireRoleNames(roles, DualTargetNativeProofClone.Administrator);
                        await InitializeCloneRolesAsync(clone, roles, token).ConfigureAwait(false);
                        var originals = new Dictionary<string, DualTargetNativeProofDatabase>(StringComparer.Ordinal);
                        var finalLogical = new Dictionary<string, DualTargetNativeProofDatabase>(StringComparer.Ordinal);
                        var dumps = new List<DualTargetNativeProofDump>();
                        int ordinal = 0;
                        foreach (string database in names)
                        {
                            observers.RequireLive(); await clone.RequireOwnedAsync(token).ConfigureAwait(false);
                            var settings = new NpgsqlConnectionStringBuilder(sourceConnection) { Database = database, Pooling = false };
                            await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(token).ConfigureAwait(false);
                            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token).ConfigureAwait(false);
                            await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", token).ConfigureAwait(false);
                            DateTimeOffset began = DateTimeOffset.UtcNow;
                            if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx,
                                "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", token).ConfigureAwait(false) != before.Authority.SystemIdentifierSha256)
                            { throw DualTargetNativeProofPreimage.Invalid(); }
                            if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SHOW server_version_num;", token).ConfigureAwait(false) != "180004")
                            { throw new MigrationExecutionException("dual_target_native_proof_server_unsupported", "Only the fixed reviewed PostgreSQL 18.4 clone image is supported."); }
                            string snapshot = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SELECT pg_export_snapshot();", token).ConfigureAwait(false);
                            DualTargetNativeProofDatabase logical = await DualTargetNativeProofLogicalCapture.ReadAsync(connection, tx, tools,
                                settings.ConnectionString, database, snapshot, token).ConfigureAwait(false);
                            string path = Path.Combine(dumpRoot, purpose + "-" + (++ordinal).ToString("D3", System.Globalization.CultureInfo.InvariantCulture) + ".dump");
                            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 65536, FileOptions.Asynchronous | FileOptions.WriteThrough))
                            { await tools.DumpAsync(settings.ConnectionString, database, snapshot, output, definition: false, token).ConfigureAwait(false); await output.FlushAsync(token).ConfigureAwait(false); output.Flush(true); }
                            FileStream archive = dumpFiles.BorrowReadStream(path); string digest = Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, token).ConfigureAwait(false)); archive.Position = 0;
                            dumps.Add(new(database, Path.GetFileName(path), archive.Length, digest, began, DateTimeOffset.UtcNow, before.Authority.SystemIdentifierSha256));
                            await tx.RollbackAsync(token).ConfigureAwait(false);
                            dumpFiles.Require(); await tools.RestoreAsync(clone, archive, token).ConfigureAwait(false); dumpFiles.Require();
                            archive.Position = 0; if (Convert.ToHexStringLower(await SHA256.HashDataAsync(archive, token).ConfigureAwait(false)) != digest) { throw DualTargetNativeProofPreimage.Invalid(); }
                            originals.Add(database, logical);
                            finalLogical.Add(database, logical);
                        }
                        await DropCloneControlAsync(clone, token).ConfigureAwait(false);
                        await RequireMappedRolesAsync(clone, roles, token).ConfigureAwait(false);
                        foreach (string database in names)
                        { DualTargetNativeProofPreimage.RequireClone(originals[database], await ReadCloneAsync(clone, database, tools, token).ConfigureAwait(false)); }
                        CurrentAppOwnedMaintenancePin maintenance = await DualTargetNativeProofPolicy.InstallAsync(clone,
                            config.ExpiresAtUtc < clone.ExpiresAtUtc ? config.ExpiresAtUtc : clone.ExpiresAtUtc, token).ConfigureAwait(false);
                        DualTargetCapturedDeltaPurpose proofPurpose = purpose == DualTargetCapturedDeltaPurpose.Production ? DualTargetCapturedDeltaPurpose.ProductionProof : DualTargetCapturedDeltaPurpose.LocalProof;
                        DualTargetCapturedEndpointKeys previous = replacements[proofPurpose];
                        string prefix = Path.Combine(root, "native-proof-" + clone.Operation.ToString("N"));
                        string connectionFile = prefix + "-operator.txt", pinFile = prefix + "-maintenance.json";
                        byte[] generatedConnection = Encoding.UTF8.GetBytes(clone.Connection);
                        try { await DualTargetNativeProofSecret.WriteGeneratedAsync(files, root, connectionFile, generatedConnection, generated, token).ConfigureAwait(false); }
                        finally { CryptographicOperations.ZeroMemory(generatedConnection); }
                        await files.WriteNewAsync(pinFile, JsonSerializer.SerializeToUtf8Bytes(maintenance), token).ConfigureAwait(false);
                        var endpoint = previous.Endpoint with
                        {
                            ConnectionFile = connectionFile,
                            MaintenancePinsPath = pinFile,
                            DockerContainerId = clone.ContainerId,
                            DockerVolumeName = clone.Name
                        };
                        DualTargetNativeProofClone.ProofLease ownership = await clone.BindProofEndpointAsync(endpoint, clone.Connection, accepted,
                            config.ExpiresAtUtc < clone.ExpiresAtUtc ? config.ExpiresAtUtc : clone.ExpiresAtUtc, token).ConfigureAwait(false);
                        ownedProofs.Add(proofPurpose, ownership);
                        DualTargetCapturedTargetObservation first = await observers.ObserveAsync(endpoint, clone.Connection, schema, ownership, token).ConfigureAwait(false);
                        string fullSchema = SchemaPlanCanonicalizer.ComputeSha256(schema);
                        foreach (DatabaseSchemaPlan database in schema.Databases)
                        {
                            DualTargetNativeProofRows fence = await DualTargetNativeProofFence.RebindAsync(clone, database, fullSchema, first, token).ConfigureAwait(false);
                            var expected = originals[database.Database] with { Tables = originals[database.Database].Tables.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal) };
                            ((Dictionary<string, DualTargetNativeProofRows>)expected.Tables)[DualTargetNativeProofLogicalCapture.Qualified("legacy_migration_internal", "delta_fence")] = fence;
                            finalLogical[database.Database] = expected;
                            DualTargetNativeProofPreimage.RequireClone(expected, await ReadCloneAsync(clone, database.Database, tools, token).ConfigureAwait(false));
                        }
                        foreach (string database in names)
                        { DualTargetNativeProofPreimage.RequireClone(finalLogical[database], await ReadCloneAsync(clone, database, tools, token).ConfigureAwait(false)); }
                        DualTargetCapturedTargetObservation baseline = await observers.ObserveAsync(endpoint, clone.Connection, schema, ownership, token).ConfigureAwait(false);
                        if (baseline.Sha256 != first.Sha256) { throw DualTargetNativeProofPreimage.Invalid(); }
                        DualTargetCapturedTargetObservation after = await observers.ObserveAsync(source.Endpoint, sourceConnection, schema, token).ConfigureAwait(false);
                        if (JsonSerializer.Serialize(before) != JsonSerializer.Serialize(after)) { throw DualTargetNativeProofPreimage.Invalid(); }
                        await dumpFiles.WriteNewAsync(Path.Combine(dumpRoot, purpose + "-verified-logical-preimages.json"), JsonSerializer.SerializeToUtf8Bytes(new
                        {
                            run,
                            purpose,
                            before,
                            after,
                            roleMapping = roles.Select(x => new { Name = x, Login = false }),
                            databases = originals.OrderBy(x => x.Key, StringComparer.Ordinal).Select(x => new { Database = x.Key, Sha256 = DualTargetNativeProofPreimage.Hash(x.Value) }),
                            dumps,
                            baseline
                        }), token).ConfigureAwait(false);
                        replacements[proofPurpose] = previous with { Endpoint = endpoint };
                        retained.Add(new { purpose, clone.Operation, clone.ContainerId, clone.Name, clone.Root, clone.Binding, baseline });
                        token = life.Token;
                    }
                    foreach (int index in Enumerable.Range(0, 3))
                    {
                        string phasePath = Path.Combine(root, "native-proof-" + run.ToString("N") + "-phase-" + index + ".json");
                        var phase = config with
                        {
                            Targets = replacements.Values.OrderBy(x => x.Endpoint.Purpose).ToArray(),
                            OutputPath = index == 0 ? config.BundlePath : Path.Combine(root, "native-proof-" + run.ToString("N") + "-" + index + "-result.json"),
                            Purpose = index == 0 ? null : index == 1 ? DualTargetCapturedDeltaPurpose.ProductionProof : DualTargetCapturedDeltaPurpose.LocalProof
                        };
                        await files.WriteNewAsync(phasePath, JsonSerializer.SerializeToUtf8Bytes(phase), token).ConfigureAwait(false); phaseInputs.Add(phasePath);
                    }
                    await dumpFiles.WriteNewAsync(Path.Combine(dumpRoot, "prepared-INCOMPLETE.json"), JsonSerializer.SerializeToUtf8Bytes(new
                    { run, accepted, createdAtUtc = DateTimeOffset.UtcNow, retained, phaseInputs, toolProcesses = tools.Processes, PhaseProofComplete = false }), token).ConfigureAwait(false);
                }
                catch (Exception failure) { sourceFailure = failure; }
                Exception? sourceCleanupFailure = null;
                try { await observers.DisposeAsync().ConfigureAwait(false); }
                catch (Exception cleanup) { sourceCleanupFailure = cleanup; }
                if (sourceFailure is not null && sourceCleanupFailure is not null) { throw new AggregateException(sourceFailure, sourceCleanupFailure); }
                if (sourceFailure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(sourceFailure).Throw(); }
                if (sourceCleanupFailure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(sourceCleanupFailure).Throw(); }
            }
            // The source root's authority is released before any existing phase reacquires it. Clone ownership stays live.
            DualTargetCapturedOwnedProofPair proofPair = DualTargetCapturedOwnedProofPair.Create(
                ownedProofs[DualTargetCapturedDeltaPurpose.ProductionProof], ownedProofs[DualTargetCapturedDeltaPurpose.LocalProof]);
            for (int index = 0; index < phaseInputs.Count; index++)
            {
                foreach (DualTargetNativeProofClone clone in clones) { await clone.RequireOwnedAsync(ct).ConfigureAwait(false); }
                if (await RunOwnedDualTargetCapturedDeltaAsync(phases[index], phaseInputs[index], TextWriter.Null, TextWriter.Null, proofPair, ct).ConfigureAwait(false) != 0)
                { throw DualTargetNativeProofPreimage.Invalid(); }
            }
            completed = true;
        }
        catch (Exception failure) { primary = failure; }
        var failures = new List<Exception>();
        foreach (DualTargetNativeProofClone clone in clones.AsEnumerable().Reverse())
        { try { await clone.DisposeAsync().ConfigureAwait(false); } catch (Exception cleanup) { failures.Add(cleanup); } }
        try { DualTargetNativeProofSecret.RemoveGenerated(root, binding, generated); } catch (Exception cleanup) { failures.Add(cleanup); }
        cleanupComplete = failures.Count == 0;
        try
        {
            await dumpFiles.WriteNewAsync(Path.Combine(dumpRoot, "cleanup.json"), JsonSerializer.SerializeToUtf8Bytes(new
            { run, completed, cleanupComplete, expiresAtUtc = initial.ExpiresAtUtc, retained, cleanupFailures = failures.Select(x => x.GetType().Name) }), CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception cleanup) { failures.Add(cleanup); cleanupComplete = false; }
        if (primary is not null && failures.Count != 0) { throw new AggregateException(primary, new AggregateException(failures)); }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        if (failures.Count != 0) { throw new AggregateException(failures); }
        if (!completed || !cleanupComplete) { throw DualTargetNativeProofPreimage.Invalid(); }
        using (WindowsLocalRunAuthority authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(request.OutputPath, JsonSerializer.SerializeToUtf8Bytes(new
            {
                Kind = "dual-target-native-proof-preparation-v1",
                run,
                accepted,
                completedAtUtc = DateTimeOffset.UtcNow,
                dumpRoot,
                phaseInputs,
                fullFleetLogicalClonesVerified = true,
                disposableProofsCompleted = true,
                cleanupComplete,
                PersistentExecutionPerformed = false
            }), ct).ConfigureAwait(false);
        }
        return 0;
    }

    private static async Task<string[]> ReadSourceRolesAsync(string connectionString, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(connectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        if (await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SHOW server_version_num;", ct).ConfigureAwait(false) != "180004")
        { throw new MigrationExecutionException("dual_target_native_proof_server_unsupported", "Only the fixed reviewed PostgreSQL 18.4 clone image is supported."); }
        await using var query = new NpgsqlCommand("SELECT rolname FROM pg_roles WHERE rolname NOT LIKE 'pg\\_%' ESCAPE '\\' ORDER BY rolname;", connection, tx);
        var roles = new List<string>(); await using (var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false))
        { while (await reader.ReadAsync(ct).ConfigureAwait(false)) { roles.Add(reader.GetString(0)); } }
        await tx.RollbackAsync(ct).ConfigureAwait(false); return roles.ToArray();
    }
    private static async Task InitializeCloneRolesAsync(DualTargetNativeProofClone clone, string[] roles, CancellationToken ct)
    {
        await clone.RequireOwnedAsync(ct).ConfigureAwait(false);
        var settings = new NpgsqlConnectionStringBuilder(clone.AdminConnection) { Database = "clone_control" };
        await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, null, "DROP DATABASE postgres;", ct).ConfigureAwait(false);
        foreach (string role in roles)
        {
            await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, null, (role == "postgres" ? "ALTER ROLE " : "CREATE ROLE ") + DualTargetNativeProofLogicalCapture.Quote(role) +
                " NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD NULL;", ct).ConfigureAwait(false);
        }
    }
    private static async Task DropCloneControlAsync(DualTargetNativeProofClone clone, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(clone.AdminConnection); await connection.OpenAsync(ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, null, "DROP DATABASE clone_control;", ct).ConfigureAwait(false);
        clone.MarkControlDropped();
    }
    private static async Task RequireMappedRolesAsync(DualTargetNativeProofClone clone, string[] expected, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(clone.AdminConnection); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var query = new NpgsqlCommand("SELECT rolname,rolcanlogin,rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls,rolpassword FROM pg_authid WHERE rolname <> 'clone_admin' AND rolname NOT LIKE 'pg\\_%' ESCAPE '\\' ORDER BY rolname;", connection);
        var actual = new List<string>(); await using var reader = await query.ExecuteReaderAsync(ct).ConfigureAwait(false);
        while (await reader.ReadAsync(ct).ConfigureAwait(false))
        {
            actual.Add(reader.GetString(0));
            if (Enumerable.Range(1, 6).Any(reader.GetBoolean) || !reader.IsDBNull(7)) { throw DualTargetNativeProofPreimage.Invalid(); }
        }
        if (!actual.SequenceEqual(expected, StringComparer.Ordinal)) { throw DualTargetNativeProofPreimage.Invalid(); }
    }
    private static async Task<DualTargetNativeProofDatabase> ReadCloneAsync(DualTargetNativeProofClone clone, string database, DualTargetNativeProofTools tools, CancellationToken ct)
    {
        var settings = new NpgsqlConnectionStringBuilder(clone.Connection) { Database = database };
        await using var connection = new NpgsqlConnection(settings.ConnectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
        await DualTargetNativeProofLogicalCapture.ExecuteAsync(connection, tx, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
        string snapshot = await DualTargetNativeProofLogicalCapture.ScalarAsync(connection, tx, "SELECT pg_export_snapshot();", ct).ConfigureAwait(false);
        var result = await DualTargetNativeProofLogicalCapture.ReadAsync(connection, tx, tools, settings.ConnectionString, database, snapshot, ct).ConfigureAwait(false);
        await tx.RollbackAsync(ct).ConfigureAwait(false); return result;
    }
}
