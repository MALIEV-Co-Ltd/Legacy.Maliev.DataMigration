using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Xunit.Abstractions;
using Npgsql;
using Testcontainers.PostgreSql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class CurrentCustomerSequenceNativeGroup
{
    public const string Name = "Current Customer sequence definition disposable feasibility";
}

/// <summary>Disposable physical feasibility only; never a production repair or signed acceptance.</summary>
[Collection(CurrentCustomerSequenceNativeGroup.Name)]
public sealed class CurrentCustomerSequenceNativeFeasibilityTests(ITestOutputHelper output)
{
    [WindowsLocalRunFact]
    public async Task Exact_customer_operand_owner_preserves_mixed_private_owners_and_allocation()
    {
        await RunOwnedAsync(async (run, containerId, admin, token) =>
        {
            // Synthetic native component only: no signed operation, bootstrap adoption or persistent permission.
            _ = run;
            _ = containerId;
            string endpoint = await BootstrapAsync(admin, 69831, true, token, idOrdinal: 9);
            await using var connection = new NpgsqlConnection(endpoint);
            await connection.OpenAsync(token);
            await ExecuteAsync(connection, "CREATE ROLE legacy_customer_owner LOGIN NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4; ALTER TABLE public.\"Customer\" OWNER TO legacy_customer_owner;", token);
            string system = await ScalarAsync<string>(connection, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", token);
            var target = new DeltaTargetAuthority(DeltaTargetAuthorityKind.ProductionCloudNativePg, "synthetic-owner-component-only", system);
            CurrentCustomerSequenceObservation before;
            string closure;
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            {
                before = await ObserveAsync(connection, tx, token);
                Assert.Equal(9, before.State.AttributeNumber);
                ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, "legacy_customer_owner");
                closure = await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, before.Snapshot, token);
                CurrentAppOwnedDatabaseSnapshot missingRole = before.Snapshot with
                { Catalog = before.Snapshot.Catalog.Where(x => x.Catalog != "pg_authid").ToArray() };
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx,
                    CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, missingRole, token));
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx,
                    CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target with { SystemIdentifierSha256 = new string('0', 64) }, before.Snapshot, token));
                await ExecuteAsync(connection, ApprovedCurrentCustomerSequenceDefinition.CandidateSql, token, tx);
                CurrentCustomerSequenceObservation after = await ObserveAsync(connection, tx, token);
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after, "legacy_customer_owner");
                Assert.Equal(closure, await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, after.Snapshot, token));
                await tx.RollbackAsync(token);
            }
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            {
                CurrentCustomerSequenceObservation rolledBack = await ObserveAsync(connection, tx, token);
                Assert.Equal(before.Snapshot.Sha256, rolledBack.Snapshot.Sha256);
                await ExecuteAsync(connection, "ALTER ROLE legacy_customer_owner SUPERUSER;", token, tx);
                CurrentCustomerSequenceObservation wrongFlags = await ObserveAsync(connection, tx, token);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx,
                    CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, wrongFlags.Snapshot, token));
                await tx.RollbackAsync(token);
            }
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            {
                await ExecuteAsync(connection, "ALTER TABLE public.\"Customer\" OWNER TO postgres;", token, tx);
                CurrentCustomerSequenceObservation wrongOwner = await ObserveAsync(connection, tx, token);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx,
                    CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, wrongOwner.Snapshot, token));
                await tx.RollbackAsync(token);
            }
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token))
            { await ExecuteAsync(connection, ApprovedCurrentCustomerSequenceDefinition.CandidateSql, token, tx); await tx.CommitAsync(token); }
            await using var independent = new NpgsqlConnection(endpoint);
            await independent.OpenAsync(token);
            await using var readback = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
            await ExecuteAsync(independent, "SET TRANSACTION READ ONLY;", token, readback);
            CurrentCustomerSequenceObservation final = await ObserveAsync(independent, readback, token);
            ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, final, "legacy_customer_owner");
            Assert.Equal(closure, await CurrentRepairOperandOwnerProfile.RequireNativeAsync(independent, readback,
                CurrentRepairOperandOwnerPurpose.CustomerSequenceStart, target, final.Snapshot, token));
            Assert.Equal(before.State.LastValue, final.State.LastValue);
            Assert.Equal(before.State.IsCalled, final.State.IsCalled);
            Assert.Equal(before.State.LogCount, final.State.LogCount);
            _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequireBefore(final, "legacy_customer_owner"));
            await readback.RollbackAsync(token);
        });
    }

    [WindowsLocalRunTheory]
    [InlineData(1L, false, false, 1)]
    [InlineData(1L, false, false, 9)]
    [InlineData(69831L, true, true, 1)]
    [InlineData(69831L, true, true, 9)]
    [InlineData(2000000000L, true, true, 1)]
    [InlineData(2000000000L, true, true, 9)]
    [InlineData(2000000000L, false, false, 1)]
    [InlineData(2000000000L, false, false, 9)]
    public async Task Start_definition_replacement_preserves_allocation_and_exact_other_facts_with_rollback_and_independent_readback(
        long last, bool called, bool requireNonzeroWalLogCount, int idOrdinal)
    {
        await RunOwnedAsync(async (run, containerId, admin, token) =>
        {
            WriteLedger(run, "definition-entered", new
            {
                run,
                containerId,
                last,
                called,
                idOrdinal,
                beganAtUtc = DateTimeOffset.UtcNow,
                coreAssemblySha256 = AssemblyHash(typeof(ApprovedCurrentCustomerSequenceDefinition).Assembly.Location),
                consoleAssemblySha256 = AssemblyHash(typeof(MigrationConsole).Assembly.Location),
                testAssemblySha256 = AssemblyHash(typeof(CurrentCustomerSequenceNativeFeasibilityTests).Assembly.Location)
            });
            string connectionString = await BootstrapAsync(admin, last, called, token, idOrdinal);
            CurrentCustomerSequenceObservation before;
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync(token);
                Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                before = await ObserveAsync(connection, tx, token);
                WriteLedger(run, "native-before", before);
                Assert.Equal(idOrdinal, before.State.AttributeNumber);
                // Allocated fixtures use genuine nextval after setval; assert actual WAL prelogging,
                // rather than relying on setval-only state whose log_cnt is normally zero.
                if (requireNonzeroWalLogCount) { Assert.True(before.State.LogCount > 0); }
                ApprovedCurrentCustomerSequenceDefinition.RequireBefore(before, "postgres");
                await ExecuteAsync(connection, ApprovedCurrentCustomerSequenceDefinition.CandidateSql, token, tx);
                CurrentCustomerSequenceObservation after = await ObserveAsync(connection, tx, token);
                WriteLedger(run, "native-candidate", after);
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, after, "postgres");
                await tx.RollbackAsync(token);
            }
            // Fresh backend and transaction: rollback restores the original storage identity and complete snapshot.
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync(token);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, token);
                CurrentCustomerSequenceObservation rolledBack = await ObserveAsync(connection, tx, token);
                WriteLedger(run, "native-rolled-back", rolledBack);
                Assert.Equal(before.State, rolledBack.State);
                Assert.Equal(before.Snapshot.Sha256, rolledBack.Snapshot.Sha256);
                ApprovedCurrentCustomerSequenceDefinition.RequireBefore(rolledBack, "postgres");
                await ExecuteAsync(connection, ApprovedCurrentCustomerSequenceDefinition.CandidateSql, token, tx);
                CurrentCustomerSequenceObservation committedCandidate = await ObserveAsync(connection, tx, token);
                WriteLedger(run, "native-commit-candidate", committedCandidate);
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, committedCandidate, "postgres");
                await tx.CommitAsync(token);
            }
            await using (var connection = new NpgsqlConnection(connectionString))
            {
                await connection.OpenAsync(token);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", token, tx);
                CurrentCustomerSequenceObservation actual = await ObserveAsync(connection, tx, token);
                WriteLedger(run, "native-independent-after", actual);
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(before, actual, "postgres");
                Assert.Equal(last, actual.State.LastValue);
                Assert.Equal(called, actual.State.IsCalled);
                Assert.Equal(before.State.LogCount, actual.State.LogCount);
                _ = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequireBefore(actual, "postgres"));
                await tx.RollbackAsync(token);
            }
        });
    }

    [WindowsLocalRunTheory]
    [InlineData("ALTER SEQUENCE public.\"Customer_ID_seq\" INCREMENT BY 2;")]
    [InlineData("ALTER SEQUENCE public.\"Customer_ID_seq\" CACHE 2;")]
    [InlineData("ALTER SEQUENCE public.\"Customer_ID_seq\" START WITH 1000;")]
    [InlineData("ALTER TABLE public.\"Customer\" ALTER COLUMN \"ID\" SET GENERATED ALWAYS;")]
    [InlineData("ALTER TABLE public.\"Customer\" OWNER TO other_owner;")]
    public async Task Unexpected_preimage_fails_before_candidate(string changed)
    {
        await RunOwnedAsync(async (run, containerId, admin, token) =>
        {
            WriteLedger(run, "definition-entered", new
            {
                run,
                containerId,
                changed,
                beganAtUtc = DateTimeOffset.UtcNow,
                coreAssemblySha256 = AssemblyHash(typeof(ApprovedCurrentCustomerSequenceDefinition).Assembly.Location),
                consoleAssemblySha256 = AssemblyHash(typeof(MigrationConsole).Assembly.Location),
                testAssemblySha256 = AssemblyHash(typeof(CurrentCustomerSequenceNativeFeasibilityTests).Assembly.Location)
            });
            string connectionString = await BootstrapAsync(admin, 69831, true, token);
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync(token);
            await ExecuteAsync(connection, changed, token);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
            CurrentCustomerSequenceObservation actual = await ObserveAsync(connection, tx, token);
            WriteLedger(run, "native-negative-before", actual);
            var rejection = Assert.Throws<MigrationExecutionException>(() => ApprovedCurrentCustomerSequenceDefinition.RequireBefore(actual, "postgres"));
            WriteLedger(run, "native-negative-rejection", new { run, code = rejection.Code, observedAtUtc = DateTimeOffset.UtcNow });
            await tx.RollbackAsync(token);
            await using var independent = new NpgsqlConnection(connectionString);
            await independent.OpenAsync(token);
            await using var readback = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, token);
            await ExecuteAsync(independent, "SET TRANSACTION READ ONLY;", token, readback);
            CurrentCustomerSequenceObservation untouched = await ObserveAsync(independent, readback, token);
            Assert.Equal(actual.State, untouched.State); Assert.Equal(actual.Snapshot.Sha256, untouched.Snapshot.Sha256);
            WriteLedger(run, "native-negative-independent-after", untouched);
            await readback.RollbackAsync(token);
        });
    }

    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    private async Task RunOwnedAsync(Func<Guid, string, string, CancellationToken, Task> body)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows owned Docker proof required."); }
        _ = RequireLedgerDirectory();
        Guid run = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        string name = "customer-sequence-feasibility-" + run.ToString("N");
        WriteLedger(run, "attempt", new { run, name, began, expires, persistent = false });
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithName(name).WithCleanUp(false).WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "current-customer-sequence-definition-feasibility").WithLabel("codex.repair.operation", run.ToString("D"))
            .WithLabel("codex.repair.run", run.ToString("D"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 512 * 1024 * 1024; parameters.HostConfig.MemorySwap = 512 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 750000000;
                foreach (IList<PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                { foreach (PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; } }
            }).Build();
        string? ownedId = null, ownedVolume = null, ownedVolumeCreatedAt = null; bool removed = false, creationAttempted = false;
        DateTimeOffset? removedAtUtc = null;
        HashSet<string> previousVolumes = new(StringComparer.Ordinal);
        try
        {
            var volumesBefore = await docker.Volumes.ListAsync(lifetime.Token);
            previousVolumes = (volumesBefore.Volumes ?? throw new InvalidOperationException("Volume inventory missing."))
                .Select(volume => volume.Name).ToHashSet(StringComparer.Ordinal);
            bool absent = false;
            try { _ = await docker.Containers.InspectContainerAsync(name, lifetime.Token); }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { absent = true; }
            if (!absent) { throw new InvalidOperationException("Fresh owned UUID name already exists"); }
            var previousContainers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, lifetime.Token);
            string[] previousNames = previousContainers.SelectMany(x => x.Names).Order(StringComparer.Ordinal).ToArray();
            if (previousNames.Any(x => x == name || x == "/" + name)) { throw new InvalidOperationException("Fresh owned UUID name inventory mismatch."); }
            WriteLedger(run, "proof-previous-container-names", previousNames);
            WriteLedger(run, "creation-attempt", new { run, name, attemptedAtUtc = DateTimeOffset.UtcNow, expires });
            creationAttempted = true;
            await container.StartAsync(lifetime.Token);
            ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(name, lifetime.Token);
            RequireOwnership(metadata); ownedId = metadata.ID; ownedVolume = metadata.Mounts.Single().Name;
            await RequireNewSoleConsumerVolumeAsync(lifetime.Token);
            WriteLedger(run, "volume-observed", new
            {
                run,
                containerId = ownedId,
                volume = ownedVolume,
                createdAt = ownedVolumeCreatedAt,
                existedBefore = false,
                soleConsumer = ownedId,
                previousInventorySha256 = Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(previousVolumes.Order(StringComparer.Ordinal))))
            });
            WriteLedger(run, "observed", new
            {
                run,
                operation = run,
                name,
                containerId = ownedId,
                volume = ownedVolume,
                began,
                expires,
                persistent = false,
                ports = (metadata.NetworkSettings?.Ports ?? throw new InvalidOperationException("Owned fixture ports missing.")).SelectMany(pair => (pair.Value ?? []).Select(binding => new { containerPort = pair.Key, binding.HostIP, binding.HostPort })).ToArray()
            });
            output.WriteLine(JsonSerializer.Serialize(new
            {
                run,
                Purpose = "current-customer-sequence-definition-feasibility",
                ContainerId = ownedId,
                began,
                expires,
                Owned = true,
                Removed = false,
                PersistentData = false
            }));
            WriteLedger(run, "proof-previous-volumes", previousVolumes.Order(StringComparer.Ordinal).ToArray());
            var proofConsumers = await docker.Containers.ListContainersAsync(new ContainersListParameters
            {
                All = true,
                Filters = new Dictionary<string, IDictionary<string, bool>>
                { ["volume"] = new Dictionary<string, bool> { [ownedVolume ?? throw new InvalidOperationException("Owned volume missing.")] = true } }
            }, lifetime.Token);
            if (proofConsumers.Count != 1 || proofConsumers.Single().ID != ownedId) { throw new InvalidOperationException("Proof volume consumer changed."); }
            WriteLedger(run, "proof-volume-consumers", proofConsumers.Select(x => x.ID).ToArray());
            var proofVolume = await docker.Volumes.InspectAsync(ownedVolume ?? throw new InvalidOperationException("Owned volume missing."), lifetime.Token);
            WriteLedger(run, "proof-volume-metadata", proofVolume);
            JsonElement actualJson = JsonSerializer.SerializeToElement(metadata);
            var config = metadata.Config ?? throw new InvalidOperationException("Owned config missing.");
            var host = metadata.HostConfig ?? throw new InvalidOperationException("Owned host missing.");
            WriteLedger(run, "proof-container", new
            {
                Id = metadata.ID,
                metadata.Name,
                metadata.Image,
                Created = actualJson.GetProperty("Created"),
                State = actualJson.GetProperty("State"),
                Config = new { config.Image, config.Labels, PgData = (config.Env ?? throw new InvalidOperationException("Actual environment missing.")).Single(x => x.StartsWith("PGDATA=", StringComparison.Ordinal))[7..] },
                HostConfig = new { host.Memory, host.MemorySwap, NanoCpus = host.NanoCPUs, host.Mounts, host.Binds, host.VolumesFrom, host.Tmpfs },
                metadata.Mounts,
                NetworkSettings = new { Ports = (metadata.NetworkSettings?.Ports ?? throw new InvalidOperationException("Actual ports missing.")).ToDictionary(x => x.Key, x => x.Value?.Select(b => new { HostIp = b.HostIP, b.HostPort }).ToArray(), StringComparer.Ordinal) }
            });
            await body(run, ownedId, container.GetConnectionString(), lifetime.Token);
            WriteLedger(run, "definition-invocation-exited", new { run, containerId = ownedId, exitedAtUtc = DateTimeOffset.UtcNow });
        }
        catch
        {
            // Retain only resource state and fixed error categories, never SQL or credentials.
            if (ownedId is not null)
            {
                using var diagnostic = new CancellationTokenSource(TimeSpan.FromSeconds(20));
                try
                {
                    ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(ownedId, diagnostic.Token);
                    RequireOwnership(metadata);
                    var state = metadata.State ?? throw new InvalidOperationException("Owned fixture state missing.");
                    var categories = new ResourceLogCategories();
                    await docker.Containers.GetContainerLogsAsync(ownedId,
                        new ContainerLogsParameters { ShowStdout = true, ShowStderr = true, Follow = false, Tail = "100" },
                        categories, diagnostic.Token);
                    WriteLedger(run, "failure-resource-diagnostic", new
                    {
                        run,
                        containerId = ownedId,
                        state.Running,
                        state.OOMKilled,
                        state.ExitCode,
                        metadata.RestartCount,
                        categories.NoSpace,
                        categories.OutOfMemory,
                        categories.Panic,
                        categories.Recovery,
                        categories.Killed,
                        categories.Lines,
                        categories.Characters
                    });
                }
                catch (Exception failure)
                {
                    WriteLedger(run, "failure-diagnostic-unavailable", new { run, exceptionType = failure.GetType().FullName });
                }
            }
            throw;
        }
        finally
        {
            if (creationAttempted) { await CompleteCleanupAsync(); }
            else
            {
                bool disposed = false;
                try { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); disposed = true; }
                finally { WriteLedger(run, "disposed", new { run, creationAttempted = false, createdResources = false, disposed, cleanupFailure = !disposed, completedAtUtc = DateTimeOffset.UtcNow }); }
            }
        }

        async Task CompleteCleanupAsync()
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try
            {
                ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(ownedId ?? name, cleanup.Token);
                RequireOwnership(metadata); ownedId ??= metadata.ID; ownedVolume ??= metadata.Mounts.Single().Name;
                if (metadata.ID != ownedId) { throw new InvalidOperationException("Disposable ownership changed"); }
                _ = await docker.Containers.StopContainerAsync(ownedId, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token);
                metadata = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token);
                RequireOwnership(metadata);
                if ((metadata.State ?? throw new InvalidOperationException("Owned disposable state missing")).Running) { throw new InvalidOperationException("Owned disposable did not stop"); }
                if (metadata.Mounts.Single().Name != ownedVolume) { throw new InvalidOperationException("Owned disposable volume changed."); }
                await RequireNewSoleConsumerVolumeAsync(cleanup.Token);
                await docker.Containers.RemoveContainerAsync(ownedId, new ContainerRemoveParameters { Force = false, RemoveVolumes = true }, cleanup.Token);
                bool containerAbsent = false;
                try { _ = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { containerAbsent = true; }
                if (!containerAbsent) { throw new InvalidOperationException("Owned disposable removal not verified"); }
                bool volumeAbsent = false;
                try { _ = await docker.Volumes.InspectAsync(ownedVolume ?? throw new InvalidOperationException("Owned volume identity missing."), cleanup.Token); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { volumeAbsent = true; }
                if (!volumeAbsent) { removed = false; throw new InvalidOperationException("Owned disposable volume absence not verified."); }
                bool nameAbsent = false;
                try { _ = await docker.Containers.InspectContainerAsync(name, cleanup.Token); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { nameAbsent = true; }
                if (!nameAbsent) { throw new InvalidOperationException("Owned disposable name absence not verified"); }
                removed = true; removedAtUtc = DateTimeOffset.UtcNow;
                await RetainProofAbsenceAsync(cleanup.Token);
            }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound && ownedId is null)
            {
                var runContainers = await docker.Containers.ListContainersAsync(new ContainersListParameters
                {
                    All = true,
                    Filters = new Dictionary<string, IDictionary<string, bool>>
                    { ["label"] = new Dictionary<string, bool> { ["codex.repair.run=" + run.ToString("D")] = true } }
                }, cleanup.Token);
                if (runContainers.Count != 0)
                { throw new InvalidOperationException("Unknown creation outcome: run-labeled container preserved for owner reconciliation."); }
                var remaining = await docker.Volumes.ListAsync(cleanup.Token);
                HashSet<string> names = (remaining.Volumes ?? throw new InvalidOperationException("Cleanup volume inventory missing."))
                    .Select(volume => volume.Name).ToHashSet(StringComparer.Ordinal);
                if (!names.SetEquals(previousVolumes))
                { throw new InvalidOperationException("Unknown creation outcome: changed volume inventory preserved for owner reconciliation."); }
                removed = true; removedAtUtc = DateTimeOffset.UtcNow;
                await RetainProofAbsenceAsync(cleanup.Token);
            }
            finally
            {
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    run,
                    Purpose = "current-customer-sequence-definition-feasibility",
                    ContainerId = ownedId,
                    began,
                    expires,
                    Removed = removed,
                    CleanupFailed = !removed,
                    PersistentData = false
                }));
                // A failed ownership observation must preserve the resource. Disposal is admitted only after exact removal/absence.
                bool disposed = false;
                try { if (removed) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); disposed = true; } }
                finally
                {
                    WriteLedger(run, "disposed", new { run, containerId = ownedId, volume = ownedVolume, removed, disposed, removedAtUtc, cleanupFailure = !removed || !disposed, completedAtUtc = DateTimeOffset.UtcNow });
                }
            }
        }

        async Task RetainProofAbsenceAsync(CancellationToken token)
        {
            if (removed && ownedId is not null && ownedVolume is not null)
            {
                var allContainers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, token);
                var allVolumes = await docker.Volumes.ListAsync(token);
                int[] listeners = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                    .Where(x => IPAddress.IsLoopback(x.Address) || x.Address.Equals(IPAddress.Any) || x.Address.Equals(IPAddress.IPv6Any))
                    .Select(x => x.Port).Distinct().Order().ToArray();
                WriteLedger(run, "proof-absence", new
                {
                    RunId = run,
                    ObservedAtUtc = DateTimeOffset.UtcNow,
                    ContainersObserved = true,
                    VolumesObserved = true,
                    ListenersObserved = true,
                    ContainerIds = allContainers.Select(x => x.ID).ToArray(),
                    ContainerNames = allContainers.SelectMany(x => x.Names).ToArray(),
                    VolumeNames = (allVolumes.Volumes ?? throw new InvalidOperationException("Actual cleanup inventory missing.")).Select(x => x.Name).ToArray(),
                    ListeningPorts = listeners
                });
            }
        }

        async Task RequireNewSoleConsumerVolumeAsync(CancellationToken token)
        {
            string volumeName = ownedVolume ?? throw new InvalidOperationException("Owned volume identity missing.");
            if (previousVolumes.Contains(volumeName)) { throw new InvalidOperationException("Disposable volume predates this run."); }
            var volume = await docker.Volumes.InspectAsync(volumeName, token);
            if (volume.Name != volumeName || volume.Driver != "local" || volume.Scope != "local" ||
                volume.Options is { Count: > 0 } || (volume.Labels is { Count: > 0 } &&
                    (volume.Labels.Count != 1 || !volume.Labels.TryGetValue("com.docker.volume.anonymous", out string? anonymous) || anonymous != string.Empty)) ||
                !DateTimeOffset.TryParse(volume.CreatedAt, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out DateTimeOffset created) ||
                created < began.AddSeconds(-1) || created > expires ||
                (ownedVolumeCreatedAt is not null && ownedVolumeCreatedAt != volume.CreatedAt))
            { throw new InvalidOperationException("Disposable volume creation identity mismatch."); }
            var consumers = await docker.Containers.ListContainersAsync(new ContainersListParameters
            {
                All = true,
                Filters = new Dictionary<string, IDictionary<string, bool>>
                { ["volume"] = new Dictionary<string, bool> { [volumeName] = true } }
            }, token);
            if (consumers.Count != 1 || consumers.Single().ID != ownedId)
            { throw new InvalidOperationException("Disposable volume has an unowned consumer."); }
            ownedVolumeCreatedAt ??= volume.CreatedAt;
        }

        void RequireOwnership(ContainerInspectResponse metadata)
        {
            JsonElement json = JsonSerializer.SerializeToElement(metadata);
            DateTimeOffset created = json.GetProperty("Created").GetDateTimeOffset();
            if (metadata.Config is not { } config || metadata.HostConfig is not { } host || metadata.NetworkSettings is not { } network ||
                metadata.ID.Length != 64 || metadata.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != Image || config.Labels["codex.repair.purpose"] != "current-customer-sequence-definition-feasibility" ||
                config.Labels["codex.repair.operation"] != run.ToString("D") || config.Labels["codex.repair.run"] != run.ToString("D") ||
                host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } || host.Mounts is { Count: > 0 } ||
                metadata.Mounts.Count != 1 || metadata.Mounts.Any(mount => mount.Type != "volume" || mount.Destination != "/var/lib/postgresql" ||
                    mount.Name is not { Length: 64 } || mount.Name.Any(character => !char.IsAsciiHexDigitLower(character)) || !mount.RW) ||
                host.Tmpfs is { Count: > 0 } || host.MemorySwap != 512 * 1024 * 1024 ||
                host.Memory != 512 * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                network.Ports.Values.SelectMany(x => x ?? []).Any(binding => binding.HostIP != "127.0.0.1"))
            { throw new InvalidOperationException("Disposable resource ownership mismatch"); }
        }
    }

    private sealed class ResourceLogCategories : IProgress<string>
    {
        internal bool NoSpace { get; private set; }
        internal bool OutOfMemory { get; private set; }
        internal bool Panic { get; private set; }
        internal bool Recovery { get; private set; }
        internal bool Killed { get; private set; }
        internal int Lines { get; private set; }
        internal int Characters { get; private set; }
        public void Report(string value)
        {
            Characters = checked(Characters + value.Length);
            if (Characters > 256 * 1024) { throw new InvalidDataException("Bounded fixture diagnostic exceeded."); }
            Lines++;
            NoSpace |= value.Contains("No space left on device", StringComparison.OrdinalIgnoreCase);
            OutOfMemory |= value.Contains("out of memory", StringComparison.OrdinalIgnoreCase);
            Panic |= value.Contains("PANIC", StringComparison.Ordinal);
            Recovery |= value.Contains("recovery", StringComparison.OrdinalIgnoreCase);
            Killed |= value.Contains("signal 9", StringComparison.OrdinalIgnoreCase);
        }
    }

    private static string RequireLedgerDirectory()
    {
        string? directory = Environment.GetEnvironmentVariable("MALIEV_CUSTOMER_SEQUENCE_NATIVE_LEDGER");
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
        { throw new InvalidOperationException("Existing owner-only Customer native ledger directory required."); }
        string full = Path.GetFullPath(directory);
        SecureLocalFile.EnsureOwnerOnlyDirectory(full);
        return full;
    }

    private static string AssemblyHash(string path)
    { using var stream = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(stream)); }

    private static void WriteLedger(Guid run, string phase, object record)
    {
        string directory = RequireLedgerDirectory();
        string path = Path.Combine(directory, run.ToString("N") + "-" + phase + ".json");
        using var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        if (!SecureLocalFile.HandleResolvesToApprovedPath(file, path) || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)))
        { throw new InvalidOperationException("Customer native ledger file ownership mismatch."); }
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
        SecureLocalFile.EnsureOwnerOnlyDirectory(directory);
    }

    private static async Task<string> BootstrapAsync(string admin, long last, bool called, CancellationToken token, int idOrdinal = 1)
    {
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync(token);
            Assert.Equal("off", await ScalarAsync<string>(connection, "SHOW autovacuum;", token));
            await ExecuteAsync(connection, "CREATE DATABASE \"Customer\" TEMPLATE template0;", token);
        }
        string connectionString = new NpgsqlConnectionStringBuilder(admin)
        { Database = "Customer", Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString;
        await using (var connection = new NpgsqlConnection(connectionString))
        {
            await connection.OpenAsync(token);
            if (idOrdinal is not (1 or 9)) { throw new InvalidOperationException("Fixed fixture ordinal required"); }
            string preceding = idOrdinal == 9 ? "p1 text,p2 text,p3 text,p4 text,p5 text,p6 text,p7 text,p8 text," : "";
            await ExecuteAsync(connection, $"""
                CREATE ROLE other_owner NOLOGIN;
                CREATE TABLE public."Customer" ({preceding}"ID" integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY, note text);
                CREATE SCHEMA private;
                CREATE TABLE private.journal (id integer PRIMARY KEY, evidence text);
                CREATE SEQUENCE private.other_sequence START WITH 37;
                INSERT INTO public."Customer" ("ID",note) VALUES (7,'synthetic retained'),(9,'ไทย');
                INSERT INTO private.journal VALUES (1,'synthetic retained journal');
                """, token);
            // Fixture construction only. The candidate above contains neither setval nor restart.
            await using var command = new NpgsqlCommand("SELECT setval('public.\"Customer_ID_seq\"',$1,$2);", connection);
            _ = command.Parameters.AddWithValue(called ? last - 1 : last);
            _ = command.Parameters.AddWithValue(called);
            _ = await command.ExecuteScalarAsync(token);
            if (called)
            { Assert.Equal(last, await ScalarAsync<long>(connection, "SELECT nextval('public.\"Customer_ID_seq\"');", token)); }
        }
        return connectionString;
    }

    private static Task<CurrentCustomerSequenceObservation> ObserveAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken token)
    {
        return CurrentCustomerSequenceNativeObservation.CaptureAsync(connection, tx, token);
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken token, NpgsqlTransaction? tx = null)
    {
        await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 };
        _ = await command.ExecuteNonQueryAsync(token);
    }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken token)
    {
        await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 30 };
        return (T)(await command.ExecuteScalarAsync(token) ?? throw new InvalidOperationException("Missing synthetic evidence"));
    }
}
