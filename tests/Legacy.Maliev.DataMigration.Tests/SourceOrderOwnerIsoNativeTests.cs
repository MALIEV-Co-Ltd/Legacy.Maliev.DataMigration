using System.Data;
using System.Net;
using System.Text.Json;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentOwnerIsoNativeProofGroup.Name)]
public sealed class SourceOrderOwnerIsoNativeTests(ITestOutputHelper output)
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    [SourceOrderOwnerIsoNativeTheory]
    [InlineData("Country")]
    [InlineData("Material")]
    public async Task Truthful_order_fixed_sql_literal_bytes_rollback_commit_private_sequence_and_all_storage(string database)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException(); }
        string ledger = SourceOrderOwnerIsoNativeTheoryAttribute.RequireLedger(Environment.GetEnvironmentVariable(SourceOrderOwnerIsoNativeTheoryAttribute.LedgerVariable));
        Guid run = Guid.NewGuid(); string name = "source-order-iso-native-" + run.ToString("N"); DateTimeOffset began = DateTimeOffset.UtcNow;
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(8)); var ct = timeout.Token;
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine").WithName(name).WithCleanUp(false)
            .WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C").WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "source-order-owner-iso-native").WithLabel("codex.repair.operation", run.ToString("D"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 512L * 1024 * 1024; parameters.HostConfig.MemorySwap = 512L * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 750_000_000;
                parameters.HostConfig.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,nosuid,size=384m" };
                foreach (IList<PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                { foreach (var binding in bindings) { binding.HostIP = "127.0.0.1"; } }
            }).Build();
        string? id = null; bool removed = false; Exception? primary = null;
        var cleanupFailures = new List<Exception>();
        Record("attempt", new { run, name, began, ExpiresAtUtc = began.AddMinutes(8), Persistent = false });
        try
        {
            await container.StartAsync(ct); var metadata = await docker.Containers.InspectContainerAsync(name, ct); Require(metadata); id = metadata.ID;
            var limits = metadata.HostConfig ?? throw new InvalidOperationException("source_order_iso_native_limits_missing");
            Record("created", new { id, name, Image, limits.Memory, limits.MemorySwap, limits.NanoCPUs });
            var source = ConsumerColumnBootstrapTestData.WithCorrectedOrder(ConsumerColumnBootstrapTestData.Logical());
            string originalSource = JsonSerializer.Serialize(source);
            var contract = SourceOrderOwnerIsoContract.Create(source, source.SourceCommitSha, false, ApprovedCurrentOwnerIsoOverlayTests.Owners(), ConsumerColumnBootstrapTestData.Now);
            string admin = container.GetConnectionString();
            await using (var connection = new NpgsqlConnection(admin))
            {
                await connection.OpenAsync(ct); await Execute(connection, "CREATE DATABASE " + PostgreSqlShadowTarget.QuoteIdentifier(database) + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", null);
            }
            string endpoint = new NpgsqlConnectionStringBuilder(admin) { Database = database, Pooling = false }.ConnectionString;
            SourceOrderOwnerIsoNativeWitness before, candidate;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(ct); await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
                {
                    await using var target = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                    var plan = contract.PhysicalPlan(database, false);
                    await target.ApplySchemaAsync(plan, ct);
                    await target.FinalizeSchemaAsync(plan, ct);
                    await tx.CommitAsync(ct);
                }
                await Execute(connection, """
                    CREATE SCHEMA legacy_source_order_iso_test;
                    CREATE TABLE legacy_source_order_iso_test.journal(id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,note text NOT NULL);
                    INSERT INTO legacy_source_order_iso_test.journal(note) VALUES ('immutable synthetic ไทย 😀');
                    INSERT INTO public."Country"("Name","ISO2","ISO3","Continent","CountryCode","CreatedDate")
                    VALUES ('synthetic ไทย 😀',NULL,NULL,'ไทย','synthetic',TIMESTAMP '2000-01-01 01:02:03.123456'),
                    ('synthetic 2','A ','B  ','ไทย','synthetic',TIMESTAMP '2000-01-01 01:02:03.123456'),
                    ('synthetic 3','กข','ไทย','ไทย','synthetic',TIMESTAMP '2000-01-01 01:02:03.123456'),
                    ('synthetic 4','😀','😀 ','ไทย','synthetic',TIMESTAMP '2000-01-01 01:02:03.123456');
                    """, null);
                await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
                {
                    await DiagnoseAsync(connection, tx, contract, false, "before");
                    before = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, false, ct);
                    await Execute(connection, PostgreSqlCurrentOwnerIsoRepair.Sql, tx);
                    await DiagnoseAsync(connection, tx, contract, true, "transactional-after");
                    candidate = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, true, ct);
                    Record("candidate", new { Before = before.Sha256, After = candidate.Sha256, before.Physical, BeforeStorage = before.Native.CopyStorage(), AfterStorage = candidate.Native.CopyStorage() });
                    SourceOrderOwnerIsoNativeWitness.RequirePreserved(before, candidate, contract); await tx.RollbackAsync(ct);
                }
                await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
                {
                    await DiagnoseAsync(connection, tx, contract, false, "rolled-back");
                    var rolledBack = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, false, ct);
                    Assert.Equal(before.Sha256, rolledBack.Sha256);
                    await Execute(connection, PostgreSqlCurrentOwnerIsoRepair.Sql, tx);
                    await DiagnoseAsync(connection, tx, contract, true, "commit-candidate");
                    candidate = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(connection, tx, contract, true, ct);
                    SourceOrderOwnerIsoNativeWitness.RequirePreserved(rolledBack, candidate, contract); await tx.CommitAsync(ct);
                }
            }
            await using (var independent = new NpgsqlConnection(endpoint))
            {
                await independent.OpenAsync(ct); await using var tx = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await Execute(independent, "SET TRANSACTION READ ONLY;", tx);
                await DiagnoseAsync(independent, tx, contract, true, "independent-readback");
                var actual = await SourceOrderOwnerIsoNativeWitness.CaptureAsync(independent, tx, contract, true, ct);
                SourceOrderOwnerIsoNativeWitness.RequirePreserved(before, actual, contract); Assert.Equal(candidate.Sha256, actual.Sha256);
                Assert.Equal(originalSource, JsonSerializer.Serialize(source)); await tx.RollbackAsync(ct);
            }
        }
        catch (Exception failure) { primary = failure; }
        finally
        {
            using var cleanupLimit = new CancellationTokenSource(TimeSpan.FromSeconds(30));
            try
            {
                var current = await docker.Containers.InspectContainerAsync(id ?? name, cleanupLimit.Token); Require(current); id = current.ID;
                if (current.State?.Running is true)
                { _ = await docker.Containers.StopContainerAsync(current.ID, new ContainerStopParameters { WaitBeforeKillSeconds = 3 }, cleanupLimit.Token); }
            }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            try
            {
                // Re-observe immediately before removing only this exact owned object; no name/tree selector.
                var current = await docker.Containers.InspectContainerAsync(id ?? name, cleanupLimit.Token); Require(current); id = current.ID;
                await docker.Containers.RemoveContainerAsync(current.ID, new ContainerRemoveParameters { Force = true, RemoveVolumes = false }, cleanupLimit.Token);
            }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            try
            {
                var remaining = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, cleanupLimit.Token);
                if (remaining.Any(x => x.ID == id || x.Names.Contains("/" + name))) { cleanupFailures.Add(new InvalidOperationException("Owned native container remains")); }
                else { removed = true; }
            }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            try { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10), CancellationToken.None); }
            catch (Exception failure) { cleanupFailures.Add(failure); }
            try { Record("cleanup", new { id, name, removed, FailureTypes = cleanupFailures.Select(x => x.GetType().FullName).ToArray() }); }
            catch (Exception retention) { cleanupFailures.Add(retention); }
        }
        if (cleanupFailures.Count != 0)
        {
            if (primary is not null) { cleanupFailures.Insert(0, primary); }
            throw new AggregateException("ISO native execution or exact owned cleanup failed.", cleanupFailures);
        }
        if (primary is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primary).Throw(); }
        async Task DiagnoseAsync(NpgsqlConnection connection, NpgsqlTransaction tx, SourceOrderOwnerIsoContract contract, bool selected, string phase)
        {
            var plan = contract.PhysicalPlan(database, selected); var tables = contract.PhysicalTables(database, selected);
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
            var (SchemaSha256, Components, Columns) = await inspector.InspectSchemaWithComponentsAsync(plan, ct);
            await using var metadata = new NpgsqlCommand("""
                SELECT jsonb_build_object(
                  'columns',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'column',a.attname,'ordinal',a.attnum,
                    'type',format_type(a.atttypid,a.atttypmod),'notNull',a.attnotnull,'identity',a.attidentity,'generated',a.attgenerated,
                    'collation',CASE WHEN a.attcollation=0 THEN NULL ELSE cn.nspname||'.'||co.collname END,
                    'default',pg_get_expr(d.adbin,d.adrelid)) ORDER BY c.relname,a.attnum),'[]')
                    FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid
                    LEFT JOIN pg_attrdef d ON d.adrelid=a.attrelid AND d.adnum=a.attnum
                    LEFT JOIN pg_collation co ON co.oid=a.attcollation LEFT JOIN pg_namespace cn ON cn.oid=co.collnamespace
                    WHERE n.nspname='public' AND c.relkind='r' AND a.attnum>0 AND NOT a.attisdropped),
                  'constraints',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'name',k.conname,'type',k.contype,
                    'definition',pg_get_constraintdef(k.oid)) ORDER BY c.relname,k.conname),'[]')
                    FROM pg_constraint k JOIN pg_class c ON c.oid=k.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
                  'indexes',(SELECT coalesce(jsonb_agg(jsonb_build_object('table',c.relname,'name',i.relname,'definition',pg_get_indexdef(i.oid),
                    'valid',x.indisvalid,'ready',x.indisready) ORDER BY c.relname,i.relname),'[]')
                    FROM pg_index x JOIN pg_class c ON c.oid=x.indrelid JOIN pg_class i ON i.oid=x.indexrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'),
                  'sequences',(SELECT coalesce(jsonb_agg(jsonb_build_object('name',c.relname,'type',format_type(s.seqtypid,NULL),
                    'start',s.seqstart,'increment',s.seqincrement,'minimum',s.seqmin,'maximum',s.seqmax,'cache',s.seqcache,'cycle',s.seqcycle)
                    ORDER BY c.relname),'[]') FROM pg_sequence s JOIN pg_class c ON c.oid=s.seqrelid
                    JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public'))::text;
                """, connection, tx) { CommandTimeout = 30 };
            string raw = (string)(await metadata.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("Native structural diagnostics missing"));
            using var parsed = JsonDocument.Parse(raw);
            Record("components-" + phase, new
            {
                Kind = "source-order-iso-native-structural-diagnostic-v1",
                Database = database,
                Phase = phase,
                Selected = selected,
                ExpectedSchemaSha256 = plan.TargetSchemaSha256,
                ActualSchemaSha256 = SchemaSha256,
                ExpectedComponents = tables.Select(PostgreSqlSchemaFingerprint.ComputeExpectedComponents).ToArray(),
                ActualComponents = Components,
                ActualColumnDiagnostics = Columns,
                ExpectedTables = tables.Select(table => new
                {
                    table.TargetSchema,
                    table.TargetTable,
                    table.OrderedColumns,
                    table.ColumnTypes,
                    table.NullableColumns,
                    table.DefaultExpressions,
                    table.GeneratedColumns,
                    table.Collations,
                    table.PrimaryKey,
                    table.UniqueConstraints,
                    table.CheckConstraints,
                    table.Indexes,
                    table.ForeignKeys,
                    Identities = table.Identities.Select(identity => new { identity.Column, identity.SeedValue, identity.IncrementValue }),
                }).ToArray(),
                ActualCatalogMetadata = parsed.RootElement.Clone(),
            });
        }
        async Task Execute(NpgsqlConnection connection, string sql, NpgsqlTransaction? tx)
        { await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 }; _ = await command.ExecuteNonQueryAsync(ct); }
        void Record(string phase, object value)
        {
            using var file = new FileStream(Path.Combine(ledger, run.ToString("N") + "-" + phase + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
            JsonSerializer.Serialize(file, value); file.Flush(true); output.WriteLine("SOURCE_ORDER_ISO_NATIVE=" + run.ToString("N") + ":" + phase);
        }
        void Require(ContainerInspectResponse value)
        {
            DateTimeOffset created = JsonSerializer.SerializeToElement(value).GetProperty("Created").GetDateTimeOffset();
            if (value.Config is not { } config || config.Labels is not { } labels || value.HostConfig is not { } host || host.Tmpfs is not { } tmpfs ||
                value.State is null || created < began.AddSeconds(-1) || created > began.AddMinutes(8) ||
                value.ID is not { Length: 64 } || value.Name != "/" + name || (id is not null && value.ID != id) || config.Image != Image ||
                !labels.TryGetValue("codex.repair.operation", out string? op) || op != run.ToString("D") ||
                !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "source-order-owner-iso-native" ||
                host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750_000_000 ||
                value.Mounts is not { Count: 0 } || tmpfs.Count != 1 || !tmpfs.TryGetValue("/var/lib/postgresql", out string? mount) || mount != "rw,nosuid,size=384m" ||
                host.PortBindings is not { Count: > 0 } ports || ports.Values.SelectMany(x => x ?? []).Any(x => x.HostIP != "127.0.0.1"))
            { throw new InvalidOperationException("Owned native fixture custody mismatch"); }
        }
    }
}
