using System.Data;
using System.Security.Cryptography;
using System.Text.Json;
using Xunit.Abstractions;
using Npgsql;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[CollectionDefinition(Name, DisableParallelization = true)]
public sealed class Production181CustomerNativeGroup
{
    public const string Name = "Production181 Customer sequential native23";
}

/// <summary>Disposable physical feasibility only; never a production repair or signed acceptance.</summary>
[Collection(Production181CustomerNativeGroup.Name)]
public sealed class Production181CustomerDefinitionNativeTests(ITestOutputHelper output)
{
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
                testAssemblySha256 = AssemblyHash(typeof(Production181CustomerDefinitionNativeTests).Assembly.Location)
            });
            string connectionString = await BootstrapAsync(admin, last, called, token, idOrdinal);
            await Production181OwnedHarness.RetainEngineAsync(run, connectionString, token);
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
                testAssemblySha256 = AssemblyHash(typeof(Production181CustomerDefinitionNativeTests).Assembly.Location)
            });
            string connectionString = await BootstrapAsync(admin, 69831, true, token);
            await Production181OwnedHarness.RetainEngineAsync(run, connectionString, token);
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


    private Task RunOwnedAsync(Func<Guid, string, string, CancellationToken, Task> body)
    {
        return Production181OwnedHarness.RunAsync(body, output, RequireLedgerDirectory(), typeof(Production181CustomerDefinitionNativeTests).Assembly.Location);
    }

    private static string RequireLedgerDirectory()
    {
        string? directory = Environment.GetEnvironmentVariable("MALIEV_PRODUCTION181_NATIVE_LEDGER");
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
                CREATE COLLATION public.legacy_ci_as (provider=icu,locale='und-u-ks-level2',deterministic=false);
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
