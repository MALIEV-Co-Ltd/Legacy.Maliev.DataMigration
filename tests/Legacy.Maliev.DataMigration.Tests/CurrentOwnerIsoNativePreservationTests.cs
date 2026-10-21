using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Docker.DotNet;
using Docker.DotNet.Models;
using Npgsql;
using Testcontainers.PostgreSql;
using Xunit.Abstractions;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Source-only fixtures; no persistent target or execution authority.</summary>
[Collection(CurrentOwnerIsoNativeProofGroup.Name)]
public sealed partial class CurrentOwnerIsoNativePreservationTests(ITestOutputHelper output)
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";

    [WindowsLocalRunTheory]
    [InlineData("Country")]
    [InlineData("Material")]
    public Task Literal_bytes_complete_rows_catalogs_sequences_rollback_commit_and_independent_readback(string database)
    {
        return RunOwnedAsync("literal-" + database, null, async (admin, ct) =>
        {
            ApprovedCurrentOwnerIsoOverlay overlay = ApprovedCurrentOwnerIsoOverlayTests.Create(
                ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
            string endpoint = await BootstrapAsync(admin, database, overlay, ct);
            CurrentOwnerIsoNativeObservation before;
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                before = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct);
                RecordSelectedStorage(database, "before", before);
                JsonObject pkClass = before.Read("pg_class").Single(x => x["relname"]?.ToString() == "PK_Country");
                JsonObject primary = before.Read("pg_index").Single(x => x["indexrelid"]?.ToString() == pkClass["oid"]?.ToString());
                JsonObject heapClass = before.Read("pg_class").Single(x => x["oid"]?.ToString() == primary["indrelid"]?.ToString());
                string toastId = heapClass["reltoastrelid"]!.ToString();
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    database,
                    heapClass,
                    indexClasses = new[] { pkClass },
                    indexes = before.Read("pg_index").Where(x => x["indexrelid"]?.ToString() == pkClass["oid"]?.ToString() || x["indrelid"]?.ToString() == toastId),
                    toastClass = before.Read("pg_class").SingleOrDefault(x => x["oid"]?.ToString() == toastId)
                }));
                CurrentOwnerIsoNativePreservation.RequireBefore(before, overlay);
                Assert.Equal(8, before.LiteralRows.Rows);
                Assert.True(before.LiteralRows.ExactWidths);
                await OverlayCandidateAsync(connection, tx, overlay, ct);
                CurrentOwnerIsoNativeObservation after = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, true, ct);
                RecordSelectedStorage(database, "transactional-after", after);
                output.WriteLine(JsonSerializer.Serialize(new { database, phase = "transactional-after-class", heapClass = after.Read("pg_class").Single(x => x["oid"]?.ToString() == primary["indrelid"]?.ToString()), indexClass = after.Read("pg_class").Single(x => x["oid"]?.ToString() == pkClass["oid"]?.ToString()) }));
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, after, overlay);
                MaliciousNegatives(before, after, overlay);
                await tx.RollbackAsync(ct);
            }
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                CurrentOwnerIsoNativeObservation restored = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct);
                RecordSelectedStorage(database, "rolled-back", restored);
                Assert.Equal(before.Snapshot.Sha256, restored.Snapshot.Sha256);
                Assert.Equal(before.LiteralRows, restored.LiteralRows);
                CurrentOwnerIsoNativePreservation.RequireBefore(restored, overlay);
                await OverlayCandidateAsync(connection, tx, overlay, ct);
                CurrentOwnerIsoNativeObservation commitCandidate = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, true, ct);
                RecordSelectedStorage(database, "commit-candidate", commitCandidate);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, commitCandidate, overlay);
                await tx.CommitAsync(ct);
            }
            await using (var connection = new NpgsqlConnection(endpoint))
            {
                await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", ct, tx);
                CurrentOwnerIsoNativeObservation readback = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, true, ct);
                RecordSelectedStorage(database, "independent-readback", readback);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, readback, overlay);
                _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireBefore(readback, overlay));
                await tx.RollbackAsync(ct);
            }
        });
    }

    [WindowsLocalRunTheory]
    [InlineData("Country")]
    [InlineData("Material")]
    public Task Fixed_iso_operand_owner_binds_native_roles_indexes_identity_and_mixed_private_state(string database)
    {
        return RunOwnedAsync("operand-owner-" + database, null, async (admin, ct) =>
        {
            // Disposable native component only; this synthetic production-kind policy issues no execution authority.
            ApprovedCurrentOwnerIsoOverlay overlay = ApprovedCurrentOwnerIsoOverlayTests.Create(
                ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
            string endpoint = await BootstrapAsync(admin, database, overlay, ct);
            CurrentRepairOperandOwnerPurpose purpose = database == "Country"
                ? CurrentRepairOperandOwnerPurpose.CountryIsoLiteral : CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral;
            await using var connection = new NpgsqlConnection(endpoint);
            await connection.OpenAsync(ct);
            string owner = database == "Country" ? "legacy_country_owner" : "legacy_material_owner";
            await ExecuteAsync(connection, "CREATE ROLE " + Quote(owner) + " LOGIN NOSUPERUSER INHERIT NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 4; ALTER TABLE public.\"Country\" OWNER TO " + Quote(owner) + ";", ct);
            string system;
            await using (var command = new NpgsqlCommand("SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", connection))
            { system = (string)(await command.ExecuteScalarAsync(ct) ?? throw new InvalidOperationException("missing native system")); }
            var target = new DeltaTargetAuthority(DeltaTargetAuthorityKind.ProductionCloudNativePg, "synthetic-iso-owner-component-only", system);
            CurrentOwnerIsoNativeObservation before;
            string closure;
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                before = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct);
                CurrentOwnerIsoNativePreservation.RequireBefore(before, overlay);
                string operandOwner = before.Read("pg_class").Single(x => x["relname"]?.ToString() == "Country" && x["relkind"]?.ToString() == "r")["relowner"]!.ToString();
                string privateOwner = before.Read("pg_class").Single(x => x["relname"]?.ToString() == "journal" && x["relkind"]?.ToString() == "r")["relowner"]!.ToString();
                Assert.NotEqual(operandOwner, privateOwner);
                closure = await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target, before.Snapshot, ct);
                var missingRole = before.Snapshot with { Catalog = before.Snapshot.Catalog.Where(x => x.Catalog != "pg_authid").ToArray() };
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target, missingRole, ct));
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target with { SystemIdentifierSha256 = new string('0', 64) }, before.Snapshot, ct));
                await OverlayCandidateAsync(connection, tx, overlay, ct);
                CurrentOwnerIsoNativeObservation candidate = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, true, ct);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, candidate, overlay);
                Assert.Equal(closure, await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target, candidate.Snapshot, ct));
                await tx.RollbackAsync(ct);
            }
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct))
            {
                var restored = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct);
                Assert.Equal(before.Snapshot.Sha256, restored.Snapshot.Sha256);
                await tx.RollbackAsync(ct);
            }
            foreach (string fault in new[]
            {
                "ALTER ROLE " + Quote(owner) + " SUPERUSER;",
                "ALTER ROLE " + Quote(owner) + " CONNECTION LIMIT 5;",
                "ALTER ROLE " + Quote(owner) + " RENAME TO changed_iso_owner;",
                "ALTER TABLE public.\"Country\" OWNER TO postgres;",
                "ALTER SEQUENCE public.\"Country_ID_seq\" RENAME TO changed_identity_sequence;",
            })
            {
                await using var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct);
                await ExecuteAsync(connection, fault, ct, tx);
                CurrentAppOwnedDatabaseSnapshot changed = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct);
                _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target, changed, ct));
                await tx.RollbackAsync(ct);
            }
            await using (var tx = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct))
            {
                await OverlayCandidateAsync(connection, tx, overlay, ct);
                var candidate = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, true, ct);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, candidate, overlay);
                Assert.Equal(closure, await CurrentRepairOperandOwnerProfile.RequireNativeAsync(connection, tx, purpose, target, candidate.Snapshot, ct));
                await tx.CommitAsync(ct);
            }
            await using var independent = new NpgsqlConnection(endpoint);
            await independent.OpenAsync(ct);
            await using var readback = await independent.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ExecuteAsync(independent, "SET TRANSACTION READ ONLY;", ct, readback);
            var final = await CurrentOwnerIsoNativePreservation.CaptureAsync(independent, readback, overlay, true, ct);
            CurrentOwnerIsoNativePreservation.RequirePreserved(before, final, overlay);
            Assert.Equal(closure, await CurrentRepairOperandOwnerProfile.RequireNativeAsync(independent, readback, purpose, target, final.Snapshot, ct));
            await readback.RollbackAsync(ct);
        });
    }

    private void RecordSelectedStorage(string database, string phase, CurrentOwnerIsoNativeObservation observation)
    {
        IsoDefinitionRecorder.Native(phase, observation);
        var storage = observation.CopyStorage();
        var indexes = observation.Read("pg_index").Select(x => x["indexrelid"]!.ToString()).ToHashSet(StringComparer.Ordinal);
        var primary = observation.Read("pg_index").Where(x => x["indisprimary"]!.ToString() == "true")
            .Select(x => x["indexrelid"]!.ToString()).ToHashSet(StringComparer.Ordinal);
        var frames = observation.Read("pg_class").Where(x => storage.ContainsKey(x["oid"]!.ToString()))
            .Select(x => CurrentOwnerIsoNativePreservation.DescribeStorage(x, storage[x["oid"]!.ToString()],
                primary.Contains(x["oid"]!.ToString()) ? observation.LiteralRows.Rows :
                indexes.Contains(x["oid"]!.ToString()) ? 0 : storage[x["oid"]!.ToString()].Rows,
                observation.Selected, indexes.Contains(x["oid"]!.ToString()))).ToArray();
        output.WriteLine(JsonSerializer.Serialize(new { database, phase, selectedStorage = frames }));
    }

    [WindowsLocalRunTheory]
    [InlineData("CREATE INDEX unknown_iso ON public.\"Country\"(\"ISO2\");")]
    [InlineData("CREATE INDEX unknown_expression ON public.\"Country\"(lower(\"ISO2\"::text));")]
    [InlineData("ALTER TABLE public.\"Country\" ADD CONSTRAINT unknown_check CHECK(octet_length(bpcharsend(\"ISO3\"))>0);")]
    [InlineData("CREATE VIEW public.unknown_view AS SELECT \"ISO2\" FROM public.\"Country\";")]
    [InlineData("CREATE STATISTICS unknown_stats ON \"ISO2\",\"ISO3\" FROM public.\"Country\";")]
    [InlineData("ANALYZE public.\"Country\";")]
    [InlineData("ALTER TABLE public.\"Country\" ALTER COLUMN \"ISO2\" TYPE varchar(2);")]
    public Task Unsupported_native_preimage_is_rejected_without_candidate(string fault)
    {
        return RunOwnedAsync(IsoDefinitionCases.Fault(fault, false), fault, async (admin, ct) =>
    {
        ApprovedCurrentOwnerIsoOverlay overlay = ApprovedCurrentOwnerIsoOverlayTests.Create(
            ApprovedCurrentOwnerIsoOverlayTests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2));
        string endpoint = await BootstrapAsync(admin, "Country", overlay, ct);
        await using var connection = new NpgsqlConnection(endpoint);
        await connection.OpenAsync(ct);
        await ExecuteAsync(connection, fault, ct);
        IsoDefinitionRecorder.Raw("before-rejection", await CaptureDefinitionRawAsync(connection, ct));
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        var rejection = await Assert.ThrowsAsync<MigrationExecutionException>(async () =>
        {
            CurrentOwnerIsoNativeObservation current = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct);
            CurrentOwnerIsoNativePreservation.RequireBefore(current, overlay);
        });
        IsoDefinitionRecorder.Rejected("native-preimage", rejection.Code);
        await tx.RollbackAsync(ct);
        IsoDefinitionRecorder.Raw("after-rejection", await CaptureDefinitionRawAsync(connection, ct));
    });
    }

    private static async Task<CurrentAppOwnedDatabaseSnapshot> CaptureDefinitionRawAsync(NpgsqlConnection connection, CancellationToken ct)
    {
        await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", ct, transaction);
        var actual = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct);
        await transaction.RollbackAsync(ct);
        return actual;
    }

    [Fact]
    public void Physical_storage_does_not_accept_invented_file_sizes_counts_or_visibility()
    {
        using IsoDefinitionRecorder? recorder = Environment.GetEnvironmentVariable("MALIEV_ISO_DEFINITION_LEDGER") is null
            ? null : new IsoDefinitionRecorder("pure-storage", null, null);
        var row = new JsonObject { ["relfilenode"] = 42, ["relpages"] = 1, ["reltuples"] = 8, ["relallvisible"] = 0, ["relallfrozen"] = 0 };
        CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 1, 8), 8, true, false);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(43, 1, 8), 8, true, false));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 2, 0), 8, true, true));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 1, 8), 7, true, false));
        row["relallvisible"] = 1;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequireStorage(row, new(42, 1, 8), 8, true, false));
        if (recorder is not null)
        {
            recorder.CompleteInvocation();
            output.WriteLine("ISO_DEFINITION_CASE=pure-storage");
        }
    }

    private static void MaliciousNegatives(CurrentOwnerIsoNativeObservation before, CurrentOwnerIsoNativeObservation after, ApprovedCurrentOwnerIsoOverlay overlay)
    {
        string ns = before.Read("pg_namespace").Single(x => x["nspname"]!.ToString() == "public")["oid"]!.ToString();
        string heap = before.Read("pg_class").Single(x => x["relnamespace"]!.ToString() == ns && x["relname"]!.ToString() == "Country")["oid"]!.ToString();
        string index = before.Read("pg_class").Single(x => x["relnamespace"]!.ToString() == ns && x["relname"]!.ToString() == "PK_Country")["oid"]!.ToString();
        foreach (string field in new[] { "relpages", "reltuples" })
        {
            // Both values are individually within the captured bounds but differ from the genuine preimage.
            CurrentOwnerIsoNativeObservation changed = Mutate(after, "pg_class", x => x["oid"]!.ToString() == heap,
                x => x[field] = field == "relpages" ? JsonValue.Create(1) : JsonValue.Create(0));
            var rejection = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, changed, overlay));
            Assert.Equal("current_owner_iso_native_heap_statistics", rejection.Code);
        }
        foreach (string field in new[] { "indclass", "indoption", "indkey", "indnullsnotdistinct" })
        {
            CurrentOwnerIsoNativeObservation changed = Mutate(after, "pg_index", x => x["indexrelid"]!.ToString() == index,
                x => x[field] = field == "indnullsnotdistinct" ? JsonValue.Create(true) : JsonValue.Create("0"));
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, changed, overlay));
        }
        CurrentOwnerIsoNativeObservation wrongType = Mutate(after, "pg_attribute", x => x["attrelid"]!.ToString() == heap && x["attname"]!.ToString() == "ISO3", x => x["atttypid"] = 25);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, wrongType, overlay));
        CurrentOwnerIsoNativeObservation outside = Mutate(after, "pg_namespace", x => x["nspname"]!.ToString() == "legacy_migration_internal", x => x["nspowner"] = 1);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, outside, overlay));
        CurrentOwnerIsoNativeObservation futureFreeze = Mutate(after, "pg_class", x => x["oid"]!.ToString() == heap,
            x => x["relfrozenxid"] = unchecked(after.SnapshotXmin + 1).ToString(System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("current_owner_iso_native_heap_freeze_boundary", Assert.Throws<MigrationExecutionException>(() =>
            CurrentOwnerIsoNativePreservation.RequirePreserved(before, futureFreeze, overlay)).Code);
        CurrentOwnerIsoNativeObservation changedMultiXact = Mutate(after, "pg_class", x => x["oid"]!.ToString() == heap,
            x => x["relminmxid"] = "2");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, changedMultiXact, overlay));
        CurrentOwnerIsoNativeObservation unrelatedFreeze = Mutate(after, "pg_class", x => x["relname"]!.ToString() == "journal",
            x => x["relfrozenxid"] = "3");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, unrelatedFreeze, overlay));
        CurrentOwnerIsoNativeObservation dependency = Mutate(after, "pg_depend", x => x["classid"]!.ToString() == "1259" && x["objid"]!.ToString() == heap && x["refclassid"]!.ToString() == "3456", x => x["deptype"] = "a");
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, dependency, overlay));
        foreach (string name in new[] { "Country", "journal" })
        {
            CurrentAppOwnedDatabaseSnapshot snapshot = after.Snapshot with { Relations = [.. after.Snapshot.Relations.Select(x => x.Name == name ? x with { RowSha256 = new string('0', 64), Rows = x.Rows + 1 } : x)] };
            var changed = new CurrentOwnerIsoNativeObservation(snapshot, after.OverlaySha256, true, after.LiteralRows, after.CopyCatalog(), after.CopyStorage(), after.SnapshotXmin);
            _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, changed, overlay));
        }
        var literal = new CurrentOwnerIsoNativeObservation(after.Snapshot, after.OverlaySha256, true, after.LiteralRows with { Sha256 = new string('0', 64) }, after.CopyCatalog(), after.CopyStorage(), after.SnapshotXmin);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, literal, overlay));
        CurrentAppOwnedDatabaseSnapshot sequence = after.Snapshot with { Sequences = [.. after.Snapshot.Sequences.Select(x => x with { TupleSha256 = new string('0', 64) })] };
        var sequenceChange = new CurrentOwnerIsoNativeObservation(sequence, after.OverlaySha256, true, after.LiteralRows, after.CopyCatalog(), after.CopyStorage(), after.SnapshotXmin);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentOwnerIsoNativePreservation.RequirePreserved(before, sequenceChange, overlay));
    }

    private static CurrentOwnerIsoNativeObservation Mutate(CurrentOwnerIsoNativeObservation original, string catalog, Func<JsonObject, bool> predicate, Action<JsonObject> mutation)
    {
        Dictionary<string, string[]> raw = original.CopyCatalog();
        int position = Array.FindIndex(raw[catalog], text => predicate(JsonNode.Parse(text)!.AsObject()));
        Assert.True(position >= 0);
        string oldHash = Hash(raw[catalog][position]); JsonObject tuple = JsonNode.Parse(raw[catalog][position])!.AsObject(); mutation(tuple);
        raw[catalog][position] = tuple.ToJsonString(); string newHash = Hash(raw[catalog][position]);
        CurrentAppOwnedDatabaseSnapshot snapshot = original.Snapshot with
        {
            Catalog = [.. original.Snapshot.Catalog.Select(x => x.Catalog == catalog && x.Sha256 == oldHash
            ? x with { Sha256 = newHash, Key = x.Key.Contains('/') ? newHash + "/1" : x.Key } : x)]
        };
        return new(snapshot, original.OverlaySha256, original.Selected, original.LiteralRows, raw, original.CopyStorage(), original.SnapshotXmin);
    }

    private static async Task<string> BootstrapAsync(string admin, string database, ApprovedCurrentOwnerIsoOverlay overlay, CancellationToken ct)
    {
        if (database is not ("Country" or "Material")) { throw new InvalidOperationException("Fixture database scope"); }
        await using (var connection = new NpgsqlConnection(admin))
        {
            await connection.OpenAsync(ct);
            await ExecuteAsync(connection, "CREATE DATABASE " + Quote(database) + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", ct);
        }
        string endpoint = new NpgsqlConnectionStringBuilder(admin) { Database = database, Pooling = false, Timeout = 5, CommandTimeout = 30 }.ConnectionString;
        await using var auth = new NpgsqlConnection(endpoint); await auth.OpenAsync(ct);
        await using (var command = new NpgsqlCommand("SHOW autovacuum;", auth)) { Assert.Equal("off", await command.ExecuteScalarAsync(ct)); }
        await using (var tx = await auth.BeginTransactionAsync(IsolationLevel.Serializable, ct))
        {
            await using var target = new PostgreSqlWholeDatabaseTransaction(auth, tx, ownsResources: false);
            TableCopyPlan[] tables = overlay.PhysicalTables(database, false);
            await target.ApplySchemaAsync(new(database, "1.0", new string('0', 64), new string('0', 64), tables), ct);
            await tx.CommitAsync(ct);
        }
        await using (var ordinal = new NpgsqlCommand("SELECT attnum::integer FROM pg_attribute WHERE attrelid='public.\"Country\"'::regclass AND attname='ID' AND NOT attisdropped;", auth))
        {
            Assert.Equal(database == "Country" ? 4 : 1, await ordinal.ExecuteScalarAsync(ct));
        }
        await ExecuteAsync(auth, "CREATE SCHEMA legacy_migration_internal; CREATE TABLE legacy_migration_internal.journal(id integer PRIMARY KEY,note text NOT NULL); INSERT INTO legacy_migration_internal.journal VALUES (1,'synthetic retained'); CREATE SEQUENCE legacy_migration_internal.allocation START WITH 77;", ct);
        (string? Two, string? Three)[] literals = [(null, null), ("", ""), (" ", "  "), ("A", "B"), ("A ", "B  "), ("กข", "ไทย"), ("'\\", "\t'\\"), ("é", "é")];
        foreach (var (two, three) in literals)
        {
            await using var command = new NpgsqlCommand("INSERT INTO public.\"Country\"(\"Name\",\"ISO2\",\"ISO3\",\"Continent\",\"CountryCode\",\"CreatedDate\",\"ModifiedDate\") VALUES($1,$2,$3,'ไทย','synthetic',timestamp '2000-01-01 01:02:03.123456',NULL);", auth);
            _ = command.Parameters.AddWithValue(database + " synthetic");
            _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Text, (object?)two ?? DBNull.Value);
            _ = command.Parameters.AddWithValue(NpgsqlTypes.NpgsqlDbType.Text, (object?)three ?? DBNull.Value);
            _ = await command.ExecuteNonQueryAsync(ct);
        }
        return endpoint;
    }

    private static async Task OverlayCandidateAsync(NpgsqlConnection connection, NpgsqlTransaction tx, ApprovedCurrentOwnerIsoOverlay overlay, CancellationToken ct)
    {
        CurrentOwnerIsoNativePreservation.RequireBefore(await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, overlay, false, ct), overlay);
        await ExecuteAsync(connection, "SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='30s'; LOCK TABLE public.\"Country\" IN ACCESS EXCLUSIVE MODE;", ct, tx);
        string changes = string.Join(',', ApprovedCurrentOwnerIsoOverlay.Operands().Where(x => x.Database == connection.Database).Select(x =>
            "ALTER COLUMN " + Quote(x.Column) + " TYPE " + x.AfterType + " COLLATE public.legacy_ci_as USING rpad(" + Quote(x.Column) + "::text," + x.CharacterWidth + ",' ')"));
        await ExecuteAsync(connection, "ALTER TABLE public.\"Country\" " + changes + ";", ct, tx);
    }

    private async Task RunOwnedAsync(string caseId, string? fault, Func<string, CancellationToken, Task> body)
    {
        if (!OperatingSystem.IsWindows()) { throw new PlatformNotSupportedException("Windows owned native proof required."); }
        Guid run = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow, expires = began.AddMinutes(8);
        string name = "iso-native-proof-" + run.ToString("N");
        using var recorder = new IsoDefinitionRecorder(caseId, run, fault);
        WriteLedger(run, "attempt", new { run, name, purpose = "current-owner-iso-native-proof", began, expires, persistent = false });
        IsoDefinitionRecorder.Resource("attempt", new { run, name, purpose = "current-owner-iso-native-proof", began, expires, persistent = false });
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(8));
        using DockerClient docker = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        PostgreSqlContainer container = new PostgreSqlBuilder(Image).WithDockerEndpoint("npipe://./pipe/docker_engine")
            .WithName(name).WithCleanUp(false).WithEnvironment("POSTGRES_INITDB_ARGS", "--encoding=UTF8 --locale=C")
            .WithCommand("-c", "autovacuum=off")
            .WithLabel("codex.repair.purpose", "current-owner-iso-native-proof").WithLabel("codex.repair.operation", run.ToString("D"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 512 * 1024 * 1024; parameters.HostConfig.MemorySwap = 512 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 750000000;
                parameters.HostConfig.Tmpfs = new Dictionary<string, string> { ["/var/lib/postgresql"] = "rw,nosuid,size=384m" };
                foreach (IList<PortBinding> bindings in parameters.HostConfig.PortBindings!.Values)
                { foreach (PortBinding binding in bindings) { binding.HostIP = "127.0.0.1"; } }
            }).Build();
        string? ownedId = null; bool removed = false; DateTimeOffset? removedAtUtc = null;
        try
        {
            await container.StartAsync(lifetime.Token);
            ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(name, lifetime.Token);
            RequireOwnership(metadata); ownedId = metadata.ID;
            var observedConfig = metadata.Config ?? throw IsoDefinitionCases.Invalid();
            var observedHost = metadata.HostConfig ?? throw IsoDefinitionCases.Invalid();
            var observedState = metadata.State ?? throw IsoDefinitionCases.Invalid();
            var observedPorts = metadata.NetworkSettings?.Ports ?? throw IsoDefinitionCases.Invalid();
            IsoDefinitionRecorder.Resource("container", new
            {
                Id = metadata.ID,
                metadata.Name,
                Created = JsonSerializer.SerializeToElement(metadata).GetProperty("Created"),
                Config = new
                {
                    observedConfig.Image,
                    observedConfig.Labels,
                    PgData = (observedConfig.Env ?? throw IsoDefinitionCases.Invalid()).Single(x => x.StartsWith("PGDATA=", StringComparison.Ordinal))[7..]
                },
                State = new { observedState.Running, StartedAt = JsonSerializer.SerializeToElement(observedState).GetProperty("StartedAt") },
                HostConfig = new
                {
                    observedHost.Memory,
                    observedHost.MemorySwap,
                    NanoCpus = observedHost.NanoCPUs,
                    observedHost.Tmpfs,
                    observedHost.Binds,
                    observedHost.VolumesFrom,
                    observedHost.Mounts
                },
                Mounts = (metadata.Mounts ?? throw IsoDefinitionCases.Invalid()).Select(x => new { x.Type, x.Name, x.Destination, x.RW }).ToArray(),
                NetworkSettings = new
                {
                    Ports = observedPorts.ToDictionary(x => x.Key,
                    x => (x.Value ?? []).Select(p => new { HostIp = p.HostIP, p.HostPort }).ToArray(), StringComparer.Ordinal)
                },
            });
            using (var capacityDeadline = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token))
            {
                capacityDeadline.CancelAfter(TimeSpan.FromSeconds(5));
                var capacity = await container.ExecAsync(["df", "-B1", "/var/lib/postgresql"], capacityDeadline.Token);
                string[] lines = capacity.Stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                string[] cells = lines.Length == 2 ? lines[1].Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries) : [];
                if (capacity.ExitCode != 0 || !string.IsNullOrWhiteSpace(capacity.Stderr) || cells.Length != 6 || cells[0] != "tmpfs" ||
                    !long.TryParse(cells[1], System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out long capacityBytes) ||
                    capacityBytes != 384L * 1024 * 1024)
                { throw new InvalidOperationException("Owned tmpfs capacity mismatch"); }
                WriteLedger(run, "filesystem-capacity", new { run, containerId = ownedId, capacityBytes });
                IsoDefinitionRecorder.Resource("capacity", new { run, containerId = ownedId, capacityBytes });
            }
            WriteLedger(run, "observed", new { run, name, purpose = "current-owner-iso-native-proof", containerId = ownedId, began, expires, persistent = false });
            output.WriteLine(JsonSerializer.Serialize(new
            {
                run,
                Purpose = "current-owner-iso-native-proof",
                ContainerId = ownedId,
                began,
                expires,
                Owned = true,
                Removed = false,
                PersistentData = false
            }));
            await body(container.GetConnectionString(), lifetime.Token);
            recorder.CompleteInvocation();
            output.WriteLine("ISO_DEFINITION_CASE=" + caseId);
        }
        finally
        {
            await CompleteCleanupAsync();
        }

        async Task CompleteCleanupAsync()
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try
            {
                ContainerInspectResponse metadata = await docker.Containers.InspectContainerAsync(ownedId ?? name, cleanup.Token);
                RequireOwnership(metadata); ownedId ??= metadata.ID;
                if (metadata.ID != ownedId) { throw new InvalidOperationException("Disposable ownership changed"); }
                _ = await docker.Containers.StopContainerAsync(ownedId, new ContainerStopParameters { WaitBeforeKillSeconds = 5 }, cleanup.Token);
                metadata = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token);
                RequireOwnership(metadata, active: false);
                if ((metadata.State ?? throw new InvalidOperationException("Owned disposable state missing")).Running) { throw new InvalidOperationException("Owned disposable did not stop"); }
                await docker.Containers.RemoveContainerAsync(ownedId, new ContainerRemoveParameters { Force = false, RemoveVolumes = false }, cleanup.Token);
                try { _ = await docker.Containers.InspectContainerAsync(ownedId, cleanup.Token); }
                catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound) { removed = true; removedAtUtc = DateTimeOffset.UtcNow; }
                if (!removed) { throw new InvalidOperationException("Owned disposable removal not verified"); }
            }
            catch (DockerApiException failure) when (failure.StatusCode == HttpStatusCode.NotFound && ownedId is null) { removed = true; }
            finally
            {
                await FinishDisposalAsync();
                output.WriteLine(JsonSerializer.Serialize(new
                {
                    run,
                    Purpose = "current-owner-iso-native-proof",
                    ContainerId = ownedId,
                    began,
                    expires,
                    Removed = removed,
                    CleanupFailed = !removed,
                    PersistentData = false
                }));

            }
        }

        async Task FinishDisposalAsync()
        {
            bool disposed = false;
            try { if (removed) { await container.DisposeAsync().AsTask().WaitAsync(TimeSpan.FromSeconds(10)); disposed = true; } }
            finally
            {
                if (removed && disposed && ownedId is not null && removedAtUtc is not null)
                {
                    using var absenceDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    var containers = await docker.Containers.ListContainersAsync(new ContainersListParameters { All = true }, absenceDeadline.Token);
                    var volumes = await docker.Volumes.ListAsync(new VolumesListParameters(), absenceDeadline.Token);
                    int[] ports = System.Net.NetworkInformation.IPGlobalProperties.GetIPGlobalProperties().GetActiveTcpListeners()
                        .Where(x => IPAddress.IsLoopback(x.Address)).Select(x => x.Port).Distinct().Order().ToArray();
                    IsoDefinitionRecorder.Resource("absence", new IsoDefinitionAbsence(run, DateTimeOffset.UtcNow, true, true, true,
                        containers.Select(x => x.ID).ToArray(), containers.SelectMany(x => x.Names).ToArray(),
                        (volumes.Volumes ?? []).Select(x => x.Name).ToArray(), ports));
                }
                IsoDefinitionRecorder.Resource("disposed", new
                {
                    run,
                    name,
                    containerId = ownedId,
                    began,
                    expires,
                    removed,
                    removedAtUtc,
                    disposed,
                    cleanupFailed = !removed || !disposed,
                    persistent = false,
                    completedAtUtc = DateTimeOffset.UtcNow
                });
                WriteLedger(run, "disposed", new
                {
                    run,
                    name,
                    purpose = "current-owner-iso-native-proof",
                    containerId = ownedId,
                    began,
                    expires,
                    removed,
                    disposed,
                    cleanupFailed = !removed || !disposed,
                    persistent = false,
                    completedAtUtc = DateTimeOffset.UtcNow
                });
            }
        }
        void RequireOwnership(ContainerInspectResponse metadata, bool active = true)
        {
            JsonElement json = JsonSerializer.SerializeToElement(metadata);
            DateTimeOffset created = json.GetProperty("Created").GetDateTimeOffset();
            if (metadata.Config is not { } config || metadata.HostConfig is not { } host || metadata.NetworkSettings is not { } network ||
                metadata.ID is not { Length: 64 } || metadata.Name != "/" + name || created < began.AddSeconds(-1) || created > expires ||
                config.Image != Image || config.Labels is not { } labels ||
                !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-owner-iso-native-proof" ||
                !labels.TryGetValue("codex.repair.operation", out string? operation) || operation != run.ToString("D") ||
                metadata.Mounts is not { } mounts || mounts.Count != 0 || host.Mounts is { Count: > 0 } ||
                host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
                host.Tmpfs is not { } tmpfsMounts || tmpfsMounts.Count != 1 || !tmpfsMounts.TryGetValue("/var/lib/postgresql", out string? tmpfs) ||
                tmpfs != "rw,nosuid,size=384m" || host.MemorySwap != 512 * 1024 * 1024 ||
                host.Memory != 512 * 1024 * 1024 || host.NanoCPUs != 750000000 ||
                metadata.State is null || metadata.State.Running != active ||
                host.PortBindings is not { Count: > 0 } configuredPorts || configuredPorts.Values.SelectMany(x => x ?? []).Any(binding => binding.HostIP != "127.0.0.1") ||
                (active && (network.Ports is not { Count: > 0 } ports || ports.Values.SelectMany(x => x ?? []).Any(binding => binding.HostIP != "127.0.0.1"))))
            { throw new InvalidOperationException("Disposable resource ownership mismatch"); }
        }
    }

    private static void WriteLedger(Guid run, string phase, object record)
    {
        string? directory = Environment.GetEnvironmentVariable("MALIEV_ISO_NATIVE_LEDGER");
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory) || !Directory.Exists(directory))
        { throw new InvalidOperationException("Mandatory ISO resource ledger directory missing"); }
        using var file = new FileStream(Path.Combine(directory, run.ToString("N") + "-" + phase + ".json"), FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        JsonSerializer.Serialize(file, record);
        file.Flush(flushToDisk: true);
    }

    private static string Hash(string text)
    {
        return Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    { await using var command = new NpgsqlCommand(sql, connection, tx) { CommandTimeout = 30 }; _ = await command.ExecuteNonQueryAsync(ct); }
}
