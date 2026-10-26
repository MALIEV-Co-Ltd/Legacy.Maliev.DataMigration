using System.Data;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed record CurrentAuthArchiveFixtureSeedCatalog(Guid Operation, string RunBindingSha256,
    string SystemIdentifierSha256, bool ReadOnly, IReadOnlyList<ReviewedRepairDatabaseFlag> Databases,
    DateTimeOffset BeganAtUtc, DateTimeOffset EndedAtUtc);
internal sealed record CurrentAuthArchiveFixtureSeedCapture(CurrentAuthArchiveFixtureSeedCatalog Before,
    CurrentAuthArchiveFixtureSeedCatalog After, IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> Databases,
    CurrentAuthLocalSessionArchiveObservation Auth, IReadOnlyDictionary<string, string> PhysicalSha256);

// Disposable synthetic fixture setup only. No installed policy, source data population or production observation.
internal static class CurrentAuthArchiveFixtureSeed
{
    internal static IReadOnlyList<string> PrivateSentinelDatabases(FreshSchemaPlan source, bool comparison)
    {
        IEnumerable<string> names = comparison ? ReviewedProductionRepairInventory.ExportProductionNames() :
            DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]);
        return Array.AsReadOnly(names.Where(name => !source.Databases.Any(database => database.Database == name)).ToArray());
    }

    internal static void RequireInput(FreshSchemaPlan original, FreshSchemaPlan held, bool comparison,
        IEnumerable<string> names, DateTimeOffset now)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(original, now);
        ProductionSchemaCatalogInspector.ValidatePlan(held, now);
        if (SchemaPlanCanonicalizer.ComputeSha256(original) != SchemaPlanCanonicalizer.ComputeSha256(held) ||
            !ApprovedConsumerOverlaySelection.IsApproved(held) || held.Databases.Count != 23 ||
            held.Databases.Sum(x => x.Tables.Count) != 100 || held.Databases.Any(x =>
                x.TargetExtensionProfile != ApprovedConsumerOverlaySelection.ProfileForDatabase(x.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3) ||
                !CurrentAuthRepairPermit.HashShape(x.TargetSchemaSha256)) ||
            !ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), names))
        { throw CurrentAuthRepairPermit.Invalid(); }
    }

    internal static async Task<CurrentAuthArchiveFixtureSeedCapture> SeedAndCaptureAsync(CurrentAuthArchiveFixtureTarget fixture,
        CurrentAppOwnedRepairCustody hostFiles, CurrentAuthArchiveProofArtifact sourceArtifact, string acceptedCommit, CancellationToken ct)
    {
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token);
        ct = lease.Token;
        try
        {
            FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(hostFiles, sourceArtifact, acceptedCommit, DateTimeOffset.UtcNow);
            RequireInput(fixture.Source, source, fixture.Comparison, fixture.Configuration.Databases, DateTimeOffset.UtcNow);
            await fixture.RequireHealthyAsync(ct);
            // Create-new, before effects: a partial attempt cannot be resumed or seeded twice.
            using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
            using (var files = new CurrentAppOwnedRepairCustody(authority))
            {
                string start = Path.Combine(fixture.Root, "auth-archive-seed-start.json");
                if (File.Exists(start)) { throw CurrentAuthRepairPermit.Invalid(); }
                await files.WriteNewAsync(start,
                    JsonSerializer.SerializeToUtf8Bytes(new { fixture.Operation, sourceArtifact, acceptedCommit, fixture.Comparison }), ct);
            }
            string system;
            await using (var connection = Connection(fixture, "postgres"))
            {
                await connection.OpenAsync(ct);
                if (await ScalarAsync<string>(connection, "SHOW server_version_num;", ct) != "180004" ||
                    await ScalarAsync<string>(connection, "SHOW autovacuum;", ct) != "off" ||
                    await ScalarAsync<string>(connection, "SHOW server_encoding;", ct) != "UTF8" ||
                    !await ScalarAsync<bool>(connection, "SELECT datcollate='C' AND datctype='C' AND datlocprovider='c' FROM pg_database WHERE datname=current_database();", ct) ||
                    await ScalarAsync<long>(connection, "SELECT count(*) FROM pg_database WHERE NOT datistemplate;", ct) != 1)
                { throw CurrentAuthRepairPermit.Invalid(); }
                system = await ScalarAsync<string>(connection, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct);
                foreach (string name in fixture.Configuration.Databases.Where(x => x != "postgres"))
                { await ExecuteAsync(connection, "CREATE DATABASE " + Quote(name) + " TEMPLATE template0 ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C';", ct); }
            }
            foreach (DatabaseSchemaPlan plan in source.Databases)
            {
                ProductionSchemaCatalogInspector.ValidatePlan(source, DateTimeOffset.UtcNow);
                CurrentAuthArchiveCapacity.Require(admission: false);
                await using var connection = Connection(fixture, plan.Database); await connection.OpenAsync(ct);
                await using var tx = await connection.BeginTransactionAsync(ct);
                var physical = plan with
                {
                    Tables = ApprovedConsumerColumnOverlayManifest.ComposePhysical(plan),
                    TargetExtensionProfile = null,
                    SourceDispositionProfile = null,
                    SourceTableDispositions = []
                };
                await using var writer = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                await writer.ApplySchemaAsync(physical, ct); await writer.FinalizeSchemaAsync(physical, ct);
                await tx.CommitAsync(ct);
            }
            await CreateAuthAsync(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Database = "Auth" }.ConnectionString, fixture.Comparison, ct);
            foreach (string name in PrivateSentinelDatabases(source, fixture.Comparison).Where(x => x != "Auth"))
            {
                await using var connection = Connection(fixture, name); await connection.OpenAsync(ct);
                await ExecuteAsync(connection, "CREATE SCHEMA private; CREATE TABLE private.journal(id integer PRIMARY KEY,evidence text NOT NULL); " +
                    "INSERT INTO private.journal VALUES (1,'ไทย synthetic journal'),(2,'ไทย synthetic journal'); " +
                    "CREATE SEQUENCE private.allocation START WITH 77; SELECT setval('private.allocation'," +
                    (fixture.Comparison ? "211" : "113") + ",true);" +
                    (fixture.Comparison ? " UPDATE private.journal SET evidence='ไทย comparison journal';" : ""), ct);
            }
            await fixture.RequireHealthyAsync(ct);
            var pool = new CurrentAppOwnedSnapshotInternPool();
            CurrentAuthArchiveFixtureSeedCapture first = await CaptureAsync(fixture, source, system, pool, ct);
            CurrentAuthArchiveFixtureSeedCapture second = await CaptureAsync(fixture, source, system, pool, ct);
            if (!first.Databases.Select(x => (x.Database, x.Sha256)).SequenceEqual(second.Databases.Select(x => (x.Database, x.Sha256))))
            { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(second.Auth, first.Auth);
            await fixture.RecordAsync("seed-captured", new
            {
                fixture.Operation,
                fixture.Comparison,
                sourceDatabases = first.PhysicalSha256.Count,
                databases = first.Databases.Count,
                catalogEntries = first.After.Databases.Count,
                sessions = first.Auth.Sessions.Count,
                system,
                synthetic = true,
                sourceRowsPopulated = false
            }, ct);
            return first;
        }
        catch { await fixture.DisposeAsync(); throw; }
    }

    internal static async Task<CurrentAuthArchiveFixtureSeedCapture> CaptureInstalledAsync(CurrentAuthArchiveFixtureTarget fixture,
        CurrentAppOwnedRepairCustody hostFiles, CurrentAuthArchiveProofArtifact sourceArtifact, string acceptedCommit,
        CurrentAuthArchiveProofArtifact operatorArtifact, CurrentAppOwnedMaintenancePin maintenance, string system, CancellationToken ct)
    {
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token); ct = lease.Token;
        FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(hostFiles, sourceArtifact, acceptedCommit, DateTimeOffset.UtcNow);
        RequireInput(fixture.Source, source, fixture.Comparison, fixture.Configuration.Databases, DateTimeOffset.UtcNow);
        if (operatorArtifact.Path != Path.Combine(fixture.Root, "archive-policy-operator.txt") ||
            maintenance.Role != "archive_policy_" + fixture.Operation.ToString("N")) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes;
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        { bytes = files.Read(operatorArtifact.Path, maximumBytes: 65536); }
        if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != operatorArtifact.Sha256) { throw CurrentAuthRepairPermit.Invalid(); }
        string installed = System.Text.Encoding.UTF8.GetString(bytes);
        var endpoint = new NpgsqlConnectionStringBuilder(installed);
        var original = new NpgsqlConnectionStringBuilder(fixture.AdminConnection);
        if (endpoint.Host != "127.0.0.1" || endpoint.Port != original.Port || endpoint.Database != "postgres" || endpoint.Username != maintenance.Role ||
            endpoint.Pooling || string.IsNullOrEmpty(endpoint.Password) || !string.IsNullOrEmpty(endpoint.Options)) { throw CurrentAuthRepairPermit.Invalid(); }
        var pool = new CurrentAppOwnedSnapshotInternPool();
        var first = await CaptureAsync(fixture, source, system, pool, ct, installed, maintenance);
        var second = await CaptureAsync(fixture, source, system, pool, ct, installed, maintenance);
        if (!first.Databases.Select(x => (x.Database, x.Sha256)).SequenceEqual(second.Databases.Select(x => (x.Database, x.Sha256))))
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthLocalSessionArchiveObservation.RequireExactPreimage(second.Auth, first.Auth);
        return second;
    }
    private static async Task<CurrentAuthArchiveFixtureSeedCapture> CaptureAsync(CurrentAuthArchiveFixtureTarget fixture,
        FreshSchemaPlan source, string system, CurrentAppOwnedSnapshotInternPool pool, CancellationToken ct,
        string? installedConnection = null, CurrentAppOwnedMaintenancePin? maintenance = null)
    {
        ProductionSchemaCatalogInspector.ValidatePlan(source, DateTimeOffset.UtcNow);
        CurrentAuthArchiveFixtureSeedCatalog before = await CatalogAsync(fixture, system, ct, installedConnection, maintenance);
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>(); var physical = new Dictionary<string, string>(StringComparer.Ordinal);
        CurrentAuthLocalSessionArchiveObservation? auth = null;
        foreach (string name in fixture.Configuration.Databases.Order(StringComparer.Ordinal))
        {
            CurrentAuthArchiveCapacity.Require(admission: false);
            ProductionSchemaCatalogInspector.ValidatePlan(source, DateTimeOffset.UtcNow);
            await using var connection = Connection(fixture, name, installedConnection); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", ct, tx);
            if (maintenance is not null) { await CurrentAuthArchiveFixturePolicy.RequireInstalledAsync(connection, tx, maintenance, system, ct); }
            DatabaseSchemaPlan? plan = source.Databases.SingleOrDefault(x => x.Database == name);
            if (plan is not null)
            {
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                string actual = await inspector.InspectSchemaAsync(plan, ct);
                if (actual != plan.TargetSchemaSha256)
                {
                    await fixture.RecordAsync("seed-physical-mismatch", new
                    {
                        database = name,
                        expectedSha256 = plan.TargetSchemaSha256,
                        actualSha256 = actual
                    }, ct);
                    throw CurrentAuthRepairPermit.Invalid();
                }
                physical.Add(name, actual);
            }
            CurrentAppOwnedDatabaseSnapshot snapshot;
            if (name == "Auth")
            { auth = await CurrentAuthLocalSessionArchiveObservation.CaptureAsync(connection, tx, fixture.Binding.ComputeSha256(), ct); snapshot = auth.Native.Snapshot; }
            else { snapshot = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct); }
            if (plan is null)
            {
                if (snapshot.Relations.Single(x => x.Schema == "private" && x.Name == "journal").Rows != 2 ||
                    !snapshot.Sequences.Any(x => x.Schema == "private" && x.Name == "allocation")) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            else if (snapshot.Relations.Any(x => x.Schema == "private") || snapshot.Sequences.Any(x => x.Schema == "private"))
            { throw CurrentAuthRepairPermit.Invalid(); }
            snapshots.Add(pool.Intern(snapshot)); await tx.RollbackAsync(ct);
        }
        CurrentAuthArchiveFixtureSeedCatalog after = await CatalogAsync(fixture, system, ct, installedConnection, maintenance);
        return auth is null || auth.Sessions.Count != (fixture.Comparison ? 0 : 2) || physical.Count != 23 ||
            !before.Databases.SequenceEqual(after.Databases)
            ? throw CurrentAuthRepairPermit.Invalid()
            : new(before, after, snapshots.AsReadOnly(), auth,
            new System.Collections.ObjectModel.ReadOnlyDictionary<string, string>(physical));
    }

    private static async Task<CurrentAuthArchiveFixtureSeedCatalog> CatalogAsync(CurrentAuthArchiveFixtureTarget fixture, string system, CancellationToken ct,
        string? installedConnection = null, CurrentAppOwnedMaintenancePin? maintenance = null)
    {
        await fixture.RequireHealthyAsync(ct);
        DateTimeOffset began = DateTimeOffset.UtcNow;
        await using var connection = Connection(fixture, "postgres", installedConnection); await connection.OpenAsync(ct);
        await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", ct, tx);
        if (maintenance is not null) { await CurrentAuthArchiveFixturePolicy.RequireInstalledAsync(connection, tx, maintenance, system, ct); }
        await ReviewedProductionRepairInventoryObservation.RequireAsync(connection, tx,
            CurrentAuthLocalSessionArchivePolicy.InventoryProfile(fixture.Comparison), system, fixture.Configuration.Databases, ct);
        var flags = new List<ReviewedRepairDatabaseFlag>();
        const string sql = """
            SELECT d.datname,d.datistemplate,d.datallowconn,
              encode(sha256(convert_to(c.system_identifier::text,'UTF8')),'hex'),current_setting('transaction_read_only')='on'
            FROM pg_database d CROSS JOIN pg_control_system() c ORDER BY d.datname COLLATE "C";
            """;
        await using (var command = new NpgsqlCommand(sql, connection, tx))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            while (await reader.ReadAsync(ct))
            {
                ReviewedProductionRepairInventoryObservation.RequireSystemBinding(reader.GetString(3), system, reader.GetBoolean(4));
                flags.Add(new(reader.GetString(0), reader.GetBoolean(1), reader.GetBoolean(2)));
            }
        }
        ReviewedProductionRepairInventory.RequireComplete(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(fixture.Comparison), flags, fixture.Configuration.Databases);
        await tx.RollbackAsync(ct); await fixture.RequireHealthyAsync(ct);
        return new(fixture.Operation, fixture.Binding.ComputeSha256(), system, true, flags.AsReadOnly(), began, DateTimeOffset.UtcNow);
    }

    private static NpgsqlConnection Connection(CurrentAuthArchiveFixtureTarget fixture, string database, string? installedConnection = null)
    {
        return new(new NpgsqlConnectionStringBuilder(installedConnection ?? fixture.AdminConnection) { Database = database }.ConnectionString);
    }

    private static string Quote(string value)
    {
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    { await using var command = new NpgsqlCommand(sql, connection, tx); _ = await command.ExecuteNonQueryAsync(ct); }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection); return (T)(await command.ExecuteScalarAsync(ct) ?? throw CurrentAuthRepairPermit.Invalid()); }
    private static async Task CreateAuthAsync(string endpoint, bool comparison, CancellationToken token)
    {
        await using var auth = new NpgsqlConnection(endpoint);
        await auth.OpenAsync(token);
        foreach (TableCopyPlan table in ApprovedCurrentAuthSchema.Tables(false))
        {
            PrimaryKeyCopyPlan key = table.PrimaryKey ?? throw new InvalidOperationException("Missing fixed primary key");
            string[] columns = [.. table.OrderedColumns.Select(name => Quote(name) + " " + table.ColumnTypes[name] +
                (table.NullableColumns.Contains(name, StringComparer.Ordinal) ? "" : " NOT NULL"))];
            string primary = "CONSTRAINT " + Quote(key.Name) + " PRIMARY KEY (" + string.Join(',', key.Columns.Select(Quote)) + ")";
            string[] checks = [.. table.CheckConstraints.Select(check => "CONSTRAINT " + Quote(check.Name) + " CHECK (" +
                (check.Name == "CK_identity_action_tokens_employee_binding"
                    ? "\"RecoveryVersion\" IS NULL OR (\"RecoveryVersion\" = 1 AND \"Purpose\" IN ('employee-password-reset', 'employee-email-confirmation') AND \"OriginalTokenSha256\" IS NOT NULL AND length(\"OriginalTokenSha256\") = 64 AND \"OwnerSubject\" IS NOT NULL AND length(\"OwnerSubject\") > 0 AND \"BoundNormalizedEmail\" IS NOT NULL AND length(\"BoundNormalizedEmail\") > 0 AND \"BoundSecurityStamp\" IS NOT NULL AND length(\"BoundSecurityStamp\") > 0)"
                    : check.Expression) + ")")];
            await ExecuteAsync(auth, "CREATE TABLE public." + Quote(table.TargetTable) + " (" + string.Join(',', columns.Append(primary).Concat(checks)) + ");", token);
            foreach (IndexCopyPlan index in table.Indexes)
            { await ExecuteAsync(auth, "CREATE " + (index.Unique ? "UNIQUE " : "") + "INDEX " + Quote(index.Name) + " ON public." + Quote(table.TargetTable) + " (" + string.Join(',', index.Columns.Select(Quote)) + ");", token); }
        }
        foreach (string id in new[] { "20260715104357_InitialRefreshSessions", "20260715140429_AddIdentityActionTokens", "20260726184305_AddGoogleIdentityNonces", "20260727193121_AddIdentityActionTokenTargetEmail", "20260930125706_AddEmployeeRecoveryBinding" })
        {
            await using var command = new NpgsqlCommand("INSERT INTO public.\"__EFMigrationsHistory\" VALUES ($1,$2);", auth);
            _ = command.Parameters.AddWithValue(id); _ = command.Parameters.AddWithValue(comparison ? "10.0.10" : "10.0.12");
            _ = await command.ExecuteNonQueryAsync(token);
        }
        await ExecuteAsync(auth, """
            CREATE SCHEMA private;
            CREATE TABLE private.journal(id integer PRIMARY KEY,evidence text NOT NULL);
            INSERT INTO private.journal VALUES (1,'ไทย synthetic journal'),(2,'ไทย synthetic journal');
            CREATE SEQUENCE private.allocation START WITH 77; SELECT setval('private.allocation',113,true);
            INSERT INTO public.refresh_sessions VALUES
              ('00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000010','ไทย '' \\',1,NULL,'session-one',
               timestamptz '2000-01-01 01:02:03.123456+00',timestamptz '2000-01-02 01:02:03+00',NULL,NULL,NULL),
              ('00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000020','synthetic-two',2,'ไทย stamp','session-two',
               timestamptz '2001-01-01 01:02:03+00',timestamptz '2001-01-02 01:02:03+00',timestamptz '2001-01-01 02:02:03+00',
               timestamptz '2001-01-01 03:02:03+00','00000000-0000-0000-0000-000000000003');
            INSERT INTO public.google_identity_nonces VALUES ('00000000-0000-0000-0000-000000000030','nonce-one','ไทย service','synthetic',timestamptz '2000-01-01 00:00:00+00',timestamptz '2000-01-01 00:00:00+00');
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt") VALUES
              ('00000000-0000-0000-0000-000000000040','ไทย','action-one','synthetic',timestamptz '2000-01-01 00:00:00+00',timestamptz '2000-01-01 00:00:00+00'),
              ('00000000-0000-0000-0000-000000000041','ไทย','action-two','synthetic',timestamptz '2000-01-01 00:00:00+00',timestamptz '2000-01-01 00:00:00+00');
            INSERT INTO public.identity_action_tokens("Id","IdentityId","TokenHash","Purpose","CreatedAt","ExpiresAt",
              "ConsumedAt","TargetEmail","BoundNormalizedEmail","BoundSecurityStamp","EffectActionId","FinalizedAt",
              "OriginalTokenSha256","OwnerSubject","RecoveryVersion") VALUES
              ('00000000-0000-0000-0000-000000000046','synthetic-employee','action-bound','employee-password-reset',timestamptz '2000-01-01 00:00:00+00',timestamptz '2000-01-01 00:00:00+00',
               timestamptz '2000-01-01 00:00:00+00','synthetic@example.invalid','SYNTHETIC@EXAMPLE.INVALID','ไทย stamp','00000000-0000-0000-0000-000000000046',timestamptz '2000-01-01 00:00:00+00',
               repeat('a',64),'ไทย synthetic owner',1);
            """, token);
        if (comparison)
        { await ExecuteAsync(auth, "DELETE FROM public.refresh_sessions; UPDATE private.journal SET evidence='ไทย comparison journal'; SELECT setval('private.allocation',211,true);", token); }
        await using var tx = await auth.BeginTransactionAsync(IsolationLevel.Serializable, token);
        await CandidateAsync(auth, tx, token); await tx.CommitAsync(token);
    }

    private static async Task CandidateAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken token)
    {
        CurrentAuthNativePreservation.RequireBefore(await CurrentAuthNativePreservation.CaptureAsync(connection, tx, token));
        await ExecuteAsync(connection, "SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='30s'; LOCK TABLE public.\"__EFMigrationsHistory\",public.refresh_sessions,public.google_identity_nonces,public.identity_action_tokens IN ACCESS EXCLUSIVE MODE;", token, tx);
        foreach (IGrouping<string, CurrentAuthCollationOperand> group in ApprovedCurrentAuthSchema.CollationOperands().GroupBy(x => x.Table))
        {
            string changes = string.Join(',', group.Select(x => "ALTER COLUMN " + Quote(x.Column) + " TYPE " + x.PostgreSqlType + " COLLATE \"C\""));
            await ExecuteAsync(connection, "ALTER TABLE public." + Quote(group.Key) + " " + changes + ";", token, tx);
        }
    }

}



