using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Actual disposable policy component. No provider, review/authorization or archive execution report.
[Collection(CurrentAuthNativeProofGroup.Name)]
public sealed class CurrentAuthArchiveFixturePolicyNativeTests
{
    [WindowsLocalRunTheory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Genuine_archive_policy_rejects_ordinary_credentials_across_exact_fleet_and_preserves_source_shapes(bool comparison)
    {
        string config = Environment.GetEnvironmentVariable("MALIEV_AUTH_ARCHIVE_FIXTURE_INPUT") ??
            throw new InvalidOperationException("archive_fixture_protected_host_input_required");
        byte[] initial = ReadProtected(config);
        var input = MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveFixtureHostInput>(initial);
        var binding = MigrationConsole.DecodeAuthRepair<LocalExecutionBinding>(ReadProtected(input.ParentRunBindingPath));
        string parent = binding.ArtifactRootCanonicalPath;
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(config)), parent) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(input.ParentRunBindingPath)), parent))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(parent, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        Assert.Equal(initial, files.Read(config, maximumBytes: 65536));
        FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(files, input.SourcePlan, input.AcceptedCommit, DateTimeOffset.UtcNow);
        string root;
        await using (var fixture = await CurrentAuthArchiveFixtureTarget.CreateAsync(parent, files, input.SourcePlan,
            input.AcceptedCommit, Guid.NewGuid(), comparison, CancellationToken.None))
        {
            root = fixture.Root;
            var seed = await CurrentAuthArchiveFixtureSeed.SeedAndCaptureAsync(fixture, files,
                input.SourcePlan, input.AcceptedCommit, fixture.Token);
            using var installed = await CurrentAuthArchiveFixturePolicy.InstallAndObserveAsync(fixture, seed, files,
                input.SourcePlan, input.AcceptedCommit, fixture.Token);
            var maintenance = installed.Maintenance;
            Assert.Equal("legacy-maliev-current-auth-session-archive-v1:" + fixture.Binding.ComputeSha256(), maintenance.RoleComment);
            Assert.True(maintenance.IssuedAtUtc < maintenance.ExpiresAtUtc);
            Assert.True(maintenance.ExpiresAtUtc <= fixture.Configuration.ExpiresAtUtc);
            Assert.Equal(fixture.Configuration.Databases.Order(StringComparer.Ordinal), installed.DeniedDatabases.Order(StringComparer.Ordinal));
            Assert.Equal(comparison ? 49 : 26, installed.Baseline.Databases.Count);
            Assert.Equal(comparison ? 51 : 28, installed.Baseline.Before.Databases.Count);
            Assert.Equal(installed.Baseline.Before.Databases, installed.Baseline.After.Databases);
            Assert.True(installed.Baseline.Before.ReadOnly); Assert.True(installed.Baseline.After.ReadOnly);
            Assert.Equal(seed.Before.SystemIdentifierSha256, installed.Baseline.Before.SystemIdentifierSha256);
            Assert.Equal(23, installed.Baseline.PhysicalSha256.Count);
            foreach (DatabaseSchemaPlan plan in source.Databases)
            { Assert.Equal(plan.TargetSchemaSha256, installed.Baseline.PhysicalSha256[plan.Database]); }
            CurrentAuthLocalSessionArchivePolicy.RequireRows(installed.Baseline.Auth.Sessions, seed.Auth.Sessions);
            Assert.Equal(seed.Auth.Native.Snapshot.Relations, installed.Baseline.Auth.Native.Snapshot.Relations);
            Assert.Equal(seed.Auth.Native.Snapshot.Sequences, installed.Baseline.Auth.Native.Snapshot.Sequences);
            // Role/HBA installation changes cluster catalogs; the new baseline must be independently captured.
            Assert.Equal(comparison ? 0 : 2, installed.Baseline.Auth.Sessions.Count);
            Assert.Equal(maintenance.HbaSha256, Hash(ReadProtected(installed.HbaFile.Path)));
            Assert.Equal(maintenance.HbaRulesSha256, Hash(ReadProtected(installed.RawRules.Path)));
            Assert.Equal(installed.HbaFile.Sha256, maintenance.HbaSha256);
            Assert.Equal(installed.RawRules.Sha256, maintenance.HbaRulesSha256);
            string op = Encoding.UTF8.GetString(ReadProtected(installed.OperatorConnectionPath));
            string ordinary = Encoding.UTF8.GetString(ReadProtected(installed.OrdinaryConnectionPath));
            foreach (string database in fixture.Configuration.Databases)
            {
                await using (var rejected = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ordinary) { Database = database }.ConnectionString))
                {
                    PostgresException failure = await Assert.ThrowsAsync<PostgresException>(() => rejected.OpenAsync(fixture.Token));
                    Assert.Equal("28000", failure.SqlState);
                }
                await RequireActualPolicyAsync(op, database, maintenance, fixture.Token);
            }
            await using (var oldAdmin = new NpgsqlConnection(fixture.AdminConnection))
            {
                PostgresException rejected = await Assert.ThrowsAsync<PostgresException>(() => oldAdmin.OpenAsync(fixture.Token));
                Assert.Equal("28000", rejected.SqlState);
            }
        }
        RequireVerifiedAbsence(root);
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-operator.txt")));
        Assert.False(File.Exists(Path.Combine(root, "archive-policy-ordinary.txt")));
    }

    private static async Task RequireActualPolicyAsync(string op, string database, CurrentAppOwnedMaintenancePin expected, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(op) { Database = database }.ConnectionString);
        await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
        await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx))
        { _ = await readOnly.ExecuteNonQueryAsync(ct); }
        await using (var command = new NpgsqlCommand("""
            SELECT current_user,rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
              rolvaliduntil,shobj_description(r.oid,'pg_authid'),
              (SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
              (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),
              (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
              NOT pg_is_in_recovery(),current_setting('transaction_read_only')='on'
            FROM pg_roles r WHERE rolname=current_user;
            """, connection, tx))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            Assert.True(await reader.ReadAsync(ct)); Assert.Equal(expected.Role, reader.GetString(0));
            Assert.True(reader.GetBoolean(1)); Assert.True(reader.GetBoolean(2));
            for (int index = 3; index <= 6; index++) { Assert.False(reader.GetBoolean(index)); }
            Assert.Equal(expected.ExpiresAtUtc, reader.GetFieldValue<DateTimeOffset>(7)); Assert.Equal(expected.RoleComment, reader.GetString(8));
            Assert.True(reader.GetBoolean(9));
            for (int index = 10; index <= 14; index++) { Assert.Equal(0, reader.GetInt64(index)); }
            Assert.True(reader.GetBoolean(15)); Assert.True(reader.GetBoolean(16)); Assert.False(await reader.ReadAsync(ct));
        }
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, expected.Role, DeltaTargetAuthorityKind.LocalAspire, ct);
        await tx.RollbackAsync(ct);
    }

    private static void RequireVerifiedAbsence(string root)
    {
        string[] paths = Directory.GetFiles(root, "*-disposed.json"); _ = Assert.Single(paths);
        using var final = JsonDocument.Parse(ReadProtected(paths[0]));
        Assert.False(final.RootElement.GetProperty("cleanupFailed").GetBoolean());
        Assert.True(final.RootElement.GetProperty("verifiedAbsence").GetBoolean());
        _ = Assert.Single(Directory.GetFiles(root, "*-absent.json"));
    }

    private static string Hash(byte[] bytes)
    { return Convert.ToHexStringLower(SHA256.HashData(bytes)); }

    private static byte[] ReadProtected(string path)
    {
        if (!Path.IsPathFullyQualified(path)) { throw CurrentAuthRepairPermit.Invalid(); }
        using var held = SecureLocalFile.OpenReadShared(path);
        if (held.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
        byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes); return bytes;
    }
}
