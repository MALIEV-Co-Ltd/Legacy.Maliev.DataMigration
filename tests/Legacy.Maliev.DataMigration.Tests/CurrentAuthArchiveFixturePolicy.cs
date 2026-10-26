using System.Data;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Microsoft.Win32.SafeHandles;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

// Installs a fixed policy on exact owned disposable targets; creates no permit or execution proof.
internal static class CurrentAuthArchiveFixturePolicy
{
    internal static async Task<CurrentAuthArchiveFixtureInstalledPolicy> InstallAndObserveAsync(CurrentAuthArchiveFixtureTarget fixture,
        CurrentAuthArchiveFixtureSeedCapture seed, CurrentAppOwnedRepairCustody hostFiles,
        CurrentAuthArchiveProofArtifact sourceArtifact, string acceptedCommit, CancellationToken ct)
    {
        using var lease = CancellationTokenSource.CreateLinkedTokenSource(ct, fixture.Token); ct = lease.Token;
        var secrets = new List<CurrentAuthArchiveFixtureOwnedCredential>();
        try
        {
            FreshSchemaPlan source = CurrentAuthArchiveFixtureSource.Read(hostFiles, sourceArtifact, acceptedCommit, DateTimeOffset.UtcNow);
            CurrentAuthArchiveFixtureSeed.RequireInput(fixture.Source, source, fixture.Comparison, fixture.Configuration.Databases, DateTimeOffset.UtcNow);
            if (seed.Before.Operation != fixture.Operation || seed.Before.RunBindingSha256 != fixture.Binding.ComputeSha256() ||
                seed.After.SystemIdentifierSha256 != seed.Before.SystemIdentifierSha256 || seed.PhysicalSha256.Count != 23 ||
                source.Databases.Any(x => seed.PhysicalSha256[x.Database] != x.TargetSchemaSha256)) { throw CurrentAuthRepairPermit.Invalid(); }
            CurrentAuthArchiveCapacity.Require(admission: true); await fixture.RequireHealthyAsync(ct);
            string role = "archive_policy_" + fixture.Operation.ToString("N"), ordinaryRole = "archive_denied_" + fixture.Operation.ToString("N");
            DateTimeOffset issued = DateTimeOffset.UtcNow, expires = fixture.Configuration.ExpiresAtUtc;
            issued = new DateTimeOffset(issued.Ticks - (issued.Ticks % 10), TimeSpan.Zero);
            expires = new DateTimeOffset(expires.Ticks - (expires.Ticks % 10), TimeSpan.Zero);
            if (expires <= issued) { throw CurrentAuthRepairPermit.Invalid(); }
            string comment = "legacy-maliev-current-auth-session-archive-v1:" + fixture.Binding.ComputeSha256();
            _ = await WriteAsync(fixture, "archive-policy-start.json", JsonSerializer.SerializeToUtf8Bytes(new
            { fixture.Operation, fixture.Comparison, sourceArtifact, acceptedCommit, role, ordinaryRole, issued, expires }), ct);
            string password = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            string deniedPassword = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
            string hbaPath;
            string hba = "local all " + role + " scram-sha-256\nhost all " + role + " 0.0.0.0/0 scram-sha-256\nhost all " + role +
                " ::/0 scram-sha-256\nlocal all all reject\nhost all all 0.0.0.0/0 reject\nhost all all ::/0 reject\n";
            await using (var admin = new NpgsqlConnection(fixture.AdminConnection))
            {
                await admin.OpenAsync(ct);
                if (await ScalarAsync<string>(admin, "SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex') FROM pg_control_system();", ct) != seed.Before.SystemIdentifierSha256 ||
                    await ScalarAsync<long>(admin, "SELECT count(*) FROM pg_roles WHERE rolname IN ('" + role + "','" + ordinaryRole + "');", ct) != 0)
                { throw CurrentAuthRepairPermit.Invalid(); }
                hbaPath = await ScalarAsync<string>(admin, "SHOW hba_file;", ct);
                if (hbaPath != "/var/lib/postgresql/18/docker/pg_hba.conf") { throw CurrentAuthRepairPermit.Invalid(); }
                await ExecuteAsync(admin, "SET password_encryption='scram-sha-256'; CREATE ROLE " + role +
                    " LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + password +
                    "' VALID UNTIL '" + expires.ToString("O", CultureInfo.InvariantCulture) + "'; COMMENT ON ROLE " + role + " IS '" + comment +
                    "'; CREATE ROLE " + ordinaryRole + " LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + deniedPassword + "';", ct);
                string values = string.Join(',', hba.Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line => "('" + line + "')"));
                await ExecuteAsync(admin, "COPY (SELECT * FROM (VALUES " + values + ") AS h(line)) TO '" + hbaPath + "';", ct);
                if (!await ScalarAsync<bool>(admin, "SELECT pg_reload_conf();", ct)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            // Admin has retired. Every later baseline uses a newly opened maintenance connection.
            bool fenced = false;
            for (int attempt = 0; attempt < 40 && !fenced; attempt++)
            {
                fenced = await RejectedAsync(fixture.AdminConnection, ct);
                if (!fenced) { await Task.Delay(TimeSpan.FromMilliseconds(50), ct); }
            }
            if (!fenced) { throw CurrentAuthRepairPermit.Invalid(); }
            string op = new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Username = role, Password = password }.ConnectionString;
            string ordinary = new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Username = ordinaryRole, Password = deniedPassword }.ConnectionString;
            var operatorCredential = await CreateSecretAsync(fixture.Root, fixture.Binding, "archive-policy-operator.txt", Encoding.UTF8.GetBytes(op), ct);
            secrets.Add(operatorCredential);
            var ordinaryCredential = await CreateSecretAsync(fixture.Root, fixture.Binding, "archive-policy-ordinary.txt", Encoding.UTF8.GetBytes(ordinary), ct);
            secrets.Add(ordinaryCredential);
            CurrentAuthArchiveProofArtifact operatorArtifact = operatorCredential.Artifact;
            CurrentAppOwnedMaintenancePin maintenance;
            byte[] actualHba, rawRules;
            await using (var connection = new NpgsqlConnection(op))
            {
                await connection.OpenAsync(ct); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
                await ExecuteAsync(connection, "SET TRANSACTION READ ONLY;", ct, tx);
                await using var command = new NpgsqlCommand("""
                    SELECT pg_postmaster_start_time(),pg_conf_load_time(),pg_read_file(current_setting('hba_file')),
                      (SELECT jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text FROM pg_hba_file_rules h)
                    """, connection, tx);
                await using (var reader = await command.ExecuteReaderAsync(ct))
                {
                    if (!await reader.ReadAsync(ct)) { throw CurrentAuthRepairPermit.Invalid(); }
                    actualHba = Encoding.UTF8.GetBytes(reader.GetString(2)); rawRules = Encoding.UTF8.GetBytes(reader.GetString(3));
                    if (!actualHba.AsSpan().SequenceEqual(Encoding.UTF8.GetBytes(hba))) { throw CurrentAuthRepairPermit.Invalid(); }
                    maintenance = new(role, comment, issued, expires, reader.GetFieldValue<DateTimeOffset>(0), reader.GetFieldValue<DateTimeOffset>(1),
                        CurrentAuthLocalSessionArchivePolicy.HashBytes(actualHba), CurrentAuthLocalSessionArchivePolicy.HashBytes(rawRules), hbaPath);
                    if (await reader.ReadAsync(ct)) { throw CurrentAuthRepairPermit.Invalid(); }
                }
                await RequireInstalledAsync(connection, tx, maintenance, seed.Before.SystemIdentifierSha256, ct);
                await tx.RollbackAsync(ct);
            }
            var hbaArtifact = await WriteAsync(fixture, "archive-policy-hba.conf", actualHba, ct);
            var rulesArtifact = await WriteAsync(fixture, "archive-policy-rules.json", rawRules, ct);
            var denied = new List<string>();
            foreach (string name in fixture.Configuration.Databases.Order(StringComparer.Ordinal))
            {
                CurrentAuthArchiveCapacity.Require(admission: false);
                if (!await RejectedAsync(new NpgsqlConnectionStringBuilder(ordinary) { Database = name }.ConnectionString, ct))
                { throw CurrentAuthRepairPermit.Invalid(); }
                denied.Add(name);
            }
            var baseline = await CurrentAuthArchiveFixtureSeed.CaptureInstalledAsync(fixture, hostFiles, sourceArtifact, acceptedCommit,
                operatorArtifact, maintenance, seed.Before.SystemIdentifierSha256, ct);
            await fixture.RecordAsync("policy-installed", new
            {
                fixture.Operation,
                fixture.Comparison,
                maintenance,
                deniedDatabases = denied,
                hbaArtifact,
                rulesArtifact,
                baselineDatabases = baseline.Databases.Count,
                synthetic = true
            }, ct);
            return new(fixture, maintenance, operatorCredential, ordinaryCredential, hbaArtifact, rulesArtifact, denied.AsReadOnly(), baseline);
        }
        catch
        {
            try { CleanupSecrets(fixture, secrets); }
            finally { await fixture.DisposeAsync(); }
            throw;
        }
    }

    internal static async Task RequireInstalledAsync(NpgsqlConnection connection, NpgsqlTransaction tx,
        CurrentAppOwnedMaintenancePin expected, string system, CancellationToken ct)
    {
        const string sql = """
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),pg_postmaster_start_time(),pg_conf_load_time(),current_user,
              encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
              (SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL),
              (SELECT count(*) FROM pg_stat_activity WHERE backend_type='client backend' AND pid<>pg_backend_pid()),
              (SELECT count(*) FROM pg_prepared_xacts),(SELECT count(*) FROM pg_event_trigger WHERE evtenabled<>'D'),
              rolvaliduntil,shobj_description(r.oid,'pg_authid'),rolsuper,rolcanlogin,rolcreaterole,rolcreatedb,rolreplication,rolbypassrls,
              (SELECT count(*) FROM pg_auth_members WHERE member=r.oid),
              (SELECT rolpassword LIKE 'SCRAM-SHA-256$%' FROM pg_authid WHERE oid=r.oid),
              (SELECT count(*) FROM pg_default_acl WHERE defaclrole=r.oid),current_setting('hba_file'),NOT pg_is_in_recovery(),
              current_setting('transaction_read_only')='on'
            FROM pg_control_system(),pg_roles r WHERE rolname=current_user;
            """;
        await using (var command = new NpgsqlCommand(sql, connection, tx))
        await using (var reader = await command.ExecuteReaderAsync(ct))
        {
            if (!await reader.ReadAsync(ct) || reader.GetString(0) != system || reader.GetFieldValue<DateTimeOffset>(1) != expected.Postmaster ||
                reader.GetFieldValue<DateTimeOffset>(2) != expected.ConfigLoaded || reader.GetString(3) != expected.Role || reader.GetString(4) != expected.HbaSha256 ||
                reader.GetString(5) != expected.HbaRulesSha256 || Enumerable.Range(6, 4).Any(i => reader.GetInt64(i) != 0) ||
                reader.GetFieldValue<DateTimeOffset>(10) != expected.ExpiresAtUtc || reader.GetString(11) != expected.RoleComment ||
                !reader.GetBoolean(12) || !reader.GetBoolean(13) || Enumerable.Range(14, 4).Any(reader.GetBoolean) || reader.GetInt64(18) != 0 ||
                !reader.GetBoolean(19) || reader.GetInt64(20) != 0 || reader.GetString(21) != expected.HbaPath || !reader.GetBoolean(22) ||
                !reader.GetBoolean(23) || DateTimeOffset.UtcNow >= expected.ExpiresAtUtc || await reader.ReadAsync(ct))
            { throw CurrentAuthRepairPermit.Invalid(); }
        }
        await CurrentAppOwnedMaintenanceHba.RequireInstalledAsync(connection, tx, expected.Role, DeltaTargetAuthorityKind.LocalAspire, ct);
    }

    private static async Task<bool> RejectedAsync(string text, CancellationToken ct)
    {
        try { await using var connection = new NpgsqlConnection(text); await connection.OpenAsync(ct); return false; }
        catch (PostgresException failure) when (failure.SqlState == "28000") { return true; }
    }

    internal static async Task<CurrentAuthArchiveFixtureOwnedCredential> CreateSecretAsync(string root, LocalExecutionBinding binding,
        string name, byte[] bytes, CancellationToken ct, CurrentAuthArchiveFixtureSecretFault fault = CurrentAuthArchiveFixtureSecretFault.None)
    {
        if (!OperatingSystem.IsWindows() || !Enum.IsDefined(fault) || bytes.Length is < 1 or > 65536 ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(root), binding.ArtifactRootCanonicalPath) ||
            name is not ("archive-policy-operator.txt" or "archive-policy-ordinary.txt")) { throw CurrentAuthRepairPermit.Invalid(); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct); deadline.CancelAfter(TimeSpan.FromSeconds(5)); ct = deadline.Token;
        ct.ThrowIfCancellationRequested();
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); authority.ValidateHeld();
        using var files = new CurrentAppOwnedRepairCustody(authority);
        SecureLocalFile.EnsureOwnerOnlyDirectory(root);
        string path = Path.Combine(root, name);
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        SafeFileHandle? handle = null; FileStream? stream = null;
        CurrentAuthArchiveFixtureOwnedCredential? owned = null;
        bool created = false;
        try
        {
            var openSecret = Marshal.GetDelegateForFunctionPointer<OpenSecretDelegate>(NativeLibrary.GetExport(library, "CreateFileW"));
            var secretInformation = Marshal.GetDelegateForFunctionPointer<SecretInformationDelegate>(NativeLibrary.GetExport(library, "GetFileInformationByHandle"));
            // CREATE_NEW, read/write/delete access, no sharing, no reparse traversal, durable writes.
            handle = openSecret(path, 0x80000000 | 0x40000000 | 0x00010000 | 0x00000080, 0, IntPtr.Zero, 1, 0x80200000, IntPtr.Zero);
            if (handle.IsInvalid) { throw new IOException("archive_policy_secret_create_new_failed"); }
            created = true;
            owned = new(new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes)), WindowsRunFileIdentity.Observe(handle));
            stream = new FileStream(handle, FileAccess.ReadWrite, 4096, isAsync: false);
            RequireCreated();
            if (fault == CurrentAuthArchiveFixtureSecretFault.CancelAfterCreate)
            {
                using var canceled = new CancellationTokenSource(); canceled.Cancel(); canceled.Token.ThrowIfCancellationRequested();
            }
            if (fault == CurrentAuthArchiveFixtureSecretFault.PartialWrite)
            {
                await stream.WriteAsync(bytes.AsMemory(0, Math.Max(1, bytes.Length / 2)), ct);
                throw new IOException("archive_policy_secret_partial_write_fault");
            }
            await stream.WriteAsync(bytes, ct); await stream.FlushAsync(ct); stream.Flush(flushToDisk: true);
            ct.ThrowIfCancellationRequested();
            stream.Position = 0; byte[] observed = new byte[bytes.Length];
            await stream.ReadExactlyAsync(observed, ct);
            try
            {
                if (stream.Length != bytes.Length || !observed.AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
            }
            finally { CryptographicOperations.ZeroMemory(observed); }
            RequireCreated(); ct.ThrowIfCancellationRequested();
            return owned ?? throw CurrentAuthRepairPermit.Invalid();

            void RequireCreated()
            {
                if (owned is null || stream is null || handle is null || handle.IsInvalid || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path) ||
                    !secretInformation(handle, out var info) || info.Links != 1 || (info.Attributes & 0x00000400) != 0 ||
                    WindowsRunFileIdentity.Observe(handle) != owned.CreationIdentity || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)))
                { throw CurrentAuthRepairPermit.Invalid(); }
                authority.ValidateHeld();
            }
        }
        catch (Exception failure)
        {
            if (created)
            {
                try
                {
                    if (owned is null || handle is null || handle.IsInvalid || WindowsRunFileIdentity.Observe(handle) != owned.CreationIdentity)
                    { throw CurrentAuthRepairPermit.Invalid(); }
                    var markSecret = Marshal.GetDelegateForFunctionPointer<MarkSecretDelegate>(NativeLibrary.GetExport(library, "SetFileInformationByHandle"));
                    authority.ValidateHeld(); var disposition = new SecretDisposition { DeleteFile = 1 };
                    if (!markSecret(handle, 4, ref disposition, 1)) { throw new IOException("archive_policy_secret_partial_delete_failed"); }
                    stream?.Dispose(); stream = null; handle.Dispose(); handle = null;
                    authority.ValidateHeld();
                    if (File.Exists(path)) { throw new IOException("archive_policy_secret_partial_absence_failed"); }
                }
                catch (Exception cleanupFailure)
                {
                    try
                    {
                        await CurrentAuthArchiveFixtureFrame.RunAsync(token => files.WriteNewAsync(Path.Combine(root,
                            "archive-policy-secret-cleanup-failed-" + Guid.NewGuid().ToString("N") + ".json"),
                            JsonSerializer.SerializeToUtf8Bytes(new
                            {
                                Name = name,
                                BindingSha256 = binding.ComputeSha256(),
                                owned?.CreationIdentity,
                                CleanupFailed = true,
                                FailureType = failure.GetType().Name,
                                CleanupFailureType = cleanupFailure.GetType().Name,
                                ObservedAtUtc = DateTimeOffset.UtcNow
                            }), token), TimeSpan.FromSeconds(5), CancellationToken.None);
                    }
                    catch (Exception publicationFailure)
                    { throw new AggregateException("archive_policy_secret_cleanup_and_publication_failed", failure, cleanupFailure, publicationFailure); }
                    throw new AggregateException("archive_policy_secret_partial_cleanup_failed", failure, cleanupFailure);
                }
            }
            throw;
        }
        finally
        {
            try { stream?.Dispose(); }
            finally
            {
                try { handle?.Dispose(); }
                finally { NativeLibrary.Free(library); }
            }
        }
    }

    private static async Task<CurrentAuthArchiveProofArtifact> WriteAsync(CurrentAuthArchiveFixtureTarget fixture, string name, byte[] bytes, CancellationToken ct)
    {
        string path = Path.Combine(fixture.Root, name);
        await CurrentAuthArchiveFixtureFrame.RunAsync(async token =>
        {
            using var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding);
            using var files = new CurrentAppOwnedRepairCustody(authority);
            await files.WriteNewAsync(path, bytes, token);
            if (!files.Read(path, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw CurrentAuthRepairPermit.Invalid(); }
        }, TimeSpan.FromSeconds(5), ct);
        return new(path, CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes));
    }

    internal static void CleanupSecrets(CurrentAuthArchiveFixtureTarget fixture, IEnumerable<CurrentAuthArchiveFixtureOwnedCredential> artifacts)
    {
        CleanupSecrets(fixture.Root, fixture.Binding, artifacts);
    }

    internal static void CleanupSecrets(string root, LocalExecutionBinding binding, IEnumerable<CurrentAuthArchiveFixtureOwnedCredential> artifacts)
    {
        if (!OperatingSystem.IsWindows() || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(root), binding.ArtifactRootCanonicalPath))
        { throw CurrentAuthRepairPermit.Invalid(); }
        CurrentAuthArchiveFixtureOwnedCredential[] owned = artifacts.ToArray();
        if (owned.Length > 2 || owned.Select(x => x.Artifact.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != owned.Length ||
            owned.Any(x => !CurrentAuthRepairPermit.HashShape(x.Artifact.Sha256) ||
                (x.Artifact.Path != Path.Combine(root, "archive-policy-operator.txt") && x.Artifact.Path != Path.Combine(root, "archive-policy-ordinary.txt"))))
        { throw CurrentAuthRepairPermit.Invalid(); }
        using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); authority.ValidateHeld();
        nint library = NativeLibrary.Load(Path.Combine(Environment.SystemDirectory, "kernel32.dll"));
        try
        {
            var openSecret = Marshal.GetDelegateForFunctionPointer<OpenSecretDelegate>(NativeLibrary.GetExport(library, "CreateFileW"));
            var secretInformation = Marshal.GetDelegateForFunctionPointer<SecretInformationDelegate>(NativeLibrary.GetExport(library, "GetFileInformationByHandle"));
            var markSecret = Marshal.GetDelegateForFunctionPointer<MarkSecretDelegate>(NativeLibrary.GetExport(library, "SetFileInformationByHandle"));
            foreach (var credential in owned)
            {
                var artifact = credential.Artifact;
                if (!File.Exists(artifact.Path)) { continue; }
                SecureLocalFile.EnsureOwnerOnlyDirectory(root);
                if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(artifact.Path))) { throw CurrentAuthRepairPermit.Invalid(); }
                // Deny write/delete sharing while validating and marking this same owned file for deletion.
                using (SafeFileHandle handle = openSecret(artifact.Path, 0x80000000 | 0x00010000 | 0x00000080, 1, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero))
                {
                    if (handle.IsInvalid) { throw new IOException("archive_policy_secret_cleanup_open_failed"); }
                    using var held = new FileStream(handle, FileAccess.Read, 4096, isAsync: false);
                    if (!SecureLocalFile.HandleResolvesToApprovedPath(held, artifact.Path) || !secretInformation(handle, out var info) ||
                        info.Links != 1 || (info.Attributes & 0x00000400) != 0 || !SecureLocalFile.IsOwnerOnlyFile(new FileInfo(artifact.Path)) ||
                        held.Length is < 1 or > 65536) { throw CurrentAuthRepairPermit.Invalid(); }
                    var identity = WindowsRunFileIdentity.Observe(handle);
                    if (identity != credential.CreationIdentity) { throw CurrentAuthRepairPermit.Invalid(); }
                    byte[] bytes = new byte[checked((int)held.Length)]; held.ReadExactly(bytes);
                    if (CurrentAuthLocalSessionArchivePolicy.HashBytes(bytes) != artifact.Sha256 ||
                        WindowsRunFileIdentity.Observe(handle) != identity) { throw CurrentAuthRepairPermit.Invalid(); }
                    authority.ValidateHeld(); var disposition = new SecretDisposition { DeleteFile = 1 };
                    if (!markSecret(handle, 4, ref disposition, 1)) { throw new IOException("archive_policy_secret_cleanup_delete_failed"); }
                }
                authority.ValidateHeld();
                if (File.Exists(artifact.Path)) { throw new IOException("archive_policy_secret_cleanup_absence_failed"); }
            }
            authority.ValidateHeld();
        }
        catch (Exception failure)
        {
            try
            {
                using var files = new CurrentAppOwnedRepairCustody(authority);
                CurrentAuthArchiveFixtureFrame.RunAsync(token => files.WriteNewAsync(Path.Combine(root,
                    "archive-policy-secret-cleanup-failed-" + Guid.NewGuid().ToString("N") + ".json"),
                    JsonSerializer.SerializeToUtf8Bytes(new
                    {
                        BindingSha256 = binding.ComputeSha256(),
                        CleanupFailed = true,
                        Names = owned.Select(x => Path.GetFileName(x.Artifact.Path)).ToArray(),
                        FailureType = failure.GetType().Name,
                        ObservedAtUtc = DateTimeOffset.UtcNow
                    }), token),
                    TimeSpan.FromSeconds(5), CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception publicationFailure)
            { throw new AggregateException("archive_policy_secret_cleanup_and_publication_failed", failure, publicationFailure); }
            throw;
        }
        finally { NativeLibrary.Free(library); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecretDisposition { internal byte DeleteFile; }
    [StructLayout(LayoutKind.Sequential)]
    private struct SecretFileInformation
    {
        internal uint Attributes, CreationLow, CreationHigh, AccessLow, AccessHigh, WriteLow, WriteHigh;
        internal uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [UnmanagedFunctionPointer(CallingConvention.Winapi, CharSet = CharSet.Unicode)]
    private delegate SafeFileHandle OpenSecretDelegate([MarshalAs(UnmanagedType.LPWStr)] string path, uint access, uint sharing,
        IntPtr security, uint creation, uint flags, IntPtr template);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool SecretInformationDelegate(SafeFileHandle handle, out SecretFileInformation information);
    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private delegate bool MarkSecretDelegate(SafeFileHandle handle, int informationClass, ref SecretDisposition value, uint size);

    private static async Task ExecuteAsync(NpgsqlConnection connection, string sql, CancellationToken ct, NpgsqlTransaction? tx = null)
    { await using var command = new NpgsqlCommand(sql, connection, tx); _ = await command.ExecuteNonQueryAsync(ct); }
    private static async Task<T> ScalarAsync<T>(NpgsqlConnection connection, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection); return (T)(await command.ExecuteScalarAsync(ct) ?? throw CurrentAuthRepairPermit.Invalid()); }
}

internal sealed class CurrentAuthArchiveFixtureInstalledPolicy(CurrentAuthArchiveFixtureTarget fixture, CurrentAppOwnedMaintenancePin maintenance,
    CurrentAuthArchiveFixtureOwnedCredential op, CurrentAuthArchiveFixtureOwnedCredential ordinary, CurrentAuthArchiveProofArtifact hba,
    CurrentAuthArchiveProofArtifact rules, IReadOnlyList<string> denied, CurrentAuthArchiveFixtureSeedCapture baseline) : IDisposable
{
    internal CurrentAppOwnedMaintenancePin Maintenance => maintenance;
    internal string OperatorConnectionPath => op.Artifact.Path;
    internal string OrdinaryConnectionPath => ordinary.Artifact.Path;
    internal CurrentAuthArchiveProofArtifact HbaFile => hba;
    internal CurrentAuthArchiveProofArtifact RawRules => rules;
    internal IReadOnlyList<string> DeniedDatabases => denied;
    internal CurrentAuthArchiveFixtureSeedCapture Baseline => baseline;
    public void Dispose() { CurrentAuthArchiveFixturePolicy.CleanupSecrets(fixture, [op, ordinary]); }
}




internal sealed record CurrentAuthArchiveFixtureOwnedCredential(CurrentAuthArchiveProofArtifact Artifact,
    WindowsRunFileIdentity.Identity CreationIdentity);
internal enum CurrentAuthArchiveFixtureSecretFault { None, CancelAfterCreate, PartialWrite }


