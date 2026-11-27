using System.Data;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record ConsumerColumnBootstrapRehearsalConfiguration(string SourceConnectionPath, string ExpectedSourceIdentitySha256,
    string IssuerRoot, string ExecutionRoot);

/// <summary>One actual owned 18.4 rehearsal. No persistent connection or caller-supplied outcome is accepted.</summary>
internal static partial class ConsumerColumnBootstrapRehearsalProducer
{
    private sealed class Completion(ConsumerColumnBootstrapRehearsalEvidence evidence) : IConsumerColumnBootstrapRehearsalCompletion
    {
        private readonly ConsumerColumnBootstrapRehearsalEvidence _evidence = ConsumerColumnBootstrapOperationalContract.Copy(evidence);
        public ConsumerColumnBootstrapRehearsalEvidence ReadEvidence()
        {
            return ConsumerColumnBootstrapOperationalContract.Copy(_evidence);
        }
    }

    private sealed class SignerMaterial : IDisposable
    {
        internal P256MigrationEvidenceSigner Signer { get; }
        internal string Pem { get; }
        internal SignerMaterial(string prefix)
        {
            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256); Pem = key.ExportPkcs8PrivateKeyPem();
            Signer = new(prefix + Guid.NewGuid().ToString("N"), Pem);
        }
        public void Dispose()
        {
            Signer.Dispose();
        }
    }

    private sealed record Keys(SignerMaterial ReviewMaterial, SignerMaterial AuthorizationMaterial, SignerMaterial ReceiptMaterial)
    {
        internal P256MigrationEvidenceSigner Review => ReviewMaterial.Signer;
        internal P256MigrationEvidenceSigner Authorization => AuthorizationMaterial.Signer;
        internal P256MigrationEvidenceSigner Receipt => ReceiptMaterial.Signer;
        internal CurrentAppOwnedRepairSigningPins Pins => new(Review.KeyId, Review.PublicKeyFingerprintSha256,
            Authorization.KeyId, Authorization.PublicKeyFingerprintSha256, Receipt.KeyId, Receipt.PublicKeyFingerprintSha256);
        internal TrustedAttestationKey[] PublicKeys => [new(Review.KeyId, Review.ExportSubjectPublicKeyInfo()),
            new(Authorization.KeyId, Authorization.ExportSubjectPublicKeyInfo()), new(Receipt.KeyId, Receipt.ExportSubjectPublicKeyInfo())];
    }

    internal static async Task<IConsumerColumnBootstrapRehearsalCompletion> ProduceAsync(ConsumerColumnBootstrapRehearsalConfiguration config, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || System.Reflection.Assembly.GetEntryAssembly() != typeof(ConsumerColumnBootstrapRehearsalProducer).Assembly)
        { throw Invalid(); }
        string commit = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        CurrentAuthRepairCapacity.Require(admission: true);
        using var lifetime = CancellationTokenSource.CreateLinkedTokenSource(ct); lifetime.CancelAfter(TimeSpan.FromMinutes(8)); ct = lifetime.Token;
        if (!Path.IsPathFullyQualified(config.IssuerRoot) || !Path.IsPathFullyQualified(config.ExecutionRoot) ||
            Directory.Exists(config.IssuerRoot) || Directory.Exists(config.ExecutionRoot) ||
            StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(config.IssuerRoot), Path.GetFullPath(config.ExecutionRoot))) { throw Invalid(); }
        using var sourceFile = SecureLocalFile.OpenReadShared(config.SourceConnectionPath);
        if (sourceFile.Length is < 1 or > 65536) { throw Invalid(); }
        using var sourceReader = new StreamReader(sourceFile, Encoding.UTF8, detectEncodingFromByteOrderMarks: true, leaveOpen: true);
        string sourceConnection = await sourceReader.ReadToEndAsync(ct).ConfigureAwait(false);
        var source = await ConsumerColumnBootstrapProofSourceCapture.CaptureAsync(sourceConnection, config.ExpectedSourceIdentitySha256, commit, ct).ConfigureAwait(false);
        SecureLocalFile.EnsureOwnerOnlyDirectory(config.IssuerRoot); SecureLocalFile.EnsureOwnerOnlyDirectory(config.ExecutionRoot);
        using var issuer = WindowsLocalRunAuthority.AcquireFresh(config.IssuerRoot);
        using var files = new CurrentAppOwnedRepairCustody(issuer);
        Guid operation = Guid.NewGuid();
        LocalExecutionBinding executionBinding;
        using (var execution = WindowsLocalRunAuthority.AcquireFresh(config.ExecutionRoot)) { executionBinding = execution.Binding; }
        using var code = ConsumerColumnBootstrapAcceptedCodeCustody.Acquire(typeof(ConsumerColumnBootstrapOperationalEnvironment), TimeProvider.System);
        using var reviewMaterial = new SignerMaterial("bootstrap-rehearsal-review-");
        using var authorizationMaterial = new SignerMaterial("bootstrap-rehearsal-authorization-");
        using var receiptMaterial = new SignerMaterial("bootstrap-rehearsal-receipt-");
        var keys = new Keys(reviewMaterial, authorizationMaterial, receiptMaterial);
        var fixture = await ConsumerColumnBootstrapProofFixture.CreateAsync(operation, ConsumerColumnBootstrapProofCohort.PostgreSql184,
            issuer, executionBinding, files, source, config.ExpectedSourceIdentitySha256, commit, ct).ConfigureAwait(false);
        ConsumerColumnBootstrapOperationalConfiguration command = null!;
        DateTimeOffset began = default, returned = default; int actualResult = -1; Exception? primaryFailure = null, cleanupFailure = null;
        try
        {
            command = await PrepareAsync(fixture, source, executionBinding, keys, ct).ConfigureAwait(false);
            string configurationPath = Path.Combine(config.ExecutionRoot, "configuration.json");
            foreach (string step in new[] { "review-consumer-column-bootstrap-proof", "authorize-consumer-column-bootstrap-proof" })
            {
                if (await MigrationConsole.RunConsumerColumnBootstrapOperationalAsync(step, configurationPath, TextWriter.Null, TextWriter.Null, ct, fixture).ConfigureAwait(false) != 0)
                { throw Invalid(); }
            }
            began = DateTimeOffset.UtcNow;
            actualResult = await MigrationConsole.RunConsumerColumnBootstrapOperationalAsync("apply-consumer-column-bootstrap-proof", configurationPath,
                TextWriter.Null, TextWriter.Null, ct, fixture).ConfigureAwait(false);
            returned = DateTimeOffset.UtcNow;
            if (actualResult != 0) { throw Invalid(); }
        }
        catch (Exception failure) { primaryFailure = failure; }
        finally
        {
            try { await fixture.DisposeAsync().ConfigureAwait(false); } catch (Exception failure) { cleanupFailure = failure; }
            try { ClearSecrets(config.ExecutionRoot, executionBinding, fixture.BeganAtUtc); }
            catch (Exception failure) { cleanupFailure = cleanupFailure is null ? failure : new AggregateException(cleanupFailure, failure); }
        }
        if (cleanupFailure is not null)
        {
            if (primaryFailure is not null) { throw new AggregateException("Rehearsal and verified cleanup failed.", primaryFailure, cleanupFailure); }
            throw new AggregateException("Verified rehearsal cleanup failed.", cleanupFailure);
        }
        if (primaryFailure is not null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(primaryFailure).Throw(); }
        var (Cleanup, Native, FinalFleet) = fixture.ReadCompleted();
        using var evidenceAuthority = WindowsLocalRunAuthority.AcquireResume(config.ExecutionRoot, executionBinding);
        using var executionFiles = new CurrentAppOwnedRepairCustody(evidenceAuthority);
        var review = Read<ConsumerColumnBootstrapOperationalClaim>(executionFiles, command.ReviewPath);
        var authorization = Read<ConsumerColumnBootstrapOperationalClaim>(executionFiles, command.AuthorizationPath);
        var receipts = new List<ConsumerColumnBootstrapOperationalReceipt>();
        foreach (string database in ConsumerColumnBootstrapOperationalContract.Databases)
        {
            foreach (string phase in new[] { "prepared", "committed-readback" })
            { receipts.Add(Read<ConsumerColumnBootstrapOperationalReceipt>(executionFiles, Path.Combine(config.ExecutionRoot, $"consumer-bootstrap-{operation:N}-{database}-{phase}.json"))); }
        }

        var run = Read<ConsumerColumnBootstrapOperationalRunReceipt>(executionFiles, Path.Combine(config.ExecutionRoot, $"consumer-bootstrap-{operation:N}-run-completed.json"));
        var evidence = new ConsumerColumnBootstrapRehearsalEvidence("consumer-column-bootstrap-rehearsal-v1", operation, source,
            ConsumerColumnBootstrapProofDefinition.Compute(source.Plan, source.SourceIdentitySha256, code.RunnerDigestSha256, fixture.Cohort, began),
            code.RunnerDigestSha256, fixture.Cohort, review, authorization, keys.Pins, keys.PublicKeys, Native,
            receipts, run, FinalFleet, began, returned, actualResult, Cleanup);
        // Acceptance is derived from the actual private completion and complete native/receipt facts,
        // never from a serialized "passed" field. No persistent scope is admitted here.
        var completion = new Completion(evidence);
        _ = ConsumerColumnBootstrapRehearsalAcceptance.Read(completion);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(evidence);
        await WriteAsync(files, Path.Combine(config.IssuerRoot, "rehearsal-evidence.json"), bytes, ct).ConfigureAwait(false);
        var attestation = new
        {
            Kind = "consumer-column-bootstrap-rehearsal-attestation-v1",
            EvidenceSha256 = ConsumerColumnBootstrapOperationalContract.Hash(bytes),
            keys.Receipt.KeyId,
            keys.Receipt.PublicKeyFingerprintSha256,
            Signature = Convert.ToBase64String(keys.Receipt.Sign([.. "Legacy.Maliev.ConsumerColumnBootstrap.RehearsalReport.v1\0"u8, .. bytes])),
        };
        await WriteAsync(files, Path.Combine(config.IssuerRoot, "rehearsal-attestation.json"), JsonSerializer.SerializeToUtf8Bytes(attestation), ct).ConfigureAwait(false);
        return completion;
    }

    private static async Task<ConsumerColumnBootstrapOperationalConfiguration> PrepareAsync(ConsumerColumnBootstrapProofFixture fixture,
        ConsumerColumnBootstrapSourceCapture source, LocalExecutionBinding binding, Keys keys, CancellationToken ct)
    {
        var contract = ConsumerColumnBootstrapContract.Create(source.Plan, source.Plan.SourceCommitSha, DateTimeOffset.UtcNow);
        string[] databases = [.. DatabaseInventory.ActiveDatabases.Concat(["Auth", "legacy_local", "postgres"]).Order(StringComparer.Ordinal)];
        await using (var admin = new NpgsqlConnection(fixture.ConnectionString))
        {
            await admin.OpenAsync(ct).ConfigureAwait(false);
            foreach (string database in databases.Where(database => database != "postgres"))
            { await ExecuteAsync(admin, null, "CREATE DATABASE " + Q(database) + ";", ct).ConfigureAwait(false); }
        }
        foreach (string database in databases)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable, ct).ConfigureAwait(false);
            if (ConsumerColumnBootstrapOperationalContract.Databases.Contains(database, StringComparer.Ordinal))
            {
                await using var schema = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                var physical = contract.Before(database);
                await schema.ApplySchemaAsync(physical, ct).ConfigureAwait(false); await schema.FinalizeSchemaAsync(physical, ct).ConfigureAwait(false);
                var operand = ConsumerColumnBootstrapContract.Operands().Single(operand => operand.Database == database);
                var root = physical.Tables.Single(table => table.TargetSchema == operand.Schema && table.TargetTable == operand.Table);
                await SeedAsync(connection, transaction, root, 1, ct).ConfigureAwait(false); await SeedAsync(connection, transaction, root, 2, ct).ConfigureAwait(false);
            }
            await ExecuteAsync(connection, transaction, """
                CREATE SCHEMA legacy_migration_internal;
                CREATE TABLE legacy_migration_internal."BootstrapJournal" ("ID" integer GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,"Payload" text NOT NULL);
                INSERT INTO legacy_migration_internal."BootstrapJournal" ("Payload") VALUES ('synthetic immutable journal ไทย  '),('synthetic immutable journal two  ');
                """, ct).ConfigureAwait(false);
            if (database == "Upload") { await ExecuteAsync(connection, transaction, ConsumerColumnBootstrapUploadFaultPreservation.CreateSql, ct).ConfigureAwait(false); }
            await transaction.CommitAsync(ct).ConfigureAwait(false);
        }
        string role = "bootstrap_operator_" + fixture.OperationId.ToString("N")[..24], ordinaryRole = "bootstrap_ordinary_" + fixture.OperationId.ToString("N")[..24];
        string password = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32)), ordinaryPassword = Convert.ToHexStringLower(RandomNumberGenerator.GetBytes(32));
        DateTimeOffset issued = DateTimeOffset.UtcNow, expiry = issued.AddMinutes(6);
        await using (var admin = new NpgsqlConnection(fixture.ConnectionString))
        {
            await admin.OpenAsync(ct).ConfigureAwait(false);
            await ExecuteAsync(admin, null, $"CREATE ROLE {Q(role)} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{password}' VALID UNTIL '{expiry:yyyy-MM-ddTHH:mm:ss.ffffffZ}';" +
                $"COMMENT ON ROLE {Q(role)} IS 'legacy-maliev-consumer-column-bootstrap-v1:{binding.ComputeSha256()}';" +
                $"CREATE ROLE {Q(ordinaryRole)} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{ordinaryPassword}';", ct).ConfigureAwait(false);
            await fixture.InstallMaintenanceHbaAsync(role, ct).ConfigureAwait(false);
            await ExecuteAsync(admin, null, "SELECT pg_reload_conf();", ct).ConfigureAwait(false);
        }
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Username = role, Password = password }.ConnectionString;
        string ordinary = new NpgsqlConnectionStringBuilder(fixture.ConnectionString) { Username = ordinaryRole, Password = ordinaryPassword }.ConnectionString;
        (CurrentAppOwnedMaintenancePin maintenance, string system) = await MaintenanceAsync(connectionString, issued, ct).ConfigureAwait(false);
        var baseline = new List<CurrentAppOwnedDatabaseSnapshot>(); var pins = new List<ConsumerColumnBootstrapNativePreimagePin>();
        foreach (string database in databases)
        {
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(connectionString) { Database = database }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await ExecuteAsync(connection, transaction, "SET TRANSACTION READ ONLY;", ct).ConfigureAwait(false);
            baseline.Add(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, ct).ConfigureAwait(false));
            if (ConsumerColumnBootstrapOperationalContract.Databases.Contains(database, StringComparer.Ordinal))
            {
                var native = await ConsumerColumnBootstrapNativePreservation.CaptureAsync(connection, transaction, contract, database, false, ct).ConfigureAwait(false);
                var provider = await ConsumerColumnBootstrapProviderCapture.CaptureAsync(connection, transaction, ct).ConfigureAwait(false);
                pins.Add(ConsumerColumnBootstrapNativePreimage.Pin(native, provider, DateTimeOffset.UtcNow));
            }
            await transaction.RollbackAsync(ct).ConfigureAwait(false);
        }
        using var authority = WindowsLocalRunAuthority.AcquireResume(binding.ArtifactRootCanonicalPath, binding);
        using var files = new CurrentAppOwnedRepairCustody(authority);
        var (Pins, Observation, Generation) = await TargetAsync(fixture, maintenance.HbaPath, files, binding.ArtifactRootCanonicalPath, ct).ConfigureAwait(false);
        var hashes = baseline.ToDictionary(snapshot => snapshot.Database, snapshot => snapshot.Sha256, StringComparer.Ordinal);
        string h = new('0', 64);
        var scope = new ConsumerColumnBootstrapOperationalScope(fixture.OperationId, ConsumerColumnBootstrapOperationalMode.DisposableClosedProof,
            source.Plan.SourceCommitSha, contract.LogicalSourcePlanSha256, contract.ComputeSha256(),
            ConsumerColumnBootstrapOperationalContract.Databases.ToDictionary(database => database, database => contract.Before(database).TargetSchemaSha256, StringComparer.Ordinal),
            ConsumerColumnBootstrapOperationalContract.Databases.ToDictionary(database => database, database => contract.After(database).TargetSchemaSha256, StringComparer.Ordinal),
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-" + fixture.ContainerId[..12], system),
            "local-aspire", "legacy-postgres-main-local", Generation, Observation, binding.ComputeSha256(), hashes,
            ConsumerColumnBootstrapOperationalContract.FleetHash(hashes), h, h, h, maintenance)
        { NativePreimages = pins.OrderBy(pin => pin.Database, StringComparer.Ordinal).ToArray(), SourceIdentitySha256 = source.SourceIdentitySha256 };
        var publicReferences = new List<DeltaTrustedKeyReference>();
        foreach (var key in keys.PublicKeys)
        {
            string path = Path.Combine(binding.ArtifactRootCanonicalPath, key.KeyId + ".spki");
            await WriteAsync(files, path, Encoding.UTF8.GetBytes(Convert.ToBase64String(key.SubjectPublicKeyInfo)), ct).ConfigureAwait(false); publicReferences.Add(new(key.KeyId, path));
        }
        async Task<string> Store<T>(string name, T value)
        {
            string path = Path.Combine(binding.ArtifactRootCanonicalPath, name);
            await WriteAsync(files, path, JsonSerializer.SerializeToUtf8Bytes(value), ct).ConfigureAwait(false); return path;
        }
        async Task<CurrentAppOwnedRepairArtifact> Preparation(string kind)
        {
            string path = Path.Combine(binding.ArtifactRootCanonicalPath, kind + ".json");
            var artifact = new ConsumerColumnBootstrapPreparationArtifact(kind, fixture.OperationId, contract.LogicalSourcePlanSha256, contract.ComputeSha256(),
                scope.TargetObservationSha256, scope.RunBindingSha256, true, false, DateTimeOffset.UtcNow, maintenance.ExpiresAtUtc, role, ordinaryRole);
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(artifact); await WriteAsync(files, path, bytes, ct).ConfigureAwait(false);
            return new(path, ConsumerColumnBootstrapOperationalContract.Hash(bytes));
        }
        var nativePreparation = await Preparation("consumer-column-bootstrap-native-preparation-v1").ConfigureAwait(false);
        var recoveryPreparation = await Preparation("consumer-column-bootstrap-recovery-preparation-v1").ConfigureAwait(false);
        var rolePreparation = await Preparation("consumer-column-bootstrap-role-preparation-v1").ConfigureAwait(false);
        scope = scope with { NativeCharacterizationSha256 = nativePreparation.Sha256, RecoveryReviewSha256 = recoveryPreparation.Sha256, RoleTransitionReviewSha256 = rolePreparation.Sha256 };
        string reviewPrivate = Path.Combine(binding.ArtifactRootCanonicalPath, "review-private.pem"), authorizationPrivate = Path.Combine(binding.ArtifactRootCanonicalPath, "authorization-private.pem"), receiptPrivate = Path.Combine(binding.ArtifactRootCanonicalPath, "receipt-private.pem");
        _ = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, reviewPrivate, Encoding.UTF8.GetBytes(keys.ReviewMaterial.Pem), ct).ConfigureAwait(false);
        _ = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, authorizationPrivate, Encoding.UTF8.GetBytes(keys.AuthorizationMaterial.Pem), ct).ConfigureAwait(false);
        _ = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, receiptPrivate, Encoding.UTF8.GetBytes(keys.ReceiptMaterial.Pem), ct).ConfigureAwait(false);
        string operatorPath = Path.Combine(binding.ArtifactRootCanonicalPath, "operator.secret"), ordinaryPath = Path.Combine(binding.ArtifactRootCanonicalPath, "ordinary.secret");
        _ = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, operatorPath, Encoding.UTF8.GetBytes(connectionString), ct).ConfigureAwait(false);
        _ = await ConsumerColumnBootstrapWindowsSecretCustody.CreateAsync(binding, files, ordinaryPath, Encoding.UTF8.GetBytes(ordinary), ct).ConfigureAwait(false);
        var config = new ConsumerColumnBootstrapOperationalConfiguration("consumer-column-bootstrap-disposable-configuration-v1", await Store("source.json", source.Plan).ConfigureAwait(false),
            await Store("scope.json", scope).ConfigureAwait(false), Path.Combine(binding.ArtifactRootCanonicalPath, "review.json"), Path.Combine(binding.ArtifactRootCanonicalPath, "authorization.json"),
            await Store("pins.json", keys.Pins).ConfigureAwait(false), await Store("binding.json", binding).ConfigureAwait(false), operatorPath, ordinaryPath,
            await Store("before-fleet.json", baseline).ConfigureAwait(false), await Store("target.json", Pins).ConfigureAwait(false), publicReferences,
            nativePreparation, recoveryPreparation, rolePreparation, reviewPrivate, authorizationPrivate, receiptPrivate);
        _ = await Store("configuration.json", config).ConfigureAwait(false); return config;
    }

    private static async Task<(CurrentAppOwnedMaintenancePin Maintenance, string System)> MaintenanceAsync(string connectionString, DateTimeOffset issued, CancellationToken ct)
    {
        await using var connection = new NpgsqlConnection(connectionString); await connection.OpenAsync(ct).ConfigureAwait(false);
        const string sql = """
            SELECT current_user,shobj_description(r.oid,'pg_authid'),rolvaliduntil,pg_postmaster_start_time(),pg_conf_load_time(),
              encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
              current_setting('hba_file'),encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex')
            FROM pg_roles r,pg_control_system() WHERE rolname=current_user;
            """;
        await using var command = new NpgsqlCommand(sql, connection) { CommandTimeout = 30 };
        await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
        if (!await reader.ReadAsync(ct).ConfigureAwait(false)) { throw Invalid(); }
        var result = new CurrentAppOwnedMaintenancePin(reader.GetString(0), reader.GetString(1), issued,
            reader.GetFieldValue<DateTimeOffset>(2), reader.GetFieldValue<DateTimeOffset>(3), reader.GetFieldValue<DateTimeOffset>(4),
            reader.GetString(5), reader.GetString(6), reader.GetString(7));
        string system = reader.GetString(8); return await reader.ReadAsync(ct).ConfigureAwait(false) ? throw Invalid() : ((CurrentAppOwnedMaintenancePin Maintenance, string System))(result, system);
    }

    private static async Task<(CurrentAppOwnedRepairTargetPins Pins, string Observation, string Generation)> TargetAsync(ConsumerColumnBootstrapProofFixture fixture,
        string hbaPath, CurrentAppOwnedRepairCustody files, string root, CancellationToken ct)
    {
        async Task<string> Docker(IReadOnlyList<string> arguments)
        {
            return await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(arguments, ct, async resource =>
            {
                await WriteAsync(files, Path.Combine(root, $"resource-{resource.RunId:N}-{Guid.NewGuid():N}.json"), JsonSerializer.SerializeToUtf8Bytes(resource), CancellationToken.None).ConfigureAwait(false);
                if (resource.CleanupFailed) { throw Invalid(); }
            }).ConfigureAwait(false);
        }
        using var containers = JsonDocument.Parse(await Docker(["inspect", fixture.ContainerId]).ConfigureAwait(false));
        using var volumes = JsonDocument.Parse(await Docker(["volume", "inspect", fixture.VolumeName]).ConfigureAwait(false));
        JsonElement container = containers.RootElement.EnumerateArray().Single(), volume = volumes.RootElement.EnumerateArray().Single();
        string imageId = container.GetProperty("Image").GetString() ?? throw Invalid();
        string image = container.GetProperty("Config").GetProperty("Image").GetString() ?? throw Invalid();
        fixture.Require(fixture.OperationId, fixture.ExecutionBindingSha256, fixture.ContainerId, fixture.VolumeName, image);
        var pins = new CurrentAppOwnedRepairTargetPins(fixture.ContainerId, fixture.VolumeName, imageId, image, hbaPath, null, null, null);
        string generation = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(new
        {
            fixture.ContainerId,
            StartedAt = container.GetProperty("State").GetProperty("StartedAt").GetString(),
            ImageId = imageId
        }));
        var sanitized = JsonNode.Parse(container.GetRawText())!.AsObject(); _ = sanitized["Config"]!.AsObject().Remove("Env");
        string observation = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(new { Container = sanitized, Volume = volume }));
        return (pins, observation, generation);
    }

    private static async Task SeedAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, TableCopyPlan table, int id, CancellationToken ct)
    {
        string[] columns = [.. table.OrderedColumns.Except(table.GeneratedColumns.Select(column => column.Column), StringComparer.Ordinal)];
        await using var command = new NpgsqlCommand($"INSERT INTO {Q(table.TargetSchema)}.{Q(table.TargetTable)} ({string.Join(',', columns.Select(Q))}) VALUES ({string.Join(',', Enumerable.Range(1, columns.Length).Select(index => "$" + index))});",
            connection, transaction)
        { CommandTimeout = 30 };
        foreach (string column in columns)
        {
            object? value = table.NullableColumns.Contains(column, StringComparer.Ordinal) ? null : table.ColumnTypes[column] switch
            {
                "integer" => id,
                "boolean" => false,
                "numeric(18,2)" => 1m,
                "timestamp without time zone" => new DateTime(2000, 1, 1, 0, 0, 0, DateTimeKind.Unspecified),
                var type when type == "text" || type.StartsWith("character varying(", StringComparison.Ordinal) => "s" + id.ToString(CultureInfo.InvariantCulture) + " ไทย  ",
                _ => throw Invalid(),
            };
            _ = command.Parameters.AddWithValue(value ?? DBNull.Value);
        }
        _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
    }

    private static string Q(string name)
    {
        return PostgreSqlShadowTarget.QuoteIdentifier(name);
    }

    private static void ClearSecrets(string root, LocalExecutionBinding binding, DateTimeOffset createdAfter)
    {
        string[] names = ["review-private.pem", "authorization-private.pem", "receipt-private.pem", "operator.secret", "ordinary.secret"];
        if (!StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(root), binding.ArtifactRootCanonicalPath)) { throw Invalid(); }
        ConsumerColumnBootstrapWindowsSecretCustody.RemoveDetached(binding, names.Select(name => (Path.Combine(root, name), string.Empty)), createdAfter);
    }
    private static T Read<T>(CurrentAppOwnedRepairCustody files, string path)
    {
        return MigrationConsole.DecodeAuthRepair<T>(files.Read(path, sharedReader: true, maximumBytes: 64 * 1024 * 1024));
    }

    private static async Task WriteAsync(CurrentAppOwnedRepairCustody files, string path, byte[] bytes, CancellationToken ct)
    {
        await files.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
        // Do not keep secret-file handles here: each fixed Console step imports and owns its own custody.
    }
    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction? transaction, string sql, CancellationToken ct)
    { await using var command = new NpgsqlCommand(sql, connection, transaction) { CommandTimeout = 30 }; _ = await command.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
    private static MigrationExecutionException Invalid()
    {
        return ConsumerColumnBootstrapOperationalContract.Invalid();
    }
}
