using System.Data;
using System.Security.Cryptography;
using Npgsql;
using Testcontainers.PostgreSql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAppOwnedInstalledPolicyNativeTests
{
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task Native_policy_rechecks_installed_role_HBA_identity_and_other_clients(bool installExclusivePolicy)
    {
        const string role = "legacy_eight_native_policy";
        string password = Guid.NewGuid().ToString("N");
        string binding = new string('f', 64);
        string comment = "legacy-maliev-current-app-owned-eight-v1:" + binding;
        DateTimeOffset issued = DateTimeOffset.UtcNow;
        await using var postgres = new PostgreSqlBuilder(
            "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382")
            .WithDatabase("Customer")
            .WithUsername("postgres").WithPassword(Guid.NewGuid().ToString("N"))
            .WithCreateParameterModifier(parameters =>
            {
                parameters.HostConfig!.Memory = 384 * 1024 * 1024;
                parameters.HostConfig.MemorySwap = 384 * 1024 * 1024;
                parameters.HostConfig.NanoCPUs = 500_000_000;
            }).Build();
        await postgres.StartAsync();
        var administrator = new NpgsqlConnectionStringBuilder(postgres.GetConnectionString()) { Pooling = false };
        await using (var setup = new NpgsqlConnection(administrator.ConnectionString))
        {
            await setup.OpenAsync();
            await using var create = new NpgsqlCommand(
                $"CREATE ROLE {role} LOGIN SUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS " +
                $"PASSWORD '{password}' VALID UNTIL '{issued.AddMinutes(30):O}'; COMMENT ON ROLE {role} IS '{comment}';", setup);
            _ = await create.ExecuteNonQueryAsync();
            if (installExclusivePolicy)
            {
                // Rewrite only this run-owned disposable container's policy file.
                await using var path = new NpgsqlCommand("SELECT current_setting('hba_file');", setup);
                string policyPath = (string)(await path.ExecuteScalarAsync())!;
                await using var install = new NpgsqlCommand(
                    $"COPY (VALUES ('local all all trust'), ('host all {role} 0.0.0.0/0 scram-sha-256'), " +
                    $"('host all {role} ::/0 scram-sha-256'), ('host all all 0.0.0.0/0 reject'), " +
                    $"('host all all ::/0 reject')) TO '{policyPath.Replace("'", "''", StringComparison.Ordinal)}'; SELECT pg_reload_conf();", setup);
                _ = await install.ExecuteNonQueryAsync();
                bool rejected = false;
                for (int attempt = 0; attempt < 20 && !rejected; attempt++)
                {
                    try
                    {
                        await using var ordinary = new NpgsqlConnection(administrator.ConnectionString);
                        await ordinary.OpenAsync();
                    }
                    catch (PostgresException failure) when (failure.SqlState == "28000") { rejected = true; }
                    if (!rejected) { await Task.Delay(TimeSpan.FromMilliseconds(50)); }
                }
                Assert.True(rejected);
            }
        }
        var executor = new NpgsqlConnectionStringBuilder(administrator.ConnectionString) { Username = role, Password = password };
        await using var connection = new NpgsqlConnection(executor.ConnectionString);
        await connection.OpenAsync();
        string identity, hba, hbaRules, hbaPath;
        DateTimeOffset postmaster, loaded, expires;
        await using (var observe = new NpgsqlCommand("""
            SELECT encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex'),
                pg_postmaster_start_time(),pg_conf_load_time(),
                encode(sha256(convert_to(pg_read_file(current_setting('hba_file')),'UTF8')),'hex'),
                (SELECT encode(sha256(convert_to(jsonb_agg(to_jsonb(h) ORDER BY rule_number)::text,'UTF8')),'hex') FROM pg_hba_file_rules h),
                current_setting('hba_file'),rolvaliduntil
            FROM pg_control_system(),pg_roles WHERE rolname=current_user;
            """, connection))
        await using (NpgsqlDataReader reader = await observe.ExecuteReaderAsync())
        {
            Assert.True(await reader.ReadAsync());
            identity = reader.GetString(0); postmaster = reader.GetFieldValue<DateTimeOffset>(1);
            loaded = reader.GetFieldValue<DateTimeOffset>(2); hba = reader.GetString(3); hbaRules = reader.GetString(4);
            hbaPath = reader.GetString(5); expires = reader.GetFieldValue<DateTimeOffset>(6);
        }
        // Component fixture scope only: no source/custody issuer, proof artifact or persistent authority is asserted.
        var scope = new CurrentAppOwnedRepairScope(Guid.NewGuid(), CurrentAppOwnedRepairOperation.CreateEightTables,
            new string('a', 40), new string('b', 64), new string('c', 64),
            CurrentAppOwnedRepairManifest.OperationSha256(CurrentAppOwnedRepairOperation.CreateEightTables),
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-native-policy", identity),
            "local-aspire", "legacy-postgres-main-local", "disposable-native-policy", new string('d', 64), binding,
            CurrentAppOwnedRepairManifest.Databases(CurrentAppOwnedRepairOperation.CreateEightTables)
                .ToDictionary(database => database, _ => new string('e', 64), StringComparer.Ordinal),
            new string('b', 64), new string('c', 64), new string('d', 64), new string('e', 64),
            new(role, comment, issued, expires, postmaster, loaded, hba, hbaRules, hbaPath));
        await CheckAsync(scope);
        foreach (CurrentAppOwnedRepairScope stale in new[]
        {
            scope with { Target = scope.Target with { SystemIdentifierSha256 = new string('0', 64) } },
            scope with { Maintenance = scope.Maintenance with { HbaSha256 = new string('0', 64) } },
            scope with { Maintenance = scope.Maintenance with { HbaRulesSha256 = new string('0', 64) } },
            scope with { Maintenance = scope.Maintenance with { Postmaster = postmaster.AddSeconds(-1) } },
            scope with { Maintenance = scope.Maintenance with { ConfigLoaded = loaded.AddSeconds(-1) } },
            scope with { Maintenance = scope.Maintenance with { RoleComment = "unbound" } },
            scope with { Maintenance = scope.Maintenance with { ExpiresAtUtc = expires.AddSeconds(-1) } },
        })
        { _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CheckAsync(stale)); }
        await using (var other = new NpgsqlConnection(executor.ConnectionString))
        {
            await other.OpenAsync();
            _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CheckAsync(scope));
        }
        await ExecuteAsync($"ALTER ROLE {role} CREATEDB;");
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CheckAsync(scope));
        await ExecuteAsync($"ALTER ROLE {role} NOCREATEDB; COMMENT ON ROLE {role} IS 'unbound';");
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CheckAsync(scope));
        await ExecuteAsync($"COMMENT ON ROLE {role} IS '{comment}';");
        await CheckAsync(scope);

        FreshSchemaPlan before = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerColumnsV1)
            with
        { CapturedAtUtc = DateTimeOffset.UtcNow };
        FreshSchemaPlan after = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV2)
            with
        { CapturedAtUtc = before.CapturedAtUtc };
        await using (var setup = await connection.BeginTransactionAsync())
        {
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, setup, ownsResources: false);
            DatabaseSchemaPlan schema = before.Databases.Single(plan => plan.Database == "Customer");
            await inspector.ApplySchemaAsync(schema, CancellationToken.None);
            await inspector.FinalizeSchemaAsync(schema, CancellationToken.None);
            await using var owner = new NpgsqlCommand("CREATE ROLE legacy_local NOLOGIN;", connection, setup);
            _ = await owner.ExecuteNonQueryAsync();
            await setup.CommitAsync();
        }
        CurrentAppOwnedDatabaseSnapshot baseline;
        await using (var snapshot = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead))
        { baseline = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, snapshot, CancellationToken.None); }
        scope = scope with
        {
            BeforeSchemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(before),
            AfterSchemaPlanSha256 = SchemaPlanCanonicalizer.ComputeSha256(after),
            BeforeDatabaseSha256 = scope.BeforeDatabaseSha256.ToDictionary(pair => pair.Key,
                pair => pair.Key == "Customer" ? baseline.Sha256 : pair.Value, StringComparer.Ordinal),
            GlobalPreservationSha256 = baseline.Sha256,
        };
        await connection.CloseAsync();
        using var reviewKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var receiptKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new ReceiptAttestationTrustStore([new("native-review", reviewKey.ExportSubjectPublicKeyInfo()),
            new("native-authorization", authorizationKey.ExportSubjectPublicKeyInfo()), new("native-receipt", receiptKey.ExportSubjectPublicKeyInfo())]);
        _ = trust.TryGetPublicKeyFingerprintSha256("native-review", out string reviewFingerprint);
        _ = trust.TryGetPublicKeyFingerprintSha256("native-authorization", out string authorizationFingerprint);
        _ = trust.TryGetPublicKeyFingerprintSha256("native-receipt", out string receiptFingerprint);
        var pins = new CurrentAppOwnedRepairSigningPins("native-review", reviewFingerprint,
            "native-authorization", authorizationFingerprint, "native-receipt", receiptFingerprint);
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var unsigned = new CurrentAppOwnedRepairSignedClaim("current-app-owned-eight-review-v1", scope,
            Guid.NewGuid(), null, now, now.AddMinutes(10), pins.ReviewKeyId, null);
        CurrentAppOwnedRepairSignedClaim review = unsigned with
        {
            Signature = Convert.ToBase64String(reviewKey.SignData(
            CurrentAppOwnedRepairPermit.Payload(unsigned), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation))
        };
        var environment = new NativeEnvironment(executor.ConnectionString, scope, baseline);
        using var authorizationSigner = new P256MigrationEvidenceSigner(pins.AuthorizationKeyId, authorizationKey.ExportPkcs8PrivateKeyPem());
        CurrentAppOwnedRepairSignedClaim authorization = await CurrentAppOwnedRepairPermit.AuthorizeAsync(review,
            before, after, trust, pins, environment, authorizationSigner, TimeProvider.System, CancellationToken.None);
        CurrentAppOwnedRepairPermit permit = await CurrentAppOwnedRepairPermit.AdmitAsync(review, authorization,
            before, after, trust, pins, environment, TimeProvider.System, CancellationToken.None);
        using var receiptSigner = new P256MigrationEvidenceSigner(pins.ReceiptKeyId, receiptKey.ExportPkcs8PrivateKeyPem());
        CurrentAppOwnedRepairReceipt result = await PostgreSqlCurrentAppOwnedEightRepair.ExecuteDatabaseAsync(
            executor.ConnectionString, "Customer", before, after, baseline, permit, receiptSigner, trust, pins, new string('0', 64), CancellationToken.None);
        Assert.Equal(CurrentAppOwnedCommitClassification.CommittedAndReadback, result.Classification);
        Assert.Equal(2, environment.Evidence.Count);
        Assert.True(environment.GlobalObservations >= 3);

        async Task CheckAsync(CurrentAppOwnedRepairScope current)
        {
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead);
            await PostgreSqlCurrentAppOwnedEightRepair.RequireInstalledPolicyAsync(connection, transaction, current, CancellationToken.None);
        }
        async Task ExecuteAsync(string sql)
        {
            await using var command = new NpgsqlCommand(sql, connection);
            _ = await command.ExecuteNonQueryAsync();
        }
    }

    // Actual Core executor and independent native catalog observer. Source/custody
    // assertions and the in-memory sink are component fixtures, not Console proof.
    private sealed class NativeEnvironment(string connectionString, CurrentAppOwnedRepairScope scope,
        CurrentAppOwnedDatabaseSnapshot baseline) : ICurrentAppOwnedRepairEnvironment
    {
        internal Dictionary<string, byte[]> Evidence { get; } = new(StringComparer.Ordinal);
        internal int GlobalObservations { get; private set; }
        public Task RequireSourceAsync(string sourceCommitSha, CancellationToken cancellationToken)
        {
            Assert.Equal(scope.SourceCommitSha, sourceCommitSha);
            return Task.CompletedTask;
        }
        public Task RequireResourceAndCustodyAsync(CurrentAppOwnedRepairScope current, CancellationToken cancellationToken)
        {
            Assert.Equal(scope.OperationId, current.OperationId);
            return Task.CompletedTask;
        }
        public async Task<string> InspectGlobalPreservationAsync(CancellationToken cancellationToken)
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync(cancellationToken);
            await using var transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, cancellationToken);
            await PostgreSqlCurrentAppOwnedEightRepair.RequireInstalledPolicyAsync(connection, transaction, scope, cancellationToken);
            CurrentAppOwnedDatabaseSnapshot observed = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, transaction, cancellationToken);
            string[] present = [.. observed.Relations.Where(relation => relation.Schema == "public" &&
                CurrentAppOwnedRepairManifest.NewTables("Customer").Contains(relation.Name, StringComparer.Ordinal)).Select(relation => relation.Name)];
            IReadOnlySet<string> closure = present.Length == 0 ? new HashSet<string>() :
                await CurrentAppOwnedRepairPreservation.ObserveNewObjectClosureAsync(connection, transaction, "Customer", "legacy_local", cancellationToken);
            CurrentAppOwnedRepairPreservation.RequirePreserved(baseline, observed, closure, present);
            GlobalObservations++;
            return scope.GlobalPreservationSha256;
        }
        public Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken cancellationToken)
        {
            Evidence.Add(name, payload);
            return Task.CompletedTask;
        }
    }
}
