using System.Data;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Console;

// Actual read-only observation producer. It issues no permit and has no DDL,
// reservation, provider, injected observation or maintenance-install callback.
internal static class IsoIntendedRuntimeObserver
{
    internal static async Task<IsoIntendedRuntimeObservation> ObserveAndRetainAsync(CurrentAppOwnedRepairCustody files,
        LocalExecutionBinding binding, IsoIntendedObservationConfiguration config, CancellationToken ct)
    {
        CurrentOwnerIsoCapacity.Require(admission: true); files.Require();
        DateTimeOffset began = DateTimeOffset.UtcNow;
        T Read<T>(string path, int maximum = 8_000_000)
        {
            return MigrationConsole.DecodeOwnerIso<T>(files.Read(path, sharedReader: true, maximumBytes: maximum));
        }

        if (Read<LocalExecutionBinding>(config.BindingPath, 65536) != binding) { throw IsoIntendedRuntimeReader.Invalid(); }
        var facts = Read<IsoIntendedRuntimeFacts>(config.FactsPath); var source = Read<FreshSchemaPlan>(config.SourcePath, 32 * 1024 * 1024); var owners = Read<CurrentOwnerIsoSourceObservation[]>(config.OwnersPath);
        IsoIntendedRuntimeReader.RequireFacts(facts, source, owners, binding, began);
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false);
        if (accepted != facts.SourceCommitSha) { throw IsoIntendedRuntimeReader.Invalid(); }
        var pins = Read<CurrentOwnerIsoRepairSigningPins>(config.SigningPinsPath, 65536); var trust = IsoIntendedRuntimeReader.Trust(files, config.TrustedKeys, pins);
        using var signer = new P256MigrationEvidenceSigner(pins.ReviewKeyId, Encoding.UTF8.GetString(files.Read(config.ReviewPrivateKeyPath, sharedReader: true, maximumBytes: 65536)));
        if (signer.PublicKeyFingerprintSha256 != pins.ReviewFingerprint) { throw IsoIntendedRuntimeReader.Invalid(); }
        var target = Read<CurrentAppOwnedRepairTargetPins>(config.TargetPinsPath, 1_000_000);
        if (CurrentAppOwnedSnapshotSerialization.Sha256(target) != facts.TargetObservationSha256 || target.CloudOptions is not null || target.CloudObservation is not null) { throw IsoIntendedRuntimeReader.Invalid(); }
        MigrationConsole.RequireCanonicalHelper(files.Read(config.MaintenanceValidatorPath, sharedReader: true, maximumBytes: 1_000_000), facts.MaintenanceValidatorSha256);
        var endpoint = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(files.Read(config.OperatorConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim());
        var ordinary = new NpgsqlConnectionStringBuilder(Encoding.UTF8.GetString(files.Read(config.OrdinaryConnectionPath, sharedReader: true, maximumBytes: 65536)).Trim());
        if (endpoint.Host != "127.0.0.1" || endpoint.Username != facts.Maintenance.Role || endpoint.Pooling || endpoint.Port is < 1 or > 65535 || endpoint.IncludeErrorDetail || string.IsNullOrWhiteSpace(endpoint.Password) || ordinary.Host != endpoint.Host || ordinary.Port != endpoint.Port || ordinary.Username != "legacy_local") { throw IsoIntendedRuntimeReader.Invalid(); }
        // This incomplete metadata view is used only by the existing source/policy
        // READERS. Empty future/recovery hashes make it invalid for every permit.
        var readOnlyView = new CurrentOwnerIsoRepairScope(facts.OperationId, CurrentOwnerIsoSelection.LiteralWidthV1, facts.SourceCommitSha, facts.SourceSchemaPlanSha256, facts.OwnerSourcesSha256, facts.ContractSha256, facts.OperationSha256, facts.Target, facts.TargetNamespace, facts.TargetCluster, facts.TargetGeneration, facts.TargetObservationSha256, facts.RunBindingSha256, facts.BeforeDatabaseSha256, facts.GlobalPreservationSha256, string.Empty, string.Empty, string.Empty, facts.Maintenance, "readonly-observation-no-authority", facts.SourceCatalogSha256, facts.MaintenanceValidatorSha256, string.Empty);
        int ordinal = 0;
        Task Resource(CurrentAppOwnedDockerResource resource)
        {
            return files.WriteNewAsync(Path.Combine(binding.ArtifactRootCanonicalPath, $"iso-intended-{facts.OperationId:N}-{Interlocked.Increment(ref ordinal):D5}-resource.json"), JsonSerializer.SerializeToUtf8Bytes(resource), CancellationToken.None);
        }

        using var sourceObserver = new CurrentOwnerIsoRepairSourceObservation(files, readOnlyView, config.SourceInputs, source, Resource);
        await RequireSourceAsync().ConfigureAwait(false); await RequireTargetAsync().ConfigureAwait(false);
        await RequirePrecursorsAsync().ConfigureAwait(false);
        var baseline = await files.ReadBaselineAsync(config.GlobalBeforePath, ct, sharedReader: true).ConfigureAwait(false);
        if (baseline.Length != 26 || CurrentAppOwnedSnapshotSerialization.Sha256(baseline) != facts.GlobalPreservationSha256 || baseline.Any(x => !facts.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || hash != x.Sha256)) { throw IsoIntendedRuntimeReader.Invalid(); }
        var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, accepted, CurrentOwnerIsoSelection.LiteralWidthV1, owners, DateTimeOffset.UtcNow);
        var snapshots = new List<CurrentAppOwnedDatabaseSnapshot>(); var natives = new Dictionary<string, IsoCapturedNative>(StringComparer.Ordinal); int version = 0;
        foreach (string database in facts.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))
        {
            CurrentOwnerIsoCapacity.Require(admission: false);
            await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(endpoint.ConnectionString) { Database = database, Pooling = false, Timeout = 5, CommandTimeout = 30, IncludeErrorDetail = false }.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false); await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, tx)) { _ = await readOnly.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
            await PostgreSqlCurrentOwnerIsoRepair.RequireInstalledPolicyAsync(connection, tx, readOnlyView, ct).ConfigureAwait(false);
            await using (var metadata = new NpgsqlCommand("SELECT current_setting('server_version_num')::int;", connection, tx)) { int actual = (int)(await metadata.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw IsoIntendedRuntimeReader.Invalid()); if (actual != 180004 || (version != 0 && actual != version)) { throw IsoIntendedRuntimeReader.Invalid(); } version = actual; }
            if (database == "postgres")
            { await using var inventory = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", connection, tx); var names = new List<string>(); await using (var rows = await inventory.ExecuteReaderAsync(ct).ConfigureAwait(false)) { while (await rows.ReadAsync(ct).ConfigureAwait(false)) { names.Add(rows.GetString(0)); } } if (!names.SequenceEqual(facts.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw IsoIntendedRuntimeReader.Invalid(); } }
            var raw = await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct).ConfigureAwait(false);
            if (raw.Sha256 != facts.BeforeDatabaseSha256[database]) { throw IsoIntendedRuntimeReader.Invalid(); }
            snapshots.Add(raw);
            if (database is "Country" or "Material")
            {
                await using (var owner = new NpgsqlCommand("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S','i','I') AND pg_get_userbyid(c.relowner)<>'legacy_local';", connection, tx)) { if ((long)(await owner.ExecuteScalarAsync(ct).ConfigureAwait(false) ?? throw IsoIntendedRuntimeReader.Invalid()) != 0) { throw IsoIntendedRuntimeReader.Invalid(); } }
                var native = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, contract, false, ct).ConfigureAwait(false); CurrentOwnerIsoNativePreservation.RequireBefore(native, contract); if (native.Snapshot.Sha256 != raw.Sha256) { throw IsoIntendedRuntimeReader.Invalid(); }
                natives.Add(database, IsoCapturedNative.Capture(native));
            }
            if (DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal))
            { var physical = source.Databases.Single(x => x.Database == database); await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false); if (await inspector.InspectSchemaAsync(physical, ct).ConfigureAwait(false) != physical.TargetSchemaSha256) { throw IsoIntendedRuntimeReader.Invalid(); } }
            await tx.RollbackAsync(ct).ConfigureAwait(false);
            ordinary.Database = database; ordinary.Pooling = false; ordinary.Timeout = 5; ordinary.IncludeErrorDetail = false; bool denied = false;
            try { await using var probe = new NpgsqlConnection(ordinary.ConnectionString); await probe.OpenAsync(ct).ConfigureAwait(false); } catch (PostgresException error) when (error.SqlState == "28000") { denied = true; }
            if (!denied) { throw IsoIntendedRuntimeReader.Invalid(); }
        }
        await RequireTargetAsync().ConfigureAwait(false); await RequireSourceAsync().ConfigureAwait(false); CurrentOwnerIsoCapacity.Require(admission: false);
        string prefix = Path.Combine(binding.ArtifactRootCanonicalPath, "iso-intended-" + facts.OperationId.ToString("N"));
        await files.WriteBaselineNewAsync(prefix + "-fleet.json", snapshots.ToArray(), ct).ConfigureAwait(false);
        foreach (var native in natives) { await files.WriteNewAsync(prefix + "-before-" + native.Key + ".json", JsonSerializer.SerializeToUtf8Bytes(native.Value), ct).ConfigureAwait(false); }
        DateTimeOffset now = DateTimeOffset.UtcNow, expires = now.AddHours(2) < facts.Maintenance.ExpiresAtUtc ? now.AddHours(2) : facts.Maintenance.ExpiresAtUtc;
        var unsigned = new IsoIntendedRuntimeObservation("current-owner-iso-intended-runtime-v1", facts, config.DefinitionSubject, config.PrecursorPins.DefinitionProofSha256,
            Artifact(config.SourcePath), Artifact(config.OwnersPath), Artifact(config.SourceInputs.AcceptedCatalogReportPath), Artifact(config.TargetPinsPath), Artifact(prefix + "-before-Country.json"), Artifact(prefix + "-before-Material.json"), Artifact(prefix + "-fleet.json"), version, now, expires, signer.KeyId, null);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(IsoIntendedRuntimeReader.Payload(unsigned))) };
        await files.WriteNewAsync(config.OutputPath, JsonSerializer.SerializeToUtf8Bytes(signed), ct).ConfigureAwait(false);
        _ = await IsoIntendedRuntimeReader.RequireHeldAsync(files, binding, new(config.BindingPath, Artifact(config.OutputPath), config.SigningPinsPath, config.TrustedKeys), source, owners, pins, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        files.Require(); return signed;
        IsoDefinitionArtifact Artifact(string path) { using var held = SecureLocalFile.OpenReadShared(path); return new(path, Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(held))); }
        async Task RequireSourceAsync()
        { if (await SourceBackedLocalRepairSourceAcceptance.RequireAsync(ct).ConfigureAwait(false) != accepted) { throw IsoIntendedRuntimeReader.Invalid(); } _ = await sourceObserver.ObserveCatalogAsync(accepted, ct).ConfigureAwait(false); var actual = await sourceObserver.ObserveOwnersAsync(owners, ct).ConfigureAwait(false); if (actual.Length != owners.Length || actual.Zip(owners).Any(x => x.First.Repository != x.Second.Repository || x.First.Head != x.Second.Head || !x.First.Clean || JsonSerializer.Serialize(x.First.Files) != JsonSerializer.Serialize(x.Second.Files))) { throw IsoIntendedRuntimeReader.Invalid(); } }
        async Task RequireTargetAsync()
        {
            foreach (string name in new[] { "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH" }) { if (!string.IsNullOrEmpty(Environment.GetEnvironmentVariable(name))) { throw IsoIntendedRuntimeReader.Invalid(); } }
            if (!CurrentOwnerIsoRepairLocalTarget.RequireClaim(facts.Target, facts.OperationId, facts.RunBindingSha256, target)) { throw IsoIntendedRuntimeReader.Invalid(); }
            Task<string> Docker(IReadOnlyList<string> args)
            {
                return CurrentAppOwnedRepairDockerProcess.RunDockerAsync(args, ct, Resource);
            }

            string container = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "container", target.DockerContainerId!]).ConfigureAwait(false), volume = await Docker(["--host", "npipe:////./pipe/docker_engine", "inspect", "--type", "volume", target.DockerVolume!]).ConfigureAwait(false);
            var actual = DockerLocalTargetObservation.Parse(container, volume, target.DockerContainerId!, target.DockerVolume!, endpoint.Port, true); using var document = JsonDocument.Parse(container); var item = document.RootElement[0];
            if (LocalDockerGenerationGuard.ComposeGeneration(actual) != facts.TargetGeneration || item.GetProperty("Image").GetString() != target.DockerImageId || item.GetProperty("Config").GetProperty("Image").GetString() != target.DockerImageReference) { throw IsoIntendedRuntimeReader.Invalid(); }
            string writers = await Docker(["--host", "npipe:////./pipe/docker_engine", "ps", "--all", "--no-trunc", "--filter", "volume=" + target.DockerVolume, "--format", "{{.ID}}"]).ConfigureAwait(false); CurrentOwnerIsoRepairLocalTarget.RequireVolumeConsumers(writers, target.DockerContainerId!);
            string stat = await Docker(["--host", "npipe:////./pipe/docker_engine", "exec", target.DockerContainerId!, "env", "TZ=UTC", "LC_ALL=C", "stat", "--printf=%d|%i|%f|%u|%g|%h|%s|%y|%z", "--", target.HbaPath]).ConfigureAwait(false); if (CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stat)) != target.HbaStatSha256) { throw IsoIntendedRuntimeReader.Invalid(); }
        }
        async Task RequirePrecursorsAsync()
        {
            using var raw = SecureLocalFile.OpenReadShared(config.CompletedPrecursors.BindingPath); if (raw.Length is < 1 or > 65536) { throw IsoIntendedRuntimeReader.Invalid(); }
            byte[] bytes = new byte[(int)raw.Length]; raw.ReadExactly(bytes); var original = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(bytes);
            if (original.ComputeSha256() != config.PrecursorPins.RootBindingSha256 || original.ComputeSha256() == binding.ComputeSha256()) { throw IsoIntendedRuntimeReader.Invalid(); }
            using var authority = WindowsLocalRunAuthority.AcquireResume(original.ArtifactRootCanonicalPath, original); using var originalFiles = new CurrentAppOwnedRepairCustody(authority);
            if (!originalFiles.Read(config.CompletedPrecursors.BindingPath, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(bytes)) { throw IsoIntendedRuntimeReader.Invalid(); }
            var originalTrust = new ReceiptAttestationTrustStore([new(config.PrecursorPins.ProofKeyId, originalFiles.Read(config.CompletedPrecursors.ComponentPublicKeyPath, sharedReader: true, maximumBytes: 4096)), new(config.PrecursorPins.DefinitionKeyId, originalFiles.Read(config.CompletedPrecursors.DefinitionPublicKeyPath, sharedReader: true, maximumBytes: 4096))]);
            foreach (var tuple in new[] { (config.CompletedPrecursors.NativeComponentPath, config.NativeComponentSha256, IsoComponentProofPhase.Native), (config.CompletedPrecursors.MaintenanceComponentPath, config.MaintenanceComponentSha256, IsoComponentProofPhase.Maintenance) })
            { var report = MigrationConsole.DecodeOwnerIso<IsoComponentProof>(IsoIntendedRuntimeReader.Read(originalFiles, new(tuple.Item1, tuple.Item2), 8_000_000)); if (report.Phase != tuple.Item3 || report.Definition.Sha256 != config.PrecursorPins.DefinitionProofSha256) { throw IsoIntendedRuntimeReader.Invalid(); } await IsoComponentProofReader.RequireAsync(originalFiles, report, config.DefinitionSubject, originalTrust, config.PrecursorPins.ProofKeyId, config.PrecursorPins.ProofFingerprint, config.PrecursorPins.DefinitionKeyId, config.PrecursorPins.DefinitionFingerprint, DateTimeOffset.UtcNow, ct).ConfigureAwait(false); }
        }
    }
}
