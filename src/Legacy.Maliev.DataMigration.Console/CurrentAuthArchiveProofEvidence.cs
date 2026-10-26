using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static partial class CurrentAuthArchiveProofReader
{
    internal static void RequireEffects(string id, CurrentAuthArchiveProofScenario scenario, IReadOnlyList<CurrentAuthArchiveReceipt> receipts,
        CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot after)
    {
        bool positive = Positive(id), same = before.Sha256 == after.Sha256;
        if (id is "complete" or "exact-reviewed-delete")
        {
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, after);
            if (scenario.Boundary != "complete" || scenario.RejectionCode is not null || !scenario.CommitAcknowledged || !scenario.LocalDeleteAttempted || receipts.Count != 2 || receipts[0].Classification != CurrentAppOwnedCommitClassification.Prepared ||
                receipts[1].Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback || receipts[1].AfterAuthSha256 != after.Sha256) { throw Invalid(); }
        }
        else if (id is "commit-ack-lost" or "terminal-publication")
        {
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(before, after);
            if (scenario.Boundary != id || !scenario.LocalDeleteAttempted || scenario.CommitAcknowledged != (id == "terminal-publication") || string.IsNullOrWhiteSpace(scenario.RejectionCode) ||
                receipts.Count is < 2 or > 3 || receipts[0].Classification != CurrentAppOwnedCommitClassification.Prepared || receipts[^1].Classification != CurrentAppOwnedCommitClassification.Uncertain ||
                receipts.Any(x => x.AfterAuthSha256 != after.Sha256) || (receipts.Count == 3 && receipts[1].Classification != CurrentAppOwnedCommitClassification.CommittedAndReadback)) { throw Invalid(); }
        }
        else if (id == "prepared-publication")
        {
            if (scenario.Boundary != "prepared-publication-before-ack" || !same || scenario.CommitAcknowledged || !scenario.LocalDeleteAttempted || string.IsNullOrWhiteSpace(scenario.RejectionCode) || receipts.Count != 1 ||
                receipts[0].Classification is not (CurrentAppOwnedCommitClassification.RolledBackBeforeCommit or CurrentAppOwnedCommitClassification.FailedBeforeCommit)) { throw Invalid(); }
        }
        else
        {
            string boundary = id switch
            {
                "host-unprobed-sdk" or "local-trust" => "maintenance-semantic",
                "CAS-field-drift" => "cas-preflight",
                "private-journal-drift" or "sequence-drift" or "production-drift" => "fleet-preflight",
                "first-only-decrypt-insert-readback" or "second-only-decrypt-insert-readback" => "decrypted-insert-independent-readback",
                _ => id
            };
            if (scenario.Boundary != boundary || !same || receipts.Count != 0 || (positive ? scenario.RejectionCode is not null : string.IsNullOrWhiteSpace(scenario.RejectionCode)) || scenario.LocalDeleteAttempted ||
                ((id is "host-unprobed-sdk" or "local-trust") && scenario.RejectionCode != "current_app_owned_maintenance_hba_not_exclusive")) { throw Invalid(); }
        }
    }
    internal static void RequireCleanup(CurrentAuthArchiveProofRun run, CurrentAuthArchiveProofCleanup cleanup, CurrentAuthArchiveProofAbsence absence,
        DateTimeOffset lastExit, DateTimeOffset proofCompleted, IReadOnlyList<int> ownedPorts)
    {
        string[] ids = [run.ContainerId, run.ComparisonContainerId], volumes = [run.Volume, run.ComparisonVolume];
        if (run.RunId == Guid.Empty || ids.Distinct(StringComparer.Ordinal).Count() != 2 || ids.Any(x => x.Length != 64 || !x.All(char.IsAsciiHexDigitLower)) ||
            volumes.Distinct(StringComparer.Ordinal).Count() != 2 || run.BeganAtUtc.Offset != TimeSpan.Zero || run.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            run.ExpiresAtUtc - run.BeganAtUtc != TimeSpan.FromMinutes(8) || cleanup.RunId != run.RunId || absence.RunId != run.RunId ||
            cleanup.RemovedAtUtc.Offset != TimeSpan.Zero || cleanup.CompletedAtUtc.Offset != TimeSpan.Zero || absence.ObservedAtUtc.Offset != TimeSpan.Zero ||
            cleanup.RemovedAtUtc < lastExit || lastExit < run.BeganAtUtc || absence.ObservedAtUtc < cleanup.RemovedAtUtc || absence.ObservedAtUtc > run.ExpiresAtUtc ||
            cleanup.CompletedAtUtc < absence.ObservedAtUtc || cleanup.CompletedAtUtc > proofCompleted || !cleanup.Exited || !cleanup.ReadersSettled || cleanup.CleanupFailed ||
            !cleanup.RemovedContainerIds.Order(StringComparer.Ordinal).SequenceEqual(ids.Order(StringComparer.Ordinal)) ||
            !cleanup.RemovedVolumes.Order(StringComparer.Ordinal).SequenceEqual(volumes.Order(StringComparer.Ordinal)) ||
            !absence.ContainerInventorySucceeded || !absence.VolumeInventorySucceeded || !absence.ListenerInventorySucceeded ||
            ids.Any(x => absence.ContainerIds.Contains(x, StringComparer.Ordinal)) || volumes.Any(x => absence.Volumes.Contains(x, StringComparer.Ordinal)) ||
            ownedPorts.Count is < 2 or > 3 || ownedPorts.Any(x => x is < 1 or > 65535 || absence.LoopbackListeners.Contains(x)) || ownedPorts.Distinct().Count() != ownedPorts.Count) { throw Invalid(); }
    }
    private static void RequireOwnership(CurrentAuthArchiveProofOwnership value, CurrentAuthArchiveProofRun run, CurrentAuthArchiveScope scope,
        CurrentAppOwnedRepairTargetPins local, CurrentAppOwnedRepairTargetPins comparison, DateTimeOffset now, Func<CurrentAuthArchiveProofArtifact, byte[]> read)
    {
        if (value.RunId != run.RunId || value.Persistent || value.Purpose != "current-auth-local-session-archive-proof" ||
            run.Volume != local.DockerVolume || run.ComparisonVolume != comparison.DockerVolume || local.DockerContainerId != run.ContainerId || comparison.DockerContainerId != run.ComparisonContainerId ||
            !value.LocalVolumeConsumers.SequenceEqual([run.ContainerId]) || !value.ComparisonVolumeConsumers.SequenceEqual([run.ComparisonContainerId]) ||
            value.LocalPort == value.ComparisonPort || value.ObservedAtUtc.Offset != TimeSpan.Zero || value.ObservedAtUtc > now || now - value.ObservedAtUtc > TimeSpan.FromMinutes(1)) { throw Invalid(); }
        Check(value.LocalContainer, value.LocalVolume, local, scope.LocalObservationPolicy, value.LocalPort, false);
        Check(value.ComparisonContainer, value.ComparisonVolume, comparison, scope.ProductionObservationPolicy, value.ComparisonPort, true);
        void Check(CurrentAuthArchiveProofArtifact c, CurrentAuthArchiveProofArtifact v, CurrentAppOwnedRepairTargetPins target, CurrentAuthRepairScope policy, int port, bool second)
        {
            using var container = JsonDocument.Parse(read(c)); using var volume = JsonDocument.Parse(read(v)); var element = container.RootElement;
            if (element.GetProperty("HostConfig").GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 ||
                element.GetProperty("HostConfig").GetProperty("NanoCpus").GetInt64() != 750_000_000 ||
                volume.RootElement.GetProperty("Driver").GetString() != "local" || volume.RootElement.GetProperty("Scope").GetString() != "local") { throw Invalid(); }
            CurrentAuthLocalSessionArchiveTarget.RequireDisposable(element, volume.RootElement, scope.OperationId, policy.RunBindingSha256, now, second);
            string pgData = element.GetProperty("Config").GetProperty("PgData").GetString() ?? throw Invalid();
            var projected = JsonSerializer.SerializeToElement(new
            {
                Id = element.GetProperty("Id"),
                Name = element.GetProperty("Name"),
                State = element.GetProperty("State"),
                Created = element.GetProperty("Created"),
                Mounts = element.GetProperty("Mounts"),
                NetworkSettings = element.GetProperty("NetworkSettings"),
                Config = new { Env = new[] { "PGDATA=" + pgData } }
            });
            var observed = DockerLocalTargetObservation.Parse("[" + projected.GetRawText() + "]", "[" + volume.RootElement.GetRawText() + "]", target.DockerContainerId!, target.DockerVolume!, port, false);
            if (element.GetProperty("Image").GetString() != target.DockerImageId || element.GetProperty("Config").GetProperty("Image").GetString() != target.DockerImageReference ||
                observed.PgData != pgData || target.HbaPath != pgData.TrimEnd('/') + "/pg_hba.conf" || LocalDockerGenerationGuard.ComposeGeneration(observed) != policy.TargetGeneration ||
                policy.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + target.DockerContainerId![..12]) { throw Invalid(); }
        }
    }
    private static void RequirePolicy(CurrentAuthArchiveProofPolicy value, CurrentAuthRepairScope policy, CurrentAuthArchiveProofInvocation invocation,
        Func<CurrentAuthArchiveProofArtifact, byte[]> read, string caseId)
    {
        if (value.Maintenance != policy.Maintenance || value.SystemIdentifierSha256 != policy.Target.SystemIdentifierSha256 || !value.Superuser || !value.Login ||
            value.CreateRole || value.CreateDatabase || value.Replication || value.BypassRls || !value.Scram || value.Memberships != 0 || value.DefaultAcls != 0 || value.OtherClients != 0 ||
            value.PreparedTransactions != 0 || value.EventTriggers != 0 || !value.Primary || value.ObservedAtUtc.Offset != TimeSpan.Zero ||
            value.ObservedAtUtc < invocation.StartedAtUtc || value.ObservedAtUtc > invocation.ExitedAtUtc || value.HbaFile.Sha256 != policy.Maintenance.HbaSha256 || value.RawRules.Sha256 != policy.Maintenance.HbaRulesSha256) { throw Invalid(); }
        _ = read(value.HbaFile); using var raw = JsonDocument.Parse(read(value.RawRules));
        var rules = raw.RootElement.EnumerateArray().Select(row => new CurrentAppOwnedMaintenanceHbaRule(row.GetProperty("rule_number").GetInt32(), row.GetProperty("type").GetString()!,
            Strings(row, "database"), Strings(row, "user_name"), Text(row, "address"), Text(row, "netmask"), row.GetProperty("auth_method").GetString()!, Strings(row, "options"), Text(row, "error"))).ToArray();
        bool rejected = false; try { CurrentAppOwnedMaintenanceHba.Require(rules, policy.Maintenance.Role, policy.Target.Kind); }
        catch (MigrationExecutionException failure) when (failure.Code == "current_app_owned_maintenance_hba_not_exclusive") { rejected = true; }
        if (rejected != (caseId is "host-unprobed-sdk" or "local-trust")) { throw Invalid(); }
        static string? Text(JsonElement row, string name)
        {
            return row.GetProperty(name).ValueKind == JsonValueKind.Null ? null : row.GetProperty(name).GetString();
        }

        static string[] Strings(JsonElement row, string name)
        {
            return row.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : row.GetProperty(name).EnumerateArray().Select(x => x.GetString()!).ToArray();
        }
    }
    private static void RequireFleet(CurrentAppOwnedDatabaseSnapshot[] values, CurrentAuthRepairScope policy, bool comparison)
    {
        if (!ReviewedProductionRepairInventory.MatchesKeys(CurrentAuthLocalSessionArchivePolicy.InventoryProfile(comparison), values.Select(x => x.Database)) ||
            values.Length != policy.BeforeDatabaseSha256.Count || values.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != values.Length ||
            values.Any(x => !policy.BeforeDatabaseSha256.TryGetValue(x.Database, out string? hash) || x.Sha256 != hash) ||
            CurrentAuthRepairPermit.FleetSha256(values.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal)) != policy.GlobalPreservationSha256) { throw Invalid(); }
    }
    private static void RequireProofCatalogs(CurrentAuthArchiveFleetCatalogs catalogs, CurrentAuthRepairScope policy, bool comparison,
        CurrentAppOwnedDatabaseSnapshot[] snapshots, CurrentAuthArchiveProofInvocation invocation)
    {
        CurrentAuthLocalSessionArchivePolicy.RequireCatalogs(catalogs, policy, comparison, snapshots.Select(x => x.Database), invocation.StartedAtUtc, invocation.ExitedAtUtc);
    }
    internal static void RequireComparisonFleetAfter(CurrentAppOwnedDatabaseSnapshot[] before, CurrentAppOwnedDatabaseSnapshot[] after, bool productionFault)
    {
        if (!ReviewedProductionRepairInventory.MatchesKeys(DeltaTargetAuthorityKind.ProductionCloudNativePg, before.Select(x => x.Database)) ||
            !after.Select(x => x.Database).SequenceEqual(before.Select(x => x.Database), StringComparer.Ordinal) ||
            before.Zip(after).Any(x => x.First.Sha256 != x.Second.Sha256 && (!productionFault || x.First.Database != "Auth"))) { throw Invalid(); }
    }
    internal static void RequireImagePath(string image, string held, string? codeBase, string? storage)
    {
        StringComparison comparison = OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
        foreach (string? path in new[] { image, held, codeBase, storage })
        { if (string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || !string.Equals(path, Path.GetFullPath(path), comparison) || !string.Equals(image, path, comparison)) { throw Invalid(); } }
    }
    private static void RequireRecovery(string phase, CurrentAuthArchiveProofCase item, CurrentAuthArchiveScope scope, CurrentAuthArchiveRecoveryManifest manifest,
        CurrentAuthArchiveProofScenario scenario, CurrentAuthArchiveSession[] rows, CurrentAppOwnedDatabaseSnapshot before, Func<CurrentAuthArchiveProofArtifact, byte[]> read)
    {
        var storage = new ProofStorage(read, item, scope, scenario);
        if (phase is not ("helper" or "recovery"))
        {
            if (scenario.FirstDomainUnavailable || scenario.SecondDomainUnavailable) { throw Invalid(); }
            CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(storage, scope, manifest, rows, CancellationToken.None).GetAwaiter().GetResult();
            return;
        }
        if (item.CaseId is "key-corruption" or "cipher-corruption")
        {
            bool rejected = false;
            try
            {
                byte[] unexpected = CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, true, CancellationToken.None).GetAwaiter().GetResult();
                CryptographicOperations.ZeroMemory(unexpected);
            }
            catch (Exception failure) when (failure is CryptographicException or MigrationExecutionException or JsonException or FormatException) { rejected = true; }
            if (!rejected || scenario.FirstDomainUnavailable || scenario.SecondDomainUnavailable) { throw Invalid(); }
            return;
        }
        if (!Positive(item.CaseId)) { throw Invalid(); }
        bool first = item.CaseId.StartsWith("first", StringComparison.Ordinal);
        if (item.CaseId == "dual-durable-readback")
        { CurrentAuthLocalSessionArchiveCrypto.VerifyAsync(storage, scope, manifest, rows, CancellationToken.None).GetAwaiter().GetResult(); }
        else
        {
            if (first ? !scenario.SecondDomainUnavailable || scenario.FirstDomainUnavailable : !scenario.FirstDomainUnavailable || scenario.SecondDomainUnavailable) { throw Invalid(); }
            byte[] plain = CurrentAuthLocalSessionArchiveCrypto.RecoverDomainAsync(storage, scope, manifest, first, CancellationToken.None).GetAwaiter().GetResult();
            try { CurrentAuthLocalSessionArchivePolicy.RequireRows(JsonSerializer.Deserialize<CurrentAuthArchiveSession[]>(plain) ?? throw Invalid(), rows); }
            finally { CryptographicOperations.ZeroMemory(plain); }
        }
        if (phase == "recovery")
        {
            var restoreBefore = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedDatabaseSnapshot>(read(item.RestoreBefore ?? throw Invalid()));
            var restoreAfter = MigrationConsole.DecodeAuthRepair<CurrentAppOwnedDatabaseSnapshot>(read(item.RestoreAfter ?? throw Invalid()));
            CurrentAuthLocalSessionArchiveObservation.RequireDeletedOnly(restoreAfter, restoreBefore);
            if (restoreAfter.Sha256 != before.Sha256 || scenario.Boundary != "decrypted-insert-independent-readback" || !scenario.CommitAcknowledged || scenario.LocalDeleteAttempted) { throw Invalid(); }
        }
    }
    internal static void RequireFault(string id, CurrentAppOwnedDatabaseSnapshot before, CurrentAppOwnedDatabaseSnapshot changed)
    {
        if (before.Database != "Auth" || changed.Database != "Auth" || before.Sha256 == changed.Sha256 || !before.Catalog.SequenceEqual(changed.Catalog) ||
            before.Relations.Count != changed.Relations.Count || before.Sequences.Count != changed.Sequences.Count) { throw Invalid(); }
        if (id == "sequence-drift")
        {
            if (!before.Relations.SequenceEqual(changed.Relations) || before.Sequences.Zip(changed.Sequences).Count(x => x.First != x.Second) != 1 ||
                before.Sequences.Zip(changed.Sequences).Any(x => x.First != x.Second && (x.First.Schema != "private" || x.First.Name != "allocation" ||
                    x.First.Schema != x.Second.Schema || x.First.Name != x.Second.Name || x.First.Owner != x.Second.Owner))) { throw Invalid(); }
            return;
        }
        if (!before.Sequences.SequenceEqual(changed.Sequences) || before.Relations.Zip(changed.Relations).Count(x => x.First != x.Second) != 1) { throw Invalid(); }
        string schema = id == "private-journal-drift" ? "private" : "public", table = id switch { "CAS-field-drift" => "refresh_sessions", "private-journal-drift" => "journal", "production-drift" => "google_identity_nonces", _ => throw Invalid() };
        if (before.Relations.Zip(changed.Relations).Any(x => x.First != x.Second && (x.First.Schema != schema || x.First.Name != table || x.Second.Schema != schema || x.Second.Name != table ||
            x.First.Rows != x.Second.Rows || x.First.RowSha256 == x.Second.RowSha256))) { throw Invalid(); }
    }
    internal static void RequireCasFaultRows(IReadOnlyList<CurrentAuthArchiveSession> rows, IReadOnlyList<CurrentAuthArchiveSession> changed)
    {
        if (rows.Count != changed.Count || rows.Count == 0) { throw Invalid(); }
        var before = rows.OrderBy(x => x.Id).ToArray(); var after = changed.OrderBy(x => x.Id).ToArray();
        if (before.Zip(after).Count(x => x.First != x.Second) != 1 || before.Zip(after).Any(x => x.First != x.Second &&
            (x.First.SecurityStamp == x.Second.SecurityStamp || (x.First with { SecurityStamp = x.Second.SecurityStamp }) != x.Second))) { throw Invalid(); }
    }
    private sealed class ProofStorage(Func<CurrentAuthArchiveProofArtifact, byte[]> read, CurrentAuthArchiveProofCase item, CurrentAuthArchiveScope scope,
        CurrentAuthArchiveProofScenario scenario) : ICurrentAuthLocalSessionArchiveStorage
    {
        public Task RequireFreshIndependentRecoveryPathsAsync(CurrentAuthArchivePaths paths, CancellationToken ct)
        {
            throw Invalid();
        }

        public Task WriteCreateNewDurableAsync(string path, byte[] bytes, CancellationToken ct)
        {
            throw Invalid();
        }

        public Task RequireCustodyAsync(CancellationToken ct) { ct.ThrowIfCancellationRequested(); return Task.CompletedTask; }
        public Task<byte[]> ReadHeldAsync(string path, int maximumBytes, CancellationToken ct)
        {
            return ReadDomainHeldAsync(path == scope.Paths.FirstCiphertext || path == scope.Paths.RecoveryPrivateKey, path, maximumBytes, ct);
        }

        public Task<byte[]> ReadDomainHeldAsync(bool first, string path, int maximumBytes, CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested(); if (first ? scenario.FirstDomainUnavailable : scenario.SecondDomainUnavailable) { throw Invalid(); }
            CurrentAuthArchiveProofArtifact value = path == scope.Paths.FirstCiphertext ? item.FirstCiphertext : path == scope.Paths.SecondCiphertext ? item.SecondCiphertext :
                path == scope.Paths.RecoveryPrivateKey ? item.FirstRecoveryKey : path == scope.Paths.SecondRecoveryPrivateKey ? item.SecondRecoveryKey : throw Invalid();
            if (first != (path == scope.Paths.FirstCiphertext || path == scope.Paths.RecoveryPrivateKey)) { throw Invalid(); }
            byte[] bytes = read(value); if (bytes.Length > maximumBytes) { CryptographicOperations.ZeroMemory(bytes); throw Invalid(); }
            return Task.FromResult(bytes);
        }
    }
}
