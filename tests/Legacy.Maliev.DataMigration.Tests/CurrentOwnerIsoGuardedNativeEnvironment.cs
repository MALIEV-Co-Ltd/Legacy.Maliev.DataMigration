using System.Data;
using System.Text.Json;
using Npgsql;
using Docker.DotNet;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Actual native disposable component composition only. It is never accepted by the closed
// persistent Console and never substitutes a component result for a completed closed proof.
internal sealed class IsoGuardedNativeEnvironment(string endpoint, string ordinary, CurrentOwnerIsoRepairScope scope,
    FreshSchemaPlan source, IReadOnlyList<CurrentOwnerIsoSourceObservation> owners,
    IReadOnlyList<CurrentAppOwnedDatabaseSnapshot> baseline,
    IReadOnlyDictionary<string, CurrentOwnerIsoNativeObservation> nativeBefore,
    ApprovedCurrentOwnerIsoOverlay contract, IReceiptAttestationTrustStore trust, CurrentOwnerIsoRepairSigningPins pins,
    IsoExecutedProofRecorder proof, string fault, IsoCommitAcknowledgementProxy? proxy)
    : ICurrentOwnerIsoRepairEnvironment, ICurrentOwnerIsoNativeProofObserver, IDisposable
{
    private readonly SemaphoreSlim _reservationGate = new(1, 1);
    private readonly Dictionary<string, byte[]> _retained = new(StringComparer.Ordinal);
    private readonly Dictionary<string, CurrentOwnerIsoRepairReceipt> _prepared = new(StringComparer.Ordinal);
    private readonly Dictionary<string, string> _candidateHashes = new(StringComparer.Ordinal);
    private string _previousAcknowledged = new('0', 64);
    private DateTimeOffset? _previousAcknowledgedAt;
    internal string CandidateSha256(string database)
    {
        return _candidateHashes[database];
    }

    private readonly HashSet<string> _completed = new(StringComparer.Ordinal);
    private bool _reserved, _pendingArm, _faultInjected;
    private int _fleetNumber, _candidateNumber, _probeNumber;
    internal string AuthorizationSha256 { get; set; } = string.Empty;
    internal int Reservations { get; private set; }
    internal int ReceiptCount => _retained.Keys.Count(x => !x.EndsWith("-iso-component-operation-start.json", StringComparison.Ordinal));

    public Task RequireSourceAsync(string commit, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); proof.Capacity(admission: false);
        if (commit != source.SourceCommitSha || commit != proof.Intended.SourceCommitSha ||
            SchemaPlanCanonicalizer.ComputeSha256(source) != proof.Intended.SourceSchemaPlanSha256 || scope.SourceCatalogSha256 != proof.SourceCatalogSha256 ||
            scope.ProofAdmission != CurrentOwnerIsoProofAdmission.DisposableNativeComponent || scope.BootstrapSubject?.Claim.Subject.DefinitionPrecursorSha256 != proof.DefinitionSha256)
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        // The source/catalog/owners are actual held accepted artifacts independently validated by
        // the complete definition reader before container creation, not invented live SQL observations.
        return Task.CompletedTask;
    }
    public Task RequireOwnerSourcesAsync(string hash, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        return hash != scope.OwnerSourcesSha256 || hash != CurrentAppOwnedSnapshotSerialization.Sha256(owners) ||
            ApprovedCurrentOwnerIsoOverlay.Create(source, source.SourceCommitSha, scope.Operation, owners, DateTimeOffset.UtcNow).ComputeSha256() != contract.ComputeSha256()
            ? throw CurrentOwnerIsoRepairPermit.Invalid()
            : Task.CompletedTask;
    }
    public async Task RequireResourceAndCustodyAsync(CurrentOwnerIsoRepairScope current, CancellationToken ct)
    {
        Same(current); proof.Capacity(admission: false); RequireRetainedSlots();
        await RequireActualDisposableResourceAsync(ct);
        if (CurrentAppOwnedRepairPermit.Hash(proof.ReadHeld("container")) != current.TargetObservationSha256 ||
            current.RunBindingSha256 != proof.Binding.ComputeSha256()) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        // Policy validates actual native system identifier/generation/role/no-other-client/HBA and
        // the complete effective allow/reject semantics, including rules not hit by this SDK probe.
        foreach (string database in new[] { "Country", "Material" })
        {
            await using var connection = Connection(database); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await IsoGuardedFleetFixture.Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
            await PostgreSqlCurrentOwnerIsoRepair.RequireInstalledPolicyAsync(connection, tx, scope, ct);
            await RequireOwnerAsync(connection, tx, ct); await tx.RollbackAsync(ct);
        }
        var rejected = new List<string>();
        foreach (string database in baseline.Select(x => x.Database).Order(StringComparer.Ordinal))
        {
            bool denied = false;
            try { await using var connection = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(ordinary) { Database = database, Pooling = false }.ConnectionString); await connection.OpenAsync(ct); }
            catch (PostgresException failure) when (failure.SqlState == "28000") { denied = true; }
            if (!denied) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            rejected.Add(database);
        }
        await proof.RecordAsync("ordinary-rejections-" + _probeNumber++, new { proof.RunId, proof.CaseId, observedAtUtc = DateTimeOffset.UtcNow, databases = rejected }, ct);
        if (_pendingArm) { proxy?.Arm(); _pendingArm = false; }
    }
    public async Task<string> InspectGlobalPreservationAsync(CancellationToken ct)
    {
        _ = await InspectFleetAsync(ct); return scope.GlobalPreservationSha256;
    }
    internal async Task<IReadOnlyList<CurrentAppOwnedDatabaseSnapshot>> InspectFleetAsync(CancellationToken ct)
    {
        proof.Capacity(admission: false); RequireRetainedSlots();
        await using (var connection = Connection("postgres"))
        {
            await connection.OpenAsync(ct); await using var query = new NpgsqlCommand("SELECT datname FROM pg_database WHERE NOT datistemplate AND datallowconn ORDER BY datname COLLATE \"C\";", connection);
            var names = new List<string>(); await using var reader = await query.ExecuteReaderAsync(ct);
            while (await reader.ReadAsync(ct)) { names.Add(reader.GetString(0)); }
            if (!names.SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal) || names.Count != 26) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        }
        var pool = new CurrentAppOwnedSnapshotInternPool(); var actual = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (var expected in baseline.OrderBy(x => x.Database, StringComparer.Ordinal))
        {
            await using var connection = Connection(expected.Database); await connection.OpenAsync(ct);
            await using var tx = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead, ct);
            await IsoGuardedFleetFixture.Sql(connection, tx, "SET TRANSACTION READ ONLY;", ct);
            await PostgreSqlCurrentOwnerIsoRepair.RequireInstalledPolicyAsync(connection, tx, scope, ct);
            var snapshot = pool.Intern(await CurrentAppOwnedRepairPreservation.CaptureAsync(connection, tx, ct));
            bool affected = expected.Database is "Country" or "Material";
            bool selected = affected && (_completed.Contains(expected.Database) || (_prepared.TryGetValue(expected.Database, out var prepared) && snapshot.Sha256 == prepared.AfterSha256));
            string expectedSha = selected ? _prepared[expected.Database].AfterSha256! : expected.Sha256;
            if (snapshot.Sha256 != expectedSha) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            if (affected)
            {
                await RequireOwnerAsync(connection, tx, ct);
                var native = await CurrentOwnerIsoNativePreservation.CaptureAsync(connection, tx, contract, selected, ct);
                if (native.Snapshot.Sha256 != snapshot.Sha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
                if (selected) { CurrentOwnerIsoNativePreservation.RequirePreserved(nativeBefore[expected.Database], native, contract); }
                else { CurrentOwnerIsoNativePreservation.RequireBefore(native, contract); }
            }
            if (DatabaseInventory.ActiveDatabases.Contains(expected.Database, StringComparer.Ordinal))
            {
                var physical = source.Databases.Single(x => x.Database == expected.Database);
                if (selected) { physical = physical with { TargetExtensionProfile = ApprovedConsumerOverlaySelection.ProfileForDatabase(expected.Database, ConsumerOverlaySelection.CurrentConsumerSchemaV3Iso) }; }
                physical = physical with { TargetSchemaSha256 = PostgreSqlSchemaFingerprint.ComputeExpected(physical) };
                await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, tx, ownsResources: false);
                if (await inspector.InspectSchemaAsync(physical, ct) != physical.TargetSchemaSha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            }
            await tx.RollbackAsync(ct); actual.Add(snapshot);
        }
        await proof.FleetAsync("observed-fleet-" + _fleetNumber++, actual, ct); return actual.AsReadOnly();
    }
    public Task RequireFreshOperationAsync(CurrentOwnerIsoRepairScope current, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested(); Same(current); proof.Capacity(admission: false);
        return _reserved || proof.OperationSlots().Length != 0 || _retained.Count != 0
            ? throw CurrentOwnerIsoRepairPermit.Invalid()
            : Task.CompletedTask;
    }
    public async Task ReserveFreshOperationAsync(CurrentOwnerIsoRepairScope current, string authorization, CancellationToken ct)
    {
        await _reservationGate.WaitAsync(ct);
        try
        {
            await RequireFreshOperationAsync(current, ct);
            if (authorization != AuthorizationSha256 || !CurrentAppOwnedRepairPermit.HashShape(authorization)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            string name = scope.OperationId.ToString("D") + "-iso-component-operation-start.json";
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(new
            {
                kind = "current-owner-iso-component-operation-start-v1",
                scope.OperationId,
                authorizationSha256 = authorization,
                scopeSha256 = CurrentAppOwnedSnapshotSerialization.Sha256(scope),
                startedAtUtc = DateTimeOffset.UtcNow
            });
            // A failed/unknown CreateNew is never cleared or adopted; the permit becomes stopped.
            await proof.RetainOperationAsync(name, bytes, ct); _retained.Add(name, bytes); _reserved = true; Reservations++;
        }
        finally { _ = _reservationGate.Release(); }
    }
    public async Task RetainNewEvidenceAsync(string name, byte[] payload, CancellationToken ct)
    {
        if (!_reserved || _retained.ContainsKey(name)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var receipt = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(payload);
        PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(receipt, scope, AuthorizationSha256, trust, pins);
        if (receipt.PreviousReceiptSha256 != _previousAcknowledged || receipt.ObservedAtUtc > scope.Maintenance.ExpiresAtUtc ||
            (_previousAcknowledgedAt is not null && receipt.ObservedAtUtc < _previousAcknowledgedAt) ||
            (receipt.AfterSha256 is not null && (!_candidateHashes.TryGetValue(receipt.Database, out string? candidateSha) || receipt.AfterSha256 != candidateSha)))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        await proof.RetainOperationAsync(name, payload, ct); _retained.Add(name, payload.ToArray());
        bool prepared = receipt.Classification == CurrentAppOwnedCommitClassification.Prepared;
        bool acknowledged = !((prepared && fault == "prepared-publication") ||
            (receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback && fault == "terminal-publication"));
        await proof.SlotAsync(name, payload, acknowledged, ct);
        if (acknowledged && prepared) { _prepared.Add(receipt.Database, receipt); _pendingArm = fault == "lost-commit-ack"; }
        if (acknowledged) { _previousAcknowledged = CurrentAppOwnedSnapshotSerialization.Sha256(receipt); _previousAcknowledgedAt = receipt.ObservedAtUtc; }
        if (!acknowledged) { throw new IOException("Actual retained receipt publication acknowledgment fault."); }
        if (receipt.Database == "Country" && receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback && fault == "fleet-drift" && !_faultInjected)
        {
            _faultInjected = true; await using var connection = Connection("Upload"); await connection.OpenAsync(ct);
            await IsoGuardedFleetFixture.Sql(connection, null, "UPDATE iso_proof_private.journal SET payload='declared Upload drift ไทย' WHERE id=1;", ct);
            await proof.RecordAsync("declared-fleet-fault", new { database = "Upload", schema = "iso_proof_private", table = "journal", key = 1, observedAtUtc = DateTimeOffset.UtcNow }, ct);
        }
    }
    public async Task ObserveCommittedDatabaseAsync(CurrentOwnerIsoRepairReceipt prepared, CancellationToken ct)
    {
        PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(prepared, scope, AuthorizationSha256, trust, pins);
        if (!_prepared.TryGetValue(prepared.Database, out var retained) || CurrentAppOwnedSnapshotSerialization.Sha256(retained) != CurrentAppOwnedSnapshotSerialization.Sha256(prepared))
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        var actual = await IsoGuardedFleetFixture.NativeAsync(endpoint, prepared.Database, contract, true, ct);
        if (actual.Snapshot.Sha256 != prepared.AfterSha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        CurrentOwnerIsoNativePreservation.RequirePreserved(nativeBefore[prepared.Database], actual, contract);
        await proof.NativeAsync("readback-" + prepared.Database, actual, ct); _ = _completed.Add(prepared.Database);
    }
    public async Task ObserveCandidateAsync(CurrentOwnerIsoNativeObservation locked, CurrentOwnerIsoNativeObservation candidate, CancellationToken ct)
    {
        string database = candidate.Snapshot.Database;
        if (locked.Snapshot.Sha256 != baseline.Single(x => x.Database == database).Sha256) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        CurrentOwnerIsoNativePreservation.RequirePreserved(locked, candidate, contract);
        if (!_candidateHashes.TryAdd(database, candidate.Snapshot.Sha256)) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        await proof.NativeAsync("candidate-" + database, candidate, ct);
        // Candidate is the actual copied private transaction snapshot. Every other database is
        // independently captured through a closed read-only connection at its real current phase.
        var pool = new CurrentAppOwnedSnapshotInternPool(); var actual = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (var expected in baseline.OrderBy(x => x.Database, StringComparer.Ordinal))
        {
            var snapshot = expected.Database == database ? candidate.Snapshot : await IsoGuardedFleetFixture.CaptureAsync(endpoint, expected.Database, ct);
            string expectedSha = expected.Database == database ? candidate.Snapshot.Sha256 : _completed.Contains(expected.Database) ? _prepared[expected.Database].AfterSha256! : expected.Sha256;
            if (snapshot.Sha256 != expectedSha) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
            actual.Add(pool.Intern(snapshot));
        }
        await proof.FleetAsync("candidate-fleet-" + _candidateNumber++, actual, ct);
    }
    private async Task RequireActualDisposableResourceAsync(CancellationToken ct)
    {
        using var held = JsonDocument.Parse(proof.ReadHeld("container"));
        using var attempt = JsonDocument.Parse(proof.ReadHeld("attempt"));
        string id = held.RootElement.GetProperty("Id").GetString() ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        DateTimeOffset began = attempt.RootElement.GetProperty("began").GetDateTimeOffset();
        DateTimeOffset expires = attempt.RootElement.GetProperty("expires").GetDateTimeOffset();
        if (DateTimeOffset.UtcNow >= expires || scope.Maintenance.ExpiresAtUtc > expires ||
            scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + id) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
        using var client = new DockerClientBuilder().WithEndpoint(new Uri("npipe://./pipe/docker_engine")).Build();
        var actual = await client.Containers.InspectContainerAsync(id, ct);
        var config = actual.Config ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        var host = actual.HostConfig ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        var network = actual.NetworkSettings ?? throw CurrentOwnerIsoRepairPermit.Invalid();
        DateTimeOffset created = JsonSerializer.SerializeToElement(actual).GetProperty("Created").GetDateTimeOffset();
        string expectedName = "/iso-component-" + proof.RunId.ToString("N");
        if (actual.ID != id || actual.Name != expectedName || created < began.AddSeconds(-1) || created > expires || actual.State?.Running != true ||
            config.Image != CurrentOwnerIsoBootstrapSubjectValidator.Image || config.Labels is not { } labels ||
            !labels.TryGetValue("codex.repair.purpose", out string? purpose) || purpose != "current-owner-iso-guarded-component" ||
            !labels.TryGetValue("codex.repair.run", out string? run) || run != proof.RunId.ToString("D") ||
            !labels.TryGetValue("codex.repair.operation", out string? operation) || operation != run ||
            actual.Mounts is not { Count: 0 } || host.Mounts is { Count: > 0 } || host.Binds is { Count: > 0 } || host.VolumesFrom is { Count: > 0 } ||
            host.Tmpfs is not { Count: 1 } tmpfs || !tmpfs.TryGetValue("/var/lib/postgresql", out string? options) || options != "rw,nosuid,size=384m" ||
            host.Memory != 512L * 1024 * 1024 || host.MemorySwap != 512L * 1024 * 1024 || host.NanoCPUs != 750000000 ||
            network.Ports is not { Count: 1 } ports || !ports.TryGetValue("5432/tcp", out var bindings) || bindings is not { Count: 1 } ||
            bindings[0].HostIP != "127.0.0.1" || bindings[0].HostPort != new NpgsqlConnectionStringBuilder(endpoint).Port.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
            config.Env is null || config.Env.Count(x => x.StartsWith("PGDATA=", StringComparison.Ordinal)) != 1 ||
            config.Env.Single(x => x.StartsWith("PGDATA=", StringComparison.Ordinal))[7..] != held.RootElement.GetProperty("Config").GetProperty("PgData").GetString())
        { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    public void Dispose()
    {
        _reservationGate.Dispose();
    }

    private NpgsqlConnection Connection(string database)
    {
        return new(new NpgsqlConnectionStringBuilder(endpoint) { Database = database, Pooling = false }.ConnectionString);
    }

    private void Same(CurrentOwnerIsoRepairScope current)
    { if (CurrentAppOwnedSnapshotSerialization.Sha256(current) != CurrentAppOwnedSnapshotSerialization.Sha256(scope)) { throw CurrentOwnerIsoRepairPermit.Invalid(); } }
    private void RequireRetainedSlots()
    {
        string[] names = proof.OperationSlots();
        if (!names.SequenceEqual(_retained.Keys.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            names.Any(name => !proof.ReadOperation(name).AsSpan().SequenceEqual(_retained[name]))) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
    private static async Task RequireOwnerAsync(NpgsqlConnection connection, NpgsqlTransaction tx, CancellationToken ct)
    {
        await using var query = new NpgsqlCommand("SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p','S','i','I') AND pg_get_userbyid(c.relowner)<>'legacy_local';", connection, tx);
        if ((long)(await query.ExecuteScalarAsync(ct) ?? throw CurrentOwnerIsoRepairPermit.Invalid()) != 0) { throw CurrentOwnerIsoRepairPermit.Invalid(); }
    }
}
