using System.Data;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal interface ISourceBackedLocalRepairSourceAcceptance
{
    Task RequireAsync(string sourceCommitSha, CancellationToken cancellationToken);
}

internal sealed record SourceBackedLocalRepairTerminalSigningPin(string PublicKeyFingerprintSha256, string KeyId);

/// <summary>
/// Trusted LOCAL composition. A caller ordinal selects retained evidence to reobserve;
/// only the sealed actual mixed observation admits the next inventory database.
/// Staging is explicit and never occurs in the capsule or execution transaction.
/// </summary>
internal sealed class SourceBackedLocalRepairRuntime
{
    private readonly string _connection;
    private readonly ISourceBackedLocalRepairMaintenance _maintenance;
    private readonly Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> _observe;
    private readonly SourceBackedLocalRepairAdmissionStore _admissions;
    private readonly SourceBackedLocalRepairContinuationStore _continuations;
    private readonly SourceBackedLocalRepairMixedStateReader _reader;
    private readonly SourceBackedLocalRepairRenewalStore _renewals;
    private readonly IReceiptAttestationTrustStore _trust;
    private readonly TimeProvider _clock;
    private readonly IRolloverClaimObjectGateway _gateway;
    private readonly ISourceBackedLocalRepairSourceAcceptance _sourceAcceptance;
    private readonly SourceBackedLocalRepairTerminalSigningPin _terminalPin;

    internal SourceBackedLocalRepairRuntime(string connection,
        SourceBackedLocalRepairMaintenance maintenance,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        IReceiptAttestationTrustStore trust, TimeProvider clock, IRolloverClaimObjectGateway gateway,
        ISourceBackedLocalRepairSourceAcceptance sourceAcceptance, SourceBackedLocalRepairSigningPins signingPins,
        SourceBackedLocalRepairTerminalSigningPin terminalPin, SourceBackedLocalRepairRenewalStore renewals)
        : this(connection, (ISourceBackedLocalRepairMaintenance)maintenance, observe, admissions, continuations,
            trust, clock, gateway, sourceAcceptance, signingPins, terminalPin, renewals)
    {
        maintenance.RequireConnection(connection);
    }

    // Internal component composition reuses the actual orchestration with the existing
    // typed maintenance contract. The protected Console selects only the concrete overload;
    // no CLI/configuration field can supply this provider or a maintenance assertion.
    internal SourceBackedLocalRepairRuntime(string connection,
        ISourceBackedLocalRepairMaintenance maintenance,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observe,
        SourceBackedLocalRepairAdmissionStore admissions, SourceBackedLocalRepairContinuationStore continuations,
        IReceiptAttestationTrustStore trust, TimeProvider clock, IRolloverClaimObjectGateway gateway,
        ISourceBackedLocalRepairSourceAcceptance sourceAcceptance, SourceBackedLocalRepairSigningPins signingPins,
        SourceBackedLocalRepairTerminalSigningPin terminalPin, SourceBackedLocalRepairRenewalStore renewals)
    {
        _connection = LocalPostgreSqlResourceAuthority.Connection(connection).ConnectionString;
        _maintenance = maintenance ?? throw new ArgumentNullException(nameof(maintenance));
        if (maintenance is SourceBackedLocalRepairMaintenance concrete)
        { concrete.RequireConnection(_connection); }
        _observe = observe ?? throw new ArgumentNullException(nameof(observe));
        _admissions = admissions ?? throw new ArgumentNullException(nameof(admissions));
        _continuations = continuations ?? throw new ArgumentNullException(nameof(continuations));
        _trust = trust ?? throw new ArgumentNullException(nameof(trust));
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _gateway = gateway ?? throw new ArgumentNullException(nameof(gateway));
        _sourceAcceptance = sourceAcceptance ?? throw new ArgumentNullException(nameof(sourceAcceptance));
        ArgumentNullException.ThrowIfNull(signingPins);
        ArgumentNullException.ThrowIfNull(terminalPin);
        if (string.IsNullOrWhiteSpace(terminalPin.KeyId) ||
            !trust.TryGetPublicKeyFingerprintSha256(terminalPin.KeyId, out string terminalFingerprint) ||
            terminalFingerprint != terminalPin.PublicKeyFingerprintSha256 ||
            terminalPin.PublicKeyFingerprintSha256 is not { Length: 64 } ||
            !terminalPin.PublicKeyFingerprintSha256.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f')) ||
            new[] { signingPins.PersistentPlanFingerprint, signingPins.DisposablePlanFingerprint,
                signingPins.AuthorizationFingerprint, signingPins.EvidenceFingerprint }
                .Contains(terminalPin.PublicKeyFingerprintSha256, StringComparer.Ordinal))
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        _terminalPin = terminalPin;
        _renewals = renewals ?? throw new ArgumentNullException(nameof(renewals));
        _reader = new(_connection, admissions, continuations, observe, maintenance, clock, renewals);
    }

    internal Task<PairedLocalTransitionAuthorization> AuthorizeAsync(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, DateTimeOffset expiresAtUtc,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        return AuthorizeMaintainedAsync(_connection, plans, proof, schema, _trust, _observe, _maintenance,
            _sourceAcceptance, _clock, expiresAtUtc, signer, cancellationToken);
    }

    // Signing authenticates the current endpoint and physical contract. Original admission
    // or renewal must subsequently verify the complete actual preimage/mixed prefix before
    // any permit is issued. Ordinary transition row-preflight remains unchanged.
    internal static async Task<PairedLocalTransitionAuthorization> AuthorizeMaintainedAsync(
        string connectionString, PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, IReceiptAttestationTrustStore trust,
        Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget,
        ISourceBackedLocalRepairMaintenance maintenance, ISourceBackedLocalRepairSourceAcceptance sourceAcceptance,
        TimeProvider clock, DateTimeOffset expiresAtUtc, P256MigrationEvidenceSigner signer,
        CancellationToken cancellationToken)
    {
        plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema);
        ArgumentNullException.ThrowIfNull(maintenance);
        ArgumentNullException.ThrowIfNull(sourceAcceptance);
        var endpoint = LocalPostgreSqlResourceAuthority.Connection(connectionString);
        if (maintenance is SourceBackedLocalRepairMaintenance concrete)
        { concrete.RequireConnection(connectionString); }
        if (!schema.Databases.Select(item => item.Database).SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal))
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        PairedCapturedDeltaPlanPublicationGate.Verify(plans, schema, trust, clock.GetUtcNow());
        DisposableDeltaProofVerifier.Verify(plans.Disposable, proof, plans.Persistent, schema, trust, clock.GetUtcNow());
        await sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation before = await observeTarget(cancellationToken).ConfigureAwait(false);
        if (before.DockerGeneration != plans.Persistent.TargetGeneration ||
            before.SystemIdentifierSha256 != plans.Persistent.TargetAuthority!.SystemIdentifierSha256)
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await maintenance.AcquireAsync(before, cancellationToken).ConfigureAwait(false);
        await lease.RequireStillQuiescentAsync(before, cancellationToken).ConfigureAwait(false);
        string? quotationHash = null;
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            endpoint.Database = database.Database;
            await using var connection = new NpgsqlConnection(endpoint.ConnectionString);
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using (var control = new NpgsqlCommand("SELECT system_identifier::text FROM pg_control_system();", connection))
            {
                string system = (string)(await control.ExecuteScalarAsync(cancellationToken).ConfigureAwait(false)
                    ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid());
                string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(system))).ToLowerInvariant();
                if (hash != before.SystemIdentifierSha256) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
            }
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead,
                cancellationToken).ConfigureAwait(false);
            await using (var readOnly = new NpgsqlCommand("SET TRANSACTION READ ONLY;", connection, transaction))
            { _ = await readOnly.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false); }
            await using var inspector = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
            string actual = await inspector.InspectSchemaAsync(database, cancellationToken).ConfigureAwait(false);
            string expected = database.Database == "Quotation"
                ? ReviewedQuotationPhysicalSchemaResolver.RequireReviewedHash(database, plans.Persistent.QuotationTransitionSchemaSha256!)
                : database.TargetSchemaSha256;
            ReconciliationDiagnostics.CompareSchema(database.Database, expected, actual);
            if (ApprovedConsumerColumnOverlayManifest.HasState(database))
            {
                _ = await ApprovedTargetExtensionStateInspector.InspectAsync(connection, transaction, database,
                    cancellationToken).ConfigureAwait(false);
            }
            if (database.Database == "Quotation") { quotationHash = actual; }
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        await lease.RequireStillQuiescentAsync(before, cancellationToken).ConfigureAwait(false);
        if (await observeTarget(cancellationToken).ConfigureAwait(false) != before)
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        await sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(plans,
            proof, schema, trust, plans.Persistent.TargetAuthority!, plans.Persistent.TargetObservationSha256,
            quotationHash ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid(), clock.GetUtcNow(), expiresAtUtc, signer);
        await lease.RequireStillQuiescentAsync(before, cancellationToken).ConfigureAwait(false);
        return authorization;
    }

    internal async Task StageAsync(PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof,
        FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization, CancellationToken cancellationToken)
    {
        plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema); authorization = Snapshot(authorization);
        PairedLocalTransitionExecutionPermit permit = LocalPermit(plans, proof, schema, authorization);
        HistoricalCurrentLocalObservation identity = await _observe(cancellationToken).ConfigureAwait(false);
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await AcquireExecutionLeaseAsync(identity, plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            permit.Require(plans.Persistent, database, _clock.GetUtcNow());
            await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
            await using var connection = new NpgsqlConnection(DatabaseConnection(database.Database));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.Serializable,
                cancellationToken).ConfigureAwait(false);
            await PostgreSqlSourceBackedLocalRepair.StageAsync(connection, transaction, cancellationToken).ConfigureAwait(false);
            await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken).ConfigureAwait(false);
        }
        await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
    }

    internal async Task<SourceBackedLocalRepairAdmissionBundle> AdmitAsync(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        DateTimeOffset expiresAtUtc, P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        plans = Snapshot(plans); proof = Snapshot(proof); schema = Snapshot(schema); authorization = Snapshot(authorization);
        PairedLocalTransitionExecutionPermit physicalPermit = LocalPermit(plans, proof, schema, authorization);
        await _sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation identity = await _observe(cancellationToken).ConfigureAwait(false);
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await _maintenance.AcquireAsync(identity, cancellationToken).ConfigureAwait(false);
        var expected = new List<SourceBackedLocalRepairDatabasePreimage>();
        foreach (DatabaseSchemaPlan database in schema.Databases)
        {
            await using var connection = new NpgsqlConnection(DatabaseConnection(database.Database));
            await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
            await using NpgsqlTransaction transaction = await connection.BeginTransactionAsync(IsolationLevel.RepeatableRead,
                cancellationToken).ConfigureAwait(false);
            // Expected observations grant no authority. The issuer immediately locks and
            // verifies all actual relations, catalog and sequences before signing them.
            SourceBackedLocalRepairDatabasePreimage actual = await SourceBackedLocalRepairPreimage.InspectAsync(connection, transaction,
                database, cancellationToken).ConfigureAwait(false);
            SourceBackedLocalRepairLockedIssuer.RequireReadyPreimage(plans.Persistent, database, actual, physicalPermit);
            await SourceBackedLocalRepairPreimage.RequireMarkerCatalogAsync(connection, transaction, 0,
                cancellationToken).ConfigureAwait(false);
            expected.Add(actual);
            await transaction.RollbackAsync(CancellationToken.None).ConfigureAwait(false);
        }
        await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
        await _sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        var issuer = new SourceBackedLocalRepairLockedIssuer(_connection, _observe, _maintenance, _clock);
        SourceBackedLocalRepairAdmissionBundle bundle = await _admissions.CreateAsync(issuer, plans, proof, schema,
            authorization, expected, expiresAtUtc, signer, cancellationToken).ConfigureAwait(false);
        await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
        return bundle;
    }

    internal async Task<SourceBackedLocalRepairMixedStateReader.Observation> ObserveAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        long retainedOrdinal, P256MigrationEvidenceSigner signer, CancellationToken cancellationToken,
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = null)
    {
        authorization = activeGrant?.Authorization ?? authorization;
        return await _reader.ObserveAndAdvanceAsync(bundle, plans, proof, schema, authorization,
            retainedOrdinal, signer, cancellationToken, activeGrant).ConfigureAwait(false);
    }

    internal Task<SourceBackedLocalRepairRenewalStore.ActiveGrant> ReadActiveGrantAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, long counter,
        CancellationToken cancellationToken)
    {
        return _renewals.ReadAsync(bundle, plans, proof, schema, counter, cancellationToken);
    }

    internal async Task<SourceBackedLocalRepairRenewalStore.ActiveGrant> RenewAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization freshAuthorization, long retainedOrdinal, long previousCounter,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken)
    {
        await _sourceAcceptance.RequireAsync(plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        HistoricalCurrentLocalObservation identity = await _observe(cancellationToken).ConfigureAwait(false);
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await AcquireExecutionLeaseAsync(identity, plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairRenewalStore.ActiveGrant grant = await _reader.RenewAsync(bundle, plans, proof,
            schema, freshAuthorization, retainedOrdinal, previousCounter, signer, cancellationToken).ConfigureAwait(false);
        await lease.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
        return grant;
    }

    internal async Task<SourceBackedLocalRepairMixedStateReader.Observation> ApplyNextAsync(
        SourceBackedLocalRepairAdmissionBundle bundle, PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization,
        long retainedOrdinal, string protectedCaptureDirectory, ReadOnlyMemory<byte> captureKey,
        P256MigrationEvidenceSigner signer, CancellationToken cancellationToken,
        SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = null)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof);
        schema = Snapshot(schema); authorization = Snapshot(activeGrant?.Authorization ?? authorization);
        SourceBackedLocalRepairMixedStateReader.Observation observed = await ObserveAsync(bundle, plans, proof,
            schema, authorization, retainedOrdinal, signer, cancellationToken, activeGrant).ConfigureAwait(false);
        if (observed.IsTerminal) { return observed; }
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await AcquireExecutionLeaseAsync(observed.Identity, plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        SourceBackedLocalRepairExecutionPermit repairPermit = await SourceBackedLocalRepairExecutionPermit.AdmitAsync(
            _admissions, _continuations, bundle, plans, proof, schema, authorization, observed,
            _observe, lease, _clock, cancellationToken).ConfigureAwait(false);
        PairedLocalTransitionExecutionPermit pairedPermit = LocalPermit(plans, proof, schema, authorization);
        string database = DatabaseInventory.ActiveDatabases[checked((int)observed.Continuation.Ordinal - 1)];
        DatabaseSchemaPlan databaseSchema = schema.Databases.Single(item => item.Database == database);
        using DeltaCapturedTableRowSource source = DeltaCapturedTableRowSource.FromSignedPlan(
            new DeltaCapturedTableArchive(protectedCaptureDirectory), plans.Persistent, _trust, _clock.GetUtcNow(), captureKey.Span);
        var target = new PostgreSqlDeltaCanonicalTarget(new(DatabaseConnection(database), database,
            plans.Persistent.TargetGeneration)
        {
            LocalTransitionPermit = pairedPermit,
            SourceRepairPermit = repairPermit,
            SignedSourceSchemaPlan = schema
        });
        var rows = new CapturedDeltaExecutionRowSessionProvider(source, new PostgreSqlDeltaRowSource(new(_connection)));
        var gate = new PairedLocalTransitionExecutionGate(pairedPermit, schema,
            token => lease.RequireStillQuiescentAsync(observed.Identity, token));
        var reconciliation = new SignedCapturedSourceReconciliationInspector(plans.Persistent, schema, _trust, _clock);
        var executor = new DeltaExecutionCoordinator(target, rows, gate, reconciliation, _trust, _clock, pairedPermit);
        _ = await executor.ExecuteDatabaseAsync(plans.Persistent, databaseSchema, database, cancellationToken).ConfigureAwait(false);
        await lease.RequireStillQuiescentAsync(observed.Identity, cancellationToken).ConfigureAwait(false);
        // A committed transaction followed by interruption is recovered by actual observation,
        // never by replaying its DML or accepting caller-supplied Applied state.
        return await ObserveAsync(bundle, plans, proof, schema, authorization, observed.Continuation.Ordinal,
            signer, cancellationToken, activeGrant).ConfigureAwait(false);
    }

    internal async Task<Terminal> ReconcileAndPublishAsync(SourceBackedLocalRepairAdmissionBundle bundle,
        PairedCapturedDeltaPlans plans, Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema,
        PairedLocalTransitionAuthorization authorization, P256MigrationEvidenceSigner signer,
        P256MigrationEvidenceSigner persistentSigner,
        CancellationToken cancellationToken, SourceBackedLocalRepairRenewalStore.ActiveGrant? activeGrant = null)
    {
        bundle = Snapshot(bundle); plans = Snapshot(plans); proof = Snapshot(proof);
        schema = Snapshot(schema); authorization = Snapshot(activeGrant?.Authorization ?? authorization);
        SourceBackedLocalRepairOriginalAuthority original = await _renewals.VerifyOriginalRetainedAsync(bundle,
            plans, proof, schema, cancellationToken).ConfigureAwait(false);
        if (original.TerminalPin != _terminalPin || persistentSigner.KeyId != _terminalPin.KeyId ||
            persistentSigner.PublicKeyFingerprintSha256 != _terminalPin.PublicKeyFingerprintSha256)
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        foreach (string keyId in new[] { plans.Persistent.AttestationKeyId, plans.Disposable.AttestationKeyId,
            authorization.AttestationKeyId, proof.AttestationKeyId })
        {
            if (!_trust.TryGetPublicKeyFingerprintSha256(keyId, out string existingRole) ||
                existingRole == _terminalPin.PublicKeyFingerprintSha256)
            { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        }
        SourceBackedLocalRepairMixedStateReader.Observation before = await ObserveAsync(bundle, plans, proof,
            schema, authorization, 24, signer, cancellationToken, activeGrant).ConfigureAwait(false);
        if (!before.IsTerminal) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        await using ISourceBackedLocalRepairMaintenanceLease lease =
            await AcquireExecutionLeaseAsync(before.Identity, plans.Persistent.SourceCommitSha, cancellationToken).ConfigureAwait(false);
        RolloverClaimBucketPolicy policy = await _gateway.ReadPolicyAsync(cancellationToken).ConfigureAwait(false);
        if (!policy.RetentionLocked || policy.RetentionSeconds < ImmutableRolloverClaimStore.MinimumRetentionSeconds ||
            !policy.UniformBucketAccess || policy.VersioningEnabled) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        SourceBackedLocalRepairClaim claim = activeGrant is null
            ? await _admissions.VerifyRetainedAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                authorization, cancellationToken).ConfigureAwait(false)
            : await activeGrant.RequireFreshAsync(bundle.Admission, bundle.Capsule, plans, proof, schema,
                authorization, before.Identity, cancellationToken).ConfigureAwait(false);
        string name = "source-backed-local-repair/v1/terminal/" + claim.ClaimId.ToString("N") + ".json";
        RolloverClaimObject? existing = await _gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false);
        Terminal terminal;
        byte[] bytes;
        if (existing is not null)
        {
            // Recover publication using its authentic original bytes. Re-signing the same
            // observations produces different ECDSA bytes and must not replace retention.
            terminal = JsonSerializer.Deserialize<Terminal>(existing.Content)
                ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
            VerifyTerminal(terminal, existing, bundle, before, plans.Persistent, schema, claim);
            bytes = existing.Content;
        }
        else
        {
            PairedLocalTransitionExecutionPermit pairedPermit = LocalPermit(plans, proof, schema, authorization);
            var reconciliation = new Exact23DeltaReconciliationCoordinator(
                new SignedCapturedSourceReconciliationInspector(plans.Persistent, schema, _trust, _clock),
                new PostgreSqlDeltaReconciliationInspector(new(_connection)
                { Plan = plans.Persistent, LocalTransitionPermit = pairedPermit }),
                new PostgreSqlExact23DeltaCheckpointReader(new(_connection)), _clock, persistentSigner,
                checkpointBound: false, localPermit: pairedPermit);
            Exact23DeltaReconciliationResult receipt = await reconciliation.ReconcileAsync(plans.Persistent,
                schema, cancellationToken).ConfigureAwait(false);
            await lease.RequireStillQuiescentAsync(before.Identity, cancellationToken).ConfigureAwait(false);
            SourceBackedLocalRepairMixedStateReader.Observation after = await ObserveAsync(bundle, plans, proof,
                schema, authorization, 24, signer, cancellationToken, activeGrant).ConfigureAwait(false);
            if (!SameTerminal(before, after)) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
            var unsigned = new Terminal("1.0", claim.ClaimId, claim.AdmissionSha256,
                SourceBackedLocalRepairContinuationStore.ComputeSha256(after.Continuation),
                Exact23DeltaReconciliationCoordinator.ComputeSha256(receipt), after.Identity, receipt,
                persistentSigner.KeyId, null);
            terminal = unsigned with { AttestationSignature = Convert.ToBase64String(persistentSigner.Sign(TerminalPayload(unsigned))) };
            bytes = JsonSerializer.SerializeToUtf8Bytes(terminal);
            // Verify before the create-only publication, including its distinct signing role.
            VerifyTerminal(terminal, new(1, _clock.GetUtcNow(), claim.ExpiresAtUtc, bytes), bundle,
                after, plans.Persistent, schema, claim);
            await lease.RequireStillQuiescentAsync(after.Identity, cancellationToken).ConfigureAwait(false);
            RolloverClaimObject created = await _gateway.CreateOnlyAsync(name, bytes, cancellationToken).ConfigureAwait(false);
            VerifyTerminal(terminal, created, bundle, after, plans.Persistent, schema, claim);
            if (!created.Content.AsSpan().SequenceEqual(bytes)) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
            existing = created;
        }
        RolloverClaimObject read = await _gateway.ReadAsync(name, cancellationToken).ConfigureAwait(false)
            ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
        if (read.Generation != existing.Generation || !read.Content.AsSpan().SequenceEqual(bytes))
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        SourceBackedLocalRepairMixedStateReader.Observation final = await ObserveAsync(bundle, plans, proof,
            schema, authorization, 24, signer, cancellationToken, activeGrant).ConfigureAwait(false);
        if (!SameTerminal(before, final)) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        VerifyTerminal(terminal, read, bundle, final, plans.Persistent, schema, claim);
        await lease.RequireStillQuiescentAsync(final.Identity, cancellationToken).ConfigureAwait(false);
        return Snapshot(terminal);
    }

    internal sealed record Terminal(string SchemaVersion, Guid ClaimId, string AdmissionSha256,
        string TerminalContinuationSha256, string ReconciliationSha256, HistoricalCurrentLocalObservation Identity,
        Exact23DeltaReconciliationResult Receipt, string AttestationKeyId, string? AttestationSignature)
    {
        internal static bool AuthorizesExecution => false;
    }

    private void VerifyTerminal(Terminal terminal, RolloverClaimObject retained,
        SourceBackedLocalRepairAdmissionBundle bundle, SourceBackedLocalRepairMixedStateReader.Observation observed,
        DeltaSynchronizationPlan plan, FreshSchemaPlan schema, SourceBackedLocalRepairClaim claim)
    {
        if (bundle.Admission.ClaimId != claim.ClaimId || bundle.Admission.TargetIdentity != observed.Identity)
        { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        VerifyTerminalEvidence(terminal, retained, observed, plan, schema, claim, _trust, _terminalPin, _clock.GetUtcNow());
    }

    internal static void VerifyTerminalEvidence(Terminal terminal, RolloverClaimObject retained,
        SourceBackedLocalRepairMixedStateReader.Observation observed, DeltaSynchronizationPlan plan,
        FreshSchemaPlan schema, SourceBackedLocalRepairClaim claim, IReceiptAttestationTrustStore trust,
        SourceBackedLocalRepairTerminalSigningPin terminalPin, DateTimeOffset nowUtc)
    {
        if (terminal.SchemaVersion != "1.0" || terminal.ClaimId != claim.ClaimId ||
            terminal.AdmissionSha256 != claim.AdmissionSha256 || terminal.Identity != observed.Identity ||
            !observed.IsTerminal || terminal.TerminalContinuationSha256 !=
                SourceBackedLocalRepairContinuationStore.ComputeSha256(observed.Continuation) ||
            terminal.ReconciliationSha256 != Exact23DeltaReconciliationCoordinator.ComputeSha256(terminal.Receipt) ||
            !trust.TryGetPublicKeyFingerprintSha256(terminal.AttestationKeyId, out string terminalFingerprint) ||
            terminalFingerprint != terminalPin.PublicKeyFingerprintSha256 || terminal.AttestationKeyId != terminalPin.KeyId ||
            terminal.Receipt.AttestationKeyId != terminal.AttestationKeyId ||
            !Exact23DeltaReconciliationCoordinator.VerifyForSchema(terminal.Receipt, plan, schema, trust) ||
            terminal.Receipt.PlanId != plan.PlanId || terminal.Receipt.PlanSha256 !=
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(plan) ||
            plan.SchemaPlanSha256 != SchemaPlanCanonicalizer.ComputeSha256(schema) ||
            terminal.Receipt.SourceCutoffUtc != plan.SourceCutoffUtc ||
            terminal.Receipt.Checkpoints.Count != 23 || retained.Generation <= 0 ||
            !retained.Content.AsSpan().SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(terminal)) ||
            retained.CreatedAtUtc.Offset != TimeSpan.Zero || retained.RetentionExpiresAtUtc.Offset != TimeSpan.Zero ||
            retained.RetentionExpiresAtUtc < claim.ExpiresAtUtc || retained.CreatedAtUtc > nowUtc ||
            retained.CreatedAtUtc < claim.CreatedAtUtc || terminal.Receipt.ReconciledAtUtc > nowUtc ||
            terminal.Receipt.ReconciledAtUtc < observed.Continuation.IssuedAtUtc ||
            string.IsNullOrEmpty(terminal.AttestationSignature)) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        foreach (DeltaDatabaseCheckpointEvidence checkpoint in terminal.Receipt.Checkpoints)
        {
            SourceBackedLocalRepairState state = observed.Continuation.Databases.Single(item => item.Database == checkpoint.Database);
            if (checkpoint.TargetObservationSha256 != plan.TargetObservationSha256 ||
                checkpoint.OperationsSha256 != DeltaSynchronizationPlanCanonicalizer.ComputeDatabaseOperationsSha256(
                    plan.Databases.Single(item => item.Database == checkpoint.Database)) ||
                checkpoint.ReconciliationSha256 != state.ReconciliationSha256)
            { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        }
        try
        {
            if (!trust.Verify(terminal.AttestationKeyId, TerminalPayload(terminal),
                Convert.FromBase64String(terminal.AttestationSignature)))
            { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
        }
        catch (FormatException) { throw SourceBackedLocalRepairAdmissionPolicy.Invalid(); }
    }

    internal static byte[] TerminalPayload(Terminal terminal)
    {
        return [.. "legacy-maliev-source-repair-terminal-v1\0"u8,
            .. JsonSerializer.SerializeToUtf8Bytes(terminal with { AttestationSignature = null })];
    }

    private static bool SameTerminal(SourceBackedLocalRepairMixedStateReader.Observation left,
        SourceBackedLocalRepairMixedStateReader.Observation right)
    {
        return left.IsTerminal && right.IsTerminal && left.Identity == right.Identity &&
            left.AdmissionSha256 == right.AdmissionSha256 &&
            SourceBackedLocalRepairContinuationStore.ComputeSha256(left.Continuation) ==
                SourceBackedLocalRepairContinuationStore.ComputeSha256(right.Continuation);
    }

    private PairedLocalTransitionExecutionPermit LocalPermit(PairedCapturedDeltaPlans plans,
        Exact23DeltaReconciliationResult proof, FreshSchemaPlan schema, PairedLocalTransitionAuthorization authorization)
    {
        return PairedLocalTransitionExecutionPermit.Admit(plans, proof, authorization, schema, _trust,
            authorization.TargetAuthority, authorization.TargetObservationSha256, _clock);
    }

    private string DatabaseConnection(string database)
    {
        return !DatabaseInventory.ActiveDatabases.Contains(database, StringComparer.Ordinal)
            ? throw SourceBackedLocalRepairAdmissionPolicy.Invalid()
            : new NpgsqlConnectionStringBuilder(_connection) { Database = database }.ConnectionString;
    }

    private async Task<ISourceBackedLocalRepairMaintenanceLease> AcquireExecutionLeaseAsync(
        HistoricalCurrentLocalObservation identity, string sourceCommitSha, CancellationToken cancellationToken)
    {
        await _sourceAcceptance.RequireAsync(sourceCommitSha, cancellationToken).ConfigureAwait(false);
        ISourceBackedLocalRepairMaintenanceLease lease = await _maintenance.AcquireAsync(identity, cancellationToken).ConfigureAwait(false);
        return new AcceptedLease(lease, _sourceAcceptance, sourceCommitSha);
    }

    private sealed class AcceptedLease(ISourceBackedLocalRepairMaintenanceLease maintenance,
        ISourceBackedLocalRepairSourceAcceptance sourceAcceptance, string sourceCommitSha) : ISourceBackedLocalRepairMaintenanceLease
    {
        public async Task RequireStillQuiescentAsync(HistoricalCurrentLocalObservation identity, CancellationToken cancellationToken)
        {
            await sourceAcceptance.RequireAsync(sourceCommitSha, cancellationToken).ConfigureAwait(false);
            await maintenance.RequireStillQuiescentAsync(identity, cancellationToken).ConfigureAwait(false);
        }
        public ValueTask DisposeAsync()
        {
            return maintenance.DisposeAsync();
        }
    }

    private static T Snapshot<T>(T value)
    {
        ArgumentNullException.ThrowIfNull(value);
        return JsonSerializer.Deserialize<T>(JsonSerializer.SerializeToUtf8Bytes(value))
            ?? throw SourceBackedLocalRepairAdmissionPolicy.Invalid();
    }
}
