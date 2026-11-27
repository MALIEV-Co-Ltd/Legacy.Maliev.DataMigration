using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Private in-process acceptance; a serialized report or caller assertion cannot recreate it.</summary>
internal sealed class ConsumerColumnBootstrapRehearsalAcceptance
{
    private static readonly CurrentAppOwnedCommitClassification[] ReceiptPhases =
        [CurrentAppOwnedCommitClassification.Prepared, CurrentAppOwnedCommitClassification.CommittedAndReadback];
    private readonly string _sourceCommit, _sourceIdentity, _definition, _runner;
    private readonly DateTimeOffset _completed;
    private readonly Dictionary<string, ConsumerColumnBootstrapProviderObservation> _providers;
    private readonly HashSet<string> _proofFingerprints;
    internal string EvidenceSha256 { get; }
    private ConsumerColumnBootstrapRehearsalAcceptance(ConsumerColumnBootstrapRehearsalEvidence evidence)
    {
        _sourceCommit = evidence.Source.Plan.SourceCommitSha; _sourceIdentity = evidence.Source.SourceIdentitySha256;
        _definition = evidence.SourceDefinitionSha256; _runner = evidence.RunnerDigestSha256; _completed = evidence.Cleanup.ObservedAtUtc;
        _providers = evidence.Review.Scope.NativePreimages.ToDictionary(pin => pin.Database, pin => pin.Provider, StringComparer.Ordinal);
        _proofFingerprints = [evidence.SigningPins.ReviewFingerprint, evidence.SigningPins.AuthorizationFingerprint, evidence.SigningPins.ReceiptFingerprint];
        EvidenceSha256 = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(evidence));
    }

    internal static ConsumerColumnBootstrapRehearsalAcceptance Read(IConsumerColumnBootstrapRehearsalCompletion completion)
    {
        // Match and hold the actual fixed completion implementation before calling it.
        using var code = ConsumerColumnBootstrapAcceptedCodeCustody.AcquireCompletion(completion.GetType());
        var evidence = ConsumerColumnBootstrapOperationalContract.Copy(completion.ReadEvidence());
        Validate(evidence, code.RunnerDigestSha256, TimeProvider.System.GetUtcNow());
        return new(evidence);
    }

    internal void RequireRunner(string actualAcceptedRunnerDigest)
    {
        if (actualAcceptedRunnerDigest != _runner) { throw Invalid(); }
    }

    internal void Require(ConsumerColumnBootstrapOperationalScope scope, FreshSchemaPlan freshSource, CurrentAppOwnedRepairSigningPins runtimePins, DateTimeOffset now)
    {
        if (scope.Mode != ConsumerColumnBootstrapOperationalMode.PersistentReviewed || scope.SourceCommitSha != _sourceCommit ||
            scope.SourceIdentitySha256 != _sourceIdentity || scope.NativeCharacterizationSha256 != EvidenceSha256 ||
            _proofFingerprints.Contains(runtimePins.ReviewFingerprint) || _proofFingerprints.Contains(runtimePins.AuthorizationFingerprint) || _proofFingerprints.Contains(runtimePins.ReceiptFingerprint) ||
            now < _completed || now - _completed > TimeSpan.FromHours(24) ||
            ConsumerColumnBootstrapProofDefinition.Compute(freshSource, _sourceIdentity, _runner, ConsumerColumnBootstrapProofCohort.PostgreSql184, now) != _definition)
        { throw Invalid(); }
        foreach (var pin in scope.NativePreimages)
        {
            if (!_providers.TryGetValue(pin.Database, out var proved)) { throw Invalid(); }
            ConsumerColumnBootstrapProviderCompatibility.RequireCompatible(proved, pin.Provider);
        }
    }

    private static void Validate(ConsumerColumnBootstrapRehearsalEvidence evidence, string actualRunner, DateTimeOffset now)
    {
        if (evidence.Kind != "consumer-column-bootstrap-rehearsal-v1" || evidence.OperationId == Guid.Empty || evidence.ActualMethodReturnCode != 0 ||
            evidence.Cohort != ConsumerColumnBootstrapProofCohort.PostgreSql184 || evidence.RunnerDigestSha256 != actualRunner ||
            evidence.MethodBeganAtUtc.Offset != TimeSpan.Zero || evidence.MethodReturnedAtUtc.Offset != TimeSpan.Zero ||
            evidence.MethodBeganAtUtc > evidence.MethodReturnedAtUtc || evidence.MethodReturnedAtUtc > evidence.Cleanup.ObservedAtUtc ||
            evidence.Cleanup.ObservedAtUtc > now || now - evidence.Cleanup.ObservedAtUtc > TimeSpan.FromMinutes(15)) { throw Invalid(); }
        evidence.Source.Require(evidence.Review.Scope.SourceCommitSha, evidence.Source.SourceIdentitySha256, evidence.MethodBeganAtUtc);
        if (ConsumerColumnBootstrapProofDefinition.Compute(evidence.Source.Plan, evidence.Source.SourceIdentitySha256, actualRunner,
            evidence.Cohort, evidence.MethodBeganAtUtc) != evidence.SourceDefinitionSha256) { throw Invalid(); }
        var trust = new ReceiptAttestationTrustStore(evidence.PublicKeys);
        ConsumerColumnBootstrapOperationalPermit.Validate(evidence.Review, evidence.Authorization, evidence.Source.Plan, trust,
            evidence.SigningPins, evidence.MethodBeganAtUtc);
        var scope = evidence.Review.Scope;
        if (scope.OperationId != evidence.OperationId || scope.Mode != ConsumerColumnBootstrapOperationalMode.DisposableClosedProof ||
            scope.SourceIdentitySha256 != evidence.Source.SourceIdentitySha256 || evidence.DatabaseReceipts.Count != 4 || evidence.NativeWitnesses.Count != 6)
        { throw Invalid(); }
        var contract = ConsumerColumnBootstrapContract.Create(evidence.Source.Plan, scope.SourceCommitSha, evidence.MethodBeganAtUtc);
        var final = scope.BeforeDatabaseSha256.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
        string previous = new('0', 64); int cursor = 0;
        foreach (string database in ConsumerColumnBootstrapOperationalContract.Databases)
        {
            var witnesses = evidence.NativeWitnesses.Where(witness => witness.Database == database).OrderBy(witness => witness.Phase).ToArray();
            if (witnesses.Length != 3 || witnesses[0].Phase != ConsumerColumnBootstrapNativePhase.LockedBefore ||
                witnesses[1].Phase != ConsumerColumnBootstrapNativePhase.TransactionalAfter || witnesses[2].Phase != ConsumerColumnBootstrapNativePhase.IndependentReadback ||
                witnesses.Any(witness => witness.ProviderVersion != evidence.Cohort.ServerVersion || witness.ContractSha256 != scope.ContractSha256 ||
                    witness.Snapshot.Database != database || witness.After != (witness.Phase != ConsumerColumnBootstrapNativePhase.LockedBefore))) { throw Invalid(); }
            var before = witnesses[0].Rehydrate(); var after = witnesses[1].Rehydrate(); var readback = witnesses[2].Rehydrate();
            var pin = scope.NativePreimages.Single(item => item.Database == database);
            ConsumerColumnBootstrapNativePreimage.Require(pin, before, pin.Provider, evidence.MethodBeganAtUtc);
            ConsumerColumnBootstrapNativePreservation.RequirePreserved(before, after, contract);
            ConsumerColumnBootstrapNativePreservation.RequirePreserved(before, readback, contract);
            if (before.Native.Snapshot.Sha256 != scope.BeforeDatabaseSha256[database] || after.Native.Snapshot.Sha256 != readback.Native.Snapshot.Sha256 ||
                readback.WalUpper < after.WalUpper) { throw Invalid(); }
            foreach (var phase in ReceiptPhases)
            {
                var receipt = evidence.DatabaseReceipts[cursor++];
                if (receipt.Kind != "consumer-column-bootstrap-receipt-v1" || receipt.OperationId != scope.OperationId || receipt.Database != database ||
                    receipt.ContractSha256 != scope.ContractSha256 || receipt.BeforeSha256 != before.Native.Snapshot.Sha256 || receipt.AfterSha256 != after.Native.Snapshot.Sha256 ||
                    receipt.PreviousReceiptSha256 != previous || receipt.Classification != phase ||
                    receipt.AuthorizationSha256 != ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(evidence.Authorization)) ||
                    receipt.ObservedAtUtc.Offset != TimeSpan.Zero || receipt.ObservedAtUtc < evidence.MethodBeganAtUtc || receipt.ObservedAtUtc > evidence.MethodReturnedAtUtc ||
                    (cursor > 1 && receipt.ObservedAtUtc < evidence.DatabaseReceipts[cursor - 2].ObservedAtUtc))
                { throw Invalid(); }
                Verify(receipt.KeyId, receipt.Signature, PostgreSqlConsumerColumnBootstrapRepair.ReceiptPayload(receipt), trust, evidence.SigningPins);
                previous = ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(receipt));
            }
            final[database] = readback.Native.Snapshot.Sha256;
        }
        var run = evidence.RunReceipt;
        if (run.Kind != "consumer-column-bootstrap-run-receipt-v1" || !run.Completed || run.OperationId != scope.OperationId || run.LastDatabaseReceiptSha256 != previous ||
            run.ObservedAtUtc.Offset != TimeSpan.Zero || run.ObservedAtUtc < evidence.DatabaseReceipts[^1].ObservedAtUtc || run.ObservedAtUtc > evidence.MethodReturnedAtUtc ||
            run.ContractSha256 != scope.ContractSha256 || run.LogicalSourcePlanSha256 != scope.LogicalSourcePlanSha256 ||
            run.AuthorizationSha256 != ConsumerColumnBootstrapOperationalContract.Hash(JsonSerializer.SerializeToUtf8Bytes(evidence.Authorization)) ||
            run.FinalFleetSha256 != ConsumerColumnBootstrapOperationalContract.FleetHash(final) ||
            !Equal(final, evidence.FinalFleetSha256) || run.CommittedDatabaseSha256.Count != 2 || run.IndependentlyVerifiedReadbackSha256.Count != 2 ||
            ConsumerColumnBootstrapOperationalContract.Databases.Any(database => run.CommittedDatabaseSha256.GetValueOrDefault(database) != final[database] ||
                run.IndependentlyVerifiedReadbackSha256.GetValueOrDefault(database) != final[database])) { throw Invalid(); }
        Verify(run.KeyId, run.Signature, PostgreSqlConsumerColumnBootstrapRepair.RunReceiptPayload(run), trust, evidence.SigningPins);
        var cleanup = evidence.Cleanup;
        string volume = "legacy-delta-proof-" + scope.OperationId.ToString("N");
        if (cleanup.ObservedAtUtc.Offset != TimeSpan.Zero || cleanup.OperationId != scope.OperationId || cleanup.ContainerId is not { Length: 64 } || !cleanup.ContainerId.All(char.IsAsciiHexDigitLower) ||
            cleanup.VolumeName != volume || cleanup.Port is < 1 or > 65535 ||
            scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + cleanup.ContainerId[..12] ||
            cleanup.RemainingContainerIds.Contains(cleanup.ContainerId, StringComparer.Ordinal) || cleanup.RemainingContainerNames.Any(name => name == volume || name == "/" + volume) ||
            cleanup.RemainingVolumeNames.Contains(volume, StringComparer.Ordinal) || cleanup.RemainingLoopbackListeners.Contains(cleanup.Port)) { throw Invalid(); }
    }

    private static bool Equal(Dictionary<string, string> left, IReadOnlyDictionary<string, string> right)
    {
        return left.Count == right.Count && left.All(pair => right.TryGetValue(pair.Key, out string? value) && value == pair.Value);
    }

    private static void Verify(string keyId, string? signature, byte[] payload, ReceiptAttestationTrustStore trust, CurrentAppOwnedRepairSigningPins pins)
    {
        if (keyId != pins.ReceiptKeyId || signature is null || !trust.TryGetPublicKeyFingerprintSha256(keyId, out string fingerprint) || fingerprint != pins.ReceiptFingerprint ||
            !trust.Verify(keyId, payload, Convert.FromBase64String(signature))) { throw Invalid(); }
    }
    private static MigrationExecutionException Invalid()
    {
        return ConsumerColumnBootstrapOperationalContract.Invalid();
    }
}
