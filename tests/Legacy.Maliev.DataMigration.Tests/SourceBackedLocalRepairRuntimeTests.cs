using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class SourceBackedLocalRepairRuntimeTests
{
    [Fact]
    public async Task DisposableMaintenanceResource_CannotReserveCanonicalLiveClaim()
    {
        DateTimeOffset now = new(2026, 10, 2, 0, 0, 0, TimeSpan.Zero);
        string hash = new('a', 64);
        string generation = "docker:" + new string('b', 64) + ":1:2:" + now.ToUnixTimeMilliseconds();
        var claim = new SourceBackedLocalRepairClaim("1.0", Guid.NewGuid(), hash, hash, hash, hash,
            generation, "repair-maintenance-test-" + Guid.NewGuid().ToString("N"), now, hash,
            [.. DatabaseInventory.ActiveDatabases.Select(database => new HistoricalLocalMetadataBinding(
                database, PairedLocalTransitionMetadataState.SettledPrior, hash))],
            now, now.Add(ImmutableRolloverClaimStore.MaximumClaimAge));
        var gateway = new NoReservationGateway();
        var store = new SourceBackedLocalRepairClaimStore(gateway);
        DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() =>
            store.ReserveAsync(claim, now, CancellationToken.None));
        Assert.Equal("delta_source_repair_claim_shape_invalid", failure.Code);
        Assert.Equal(0, gateway.CreateCalls);
        Assert.Equal(0, gateway.ReadCalls);
    }

    private sealed class NoReservationGateway : IRolloverClaimObjectGateway
    {
        internal int CreateCalls { get; private set; }
        internal int ReadCalls { get; private set; }
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return Task.FromResult(new RolloverClaimBucketPolicy(true,
                ImmutableRolloverClaimStore.MinimumRetentionSeconds, true, false));
        }
        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            CreateCalls++;
            throw new InvalidOperationException("An unadmitted fixture must never create a retained object.");
        }
        public Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            ReadCalls++;
            throw new InvalidOperationException("An unadmitted fixture must never read a claim object.");
        }
    }
}

// This is a native component pipeline with TEST maintenance/identity. It is never
// a live Console acceptance proof or permission to access the canonical volume.
public sealed partial class DisposableDeltaProofVerifierTests
{
    private static readonly JsonSerializerOptions TerminalProgressJsonOptions = new(JsonSerializerDefaults.Web);

    [Fact]
    public async Task NativeTerminalEvidence_UsesDistinctPersistentSignerAndRejectsBindingForgery()
    {
        await using MixedNativeFixture fixture = await CreateMixedNativeFixture();
        using var proofSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairMixedStateReader.Observation observed = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 0, proofSigner, CancellationToken.None);
        for (int index = 0; index < 23; index++)
        {
            await fixture.ApplyNext(observed);
            observed = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle, fixture.Plans, fixture.Proof,
                fixture.Schema, fixture.Authorization, observed.Continuation.Ordinal, proofSigner, CancellationToken.None);
        }
        Assert.True(observed.IsTerminal);
        JsonElement progress = JsonSerializer.SerializeToElement(
            Legacy.Maliev.DataMigration.Console.MigrationConsole.ObservationEvidence(observed, 0),
            TerminalProgressJsonOptions);
        Assert.Equal(24, progress.GetProperty("continuation").GetProperty("ordinal").GetInt64());
        Assert.Equal(observed.AdmissionSha256, progress.GetProperty("admissionSha256").GetString());
        Assert.True(progress.GetProperty("isTerminal").GetBoolean());
        Assert.False(progress.TryGetProperty("authorizesExecution", out _));
        SourceBackedLocalRepairTerminalSigningPin pin = fixture.TerminalPin;
        using var persistentSigner = new P256MigrationEvidenceSigner(pin.KeyId, _continuityKey.ExportECPrivateKeyPem());
        Assert.NotEqual(proofSigner.PublicKeyFingerprintSha256, persistentSigner.PublicKeyFingerprintSha256);
        ReceiptAttestationTrustStore terminalTrust = fixture.Trust;
        foreach (string keyId in new[] { fixture.Plans.Persistent.AttestationKeyId, fixture.Plans.Disposable.AttestationKeyId,
            fixture.Authorization.AttestationKeyId, fixture.Proof.AttestationKeyId })
        {
            Assert.True(terminalTrust.TryGetPublicKeyFingerprintSha256(keyId, out string fingerprint));
            Assert.NotEqual(pin.PublicKeyFingerprintSha256, fingerprint);
        }
        fixture.Clock.Now = DateTimeOffset.UtcNow;
        var paired = PairedLocalTransitionExecutionPermit.Admit(fixture.Plans, fixture.Proof, fixture.Authorization,
            fixture.Schema, fixture.Trust, fixture.Plans.Persistent.TargetAuthority!, fixture.Plans.Persistent.TargetObservationSha256, fixture.Clock);
        var reconciliation = new Exact23DeltaReconciliationCoordinator(
            new SignedCapturedSourceReconciliationInspector(fixture.Plans.Persistent, fixture.Schema, fixture.Trust, fixture.Clock),
            new PostgreSqlDeltaReconciliationInspector(new(fixture.Connection)
            { Plan = fixture.Plans.Persistent, LocalTransitionPermit = paired }),
            new PostgreSqlExact23DeltaCheckpointReader(new(fixture.Connection)), fixture.Clock, persistentSigner,
            checkpointBound: false, localPermit: paired);
        Exact23DeltaReconciliationResult receipt = await reconciliation.ReconcileAsync(fixture.Plans.Persistent,
            fixture.Schema, CancellationToken.None);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(receipt, terminalTrust));
        Assert.Equal(23, receipt.Checkpoints.Count);
        var unsigned = new SourceBackedLocalRepairRuntime.Terminal("1.0", fixture.Bundle.VerifiedClaim.ClaimId,
            observed.AdmissionSha256, SourceBackedLocalRepairContinuationStore.ComputeSha256(observed.Continuation),
            Exact23DeltaReconciliationCoordinator.ComputeSha256(receipt), observed.Identity, receipt, persistentSigner.KeyId, null);
        SourceBackedLocalRepairRuntime.Terminal terminal = unsigned with
        { AttestationSignature = Convert.ToBase64String(persistentSigner.Sign(SourceBackedLocalRepairRuntime.TerminalPayload(unsigned))) };
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var retained = new RolloverClaimObject(7, now, fixture.Bundle.VerifiedClaim.ExpiresAtUtc, JsonSerializer.SerializeToUtf8Bytes(terminal));
        SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(terminal, retained, observed, fixture.Plans.Persistent,
            fixture.Schema, fixture.Bundle.VerifiedClaim, terminalTrust, pin, now);
        foreach (SourceBackedLocalRepairRuntime.Terminal forged in new[]
        {
            terminal with { ClaimId = Guid.NewGuid() },
            terminal with { TerminalContinuationSha256 = new string('0', 64) },
            terminal with { ReconciliationSha256 = new string('0', 64) },
            terminal with { Identity = terminal.Identity with { ContainerId = new string('0', 64) } },
            terminal with { AttestationSignature = Convert.ToBase64String(new byte[64]) },
        })
        {
            _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(
                forged, retained, observed, fixture.Plans.Persistent, fixture.Schema, fixture.Bundle.VerifiedClaim, terminalTrust, pin, now));
        }
        _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(
            terminal, retained with { RetentionExpiresAtUtc = now }, observed, fixture.Plans.Persistent, fixture.Schema,
            fixture.Bundle.VerifiedClaim, terminalTrust, pin, now));
        _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(
            terminal, retained with { Content = JsonSerializer.SerializeToUtf8Bytes(terminal with { ClaimId = Guid.NewGuid() }) },
            observed, fixture.Plans.Persistent, fixture.Schema, fixture.Bundle.VerifiedClaim, terminalTrust, pin, now));
        _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(
            terminal, retained, observed, fixture.Plans.Persistent, fixture.Schema, fixture.Bundle.VerifiedClaim,
            terminalTrust, new(proofSigner.PublicKeyFingerprintSha256, proofSigner.KeyId), now));
        _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairRuntime.VerifyTerminalEvidence(
            terminal, retained, observed, fixture.Plans.Persistent, fixture.Schema, fixture.Bundle.VerifiedClaim,
            terminalTrust, pin with { KeyId = "unretained-terminal-key" }, now));
    }
}
