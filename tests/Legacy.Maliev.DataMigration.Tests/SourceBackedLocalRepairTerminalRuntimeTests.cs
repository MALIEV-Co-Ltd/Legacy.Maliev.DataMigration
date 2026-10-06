using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

// Native real PostgreSQL exact23 component acceptance. Resource custody and
// immutable storage are TEST adapters; this is never live Console authority.
public sealed partial class DisposableDeltaProofVerifierTests
{
    [Fact]
    public async Task NativeTerminalRuntime_PublishesRecoversOriginalBytesAndFailsClosedOnRetentionAndFinalDrift()
    {
        await using MixedNativeFixture fixture = await CreateMixedNativeFixture();
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        using var terminalSigner = new P256MigrationEvidenceSigner(fixture.TerminalPin.KeyId, _continuityKey.ExportECPrivateKeyPem());
        SourceBackedLocalRepairMixedStateReader.Observation current = await fixture.Reader.ObserveAndAdvanceAsync(
            fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema, fixture.Authorization, 0, evidenceSigner, CancellationToken.None);
        for (int ordinal = 1; ordinal <= 23; ordinal++)
        {
            await fixture.ApplyNext(current);
            current = await fixture.Reader.ObserveAndAdvanceAsync(fixture.Bundle, fixture.Plans, fixture.Proof,
                fixture.Schema, fixture.Authorization, current.Continuation.Ordinal, evidenceSigner, CancellationToken.None);
        }
        Assert.True(current.IsTerminal);
        Assert.Equal(24, current.Continuation.Ordinal);
        string[] before = await TerminalDatabaseState(fixture);

        // Each adapter owns an independent immutable TEST terminal slot. Original
        // claim, admission, epochs and progress remain in the shared real stores;
        // no retained terminal is updated, deleted or reset between scenarios.
        var publish = new TerminalRuntimeGateway(fixture.Gateway, fixture.Clock);
        var acceptance = new TerminalRuntimeAcceptance(fixture.Schema.SourceCommitSha);
        SourceBackedLocalRepairRuntime normal = TerminalRuntime(fixture, publish, acceptance);
        SourceBackedLocalRepairRuntime.Terminal completed = await Publish(normal);
        Assert.Equal(1, publish.TerminalCreates);
        Assert.Equal(fixture.Bundle.VerifiedClaim.ClaimId, completed.ClaimId);
        Assert.True(Exact23DeltaReconciliationCoordinator.Verify(completed.Receipt, fixture.Trust));
        Assert.Equal(23, completed.Receipt.Checkpoints.Count);
        Assert.Equal(JsonSerializer.SerializeToUtf8Bytes(completed), publish.Retained!.Content);
        Assert.True(acceptance.Checks > 0);
        Assert.Equal(before, await TerminalDatabaseState(fixture));

        var lost = new TerminalRuntimeGateway(fixture.Gateway, fixture.Clock) { LoseCreateAcknowledgement = true };
        SourceBackedLocalRepairRuntime interrupted = TerminalRuntime(fixture, lost, acceptance);
        _ = await Assert.ThrowsAsync<IOException>(() => Publish(interrupted));
        Assert.Equal(1, lost.TerminalCreates);
        RolloverClaimObject original = lost.Retained!;
        byte[] immutableBytes = original.Content.ToArray();
        Assert.Equal(before, await TerminalDatabaseState(fixture));
        SourceBackedLocalRepairRuntime.Terminal recovered = await Publish(interrupted);
        Assert.Equal(1, lost.TerminalCreates);
        Assert.Equal(original.Generation, lost.Retained!.Generation);
        Assert.Equal(immutableBytes, lost.Retained.Content);
        Assert.Equal(immutableBytes, JsonSerializer.SerializeToUtf8Bytes(recovered));
        Assert.Equal(before, await TerminalDatabaseState(fixture));

        var shortRetention = new TerminalRuntimeGateway(fixture.Gateway, fixture.Clock) { InsufficientRetention = true };
        SourceBackedLocalRepairRuntime unretained = TerminalRuntime(fixture, shortRetention, acceptance);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => Publish(unretained));
        Assert.Equal(1, shortRetention.TerminalCreates);
        Assert.NotNull(shortRetention.Retained);
        Assert.True(shortRetention.Retained.RetentionExpiresAtUtc < fixture.Bundle.VerifiedClaim.ExpiresAtUtc);
        _ = await Assert.ThrowsAsync<DeltaExecutionException>(() => Publish(unretained));
        Assert.Equal(1, shortRetention.TerminalCreates);
        Assert.Equal(before, await TerminalDatabaseState(fixture));

        var finalDrift = new TerminalRuntimeGateway(fixture.Gateway, fixture.Clock)
        {
            BeforeFirstRetainedRead = () => LockedIssuerExecute(LockedIssuerDatabase(fixture.Connection, "ContactRequest"),
                "UPDATE legacy_migration_internal.effects SET value='terminal-final-drift';")
        };
        SourceBackedLocalRepairRuntime changed = TerminalRuntime(fixture, finalDrift, acceptance);
        try
        {
            DeltaExecutionException failure = await Assert.ThrowsAsync<DeltaExecutionException>(() => Publish(changed));
            Assert.Equal("delta_source_repair_preimage_changed", failure.Code);
            Assert.Equal(1, finalDrift.TerminalCreates);
            Assert.Equal(1, finalDrift.MutationCalls);
            Assert.NotNull(finalDrift.Retained);
            // Publication alone never proves terminal completion: the actual
            // final exact23 observation detects the changed immutable effect.
            Assert.NotEqual(before, await TerminalDatabaseState(fixture));
        }
        finally
        {
            await LockedIssuerExecute(LockedIssuerDatabase(fixture.Connection, "ContactRequest"),
                "UPDATE legacy_migration_internal.effects SET value='immutable';");
        }
        Assert.Equal(before, await TerminalDatabaseState(fixture));

        Task<SourceBackedLocalRepairRuntime.Terminal> Publish(SourceBackedLocalRepairRuntime runtime)
        {
            return runtime.ReconcileAndPublishAsync(fixture.Bundle, fixture.Plans, fixture.Proof, fixture.Schema,
                fixture.Authorization, evidenceSigner, terminalSigner, CancellationToken.None);
        }
    }

    private static SourceBackedLocalRepairRuntime TerminalRuntime(MixedNativeFixture fixture,
        TerminalRuntimeGateway gateway, TerminalRuntimeAcceptance acceptance)
    {
        string Fingerprint(string key)
        {
            Assert.True(fixture.Trust.TryGetPublicKeyFingerprintSha256(key, out string result));
            return result;
        }
        var pins = new SourceBackedLocalRepairSigningPins(Fingerprint(fixture.Plans.Persistent.AttestationKeyId),
            Fingerprint(fixture.Plans.Disposable.AttestationKeyId), Fingerprint(fixture.Authorization.AttestationKeyId),
            Fingerprint(fixture.Proof.AttestationKeyId));
        return new(fixture.Connection, new LockedIssuerMaintenance(_ => Task.CompletedTask),
            _ => Task.FromResult(fixture.Identity), fixture.Admissions, fixture.Continuations, fixture.Trust,
            fixture.Clock, gateway, acceptance, pins, fixture.TerminalPin, fixture.Admissions.Renewals);
    }

    private static async Task<string[]> TerminalDatabaseState(MixedNativeFixture fixture)
    {
        var result = new List<string>();
        foreach (DatabaseSchemaPlan database in fixture.Schema.Databases)
        {
            SourceBackedLocalRepairDatabasePreimage observed = await LockedIssuerRead(
                LockedIssuerDatabase(fixture.Connection, database.Database), database);
            result.Add(JsonSerializer.Serialize(observed));
        }
        return result.ToArray();
    }

    private sealed class TerminalRuntimeAcceptance(string sourceCommit) : ISourceBackedLocalRepairSourceAcceptance
    {
        internal int Checks { get; private set; }
        public Task RequireAsync(string sourceCommitSha, CancellationToken cancellationToken)
        {
            Assert.Equal(sourceCommit, sourceCommitSha);
            cancellationToken.ThrowIfCancellationRequested();
            Checks++;
            return Task.CompletedTask;
        }
    }

    private sealed class TerminalRuntimeGateway(IRolloverClaimObjectGateway original, TimeProvider clock)
        : IRolloverClaimObjectGateway
    {
        private const string TerminalPrefix = "source-backed-local-repair/v1/terminal/";
        internal int TerminalCreates { get; private set; }
        internal int MutationCalls { get; private set; }
        internal bool LoseCreateAcknowledgement { get; init; }
        internal bool InsufficientRetention { get; init; }
        internal Func<Task>? BeforeFirstRetainedRead { get; init; }
        internal RolloverClaimObject? Retained { get; private set; }
        public Task<RolloverClaimBucketPolicy> ReadPolicyAsync(CancellationToken cancellationToken)
        {
            return original.ReadPolicyAsync(cancellationToken);
        }

        public async Task<RolloverClaimObject?> ReadAsync(string name, CancellationToken cancellationToken)
        {
            if (!name.StartsWith(TerminalPrefix, StringComparison.Ordinal)) { return await original.ReadAsync(name, cancellationToken); }
            if (Retained is not null && BeforeFirstRetainedRead is not null && MutationCalls == 0)
            { MutationCalls++; await BeforeFirstRetainedRead(); }
            return Retained is null ? null : Retained with { Content = Retained.Content.ToArray() };
        }
        public Task<RolloverClaimObject> CreateOnlyAsync(string name, byte[] content, CancellationToken cancellationToken)
        {
            if (!name.StartsWith(TerminalPrefix, StringComparison.Ordinal)) { return original.CreateOnlyAsync(name, content, cancellationToken); }
            cancellationToken.ThrowIfCancellationRequested();
            TerminalCreates++;
            if (Retained is not null) { throw new DeltaExecutionException("delta_rollover_claim_conflict", "A terminal is already retained."); }
            DateTimeOffset now = clock.GetUtcNow();
            Retained = new(1001, now, InsufficientRetention ? now.AddMinutes(1) : now.AddDays(366), content.ToArray());
            return LoseCreateAcknowledgement
                ? throw new IOException("The TEST acknowledgement was lost after immutable publication.")
                : Task.FromResult(Retained with { Content = Retained.Content.ToArray() });
        }
    }
}
