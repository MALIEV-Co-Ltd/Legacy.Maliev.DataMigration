using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Authenticated mixed-state readback; this is not an execution permit.</summary>
internal sealed record AuthenticatedHistoricalLocalRolloverSnapshot(
    ImmutableRolloverClaim Claim,
    HistoricalLocalRolloverClaimSnapshot ContinuationClaim,
    IReadOnlyList<HistoricalLocalRolloverDatabaseState> Databases,
    HistoricalCurrentLocalObservation TargetIdentity,
    DateTimeOffset ObservedAtUtc);

/// <summary>
/// Brackets two exact-23 read-only scans with durable claim and target identity
/// reads. Individual databases are still protected by their own transaction
/// rechecks before any future write.
/// </summary>
internal sealed class AuthenticatedHistoricalLocalRolloverReader(
    ImmutableRolloverClaimStore store,
    PostgreSqlRolloverDatabaseReader databases,
    Func<CancellationToken, Task<HistoricalCurrentLocalObservation>> observeTarget,
    TimeProvider clock)
{
    internal Task<HistoricalCurrentLocalObservation> ObserveTargetAsync(
        CancellationToken cancellationToken)
    {
        return observeTarget(cancellationToken);
    }

    internal async Task<AuthenticatedHistoricalLocalRolloverSnapshot> ReadAsync(
        Guid claimId, HistoricalLocalContinuityAttestation attestation,
        DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt,
        FreshSchemaPlan historicalSchema, PairedCapturedDeltaPlans futurePlans,
        Exact23DeltaReconciliationResult disposableProof, FreshSchemaPlan futureSchema,
        IReceiptAttestationTrustStore trust, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        ImmutableRolloverClaim claim = await store.ReadAuthenticatedAsync(claimId,
            attestation, historicalPlan, historicalReceipt, trust, now,
            cancellationToken).ConfigureAwait(false);
        if (futurePlans.Persistent.SchemaVersion != "1.4" ||
            futureSchema.SchemaVersion != "2.0" ||
            futureSchema.Databases is null || historicalSchema.Databases is null ||
            !futureSchema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !historicalSchema.Databases.Select(item => item.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) ||
            !Fixed(claim.FuturePlanSha256,
                DeltaSynchronizationPlanCanonicalizer.ComputeSha256(futurePlans.Persistent)) ||
            !Fixed(futurePlans.Persistent.SchemaPlanSha256,
                SchemaPlanCanonicalizer.ComputeSha256(futureSchema)) ||
            !Fixed(historicalPlan.SchemaPlanSha256,
                SchemaPlanCanonicalizer.ComputeSha256(historicalSchema)) ||
            futurePlans.Persistent.TargetGeneration != claim.TargetGeneration ||
            !Fixed(futurePlans.Persistent.TargetAuthority?.SystemIdentifierSha256,
                claim.SystemIdentifierSha256))
        {
            throw Invalid();
        }
        ZeroDeleteCapturedDeltaProofValidator.Verify(futurePlans.Disposable,
            disposableProof, futurePlans.Persistent, futureSchema, trust, now);
        HistoricalCurrentLocalObservation before = await observeTarget(cancellationToken)
            .ConfigureAwait(false);
        RequireIdentity(claim, before);
        IReadOnlyList<ImmutableRolloverClaimStore.SignedClaimOrdinal> ordinals =
            await ReadOrdinalsAsync(claim, trust, now, cancellationToken).ConfigureAwait(false);
        HistoricalLocalRolloverDatabaseState[] first = await ScanAsync(claim,
            historicalPlan, historicalReceipt, historicalSchema, futurePlans.Persistent,
            disposableProof, futureSchema, trust, ordinals.Count, cancellationToken)
            .ConfigureAwait(false);
        HistoricalLocalRolloverDatabaseState[] second = await ScanAsync(claim,
            historicalPlan, historicalReceipt, historicalSchema, futurePlans.Persistent,
            disposableProof, futureSchema, trust, ordinals.Count, cancellationToken)
            .ConfigureAwait(false);
        if (!first.SequenceEqual(second) ||
            (ordinals.Count == 0 && first.Any(item =>
                item.Phase != HistoricalLocalRolloverDatabasePhase.Prior)))
        {
            throw Invalid();
        }
        HistoricalCurrentLocalObservation after = await observeTarget(cancellationToken)
            .ConfigureAwait(false);
        RequireIdentity(claim, after);
        if (before != after)
        {
            throw Invalid();
        }
        ImmutableRolloverClaim finalClaim = await store.ReadAuthenticatedAsync(claimId,
            attestation, historicalPlan, historicalReceipt, trust, clock.GetUtcNow(),
            cancellationToken).ConfigureAwait(false);
        if (!JsonSerializer.SerializeToUtf8Bytes(claim).AsSpan()
                .SequenceEqual(JsonSerializer.SerializeToUtf8Bytes(finalClaim)))
        {
            throw Invalid();
        }
        IReadOnlyList<ImmutableRolloverClaimStore.SignedClaimOrdinal> finalOrdinals =
            await ReadOrdinalsAsync(claim, trust, clock.GetUtcNow(), cancellationToken)
                .ConfigureAwait(false);
        if (ordinals.Count != finalOrdinals.Count ||
            ordinals.Zip(finalOrdinals).Any(pair =>
                pair.First.Continuation.AttestationSignature !=
                pair.Second.Continuation.AttestationSignature ||
                pair.First.Authorization.AttestationSignature !=
                pair.Second.Authorization.AttestationSignature))
        {
            throw Invalid();
        }
        var snapshot = new HistoricalLocalRolloverClaimSnapshot(claim.ClaimId,
            claim.InitialAttestationSha256, claim.FuturePlanSha256, claim.TargetGeneration,
            ordinals.Count + 1, claim.InitialMetadata);
        return new(claim, snapshot, first, after, clock.GetUtcNow());
    }

    private async Task<HistoricalLocalRolloverDatabaseState[]> ScanAsync(
        ImmutableRolloverClaim claim, DeltaSynchronizationPlan historicalPlan,
        Exact23DeltaReconciliationResult historicalReceipt, FreshSchemaPlan historicalSchema,
        DeltaSynchronizationPlan futurePlan, Exact23DeltaReconciliationResult disposableProof,
        FreshSchemaPlan futureSchema, IReceiptAttestationTrustStore trust,
        long maxReservedOrdinal,
        CancellationToken cancellationToken)
    {
        var states = new List<HistoricalLocalRolloverDatabaseState>(
            DatabaseInventory.ActiveDatabases.Count);
        foreach (string database in DatabaseInventory.ActiveDatabases)
        {
            states.Add(await databases.ReadAsync(database, claim, historicalPlan,
                historicalReceipt, historicalSchema, futurePlan, disposableProof,
                futureSchema, store, trust, maxReservedOrdinal, clock.GetUtcNow(),
                cancellationToken)
                .ConfigureAwait(false));
        }
        return [.. states];
    }

    private async Task<IReadOnlyList<ImmutableRolloverClaimStore.SignedClaimOrdinal>>
        ReadOrdinalsAsync(ImmutableRolloverClaim claim, IReceiptAttestationTrustStore trust,
        DateTimeOffset nowUtc, CancellationToken cancellationToken)
    {
        var ordinals = new List<ImmutableRolloverClaimStore.SignedClaimOrdinal>();
        var authorizationIds = new HashSet<Guid>();
        for (long ordinal = 1; ordinal <= 999_999; ordinal++)
        {
            ImmutableRolloverClaimStore.SignedClaimOrdinal item;
            try
            {
                item = await store.ReadSignedOrdinalAsync(claim, ordinal, trust,
                    nowUtc, cancellationToken).ConfigureAwait(false);
            }
            catch (DeltaExecutionException exception)
                when (exception.Code == "delta_rollover_claim_object_missing")
            {
                return ordinals.AsReadOnly();
            }
            if (!authorizationIds.Add(item.Authorization.AuthorizationId) ||
                (ordinals.Count != 0 &&
                 (ordinals[^1].Continuation.ExpiresAtUtc > item.CreatedAtUtc ||
                  ordinals[^1].Continuation.Databases.Zip(item.Continuation.Databases)
                      .Any(pair => pair.First.Phase ==
                          HistoricalLocalRolloverDatabasePhase.Adopted &&
                          pair.Second.Phase != HistoricalLocalRolloverDatabasePhase.Adopted))))
            {
                throw Invalid();
            }
            ordinals.Add(item);
        }
        throw Invalid();
    }

    private static void RequireIdentity(ImmutableRolloverClaim claim,
        HistoricalCurrentLocalObservation observation)
    {
        string[] parts = observation.DockerGeneration?.Split(':') ?? [];
        if (parts.Length != 5 || parts[0] != "docker" ||
            parts[1] != observation.ContainerId ||
            observation.DockerGeneration != claim.TargetGeneration ||
            observation.VolumeName != claim.VolumeName ||
            observation.VolumeCreatedAtUtc != claim.VolumeCreatedAtUtc ||
            !Fixed(observation.SystemIdentifierSha256, claim.SystemIdentifierSha256) ||
            string.IsNullOrWhiteSpace(observation.VolumeMountpoint) ||
            string.IsNullOrWhiteSpace(observation.VolumeDestination) ||
            !(observation.PgData == observation.VolumeDestination ||
              observation.PgData.StartsWith(
                  observation.VolumeDestination.TrimEnd('/') + "/",
                  StringComparison.Ordinal)))
        {
            throw Invalid();
        }
    }

    private static bool Fixed(string? left, string? right)
    {
        return left is { Length: 64 } && right is { Length: 64 } &&
            left.All(char.IsAsciiHexDigit) && right.All(char.IsAsciiHexDigit) &&
            CryptographicOperations.FixedTimeEquals(
                Encoding.ASCII.GetBytes(left.ToLowerInvariant()),
                Encoding.ASCII.GetBytes(right.ToLowerInvariant()));
    }

    private static DeltaExecutionException Invalid()
    {
        return new("delta_rollover_mixed_state_invalid",
            "The exact-23 LOCAL target changed or lacks signed claim-bound evidence.");
    }
}
