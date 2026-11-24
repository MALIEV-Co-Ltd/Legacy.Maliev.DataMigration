namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapCleanupEvidence(Guid OperationId, string ContainerId, string VolumeName, int Port,
    DateTimeOffset ObservedAtUtc, IReadOnlyList<string> RemainingContainerIds, IReadOnlyList<string> RemainingContainerNames,
    IReadOnlyList<string> RemainingVolumeNames, IReadOnlyList<int> RemainingLoopbackListeners);

internal sealed record ConsumerColumnBootstrapRehearsalEvidence(string Kind, Guid OperationId, ConsumerColumnBootstrapSourceCapture Source,
    string SourceDefinitionSha256, string RunnerDigestSha256, ConsumerColumnBootstrapProofCohort Cohort,
    ConsumerColumnBootstrapOperationalClaim Review, ConsumerColumnBootstrapOperationalClaim Authorization,
    CurrentAppOwnedRepairSigningPins SigningPins, IReadOnlyList<TrustedAttestationKey> PublicKeys,
    IReadOnlyList<ConsumerColumnBootstrapNativeWitness> NativeWitnesses,
    IReadOnlyList<ConsumerColumnBootstrapOperationalReceipt> DatabaseReceipts, ConsumerColumnBootstrapOperationalRunReceipt RunReceipt,
    IReadOnlyDictionary<string, string> FinalFleetSha256, DateTimeOffset MethodBeganAtUtc, DateTimeOffset MethodReturnedAtUtc,
    int ActualMethodReturnCode, ConsumerColumnBootstrapCleanupEvidence Cleanup);

/// <summary>Implemented only by a private fixed Console completion, never a deserializable proof input.</summary>
internal interface IConsumerColumnBootstrapRehearsalCompletion
{
    ConsumerColumnBootstrapRehearsalEvidence ReadEvidence();
}
