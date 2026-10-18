namespace Legacy.Maliev.DataMigration;

// Only the signed named-disposable Console route may supply this physical ACK observer.
internal interface ICurrentCustomerSequenceClosedCommitObserver
{
    Task ArmImmediatelyBeforeCommitAsync(CancellationToken ct);
}
