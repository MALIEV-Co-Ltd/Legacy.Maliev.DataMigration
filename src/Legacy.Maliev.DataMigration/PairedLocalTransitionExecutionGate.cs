namespace Legacy.Maliev.DataMigration;

/// <summary>Rechecks the short-lived signed LOCAL admission for every database.</summary>
public sealed class PairedLocalTransitionExecutionGate(
    PairedLocalTransitionExecutionPermit permit,
    FreshSchemaPlan schema) : IDeltaExecutionAuthorizationGate
{
    public Task ValidateAsync(DeltaSynchronizationPlan plan, string database,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DatabaseSchemaPlan selected = schema.Databases.Single(item => item.Database == database);
        permit.Require(plan, selected, permit.NowUtc);
        return Task.CompletedTask;
    }
}
