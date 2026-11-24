namespace Legacy.Maliev.DataMigration.Console;

// Accepted only from the fixed qualified Tests factory. No endpoint, role, signer or operation callback crosses this seam.
internal interface ICurrentAuthArchiveDefinitionAnchorLease : IAsyncDisposable
{
    CurrentAuthRepairScope Intent { get; }
    LocalExecutionBinding Binding { get; }
    string SourcePath { get; }
    Task RequireAsync(CancellationToken ct);
}
