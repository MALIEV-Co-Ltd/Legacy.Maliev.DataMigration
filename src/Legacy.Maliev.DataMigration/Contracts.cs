namespace Legacy.Maliev.DataMigration;

public enum DatabaseDisposition
{
    Migrate,
    ArchiveOnly,
    Excluded,
}

public sealed record DatabaseDispositionEntry(
    string Owner,
    DatabaseDisposition Disposition);

public sealed record BackupArtifact(
    string Database,
    string BackupType,
    string FileName,
    long ByteLength,
    string Sha256,
    string ObservedSha256);

public sealed record BackupReceipt(
    string SchemaVersion,
    DateTimeOffset CapturedAtUtc,
    string DatabaseInventorySha256,
    string ManifestSha256,
    IReadOnlyList<BackupArtifact> Artifacts);

public sealed record MigrationPlan(
    string Mode,
    bool AllowTargetWrites,
    Dictionary<string, string> TargetSchemaVersions,
    IReadOnlyList<string> RequestedExternalActions);

public sealed record PreflightError(string Code, string Message);

public sealed record PreflightResult(IReadOnlyList<PreflightError> Errors)
{
    public bool IsValid => Errors.Count == 0;
}

public interface IExternalCommandExecutor
{
    Task<int> ExecuteAsync(string command, CancellationToken cancellationToken);
}
