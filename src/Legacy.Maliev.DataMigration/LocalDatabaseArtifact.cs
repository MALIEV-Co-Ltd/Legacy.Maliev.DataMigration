namespace Legacy.Maliev.DataMigration;

public interface IDatabaseCheckpointDelivery
{
    Task DeliverAndVerifyAsync(DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken);
}

public interface ILocalDatabaseArchiveVerifier
{
    Task VerifyAsync(Stream authenticatedPlaintext, DatabaseMigrationCheckpoint checkpoint, CancellationToken cancellationToken);
}

public sealed record LocalDatabaseArtifact(
    int SchemaVersion,
    string SnapshotId,
    string CheckpointJson,
    string CheckpointSha256,
    LocalSnapshotDatabase Archive,
    string MetadataMacSha256);
