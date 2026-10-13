using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(LocalSnapshotIoTestGroup.Name)]
public sealed class CurrentAuthExecutedProofRecorderTests
{
    [WindowsLocalRunFact]
    public async Task Actual_fresh_recorder_protects_its_child_and_rejects_reuse()
    {
        string parent = Path.Combine(Path.GetTempPath(), $"auth-recorder-{Guid.NewGuid():N}");
        SecureSnapshotFileCreation.CreateRestrictedDirectory(parent);
        string? previous = Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_PROOF_ROOT");
        try
        {
            Assert.Null(previous);
            Assert.Null(Environment.GetEnvironmentVariable("MALIEV_AUTH_TYPED_COMPONENT_SEED"));
            Environment.SetEnvironmentVariable("MALIEV_AUTH_TYPED_PROOF_ROOT", parent);
            Guid run = Guid.NewGuid();
            using var authority = CurrentAuthExecutedProofRecorder.CreateFreshRootAuthority(parent, run);
            using var recorder = new CurrentAuthExecutedProofRecorder(authority, run, "history-10.0.12");
            Assert.NotNull(recorder);
            var artifact = await recorder.RecordAsync("actual-regression", new { Value = 1 }, CancellationToken.None);
            Assert.True(File.Exists(artifact.Path));
            Assert.Throws<IOException>(() => File.WriteAllText(artifact.Path, "changed"));
            Assert.Throws<InvalidOperationException>(() => CurrentAuthExecutedProofRecorder.CreateFreshRootAuthority(parent, run));
        }
        finally
        {
            Environment.SetEnvironmentVariable("MALIEV_AUTH_TYPED_PROOF_ROOT", previous);
            Directory.Delete(parent, recursive: true);
        }
    }
}
