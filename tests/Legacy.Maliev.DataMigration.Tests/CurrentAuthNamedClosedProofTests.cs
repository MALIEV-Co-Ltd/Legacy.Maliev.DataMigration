using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Pure negatives only. These unit values are not native/Console proof artifacts.
public sealed class CurrentAuthNamedClosedProofTests
{
    [Fact]
    public void Closed_case_set_rejects_component_subset_unknown_duplicate_operation_and_root()
    {
        CurrentAuthNamedClosedCase[] complete = [.. CurrentAuthNamedClosedProofReadback.Cases.Select(id =>
            new CurrentAuthNamedClosedCase(id, Guid.NewGuid(), @"D:\pure-unit\" + id, @"D:\pure-unit\binding.json", new string('a', 64), []))];
        CurrentAuthNamedClosedProofReadback.RequireCaseSet(complete);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNamedClosedProofReadback.RequireCaseSet(complete.Take(6).ToArray()));
        var changed = complete.ToArray(); changed[0] = changed[0] with { CaseId = "component-success" };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNamedClosedProofReadback.RequireCaseSet(changed));
        changed = complete.ToArray(); changed[0] = changed[0] with { OperationId = changed[1].OperationId };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNamedClosedProofReadback.RequireCaseSet(changed));
        changed = complete.ToArray(); changed[0] = changed[0] with { Root = changed[1].Root.ToUpperInvariant() };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthNamedClosedProofReadback.RequireCaseSet(changed));
    }
    [Fact]
    public void Report_signature_binds_phase_scope_artifacts_and_original_case_custody()
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var artifact = new CurrentAuthProofArtifact(@"D:\pure-unit\held.json", new string('a', 64));
        var report = new CurrentAuthNamedClosedReport("current-auth-eight-named-console-proof-v1", "native", new string('b', 64), new string('c', 40),
            artifact, artifact, artifact, DateTimeOffset.UtcNow, [new("success", Guid.NewGuid(), @"D:\pure-unit\original", @"D:\pure-unit\binding.json", new string('d', 64), [artifact])], "pure-unit", null);
        byte[] signature = key.SignData(CurrentAuthNamedClosedProofReadback.Payload(report), HashAlgorithmName.SHA256);
        bool Valid(CurrentAuthNamedClosedReport value)
        {
            return key.VerifyData(CurrentAuthNamedClosedProofReadback.Payload(value), signature, HashAlgorithmName.SHA256);
        }

        Assert.True(Valid(report with { Signature = "signature-excluded-from-payload" }));
        Assert.False(Valid(report with { Phase = "maintenance" }));
        Assert.False(Valid(report with { SubjectSha256 = new string('e', 64) }));
        Assert.False(Valid(report with { Cases = [report.Cases[0] with { Root = @"D:\pure-unit\different" }] }));
        Assert.False(Valid(report with { Host = artifact with { Sha256 = new string('f', 64) } }));
    }
    [Fact]
    public void Host_closed_filter_is_fixed_and_has_no_caller_commands()
    {
        Assert.Equal("FullyQualifiedName~CurrentAuthClosedConsoleExecutionTests.Genuine_named_closed_auth_console_preserves_or_stops", CurrentAuthTypedHostProducer.Filter("closed"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedHostProducer.Filter("closed|FullyQualifiedName~OtherTests"));
    }
}
