using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentOwnerIsoNamedClosedProofReaderTests
{
    [Fact]
    public void Failed_apply_requires_actual_replay_rejection_and_ordered_public_commands()
    {
        Guid operation = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.Parse("2026-10-13T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        string[] commands = ["review-current-owner-iso-repair", "authorize-current-owner-iso-repair", "verify-current-owner-iso-repair", "apply-current-owner-iso-repair", "apply-current-owner-iso-repair"];
        var calls = commands.Select((command, index) => new IsoNamedClosedInvocation(command, operation, began.AddSeconds(index * 2), began.AddSeconds((index * 2) + 1), index < 3 ? 0 : 1, new('a', 64), new('b', 64))).ToArray();
        IsoNamedClosedProofReader.RequireCalls("lost-commit-ack", calls, operation);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoNamedClosedProofReader.RequireCalls("lost-commit-ack", calls.Take(4).ToArray(), operation));
        var replayed = calls.ToArray(); replayed[4] = replayed[4] with { ExitCode = 0 };
        _ = Assert.Throws<MigrationExecutionException>(() => IsoNamedClosedProofReader.RequireCalls("lost-commit-ack", replayed, operation));
        var overlap = calls.ToArray(); overlap[1] = overlap[1] with { StartedAtUtc = began };
        _ = Assert.Throws<MigrationExecutionException>(() => IsoNamedClosedProofReader.RequireCalls("lost-commit-ack", overlap, operation));
    }
    [Theory]
    [InlineData("unsafe-host")]
    [InlineData("local-trust")]
    [InlineData("wrong-owner")]
    public void Rejected_review_cannot_be_replaced_by_operational_claims(string id)
    {
        Guid operation = Guid.NewGuid(); DateTimeOffset now = DateTimeOffset.Parse("2026-10-13T00:00:00Z", System.Globalization.CultureInfo.InvariantCulture);
        var call = new IsoNamedClosedInvocation("review-current-owner-iso-repair", operation, now, now.AddSeconds(1), 1, new('a', 64), new('b', 64));
        IsoNamedClosedProofReader.RequireCalls(id, [call], operation);
        _ = Assert.Throws<MigrationExecutionException>(() => IsoNamedClosedProofReader.RequireCalls(id, [call with { ExitCode = 0 }], operation));
        _ = Assert.Throws<MigrationExecutionException>(() => IsoNamedClosedProofReader.RequireCalls(id, [call, call with { Command = "authorize-current-owner-iso-repair" }], operation));
    }
    [Fact]
    public void Host_groups_bind_only_real_named_Console_cases()
    {
        string native = OwnerIsoNamedClosedBootstrapHostLauncher.Filter("native-closed"), maintenance = OwnerIsoNamedClosedBootstrapHostLauncher.Filter("maintenance-closed");
        Assert.Equal(6, native.Split('|').Length); Assert.Equal(4, maintenance.Split('|').Length);
        Assert.Contains("CurrentOwnerIsoClosedConsoleExecutionTests.", native, StringComparison.Ordinal);
        Assert.DoesNotContain("CurrentOwnerIsoGuardedNativeExecutionTests", native, StringComparison.Ordinal);
        _ = Assert.Throws<MigrationExecutionException>(() => OwnerIsoNamedClosedBootstrapHostLauncher.Filter("native-component"));
    }
    [Theory]
    [InlineData("operator.txt", false)]
    [InlineData("source-connection.txt", false)]
    [InlineData("key.private.pem", false)]
    [InlineData("key.public.txt", true)]
    [InlineData("iso-closed-case-x-closed-scope.json", true)]
    public void Proof_import_excludes_secret_material(string name, bool accepted)
    {
        Assert.Equal(accepted, IsoNamedClosedProofAssembler.IsNonSecretCaseArtifact(name));
    }
}
