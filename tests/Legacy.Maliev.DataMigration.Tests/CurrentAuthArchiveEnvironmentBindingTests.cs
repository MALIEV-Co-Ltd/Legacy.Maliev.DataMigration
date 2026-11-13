using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

// Synthetic identity contracts only. These do not fabricate a successful held observer or native proof.
public sealed class CurrentAuthArchiveEnvironmentBindingTests
{
    [Fact]
    public void Catalog_subject_digest_repeats_across_capture_clocks_but_binds_native_identity_and_flags()
    {
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var before = new CurrentAuthArchiveCatalogObservation(new('a', 64), new('b', 64), new('c', 64), true,
            [new("postgres", false, true), new("template0", true, false)], now.AddSeconds(-3), now.AddSeconds(-2));
        var original = new CurrentAuthArchiveFleetCatalogs(before, before with { BeganAtUtc = now.AddSeconds(-1), EndedAtUtc = now },
            now.AddSeconds(-2), now.AddSeconds(-1));
        string digest = CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(original);
        var later = original with
        {
            Before = before with { BeganAtUtc = now, EndedAtUtc = now.AddSeconds(1) },
            After = before with { BeganAtUtc = now.AddSeconds(2), EndedAtUtc = now.AddSeconds(3) },
            CaptureBeganAtUtc = now.AddSeconds(1),
            CaptureEndedAtUtc = now.AddSeconds(2),
        };
        Assert.Equal(digest, CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(later));
        Assert.NotEqual(digest, CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(original with
        { After = original.After with { SystemIdentifierSha256 = new('d', 64) } }));
        Assert.NotEqual(digest, CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(original with
        { After = original.After with { ReadOnly = false } }));
        Assert.NotEqual(digest, CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(original with
        { After = original.After with { Databases = [new("postgres", false, true), new("template0", true, true)] } }));
        Assert.NotEqual(digest, CurrentAuthLocalSessionArchiveEnvironment.ComponentCatalogSha256(original with
        { After = original.After with { Databases = [.. original.After.Databases, new("unreviewed", false, true)] } }));
    }

    [Fact]
    public void Matching_decoded_environment_identity_does_not_require_reference_equality()
    {
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow);
        var source = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        var decodedScope = JsonSerializer.Deserialize<CurrentAuthArchiveScope>(JsonSerializer.SerializeToUtf8Bytes(scope))!;
        var decodedSource = JsonSerializer.Deserialize<FreshSchemaPlan>(JsonSerializer.SerializeToUtf8Bytes(source))!;
        CurrentAuthArchiveComponentReadback.RequireSameEnvironment(scope, source, decodedScope, decodedSource);
    }

    [Theory]
    [InlineData("operation")]
    [InlineData("target")]
    [InlineData("lease")]
    [InlineData("recovery-path")]
    [InlineData("source")]
    public void Bound_environment_rejects_substituted_operands(string fault)
    {
        var scope = CurrentAuthLocalSessionArchiveConsoleTests.Scope(DateTimeOffset.UtcNow);
        var source = CurrentConsumerSchemaV2Tests.Schema(ConsumerOverlaySelection.CurrentConsumerSchemaV3);
        var changed = fault switch
        {
            "operation" => scope with { OperationId = Guid.NewGuid() },
            "target" => scope with { LocalObservationPolicy = scope.LocalObservationPolicy with { TargetGeneration = "different" } },
            "lease" => scope with { ExpiresAtUtc = scope.ExpiresAtUtc.AddTicks(1) },
            "recovery-path" => scope with { Paths = scope.Paths with { FirstCiphertext = scope.Paths.FirstCiphertext + ".substituted" } },
            _ => scope,
        };
        var changedSource = fault == "source" ? source with { SourceCommitSha = new('b', 40) } : source;
        _ = Assert.Throws<MigrationExecutionException>(() =>
            CurrentAuthArchiveComponentReadback.RequireSameEnvironment(scope, source, changed, changedSource));
    }
}
