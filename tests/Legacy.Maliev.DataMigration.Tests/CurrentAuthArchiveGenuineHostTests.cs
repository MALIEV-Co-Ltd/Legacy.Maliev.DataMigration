using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveGenuineHostTests
{
    [Fact]
    public void Fixed_inventory_matches_existing_reader_without_creating_case_results()
    {
        CurrentAuthArchiveGenuineCase[] cases = CurrentAuthArchiveGenuineCases.Inventory();
        Assert.Equal(18, cases.Length);
        Assert.Equal(18, cases.Select(x => x.MethodName).Distinct(StringComparer.Ordinal).Count());
        foreach (string phase in new[] { "helper", "native", "delete", "recovery" })
        {
            Assert.Equal(CurrentAuthArchiveProofReader.Cases(phase), cases.Where(x => x.Phase == phase).Select(x => x.CaseId));
        }
        foreach (var item in cases)
        {
            Assert.Equal("FullyQualifiedName=Legacy.Maliev.DataMigration.Tests.CurrentAuthArchiveGuardedExecutionTests." + item.MethodName,
                CurrentAuthTypedHostProducer.ArchiveFilter(item.Phase, item.CaseId));
        }
        cases[0] = cases[0] with { CaseId = "unreviewed" };
        Assert.Equal("dual-durable-readback", CurrentAuthArchiveGenuineCases.Inventory()[0].CaseId);
    }

    [Theory]
    [InlineData("helper", "complete")]
    [InlineData("native", "arbitrary-command")]
    [InlineData("closed", "dual-durable-readback")]
    [InlineData("Helper", "dual-durable-readback")]
    public void Unknown_or_cross_family_cases_cannot_select_a_test(string phase, string id)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedHostProducer.ArchiveFilter(phase, id));
    }

    [Fact]
    public void Old_auth16_family_cannot_select_archive_tests()
    {
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthTypedHostProducer.Filter("archive"));
        Assert.DoesNotContain("CurrentAuthArchiveGuardedExecutionTests", CurrentAuthTypedHostProducer.Filter("provider"), StringComparison.Ordinal);
        var request = JsonSerializer.Deserialize<CurrentAuthArchiveGenuineHostConfiguration>(
            """{"Group":"provider","Root":"ignored","TestAssemblyPath":"ignored"}""")!;
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineHost.RequireInput(request));
    }

    [Fact]
    public void Missing_real_cases_are_a_refusal_and_never_an_empty_successful_suite()
    {
        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(() =>
            CurrentAuthArchiveGenuineHost.RequireCompleteCaseInventory(typeof(CurrentAuthArchiveGuardedExecutionTests).Assembly));
        Assert.Equal("current_auth_archive_genuine_cases_missing", failure.Code);
        Assert.Equal(CurrentAuthArchiveGenuineCases.Inventory().Where(x => x.Phase == "helper" || x.CaseId is "complete" or "exact-reviewed-delete" or "prepared-publication" or "terminal-publication" or "commit-ack-lost" or "CAS-field-drift" or "private-journal-drift" or "sequence-drift" or "production-drift" or "host-unprobed-sdk" or "local-trust").Select(x => x.MethodName).Order(StringComparer.Ordinal),
            typeof(CurrentAuthArchiveGuardedExecutionTests).GetMethods().Where(x => x.Name.StartsWith("Archive_", StringComparison.Ordinal))
                .Select(x => x.Name).Order(StringComparer.Ordinal));
    }

    [Fact]
    public async Task Cancelled_provider_stops_before_images_inputs_or_targets()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveGenuineHost.AuthenticateAsync(null!, cancelled.Token));
    }

    [Fact]
    public async Task Cancelled_child_stops_before_runtime_inputs_or_target_creation()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveGenuineHost.AuthenticateChildAsync(null!, cancelled.Token));
    }

    [Fact]
    public void Case_inventory_cannot_be_supplied_by_a_different_assembly()
    {
        _ = Assert.Throws<MigrationExecutionException>(() =>
            CurrentAuthArchiveGenuineHost.RequireCompleteCaseInventory(typeof(CurrentAuthArchiveGenuineHostConfiguration).Assembly));
    }

    [Fact]
    public void Dispatcher_keeps_archive_and_auth16_configuration_families_distinct()
    {
        Assert.Equal(CurrentAuthArchiveGenuineHost.ProviderCommand,
            ConsoleInvocation.Parse([CurrentAuthArchiveGenuineHost.ProviderCommand, "--config", Path.Combine(Path.GetTempPath(), "protected.json")]).Command);
        Assert.Equal(CurrentAuthArchiveGenuineHost.ChildCommand,
            ConsoleInvocation.Parse([CurrentAuthArchiveGenuineHost.ChildCommand, "--config", Path.Combine(Path.GetTempPath(), "protected.json")]).Command);
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("scope")]
    [InlineData("same-root")]
    [InlineData("relative-root")]
    [InlineData("case")]
    [InlineData("image")]
    public void Typed_archive_request_rejects_mixed_or_unbound_inputs_before_any_io(string fault)
    {
        var request = Request();
        request = fault switch
        {
            "kind" => request with { Kind = "current-auth-typed-host" },
            "scope" => request with
            {
                Inputs = request.Inputs with
                { Scope = request.Inputs.ParentSeed }
            },
            "same-root" => request with { SecondFixtureParent = request.FirstFixtureParent },
            "relative-root" => request with { FirstFixtureParent = "relative" },
            "case" => request with { CaseId = "arbitrary-command" },
            "image" => request with
            {
                Inputs = request.Inputs with
                { TestImage = request.Inputs.TestImage with { Path = Path.Combine(Path.GetTempPath(), "Different.dll") } }
            },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineHost.RequireInput(request));
    }

    [Theory]
    [InlineData("kind")]
    [InlineData("root")]
    [InlineData("binding")]
    [InlineData("nonce")]
    [InlineData("gate")]
    [InlineData("expired")]
    [InlineData("lease")]
    public void Archive_child_cannot_adopt_another_family_root_gate_or_lease(string fault)
    {
        var request = Request();
        string root = Path.GetDirectoryName(request.Inputs.ParentBinding.Path)!;
        string nonce = Guid.NewGuid().ToString("N");
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var child = new CurrentAuthArchiveGenuineChildConfiguration(CurrentAuthArchiveGenuineHost.ChildKind,
            root, request.Inputs.ParentBinding.Sha256, Path.Combine(root, "auth-archive-genuine-gate-" + nonce + ".json"),
            nonce, now.AddMinutes(1), request);
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        CurrentAuthArchiveGenuineHost.RequireChildInput(child, now); // Shape only, not authenticated custody or job membership.
        child = fault switch
        {
            "kind" => child with { Kind = CurrentAuthArchiveGenuineHost.ProviderKind },
            "root" => child with { Root = Path.Combine(root, "other") },
            "binding" => child with { RunBindingSha256 = new('1', 64) },
            "nonce" => child with { GateNonce = "unbound" },
            "gate" => child with { GatePath = Path.Combine(root, "unbound.json") },
            "expired" => child with { ExpiresAtUtc = now },
            "lease" => child with { ExpiresAtUtc = now.AddMinutes(9) },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveGenuineHost.RequireChildInput(child, now));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public void No_marker_or_valid_shape_can_activate_the_missing_owned_pair_producer()
    {
        MigrationExecutionException failure = Assert.Throws<MigrationExecutionException>(CurrentAuthArchiveGenuineHost.RequireOwnedPairProducer);
        Assert.Equal("current_auth_archive_genuine_owned_pair_producer_unavailable", failure.Code);
    }

    private static CurrentAuthArchiveGenuineHostConfiguration Request()
    {
        string root = Path.Combine(Path.GetTempPath(), "auth-archive-genuine-pure-" + Guid.NewGuid().ToString("N"));
        CurrentAuthArchiveProofArtifact Artifact(string name)
        {
            return new(Path.Combine(root, name), new('0', 64));
        }

        DeltaTrustedKeyReference[] Keys(string prefix)
        {
            return [.. Enumerable.Range(1, 3).Select(index =>
            new DeltaTrustedKeyReference(prefix + index, Path.Combine(root, prefix + index + ".public")))];
        }

        var inputs = new CurrentAuthArchiveComponentReadbackInput(Artifact("parent-binding.json"), Artifact("seed.json"), null,
            Artifact("source.json"), Artifact("pins.json"), Keys("archive-"), Artifact("Legacy.Maliev.DataMigration.Tests.dll"),
            Artifact("console.dll"), Artifact("core.dll"), Artifact("precursor-binding.json"), Artifact("precursor-scope.json"),
            Artifact("precursor-source.json"), Artifact("precursor-pins.json"), Keys("precursor-"), Artifact("definition.json"));
        return new(CurrentAuthArchiveGenuineHost.ProviderKind, "helper", "dual-durable-readback", inputs,
            Path.Combine(root, "first"), Path.Combine(root, "second"));
    }
}

// Whitelisted accepted Tests-bundle entry. Authentication only; creates no fixture, result or resource.
internal static class CurrentAuthArchiveGenuineInputReader
{
    internal static async Task AuthenticateAsync(CurrentAuthArchiveGenuineHostConfiguration request, CancellationToken ct)
    {
        CurrentAuthArchiveGenuineHost.RequireInput(request);
        using var inputs = await CurrentAuthArchiveComponentReadback.OpenInitialAsync(request.Inputs, ct);
        _ = await inputs.ReadSeedAsync(ct);
        await inputs.RequireAsync(ct);
        CurrentAuthArchiveGenuineHost.RequireCompleteCaseInventory(typeof(CurrentAuthArchiveGuardedExecutionTests).Assembly);
    }
}
