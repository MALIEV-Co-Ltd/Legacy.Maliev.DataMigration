using System.Security.Cryptography;
using System.Reflection;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveInitialProducerTests
{
    [Theory]
    [InlineData("roll-forward", true)]
    [InlineData("same", true)]
    [InlineData("roll-back", false)]
    [InlineData("name", false)]
    [InlineData("culture", false)]
    [InlineData("token", false)]
    [InlineData("content", false)]
    [InlineData("unsigned-request", false)]
    [InlineData("unspecified-request-version", true)]
    [InlineData("unspecified-actual-version", false)]
    public void Managed_identity_allows_version_unification_only_for_the_same_accepted_identity(string fault, bool expected)
    {
        var requested = new AssemblyName("Microsoft.Extensions.Logging.Abstractions, Version=8.0.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60");
        var actual = new AssemblyName("Microsoft.Extensions.Logging.Abstractions, Version=10.0.0.0, Culture=neutral, PublicKeyToken=adb9793829ddae60");
        switch (fault)
        {
            case "same": actual.Version = requested.Version; break;
            case "roll-back": requested.Version = new(10, 0, 0, 0); actual.Version = new(8, 0, 0, 0); break;
            case "name": actual.Name = "Different.Dependency"; break;
            case "culture": actual.CultureName = "th-TH"; break;
            case "token": actual.SetPublicKeyToken([1, 2, 3, 4, 5, 6, 7, 8]); break;
            case "content": actual.ContentType = AssemblyContentType.WindowsRuntime; break;
            case "unsigned-request": requested.SetPublicKeyToken([]); break;
            case "unspecified-request-version": requested.Version = null; break;
            case "unspecified-actual-version": actual.Version = null; break;
            default:
                break;
        }
        Assert.Equal(expected, CurrentAuthArchiveInitialProducer.CompatibleManagedIdentity(requested, actual));
    }

    [Fact]
    public void Framework_reference_can_bind_to_the_newer_actual_runtime_identity()
    {
        var requested = new AssemblyName("System.Runtime, Version=6.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        var actual = new AssemblyName("System.Runtime, Version=10.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        Assert.True(CurrentAuthArchiveInitialProducer.CompatibleManagedIdentity(requested, actual));
    }

    [Theory]
    [InlineData("same")]
    [InlineData("changed-same-length")]
    [InlineData("shorter")]
    [InlineData("empty")]
    public void Shared_dependency_requires_identical_complete_bytes(string fault)
    {
        using var running = new MemoryStream("accepted-Npgsql-api-identity"u8.ToArray());
        using var test = new MemoryStream(fault switch
        {
            "same" => "accepted-Npgsql-api-identity"u8.ToArray(),
            "changed-same-length" => "accepted-Npgsql-api-identitX"u8.ToArray(),
            "shorter" => "accepted-Npgsql-api"u8.ToArray(),
            "empty" => [],
            _ => throw new InvalidOperationException(),
        });
        running.Position = running.Length; test.Position = test.Length;
        if (fault == "same")
        {
            CurrentAuthArchiveInitialProducer.RequireSharedDependencyBytes(running, test);
            Assert.Equal(0, running.Position); Assert.Equal(0, test.Position);
        }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveInitialProducer.RequireSharedDependencyBytes(running, test)); }
    }

    [Theory]
    [InlineData("bundle")]
    [InlineData("sibling")]
    [InlineData("escape")]
    [InlineData("unresolved")]
    [InlineData("relative")]
    public void Managed_and_native_resolution_require_a_canonical_path_inside_the_held_bundle(string fault)
    {
        string root = Path.Combine(Path.GetTempPath(), "held-loader-bundle");
        string? path = fault switch
        {
            "bundle" => Path.Combine(root, "runtimes", "win-x64", "native", "dependency.dll"),
            "sibling" => Path.Combine(root + "-unaccepted", "dependency.dll"),
            "escape" => Path.Combine(root, "..", "dependency.dll"),
            "unresolved" => null,
            "relative" => "dependency.dll",
            _ => throw new InvalidOperationException(),
        };
        if (fault == "bundle") { Assert.Equal(path, CurrentAuthArchiveInitialProducer.RequireBundleOrigin(path, root)); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveInitialProducer.RequireBundleOrigin(path, root)); }
    }

    [Theory]
    [InlineData("completed-scope")]
    [InlineData("source-hash")]
    [InlineData("precursor-binding")]
    [InlineData("same-root")]
    public async Task Rejected_initial_inputs_cannot_create_either_target_root(string fault)
    {
        // Names only. Neither directory is created by this test, including its failure path.
        string root = Path.Combine(Path.GetTempPath(), "archive-initial-rejected-" + Guid.NewGuid().ToString("N"));
        CurrentAuthArchiveProofArtifact Artifact(string name)
        {
            return new(Path.Combine(root, name), new('a', 64));
        }

        DeltaTrustedKeyReference[] Keys(string prefix)
        {
            return [new(prefix + "review", Path.Combine(root, prefix + "review.der")),
            new(prefix + "authorization", Path.Combine(root, prefix + "authorization.der")), new(prefix + "evidence", Path.Combine(root, prefix + "evidence.der"))];
        }

        var input = new CurrentAuthArchiveComponentReadbackInput(Artifact("parent.json"), Artifact("seed.json"), null,
            Artifact("source.json"), Artifact("pins.json"), Keys("parent"), Artifact("Legacy.Maliev.DataMigration.Tests.dll"),
            Artifact("console.dll"), Artifact("core.dll"), Artifact("precursor.json"), Artifact("precursor-scope.json"),
            Artifact("precursor-source.json"), Artifact("precursor-pins.json"), Keys("precursor"), Artifact("definition.json"));
        input = fault switch
        {
            "completed-scope" => input with { Scope = Artifact("caller-completed-scope.json") },
            "source-hash" => input with { Source = input.Source with { Sha256 = "unverified" } },
            "precursor-binding" => input with { PrecursorBinding = input.ParentBinding },
            _ => input,
        };
        var config = new CurrentAuthArchiveInitialProducerConfiguration(input, Path.Combine(root, "first"),
            Path.Combine(root, fault == "same-root" ? "first" : "second"));
        Assert.False(Directory.Exists(root));
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => CurrentAuthArchiveInitialNativeProducer.ObserveAsync(config, CancellationToken.None));
        Assert.False(Directory.Exists(root));
    }

    [Fact]
    public async Task Cancelled_initial_observation_stops_before_input_read_or_target_creation()
    {
        using var cancelled = new CancellationTokenSource();
        cancelled.Cancel();
        _ = await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            CurrentAuthArchiveInitialProducer.ObserveAsync(null!, cancelled.Token));
    }

    [Theory]
    [InlineData("none")]
    [InlineData("signature")]
    [InlineData("source")]
    [InlineData("parent")]
    [InlineData("image")]
    [InlineData("expired")]
    [InlineData("case")]
    public void Initial_seed_authentication_rejects_invalid_operands_without_completed_scope(string fault)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var authorizationKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var evidenceKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("review", key.ExportECPrivateKeyPem());
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var seed = scope.ComponentSubject!.Seed with { KeyId = signer.KeyId, CaseId = "dual-durable-readback" };
        var pins = new CurrentAuthArchivePins(signer.KeyId, signer.PublicKeyFingerprintSha256,
            "authorization", Convert.ToHexStringLower(SHA256.HashData(authorizationKey.ExportSubjectPublicKeyInfo())),
            "evidence", Convert.ToHexStringLower(SHA256.HashData(evidenceKey.ExportSubjectPublicKeyInfo())));
        seed = seed with { SigningPinsSha256 = CurrentAuthLocalSessionArchivePolicy.Hash(pins) };
        seed = fault switch
        {
            "source" => seed with { AcceptedSourceCommitSha = "not-a-commit" },
            "parent" => seed with { ParentRunBindingSha256 = "not-a-binding" },
            "image" => seed with { TestAssemblySha256 = string.Empty },
            "expired" => seed with { ExpiresAtUtc = now.AddSeconds(-1) },
            "case" => seed with { CaseId = "arbitrary-command" },
            _ => seed,
        };
        seed = seed with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthArchiveComponentBootstrap.SeedPayload(seed))) };
        var trust = new ReceiptAttestationTrustStore([new TrustedAttestationKey(signer.KeyId, key.ExportSubjectPublicKeyInfo()),
            new TrustedAttestationKey("authorization", authorizationKey.ExportSubjectPublicKeyInfo()), new TrustedAttestationKey("evidence", evidenceKey.ExportSubjectPublicKeyInfo())]);
        if (fault == "signature") { seed = seed with { Signature = Convert.ToBase64String(new byte[64]) }; }
        if (fault == "none") { CurrentAuthArchiveComponentBootstrap.RequireInitialSeed(seed, pins, trust, now); }
        else { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveComponentBootstrap.RequireInitialSeed(seed, pins, trust, now)); }
    }
}
