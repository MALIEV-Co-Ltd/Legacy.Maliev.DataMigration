using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class DualTargetCapturedProofOwnershipTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
    private static readonly string Accepted = new('a', 40);
    private const string Connection = "Host=127.0.0.1;Port=15432;Database=postgres;Username=synthetic;Password=synthetic";

    [Theory]
    [InlineData("plan-dual-target-captured-delta", null)]
    [InlineData("prove-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.ProductionProof)]
    [InlineData("prove-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.LocalProof)]
    public void Direct_proof_route_refuses_without_actual_owned_pair(string command, int? purpose)
    { _ = Assert.Throws<MigrationExecutionException>(() => DualTargetCapturedOwnedProofPair.RequireCommand(command, (DualTargetCapturedDeltaPurpose?)purpose, null)); }

    [Theory]
    [InlineData((int)DualTargetCapturedDeltaPurpose.ProductionProof)]
    [InlineData((int)DualTargetCapturedDeltaPurpose.LocalProof)]
    public async Task Proof_looking_endpoint_without_owner_refuses_before_connection_parsing(int purpose)
    {
        DualTargetCapturedDeltaEndpoint endpoint = Endpoint() with { Purpose = (DualTargetCapturedDeltaPurpose)purpose };
        _ = await Assert.ThrowsAsync<MigrationExecutionException>(() => DualTargetNativeProofClone.ProofLease.RequireEndpointAsync(
            endpoint, "not even a connection string", Accepted, null, default));
    }

    [Theory]
    [InlineData("review-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.Production)]
    [InlineData("review-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.PersistentLocal)]
    [InlineData("apply-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.Production)]
    [InlineData("apply-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.PersistentLocal)]
    public void Persistent_receipt_admission_does_not_require_live_disposed_proof_clones(string command, int purpose)
    {
        DualTargetCapturedOwnedProofPair.RequireCommand(command, (DualTargetCapturedDeltaPurpose?)purpose, null);
    }

    [Theory]
    [InlineData("apply-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.ProductionProof)]
    [InlineData("review-dual-target-captured-delta", (int)DualTargetCapturedDeltaPurpose.LocalProof)]
    public void Persistent_commands_cannot_be_reused_as_proof_endpoint_writers(string command, int purpose)
    { _ = Assert.Throws<MigrationExecutionException>(() => DualTargetCapturedOwnedProofPair.RequireCommand(command, (DualTargetCapturedDeltaPurpose?)purpose, null)); }

    [Fact]
    public void Closed_lease_has_no_JSON_constructor_and_binding_JSON_is_not_authority()
    {
        Assert.Empty(typeof(DualTargetNativeProofClone.ProofLease).GetConstructors());
        _ = Assert.Throws<NotSupportedException>(() => JsonSerializer.Deserialize<DualTargetNativeProofClone.ProofLease>(JsonSerializer.Serialize(Binding())));
        _ = Assert.Throws<MigrationExecutionException>(() => DualTargetCapturedOwnedProofPair.RequireCommand(
            "prove-dual-target-captured-delta", Binding().Purpose, null));
    }

    [Fact]
    public void Binding_swap_checks_start_with_valid_fixture_then_reject_each_changed_field()
    {
        var endpoint = Endpoint(); var binding = Binding();
        binding.Require(endpoint, Connection, Accepted, Now);
        DualTargetCapturedDeltaEndpoint[] swapped =
        [
            endpoint with { Purpose = DualTargetCapturedDeltaPurpose.LocalProof },
            endpoint with { DockerContainerId = new string('c', 64) },
            endpoint with { DockerVolumeName = "another-proof-volume" },
            endpoint with { ConnectionFile = "another-operator.txt" },
            endpoint with { MaintenancePinsPath = "another-maintenance.json" }
        ];
        foreach (var candidate in swapped)
        { _ = Assert.Throws<MigrationExecutionException>(() => binding.Require(candidate, Connection, Accepted, Now)); }
        _ = Assert.Throws<MigrationExecutionException>(() => binding.Require(endpoint, Connection + ";Application Name=changed", Accepted, Now));
        _ = Assert.Throws<MigrationExecutionException>(() => binding.Require(endpoint, Connection, new string('b', 40), Now));
        _ = Assert.Throws<MigrationExecutionException>(() => binding.Require(endpoint, Connection, Accepted, binding.ExpiresAtUtc));
        _ = Assert.Throws<MigrationExecutionException>(() => (binding with { ExpiresAtUtc = Now.AddSeconds(-1) }).Require(endpoint, Connection, Accepted, Now));
    }

    [Fact]
    public void Factory_label_commitment_binds_every_label_including_tool_metadata()
    {
        var labels = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["codex.repair.purpose"] = "dual-target-native-proof-preimage",
            ["codex.repair.operation"] = "synthetic-operation",
            ["codex.repair.run-binding"] = "synthetic-binding",
            ["org.testcontainers.synthetic"] = "synthetic-metadata"
        };
        string before = DualTargetNativeProofClone.LabelHash(labels);
        Assert.Equal(before, DualTargetNativeProofClone.LabelHash(labels.Reverse().ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal)));
        var changed = labels.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal);
        changed["org.testcontainers.synthetic"] = "rebound";
        Assert.NotEqual(before, DualTargetNativeProofClone.LabelHash(changed));
        changed = labels.ToDictionary(x => x.Key, x => x.Value, StringComparer.Ordinal); changed.Add("extra", "unexpected");
        Assert.NotEqual(before, DualTargetNativeProofClone.LabelHash(changed));
        _ = changed.Remove("org.testcontainers.synthetic");
        Assert.NotEqual(before, DualTargetNativeProofClone.LabelHash(changed));
    }

    private static DualTargetCapturedProofBinding Binding()
    {
        var endpoint = Endpoint();
        return new(endpoint.Purpose, endpoint.DockerContainerId!, endpoint.DockerVolumeName!,
            DualTargetCapturedProofBinding.ConnectionHash(Connection), DualTargetCapturedProofBinding.EndpointHash(endpoint), Accepted, Now.AddMinutes(1));
    }
    private static DualTargetCapturedDeltaEndpoint Endpoint()
    {
        return new(DualTargetCapturedDeltaPurpose.ProductionProof,
        "synthetic-operator.txt", new string('d', 64), "legacy-delta-proof-synthetic", "synthetic-maintenance.json",
        new("plan", "plan.spki"), new("authorization", "authorization.spki"), new("evidence", "evidence.spki"));
    }
}
