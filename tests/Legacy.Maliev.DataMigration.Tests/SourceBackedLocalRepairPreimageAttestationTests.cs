using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed partial class DisposableDeltaProofVerifierTests
{
    [Theory]
    [InlineData("signature")]
    [InlineData("preimage")]
    [InlineData("identity")]
    [InlineData("capture")]
    [InlineData("proof")]
    [InlineData("authorization")]
    [InlineData("expiry")]
    [InlineData("inventory")]
    public async Task Source_repair_signed_preimages_bind_fresh_proof_and_all_database_digests(string mutation)
    {
        Fixture fixture = await CreateAsync(pairedTransition: true, quotationDisposition: true,
            captured: true, historicalLocal: true);
        var plans = new PairedCapturedDeltaPlans(fixture.ProofPlan, fixture.LocalPlan);
        using var authorizationSigner = new P256MigrationEvidenceSigner("local-transition-authorization",
            _authorizationKey.ExportECPrivateKeyPem());
        using var evidenceSigner = new P256MigrationEvidenceSigner("proof-evidence", _evidenceKey.ExportECPrivateKeyPem());
        PairedLocalTransitionAuthorization authorization = PairedLocalTransitionAuthorizationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, fixture.Trust, fixture.LocalPlan.TargetAuthority!,
            fixture.LocalPlan.TargetObservationSha256, fixture.LocalPlan.QuotationTransitionSchemaSha256!,
            fixture.Now.AddMinutes(-1), fixture.Now.AddMinutes(5), authorizationSigner);
        var identity = new HistoricalCurrentLocalObservation(Hash('7'), fixture.LocalPlan.TargetGeneration,
            "legacy-maliev-exact23-postgres-data", DateTimeOffset.FromUnixTimeMilliseconds(3),
            "/var/lib/docker/volumes/legacy-maliev-exact23-postgres-data/_data", "/var/lib/postgresql",
            "/var/lib/postgresql/18/docker", fixture.LocalPlan.TargetAuthority!.SystemIdentifierSha256);
        SourceBackedLocalRepairDatabasePreimage[] snapshots = [.. fixture.Schema.Databases.Select(database =>
            new SourceBackedLocalRepairDatabasePreimage(database.Database, Hash('a'), Hash('b'),
                [new("public", "source", 1, Hash('c'), Hash('d'))], []))];
        SourceBackedLocalRepairPreimageAttestation attestation = SourceBackedLocalRepairPreimageAttestationPolicy.Produce(
            plans, fixture.ProofResult, fixture.Schema, authorization, identity, snapshots, fixture.Trust,
            fixture.Now, fixture.Now.AddMinutes(5), evidenceSigner);
        Assert.False(SourceBackedLocalRepairPreimageAttestation.AuthorizesExecution);
        SourceBackedLocalRepairPreimageAttestationPolicy.Verify(attestation, plans, fixture.ProofResult,
            fixture.Schema, authorization, identity, snapshots, fixture.Trust, fixture.Now);
        var roundtrip = JsonSerializer.Deserialize<SourceBackedLocalRepairPreimageAttestation>(JsonSerializer.Serialize(attestation))!;
        SourceBackedLocalRepairPreimageAttestationPolicy.Verify(roundtrip, plans, fixture.ProofResult,
            fixture.Schema, authorization, identity, snapshots, fixture.Trust, fixture.Now);
        SourceBackedLocalRepairPreimageAttestation changed = mutation switch
        {
            "signature" => attestation with { AttestationSignature = "bad" },
            "capture" => attestation with { SourceCaptureSha256 = Hash('f') },
            "proof" => attestation with { DisposableReceiptSha256 = Hash('f') },
            "authorization" => attestation with { AuthorizationId = Guid.NewGuid() },
            "inventory" => attestation with { Databases = snapshots[..^1] },
            _ => attestation,
        };
        if (mutation is "capture" or "proof" or "authorization" or "inventory")
        {
            changed = changed with
            {
                AttestationSignature = Convert.ToBase64String(
                evidenceSigner.Sign(SourceBackedLocalRepairPreimageAttestationPolicy.CreatePayload(changed)))
            };
        }
        SourceBackedLocalRepairDatabasePreimage[] observed = mutation == "preimage"
            ? [snapshots[0] with { Relations = [snapshots[0].Relations[0] with { Rows = 2 }] }, .. snapshots.Skip(1)]
            : snapshots;
        HistoricalCurrentLocalObservation currentIdentity = mutation == "identity"
            ? identity with { VolumeMountpoint = "/other-volume" } : identity;
        _ = Assert.Throws<DeltaExecutionException>(() => SourceBackedLocalRepairPreimageAttestationPolicy.Verify(
            changed, plans, fixture.ProofResult, fixture.Schema, authorization, currentIdentity, observed,
            fixture.Trust, mutation == "expiry" ? fixture.Now.AddMinutes(5) : fixture.Now));
    }
}
