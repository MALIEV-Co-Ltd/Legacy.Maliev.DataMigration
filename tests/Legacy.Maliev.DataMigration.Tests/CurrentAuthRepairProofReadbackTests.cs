using System.Security.Cryptography;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthRepairProofReadbackTests
{
    [Theory]
    [InlineData(3UL * 1024 * 1024 * 1024 - 1, 0UL, true)]
    [InlineData(1024UL * 1024 * 1024 - 1, 0UL, false)]
    [InlineData(4UL * 1024 * 1024 * 1024, 5UL * 1024 * 1024 * 1024 + 1, false)]
    public void Capacity_limits_cannot_be_lowered(ulong available, ulong rss, bool admission)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairCapacity.RequireValues(available, rss, admission)); }
    [Fact]
    public void Exact_capacity_thresholds_are_accepted_without_native_observation()
    {
        CurrentAuthRepairCapacity.RequireValues(3UL * 1024 * 1024 * 1024, 5UL * 1024 * 1024 * 1024, true);
        CurrentAuthRepairCapacity.RequireValues(1024UL * 1024 * 1024, 0, false);
    }
    [Fact]
    public void Component_mode_never_grants_a_persistent_target()
    {
        CurrentAuthRepairScope scope = Scope(DateTimeOffset.UtcNow);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairPermit.RequireProofAdmission(scope with { ProofAdmission = CurrentAuthProofAdmission.DisposableNativeBootstrap }));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairPermit.RequireProofAdmission(scope with { ProofAdmission = (CurrentAuthProofAdmission)9 }));
        CurrentAuthRepairPermit.RequireProofAdmission(scope);
        CurrentAuthRepairPermit.RequireProofAdmission(scope with
        { ProofAdmission = CurrentAuthProofAdmission.DisposableNativeBootstrap, Target = scope.Target with { AuthorityId = "aspire://legacy-postgres-main-local/disposable-aaaaaaaaaaaa" } });
    }
    [Fact]
    public void Precursor_subject_excludes_digest_cycle_but_binds_target_source_and_mode()
    {
        CurrentAuthRepairScope scope = Scope(DateTimeOffset.UtcNow); string subject = CurrentAuthRepairProofReader.Subject(scope);
        Assert.Equal(subject, CurrentAuthRepairProofReader.Subject(scope with { AuthHelperProofSha256 = new string('1', 64), NativeProofSha256 = new string('2', 64), OperationSha256 = new string('3', 64) }));
        Assert.NotEqual(subject, CurrentAuthRepairProofReader.Subject(scope with { SourceCommitSha = new string('b', 40) }));
        Assert.NotEqual(subject, CurrentAuthRepairProofReader.Subject(scope with { RunBindingSha256 = new string('b', 64) }));
        Assert.NotEqual(subject, CurrentAuthRepairProofReader.Subject(scope with { ProofAdmission = CurrentAuthProofAdmission.DisposableNativeBootstrap }));
    }
    [Theory]
    [InlineData("marker")]
    [InlineData("subject")]
    [InlineData("source")]
    [InlineData("assembly")]
    [InlineData("expiry")]
    [InlineData("domain")]
    public void Genuine_resigned_wrong_semantics_or_foreign_domain_is_rejected(string fault)
    {
        DateTimeOffset now = DateTimeOffset.UtcNow; CurrentAuthRepairScope scope = Scope(now);
        using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var signer = new P256MigrationEvidenceSigner("proof-receipt", key.ExportPkcs8PrivateKeyPem());
        var trust = new ReceiptAttestationTrustStore([new("proof-receipt", key.ExportSubjectPublicKeyInfo())]);
        var pins = new CurrentAuthRepairSigningPins("review", new string('b', 64), "authorize", new string('c', 64), signer.KeyId, signer.PublicKeyFingerprintSha256);
        var artifact = new CurrentAuthProofArtifact("synthetic", new string('a', 64));
        var proof = new CurrentAuthClosedProof("current-auth-native-closed-console-proof-v1", CurrentAuthRepairProofReader.Subject(scope), scope.SourceCommitSha,
            new string('a', 64), new string('a', 64), now.AddMinutes(-1), now, now.AddMinutes(5), artifact, [], [], signer.KeyId, null);
        proof = fault switch
        {
            "marker" => proof with { Kind = "verified" }, "subject" => proof with { SubjectSha256 = new string('b', 64) },
            "source" => proof with { SourceCommitSha = new string('b', 40) }, "assembly" => proof with { CoreAssemblySha256 = new string('b', 64) },
            "expiry" => proof with { ExpiresAtUtc = now }, _ => proof
        };
        proof = proof with { Signature = Convert.ToBase64String(signer.Sign(CurrentAuthRepairProofReader.Payload(proof, fault == "domain" ? "maintenance" : "native"))) };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairProofReader.RequireHeader(proof, "native", scope, trust, pins, now, new string('a', 64), new string('a', 64)));
    }
    [Theory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("final-fleet")]
    [InlineData("replay")]
    public void Marker_outcomes_without_required_acknowledged_chain_are_rejected(string id)
    {
        var scenario = new CurrentAuthProofScenario(id, Guid.NewGuid(), new string('a', 64), "complete", null, true, false, [], []);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairProofReader.RequireEffects(id, scenario, [], new string('a', 64), new string('b', 64)));
    }
    [Fact]
    public void Persistent_closed_proof_requires_final_fleet_and_replay_cases()
    {
        Assert.Contains("final-fleet", CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.ClosedConsole));
        Assert.Contains("replay", CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.ClosedConsole));
        Assert.Contains("final-fleet", CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.DisposableNativeBootstrap));
        Assert.DoesNotContain("final-fleet", CurrentAuthRepairProofReader.Cases("native", CurrentAuthProofAdmission.DisposableNativeBootstrap, component: true));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthRepairProofReader.Cases("arbitrary", CurrentAuthProofAdmission.ClosedConsole));
    }
    [Fact]
    public void Genuine_claim_scope_cannot_be_borrowed_for_a_different_held_operation()
    {
        var scope=Scope(DateTimeOffset.UtcNow);
        CurrentAuthRepairProofReader.RequireCaseScope(scope,scope);
        Assert.Throws<MigrationExecutionException>(()=>CurrentAuthRepairProofReader.RequireCaseScope(scope,scope with {OperationId=Guid.NewGuid()}));
    }
    [Theory]
    [InlineData("before-exit")]
    [InlineData("before-removal")]
    [InlineData("after-disposal")]
    [InlineData("after-lease")]
    public void Absence_inventory_must_follow_exit_and_actual_removal_within_cleanup_lease(string fault)
    {
        DateTimeOffset now=DateTimeOffset.UtcNow;
        DateTimeOffset exited=now,removed=now.AddSeconds(1),observed=now.AddSeconds(2),disposed=now.AddSeconds(3),lease=now.AddMinutes(1);
        CurrentAuthRepairProofReader.RequireCleanupChronology(exited,removed,observed,disposed,lease,lease);
        if(fault=="before-exit") {removed=now.AddSeconds(-1);}
        if(fault=="before-removal") {observed=now;}
        if(fault=="after-disposal") {observed=now.AddSeconds(4);}
        if(fault=="after-lease") {disposed=lease.AddMinutes(2);}
        Assert.Throws<MigrationExecutionException>(()=>CurrentAuthRepairProofReader.RequireCleanupChronology(exited,removed,observed,disposed,lease,lease));
    }
    [Fact]
    public void Unacknowledged_slot_cannot_reverse_receipt_observation_time()
    {
        DateTimeOffset now=DateTimeOffset.UtcNow;
        CurrentAuthRepairProofReader.RequireReceiptObservation(now,now);
        Assert.Throws<MigrationExecutionException>(()=>CurrentAuthRepairProofReader.RequireReceiptObservation(now,now.AddTicks(-1)));
    }
    [Theory]
    [InlineData("image")]
    [InlineData("port")]
    [InlineData("mount")]
    [InlineData("generation")]
    public void Proof_container_identity_cannot_borrow_unrelated_image_port_mount_or_generation(string fault)
    {
        DateTimeOffset now=DateTimeOffset.UtcNow.AddMinutes(-1),created=now.AddSeconds(1),started=now.AddSeconds(2);
        string id=new('a',64),imageId="sha256:"+new string('b',64),volume="legacy-delta-proof-"+Guid.NewGuid().ToString("N");
        const string image="postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
        string pgData="/var/lib/postgresql/18/docker";
        var target=new CurrentAppOwnedRepairTargetPins(id,volume,imageId,image,pgData+"/pg_hba.conf",new('c',64),null,null);
        var scope=Scope(DateTimeOffset.UtcNow) with {TargetGeneration=$"docker:{id}:{created.ToUnixTimeMilliseconds()}:{started.ToUnixTimeMilliseconds()}:{now.ToUnixTimeMilliseconds()}"};
        System.Text.Json.JsonElement Container(string digest,int port,string destination)=>System.Text.Json.JsonSerializer.SerializeToElement(new
        {
            Id=id,Name="/"+volume,Image=digest,Created=created,State=new {Running=true,StartedAt=started},
            Config=new {Image=image,PgData=pgData},Mounts=new[] {new {Type="volume",Name=volume,RW=true,Destination=destination}},
            NetworkSettings=new {Ports=new Dictionary<string,object> { ["5432/tcp"]=new[] {new {HostIp="127.0.0.1",HostPort=port.ToString(System.Globalization.CultureInfo.InvariantCulture)}}}}
        });
        var metadata=System.Text.Json.JsonSerializer.SerializeToElement(new {Name=volume,Driver="local",CreatedAt=now});
        CurrentAuthRepairProofReader.RequireDockerIdentity(Container(imageId,54321,"/var/lib/postgresql"),metadata,scope,target,54321);
        var bad=Container(fault=="image"?"sha256:"+new string('d',64):imageId,fault=="port"?54322:54321,fault=="mount"?"/var/lib":"/var/lib/postgresql");
        if(fault=="generation") {scope=scope with {TargetGeneration="unrelated"};}
        Assert.Throws<MigrationExecutionException>(()=>CurrentAuthRepairProofReader.RequireDockerIdentity(bad,metadata,scope,target,54321));
    }    private static CurrentAuthRepairScope Scope(DateTimeOffset now) => new(Guid.NewGuid(), CurrentAuthRepairOperation.SixteenSameTypeTextCollations,
        new string('a', 40), new string('a', 64), ApprovedCurrentAuthSchema.AuthServiceCommit, CurrentAuthRepairPermit.OwnerPinsSha256,
        ApprovedCurrentAuthSchema.ClosureSha256, ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true),
        new string('a', 64), new string('a', 64), CurrentAuthRepairPermit.MaintenanceValidator,
        new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)),
        "local-aspire", "legacy-postgres-main-local", "synthetic", new string('a', 64), new string('a', 64),
        new Dictionary<string, string>(), new string('a', 64), new string('a', 64), new string('a', 64), new string('a', 64),
        new("synthetic", "synthetic", now.AddMinutes(-1), now.AddHours(1), now.AddMinutes(-2), now.AddMinutes(-2), new string('a', 64), new string('a', 64), "synthetic"));
}
