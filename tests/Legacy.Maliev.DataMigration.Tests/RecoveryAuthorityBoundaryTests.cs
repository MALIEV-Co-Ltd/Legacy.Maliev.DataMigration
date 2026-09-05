using System.Collections.Immutable;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RecoveryAuthorityBoundaryTests
{
    [Fact]
    public async Task ExactPayload_RejectsIgnoredDerivedFieldContradictionsEvenWhenResigned()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        var envelope = System.Text.Json.Nodes.JsonNode.Parse(data.Resume.ExactJson)!.AsObject();
        var payload = System.Text.Json.Nodes.JsonNode.Parse(envelope["PayloadJson"]!.GetValue<string>())!.AsObject();
        payload["Target"]!["Target"]!["IsHealthy"] = false;
        envelope["PayloadJson"] = payload.ToJsonString();
        using var bytes = new MemoryStream();
        using (var writer = new BinaryWriter(bytes, new UTF8Encoding(false, true), leaveOpen: true))
        {
            foreach (string name in new[] { "Domain", "Version", "AttestationKeyId", "PayloadJson" }) { writer.Write(envelope[name]!.GetValue<string>()); }
        }
        envelope["AttestationSignature"] = Convert.ToBase64String(data.Signers[1].Sign(bytes.ToArray()));
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume(ResumeAuthorizationReceipt.Parse(envelope.ToJsonString())));
    }

    [Theory]
    [InlineData("source")]
    [InlineData("runner")]
    [InlineData("target")]
    public async Task Resume_IndependentObservationsPredatingAdmissionCannotServeAsNewMeasurement(string kind)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(resumeDelay: TimeSpan.FromMinutes(5));
        if (kind == "source") { data.Source = data.Source with { ObservedAtUtc = data.AdmittedAt.AddSeconds(-1) }; }
        if (kind == "runner") { data.Runner = data.Runner with { ObservedAtUtc = data.AdmittedAt.AddSeconds(-1) }; }
        if (kind == "target") { data.Target = data.Target with { ObservedAtUtc = data.AdmittedAt.AddSeconds(-1) }; }
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume());
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("null")]
    [InlineData("missing")]
    public async Task SignedPayload_RejectsMalformedInnerDocumentsEvenWithAnIntactEnvelope(string kind)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        var envelope = System.Text.Json.Nodes.JsonNode.Parse(data.Admission.ExactJson)!.AsObject();
        var payload = System.Text.Json.Nodes.JsonNode.Parse(envelope["PayloadJson"]!.GetValue<string>())!.AsObject();
        if (kind == "unknown") { payload["NotApproved"] = true; }
        if (kind == "null") { payload["SourceObservation"] = null; }
        if (kind == "missing") { _ = payload.Remove("Identity"); }
        string json = payload.ToJsonString();
        if (kind == "duplicate") { json = "{\"InventorySha256\":\"duplicate\"," + json[1..]; }
        envelope["PayloadJson"] = json;
        _ = Assert.Throws<MigrationExecutionException>(() => InitialMigrationAdmission.Parse(envelope.ToJsonString()));
    }

    [Fact]
    public async Task UntrustedKeyMaterial_CannotImpersonateAConfiguredSigningRole()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        using var other = await RecoveryAuthorityTestData.CreateAsync();
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateAdmission(InitialMigrationAdmission.Sign(data.AdmissionPayload, other.Signers[2]), data.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateContinuity(SourceContinuityAttestation.Sign(data.Continuity.Payload, other.Signers[3])));
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume(ResumeAuthorizationReceipt.Sign(data.Resume.Payload, other.Signers[1])));
    }

    [Fact]
    public async Task InitialAcquisition_RechecksOriginalApprovalAtCurrentLockedClock()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        data.Verifier.ValidateInitialAcquisition(data.Admission, data.AdmissionPayload.SourceObservation, data.Binding, data.AdmittedAt);
        data.Verifier.ValidateAdmission(data.Admission, data.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateInitialAcquisition(data.Admission, data.Source, data.Binding, data.Now));
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.PrepareAdmission(data.AdmissionPayload, data.Signers[2], data.Now));
    }

    [Fact]
    public async Task SignatureCapture_DetachesNestedObservationAndOriginalDocumentCollections()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        SqlObservedDatabase[] borrowed = data.AdmissionPayload.SourceObservation.State.Sql.Databases.ToArray();
        InitialMigrationAdmissionPayload payload = data.AdmissionPayload with
        {
            SourceObservation = data.AdmissionPayload.SourceObservation with
            {
                State = data.AdmissionPayload.SourceObservation.State with
                {
                    Sql = data.AdmissionPayload.SourceObservation.State.Sql with { Databases = ImmutableCollectionsMarshal.AsImmutableArray(borrowed) },
                },
            },
        };
        InitialMigrationAdmission signed = data.Verifier.PrepareAdmission(payload, data.Signers[2], data.AdmittedAt);
        string retained = signed.ExactJson;
        borrowed[0] = borrowed[0] with { ReadOnly = false };
        FreshSchemaPlan parsed = JsonSerializer.Deserialize<FreshSchemaPlan>(signed.Payload.OriginalSchemaPlanJson)!;
        ((List<DatabaseSchemaPlan>)parsed.Databases).Clear();
        data.Verifier.ValidateAdmission(signed, data.Now);
        Assert.Equal(retained, signed.ExactJson);
        Assert.True(signed.Payload.SourceObservation.State.Sql.Databases[0].ReadOnly);
        Assert.NotEmpty(JsonSerializer.Deserialize<FreshSchemaPlan>(signed.Payload.OriginalSchemaPlanJson)!.Databases);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(3601)]
    public async Task ObservationPolicy_RejectsInvalidOrWiderLimits(int seconds)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        _ = Assert.Throws<MigrationExecutionException>(() => CreateVerifier(data, TimeSpan.FromSeconds(seconds)));
    }

    [Fact]
    public async Task StricterObservationPolicy_IsExplicitAndBoundIntoAdmission()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        RecoveryAuthorityVerifier strict = CreateVerifier(data, TimeSpan.FromMinutes(10));
        _ = Assert.Throws<MigrationExecutionException>(() => strict.ValidateAdmission(data.Admission, data.Now));
        InitialMigrationAdmission signed = strict.PrepareAdmission(data.AdmissionPayload with { MaximumObservationAge = TimeSpan.FromMinutes(10) }, data.Signers[2], data.AdmittedAt);
        strict.ValidateAdmission(signed, data.Now);
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateAdmission(signed, data.Now));
    }

    [Fact]
    public async Task ObservationDefault_PreservesEstablishedHourAndRejectsStalenessOnUse()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        data.Verifier.ValidateResume(data.Admission, data.Continuity, data.Resume, data.Baseline, data.Source, data.Binding, data.Runner, data.Target, data.Now.AddMinutes(59));
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateResume(data.Admission, data.Continuity, data.Resume, data.Baseline, data.Source, data.Binding, data.Runner, data.Target, data.Now.AddHours(1)));
    }

    [Fact]
    public async Task ValidSignedCheckpoint_DerivesRevalidatePermissionAndPreservesOriginalFence()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        AddCheckpoint(data);
        ImmutableArray<PermittedDatabaseRecovery> operations = data.Verifier.GetPermittedOperations(data.Admission, data.Baseline, data.Now);
        Assert.Equal(RecoveryDatabaseOperation.RevalidateCheckpointAndDeliver, operations[0].Operation);
        Assert.Equal(RecoveryDatabaseOperation.CreateCopyAndDeliver, operations[1].Operation);
        data.Baseline = data.Baseline with { LeaseAttempt = 3, FencingToken = Guid.NewGuid(), LeaseOwner = "new-coordinator" };
        ResumeAuthorizationReceipt signed = data.PrepareResume();
        data.ValidateResume(signed);
        Assert.Equal(1, data.Baseline.Shadows[0].Shadow.OwnerAttempt);
        Assert.NotEqual(data.Baseline.FencingToken, data.Baseline.Shadows[0].Shadow.FencingToken);
    }

    [Fact]
    public async Task PendingOwnedCandidate_PermitsInspectionAndProvenEmptyReuseNotBlindCopy()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        AddCheckpoint(data);
        data.Baseline = data.Baseline with { Checkpoints = [] };
        Assert.Equal(RecoveryDatabaseOperation.ReconcileOwnedShadowAndReuseOnlyIfEmpty,
            data.Verifier.GetPermittedOperations(data.Admission, data.Baseline, data.Now)[0].Operation);
    }

    [Theory]
    [InlineData("checkpoint-missing-owner")]
    [InlineData("checkpoint-index")]
    [InlineData("checkpoint-tamper")]
    [InlineData("checkpoint-duplicate")]
    [InlineData("owner-run")]
    [InlineData("owner-attempt")]
    [InlineData("owner-fence")]
    [InlineData("owner-name")]
    [InlineData("owner-duplicate")]
    [InlineData("owner-deleted")]
    [InlineData("cleanup-attempts")]
    public async Task Baseline_UnownedOrConflictingCheckpointsAndCandidatesReject(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        AddCheckpoint(data);
        RecoveryJournalBaseline baseline = data.Baseline;
        RecoveryShadowState owner = baseline.Shadows[0];
        data.Baseline = failure switch
        {
            "checkpoint-missing-owner" => baseline with { Shadows = [] },
            "checkpoint-index" => baseline with { Checkpoints = [baseline.Checkpoints[0] with { Database = "not-approved" }] },
            "checkpoint-tamper" => baseline with { Checkpoints = [baseline.Checkpoints[0] with { SignedCheckpointJson = baseline.Checkpoints[0].SignedCheckpointJson.Replace("\"RowCount\":0", "\"RowCount\":1", StringComparison.Ordinal) }] },
            "checkpoint-duplicate" => baseline with { Checkpoints = baseline.Checkpoints.Add(baseline.Checkpoints[0]) },
            "owner-run" => baseline with { Shadows = [owner with { Shadow = owner.Shadow with { OwnerRunId = Guid.NewGuid().ToString("D") } }] },
            "owner-attempt" => baseline with { Shadows = [owner with { Shadow = owner.Shadow with { OwnerAttempt = 2 } }] },
            "owner-fence" => baseline with { Shadows = [owner with { Shadow = owner.Shadow with { FencingToken = Guid.NewGuid() } }] },
            "owner-name" => baseline with { Shadows = [owner with { Shadow = owner.Shadow with { Name = "different" } }] },
            "owner-duplicate" => baseline with { Shadows = baseline.Shadows.Add(owner) },
            "owner-deleted" => baseline with { Shadows = [owner with { CleanupStatus = "deleted" }] },
            "cleanup-attempts" => baseline with { Shadows = [owner with { CleanupAttempts = -1 }] },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(data.PrepareResume);
    }

    [Fact]
    public async Task BaselineDigest_CoversCheckpointExactTextOwnershipStatusAndFailures()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        AddCheckpoint(data);
        RecoveryJournalBaseline original = data.Baseline;
        RecoveryShadowState shadow = original.Shadows[0];
        foreach (RecoveryJournalBaseline changed in new[]
        {
            original with { Identity = original.Identity with { RunId = Guid.NewGuid() } }, original with { AdmissionSha256 = new string('f', 64) },
            original with { TerminalReceiptSignedJson = "different" }, original with { FailureHistoryJson = "[{}]" },
            original with { Shadows = [shadow with { LastErrorCode = "changed" }] }, original with { Shadows = [shadow with { CleanupAttempts = 1 }] },
            original with { Shadows = [shadow with { CleanupStatus = "failed" }] }, original with { Checkpoints = [] },
            original with { Checkpoints = [original.Checkpoints[0] with { SignedCheckpointJson = " " + original.Checkpoints[0].SignedCheckpointJson }] },
        }) { Assert.NotEqual(original.ComputeSha256(), changed.ComputeSha256()); }
    }

    [Fact]
    public async Task NestedNullOrUnknownContractField_FailsClosedWithStructuredError()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        InitialMigrationAdmissionPayload payload = data.AdmissionPayload with
        {
            SourceObservation = data.AdmissionPayload.SourceObservation with
            {
                State = data.AdmissionPayload.SourceObservation.State with { Docker = data.AdmissionPayload.SourceObservation.State.Docker with { Mounts = [null!] } },
            },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.PrepareAdmission(payload, data.Signers[2], data.AdmittedAt));
    }

    private static RecoveryAuthorityVerifier CreateVerifier(RecoveryAuthorityTestData data, TimeSpan age)
    {
        return new(new(
        new(data.AdmissionPayload.Identity.SourceCommitSha, data.Runner.RunnerDigestSha256), RecoveryAuthorityTestData.Roles, data.Trust, age));
    }

    private static void AddCheckpoint(RecoveryAuthorityTestData data)
    {
        DatabaseSchemaPlan plan = JsonSerializer.Deserialize<FreshSchemaPlan>(data.AdmissionPayload.OriginalSchemaPlanJson)!.Databases[0];
        ShadowDatabase shadow = new(GuardedShadowMigrationRunner.CreateShadowName(plan.Database, data.AdmissionPayload.Identity.RunId), data.AdmissionPayload.Identity.RunId.ToString("D"), plan.Database)
        { OwnerAttempt = 1, FencingToken = data.Baseline.FencingToken!.Value };
        var table = new TableReconciliationEvidence("public.Rows", 0, new string('a', 64), new string('b', 64), new Dictionary<string, long> { ["ID"] = 0 }, new Dictionary<string, long>());
        var reconciliation = new DatabaseReconciliationEvidence(plan.Database, plan.SourceSchemaSha256, plan.TargetSchemaSha256, [table]);
        var database = new MigratedShadowDatabase(plan.Database, shadow.Name, 0, RecoveryAuthorityTestData.Hash($"public.Rows|0|{table.ContentSha256}|{table.AggregateSha256}"))
        { OwnerAttempt = shadow.OwnerAttempt, FencingToken = shadow.FencingToken };
        var checkpoint = new DatabaseMigrationCheckpoint(data.AdmissionPayload.Identity, shadow, database, reconciliation, data.AdmittedAt.AddMinutes(1), "execution", null);
        checkpoint = checkpoint with { AttestationSignature = Convert.ToBase64String(data.Signers[2].Sign(MigrationEvidenceAttestation.CreatePayload(checkpoint))) };
        data.Baseline = data.Baseline with { Shadows = [new(shadow, "pending", 0, null)], Checkpoints = [new(plan.Database, Encoding.UTF8.GetString(MigrationEvidenceAttestation.SerializeCheckpoint(checkpoint)))] };
    }
}
