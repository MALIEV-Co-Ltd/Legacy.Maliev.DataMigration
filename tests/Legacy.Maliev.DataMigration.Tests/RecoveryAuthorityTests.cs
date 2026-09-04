using System.Text.Json;
using System.Text.Json.Nodes;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class RecoveryAuthorityTests
{
    [Fact]
    public async Task RuntimeTargetCompatibility_ExcludesOnlyResourceVersion()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        CloudNativePgTargetObservation value = data.Target.Target;
        Assert.True(value.SameRuntimeTarget(value with { ResourceVersion = "routine-update" }));
        CloudNativePgTargetObservation[] changed =
        [
            value with { Namespace = "changed" }, value with { Cluster = "changed" }, value with { Uid = "changed" },
            value with { Generation = value.Generation + 1 }, value with { ObservedGeneration = value.ObservedGeneration + 1 },
            value with { Phase = "changed" }, value with { Instances = value.Instances + 1 },
            value with { ReadyInstances = value.ReadyInstances + 1 }, value with { CurrentPrimary = "changed" },
            value with { TargetPrimary = "changed" }, value with { Ready = !value.Ready },
            value with { ConsistentSystemId = !value.ConsistentSystemId }, value with { ContinuousArchiving = !value.ContinuousArchiving },
            value with { LastBackupSucceeded = !value.LastBackupSucceeded }, value with { ReconciliationEvidence = "changed" },
            value with { ObservationReadCount = value.ObservationReadCount + 1 }, value with { StatusInstances = value.StatusInstances + 1 },
            value with { SystemId = "changed" }, value with { InstanceNames = "changed" }, value with { HealthyInstances = "changed" },
            value with { PvcCount = value.PvcCount + 1 }, value with { HealthyPvcs = "changed" }, value with { DanglingPvcs = "changed" },
            value with { InitializingPvcs = "changed" }, value with { ResizingPvcs = "changed" }, value with { UnusablePvcs = "changed" },
            value with { ReadyReason = "changed" }, value with { ConsistentSystemIdReason = "changed" },
            value with { ContinuousArchivingReason = "changed" }, value with { LastBackupSucceededReason = "changed" },
        ];
        Assert.All(changed, item => Assert.False(value.SameRuntimeTarget(item)));
    }

    [Fact]
    public async Task FreshResume_AfterOriginalApprovalExpired_RequiresThreeDistinctValidAuthorities()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        data.Verifier.ValidateAdmission(data.Admission, data.Now);
        data.ValidateContinuity(data.Continuity);
        data.ValidateResume();
        Assert.Equal(data.AdmissionPayload.OriginalBackupReceiptJson, data.Admission.Payload.OriginalBackupReceiptJson);
        Assert.All(data.Resume.Payload.PermittedOperations, operation => Assert.Equal(RecoveryDatabaseOperation.CreateCopyAndDeliver, operation.Operation));
        Assert.Equal(DatabaseInventory.ActiveDatabases, data.Resume.Payload.PermittedOperations.Select(item => item.Database));
    }

    [Fact]
    public async Task FreshResume_ExplicitRecoveryRunnerPolicy_BindsCurrentRunnerWithoutRewritingAdmission()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        string recoveryDigest = new('c', 64);
        var verifier = new RecoveryAuthorityVerifier(new(
            new(data.AdmissionPayload.Identity.SourceCommitSha, data.AdmissionPayload.Identity.RunnerDigestSha256),
            RecoveryAuthorityTestData.Roles,
            data.Trust,
            RecoveryRunnerPolicy: new(data.AdmissionPayload.Identity.SourceCommitSha, recoveryDigest)));
        FreshRunnerObservation runner = data.Runner with { RunnerDigestSha256 = recoveryDigest };

        _ = Assert.Throws<MigrationExecutionException>(() => verifier.PrepareResume(data.Admission, data.Continuity, data.Baseline,
            data.Source, data.Binding, runner, data.Target, Guid.NewGuid(), data.Now, data.Now.AddMinutes(30), data.Signers[1], data.Now));
        ResumeAuthorizationReceipt resume = verifier.PrepareCompatibleResume(data.Admission, data.Continuity, data.Baseline,
            data.Source, data.Binding, runner, data.Target, Guid.NewGuid(), data.Now, data.Now.AddMinutes(30), data.Signers[1], data.Now);

        verifier.ValidateResume(data.Admission, data.Continuity, resume, data.Baseline,
            data.Source, data.Binding, runner, data.Target, data.Now);
        Assert.Equal(recoveryDigest, resume.Payload.Runner.RunnerDigestSha256);
        Assert.Equal(data.AdmissionPayload.Identity.RunnerDigestSha256, resume.Payload.Identity.RunnerDigestSha256);
        Assert.Equal(recoveryDigest, resume.Payload.RunnerCompatibility!.ReplacementRunnerDigestSha256);
    }

    [Theory]
    [InlineData("policy")]
    [InlineData("statement")]
    [InlineData("admitted")]
    [InlineData("source")]
    [InlineData("replacement")]
    public async Task CompatibleResume_ResignedCompatibilityTamperRejects(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        string recoveryDigest = new('c', 64);
        var verifier = new RecoveryAuthorityVerifier(new(
            new(data.AdmissionPayload.Identity.SourceCommitSha, data.AdmissionPayload.Identity.RunnerDigestSha256),
            RecoveryAuthorityTestData.Roles, data.Trust,
            RecoveryRunnerPolicy: new(data.AdmissionPayload.Identity.SourceCommitSha, recoveryDigest)));
        FreshRunnerObservation runner = data.Runner with { RunnerDigestSha256 = recoveryDigest };
        ResumeAuthorizationReceipt resume = verifier.PrepareCompatibleResume(data.Admission, data.Continuity, data.Baseline,
            data.Source, data.Binding, runner, data.Target, Guid.NewGuid(), data.Now, data.Now.AddMinutes(30), data.Signers[1], data.Now);
        RecoveryRunnerCompatibility compatibility = resume.Payload.RunnerCompatibility!;
        compatibility = failure switch
        {
            "policy" => compatibility with { PolicyVersion = "unknown" },
            "statement" => compatibility with { Statement = "weakened" },
            "admitted" => compatibility with { AdmittedRunnerDigestSha256 = new string('d', 64) },
            "source" => compatibility with { ReplacementSourceCommitSha = new string('d', 40) },
            "replacement" => compatibility with { ReplacementRunnerDigestSha256 = new string('d', 64) },
            _ => throw new InvalidOperationException(),
        };
        ResumeAuthorizationReceipt changed = ResumeAuthorizationReceipt.Sign(
            resume.Payload with { RunnerCompatibility = compatibility }, data.Signers[1]);

        _ = Assert.Throws<MigrationExecutionException>(() => verifier.ValidateResume(data.Admission, data.Continuity,
            changed, data.Baseline, data.Source, data.Binding, runner, data.Target, data.Now));
    }

    [Theory]
    [InlineData("admission")]
    [InlineData("continuity")]
    [InlineData("resume")]
    public async Task ExactSignedDocument_RoundtripsAndRejectsEveryPayloadScalarTamper(string kind)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        string json = kind == "admission" ? data.Admission.ExactJson : kind == "continuity" ? data.Continuity.ExactJson : data.Resume.ExactJson;
        Validate(json);
        JsonObject envelope = JsonNode.Parse(json)!.AsObject();
        JsonNode payload = JsonNode.Parse(envelope["PayloadJson"]!.GetValue<string>())!;
        foreach (string[] path in ScalarPaths(payload, []))
        {
            JsonNode changed = payload.DeepClone();
            JsonNode parent = changed;
            foreach (string segment in path[..^1]) { parent = parent is JsonArray a ? a[int.Parse(segment, System.Globalization.CultureInfo.InvariantCulture)]! : parent[segment]!; }
            string key = path[^1];
            JsonNode? value = parent is JsonArray array ? array[int.Parse(key, System.Globalization.CultureInfo.InvariantCulture)] : parent[key];
            JsonNode replacement = JsonValue.Create("tampered")!;
            if (value?.GetValueKind() is JsonValueKind.True or JsonValueKind.False) { replacement = JsonValue.Create(value.GetValueKind() == JsonValueKind.False)!; }
            if (value?.GetValueKind() == JsonValueKind.Number) { replacement = JsonValue.Create(value.GetValue<long>() + 1)!; }
            if (parent is JsonArray list) { list[int.Parse(key, System.Globalization.CultureInfo.InvariantCulture)] = replacement; } else { parent[key] = replacement; }
            JsonObject changedEnvelope = envelope.DeepClone().AsObject();
            changedEnvelope["PayloadJson"] = changed.ToJsonString();
            _ = Assert.Throws<MigrationExecutionException>(() => Validate(changedEnvelope.ToJsonString()));
        }
        foreach (string field in new[] { "Domain", "Version", "AttestationKeyId", "AttestationSignature" })
        {
            JsonObject changed = envelope.DeepClone().AsObject(); changed[field] = "tampered";
            _ = Assert.Throws<MigrationExecutionException>(() => Validate(changed.ToJsonString()));
        }
        void Validate(string exact)
        {
            if (kind == "admission") { InitialMigrationAdmission receipt = InitialMigrationAdmission.Parse(exact); Assert.Equal(exact, receipt.ExactJson); data.Verifier.ValidateAdmission(receipt, data.Now); }
            else if (kind == "continuity") { SourceContinuityAttestation receipt = SourceContinuityAttestation.Parse(exact); Assert.Equal(exact, receipt.ExactJson); data.ValidateContinuity(receipt); }
            else { ResumeAuthorizationReceipt receipt = ResumeAuthorizationReceipt.Parse(exact); Assert.Equal(exact, receipt.ExactJson); data.ValidateResume(receipt); }
        }
    }

    [Theory]
    [InlineData("unknown")]
    [InlineData("duplicate")]
    [InlineData("missing")]
    [InlineData("null")]
    public async Task SignedEnvelope_MalformedFieldsFailClosed(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        JsonObject envelope = JsonNode.Parse(data.Admission.ExactJson)!.AsObject();
        if (failure == "unknown") { envelope["Unapproved"] = true; }
        if (failure == "missing") { _ = envelope.Remove("PayloadJson"); }
        if (failure == "null") { envelope["PayloadJson"] = null; }
        string json = envelope.ToJsonString();
        if (failure == "duplicate") { json = "{\"Version\":\"1.0\"," + json[1..]; }
        _ = Assert.Throws<MigrationExecutionException>(() => InitialMigrationAdmission.Parse(json));
    }

    [Theory]
    [InlineData("backup-stale")]
    [InlineData("plan-stale")]
    [InlineData("authorization-expired")]
    [InlineData("future-admission")]
    [InlineData("observation-stale")]
    [InlineData("observation-future")]
    [InlineData("policy")]
    [InlineData("statement")]
    [InlineData("inventory")]
    [InlineData("identity")]
    [InlineData("restore-digest")]
    [InlineData("authorization-digest")]
    [InlineData("local-binding")]
    [InlineData("readonly")]
    public async Task Admission_ResignedInvalidSemanticsCannotPassFreshGates(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync(prepare: false);
        InitialMigrationAdmissionPayload payload = data.AdmissionPayload;
        payload = failure switch
        {
            "backup-stale" => payload with { AdmittedAtUtc = data.AdmittedAt.AddHours(27) },
            "plan-stale" => payload with { AdmittedAtUtc = data.AdmittedAt.AddHours(7) },
            "authorization-expired" => payload with { AdmittedAtUtc = data.AdmittedAt.AddHours(1) },
            "future-admission" => payload with { AdmittedAtUtc = data.Now.AddMinutes(1) },
            "observation-stale" => payload with { SourceObservation = payload.SourceObservation with { ObservedAtUtc = data.AdmittedAt.AddHours(-2) } },
            "observation-future" => payload with { SourceObservation = payload.SourceObservation with { ObservedAtUtc = data.AdmittedAt.AddSeconds(1) } },
            "policy" => payload with { ValidationPolicyVersion = "unknown" },
            "statement" => payload with { ValidationStatement = "metadata only" },
            "inventory" => payload with { InventorySha256 = new string('f', 64) },
            "identity" => payload with { Identity = payload.Identity with { RunId = Guid.NewGuid() } },
            "restore-digest" => payload with { VerifiedRestoreSha256 = new string('f', 64) },
            "authorization-digest" => payload with { OriginalAuthorizationSha256 = new string('f', 64) },
            "local-binding" => payload with { LocalBinding = payload.LocalBinding with { LockProtocolVersion = 2 } },
            "readonly" => payload with { SourceObservation = payload.SourceObservation with { State = payload.SourceObservation.State with { Sql = payload.SourceObservation.State.Sql with { Databases = payload.SourceObservation.State.Sql.Databases.SetItem(0, payload.SourceObservation.State.Sql.Databases[0] with { ReadOnly = false }) } } } },
            _ => throw new InvalidOperationException(),
        };
        InitialMigrationAdmission signed = InitialMigrationAdmission.Sign(payload, data.Signers[2]);
        _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateAdmission(signed, data.Now));
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("from")]
    [InlineData("through")]
    [InlineData("issued")]
    [InlineData("expired")]
    [InlineData("lifetime")]
    [InlineData("version")]
    [InlineData("statement")]
    [InlineData("admission")]
    [InlineData("identity")]
    [InlineData("initial-observation")]
    [InlineData("current-observation")]
    [InlineData("stable-state")]
    [InlineData("restore")]
    [InlineData("inventory")]
    public async Task ExternalContinuity_ResignedInvalidIntervalOrBindingIsRejected(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        SourceContinuityPayload payload = data.Continuity.Payload;
        payload = failure switch
        {
            "nonce" => payload with { Nonce = Guid.Empty },
            "from" => payload with { ContinuousFromUtc = payload.ContinuousFromUtc.AddTicks(1) },
            "through" => payload with { ContinuousThroughUtc = payload.ContinuousThroughUtc.AddTicks(-1) },
            "issued" => payload with { IssuedAtUtc = data.Now.AddMinutes(1) },
            "expired" => payload with { ExpiresAtUtc = data.Now },
            "lifetime" => payload with { ExpiresAtUtc = data.Now.AddHours(2) },
            "version" => payload with { StatementVersion = "unknown" },
            "statement" => payload with { Statement = "readonly now" },
            "admission" => payload with { AdmissionSha256 = new string('f', 64) },
            "identity" => payload with { RunIdentitySha256 = new string('f', 64) },
            "initial-observation" => payload with { InitialObservationSha256 = new string('f', 64) },
            "current-observation" => payload with { CurrentObservationSha256 = new string('f', 64) },
            "stable-state" => payload with { StableSourceStateSha256 = new string('f', 64) },
            "restore" => payload with { VerifiedRestoreSha256 = new string('f', 64) },
            "inventory" => payload with { InventorySha256 = new string('f', 64) },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateContinuity(SourceContinuityAttestation.Sign(payload, data.Signers[3])));
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("continuity-nonce")]
    [InlineData("identity")]
    [InlineData("admission")]
    [InlineData("continuity")]
    [InlineData("baseline")]
    [InlineData("binding")]
    [InlineData("runner")]
    [InlineData("target")]
    [InlineData("operations-missing")]
    [InlineData("operations-duplicate")]
    [InlineData("operations-wrong")]
    [InlineData("future")]
    [InlineData("expired")]
    [InlineData("long")]
    [InlineData("stale-runner")]
    [InlineData("stale-target")]
    public async Task Resume_ResignedInvalidApprovalCannotAuthorizeRecovery(string failure)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        ResumeAuthorizationPayload payload = data.Resume.Payload;
        payload = failure switch
        {
            "nonce" => payload with { Nonce = Guid.Empty },
            "continuity-nonce" => payload with { Nonce = data.Continuity.Payload.Nonce },
            "identity" => payload with { Identity = payload.Identity with { RunId = Guid.NewGuid() } },
            "admission" => payload with { AdmissionSha256 = new string('f', 64) },
            "continuity" => payload with { ContinuitySha256 = new string('f', 64) },
            "baseline" => payload with { BaselineSha256 = new string('f', 64) },
            "binding" => payload with { LocalBindingSha256 = new string('f', 64) },
            "runner" => payload with { Runner = payload.Runner with { RunnerDigestSha256 = new string('f', 64) } },
            "target" => payload with { Target = payload.Target with { Target = payload.Target.Target with { Uid = "replaced" } } },
            "operations-missing" => payload with { PermittedOperations = payload.PermittedOperations.RemoveAt(0) },
            "operations-duplicate" => payload with { PermittedOperations = payload.PermittedOperations.Add(payload.PermittedOperations[0]) },
            "operations-wrong" => payload with { PermittedOperations = payload.PermittedOperations.SetItem(0, payload.PermittedOperations[0] with { Operation = RecoveryDatabaseOperation.ReconcileOwnedShadowAndReuseOnlyIfEmpty }) },
            "future" => payload with { IssuedAtUtc = data.Now.AddMinutes(1) },
            "expired" => payload with { ExpiresAtUtc = data.Now },
            "long" => payload with { ExpiresAtUtc = data.Now.AddHours(2) },
            "stale-runner" => payload with { Runner = payload.Runner with { ObservedAtUtc = data.Now.AddHours(-2) } },
            "stale-target" => payload with { Target = payload.Target with { ObservedAtUtc = data.Now.AddHours(-2) } },
            _ => throw new InvalidOperationException(),
        };
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume(ResumeAuthorizationReceipt.Sign(payload, data.Signers[1])));
    }

    [Fact]
    public async Task RepeatedObservations_CompareStableStateWhilePreservingSignedTimestamp()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        data.Source = data.Source with { ObservedAtUtc = data.Now.AddSeconds(-1) };
        data.Runner = data.Runner with { ObservedAtUtc = data.Now.AddSeconds(-1) };
        data.Target = data.Target with { ObservedAtUtc = data.Now.AddSeconds(-1) };
        data.ValidateResume();
        data.Source = data.Source with { State = data.Source.State with { Docker = data.Source.State.Docker with { CreatedAt = "replacement" } } };
        _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume());
    }

    [Fact]
    public async Task BaselineDrift_AndCompletedRunCannotPrepareResume()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        RecoveryJournalBaseline original = data.Baseline;
        foreach (RecoveryJournalBaseline changed in new[] { original with { Status = "completed" }, original with { LeaseOwner = "new-owner" },
            original with { LeaseAttempt = 2 }, original with { FencingToken = Guid.NewGuid() }, original with { FailureHistoryJson = "[{}]" } })
        {
            data.Baseline = changed;
            Assert.NotEqual(original.ComputeSha256(), changed.ComputeSha256());
            _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume());
        }
        data.Baseline = original with { Status = "completed" };
        _ = Assert.Throws<MigrationExecutionException>(data.PrepareResume);
    }

    [Fact]
    public async Task NoContinuity_MatchingCurrentMetadataCannotPrepareResume()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        data.Continuity = null!;
        _ = Assert.ThrowsAny<ArgumentException>(data.PrepareResume);
    }

    [Theory]
    [InlineData("id")]
    [InlineData("fingerprint")]
    public async Task RoleReuse_IsRejectedEvenWhenKeysAreTrusted(string kind)
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        RecoveryAuthorityRoles roles = RecoveryAuthorityTestData.Roles;
        if (kind == "id") { roles = roles with { ProvenanceKeyId = roles.ExecutionKeyId }; }
        ReceiptAttestationTrustStore trust = kind == "fingerprint" ? new(data.Signers.Select((signer, index) => new TrustedAttestationKey(signer.KeyId, data.Signers[index == 3 ? 2 : index].ExportSubjectPublicKeyInfo()))) : data.Trust;
        _ = Assert.Throws<MigrationExecutionException>(() => new RecoveryAuthorityVerifier(new(new(data.AdmissionPayload.Identity.SourceCommitSha, data.Runner.RunnerDigestSha256), roles, trust)));
    }

    [Fact]
    public async Task TrustedWrongRole_CannotSignAnyRecoveryAuthority()
    {
        using var data = await RecoveryAuthorityTestData.CreateAsync();
        foreach (P256MigrationEvidenceSigner signer in data.Signers)
        {
            if (signer.KeyId != "execution") { _ = Assert.Throws<MigrationExecutionException>(() => data.Verifier.ValidateAdmission(InitialMigrationAdmission.Sign(data.AdmissionPayload, signer), data.Now)); }
            if (signer.KeyId != "provenance") { _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateContinuity(SourceContinuityAttestation.Sign(data.Continuity.Payload, signer))); }
            if (signer.KeyId != "authorization") { _ = Assert.Throws<MigrationExecutionException>(() => data.ValidateResume(ResumeAuthorizationReceipt.Sign(data.Resume.Payload, signer))); }
        }
    }

    private static IEnumerable<string[]> ScalarPaths(JsonNode node, string[] path)
    {
        if (node is JsonObject obj) { foreach ((string key, JsonNode? value) in obj) { if (value is not null) { foreach (string[] result in ScalarPaths(value, [.. path, key])) { yield return result; } } } }
        else if (node is JsonArray array) { for (int i = 0; i < array.Count; i++) { foreach (string[] result in ScalarPaths(array[i]!, [.. path, i.ToString(System.Globalization.CultureInfo.InvariantCulture)])) { yield return result; } } }
        else { yield return path; }
    }
}
