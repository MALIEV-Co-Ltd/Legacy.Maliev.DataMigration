using System.Security.Cryptography;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

/// <summary>Pure signed-envelope and scenario regressions, never execution or a generated native proof.</summary>
public sealed class CurrentCustomerSequenceClosedProofTests
{
    [Fact]
    public void Executed_test_image_must_match_held_image_and_both_TRX_paths()
    {
        string image = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "customer-proof", "tests.dll"));
        CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, image, image, image);
        string different = Path.GetFullPath(Path.Combine(Path.GetTempPath(), "other-proof", "tests.dll"));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, different, image, image));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, image, different, image));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, image, image, different));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, image, null, image));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath("tests.dll", image, image, image));
        if (OperatingSystem.IsWindows())
        { CurrentCustomerSequenceClosedProofReader.RequireExecutedAssemblyPath(image, image.ToUpperInvariant(), image.ToUpperInvariant(), image.ToLowerInvariant()); }
    }
    [Theory]
    [InlineData(-1)]
    [InlineData(61)]
    public void Retained_receipts_outside_invocation_are_rejected(int seconds)
    { _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireReceiptChronology(Now.AddSeconds(seconds), Now, Now.AddMinutes(1))); }
    [Fact]
    public void Retained_receipt_exact_invocation_boundaries_are_admitted()
    {
        CurrentCustomerSequenceClosedProofReader.RequireReceiptChronology(Now, Now, Now.AddMinutes(1));
        CurrentCustomerSequenceClosedProofReader.RequireReceiptChronology(Now.AddMinutes(1), Now, Now.AddMinutes(1));
    }
    [Theory]
    [InlineData("before-exit")]
    [InlineData("before-removal")]
    [InlineData("removal-before-exit")]
    [InlineData("outside-lease")]
    [InlineData("before-inventory")]
    [InlineData("after-proof")]
    [InlineData("non-UTC")]
    public void Cleanup_absence_must_follow_execution_and_removal_within_lease(string fault)
    {
        DateTimeOffset observed = Now.AddMinutes(4), exited = Now.AddMinutes(2), removed = Now.AddMinutes(3),
            completed = Now.AddMinutes(5), proofCompleted = Now.AddMinutes(6);
        switch (fault)
        {
            case "before-exit": observed = Now.AddMinutes(1); break;
            case "before-removal": observed = Now.AddMinutes(2); break;
            case "removal-before-exit": removed = Now.AddMinutes(1); break;
            case "outside-lease": observed = Now.AddMinutes(9); completed = Now.AddMinutes(10); proofCompleted = Now.AddMinutes(11); break;
            case "before-inventory": completed = Now.AddMinutes(3); break;
            case "after-proof": proofCompleted = Now.AddMinutes(4); break;
            case "non-UTC": removed = removed.ToOffset(TimeSpan.FromHours(7)); break;
            default:
                break;
        }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireAbsenceChronology(
            observed, exited, removed, Now, Now.AddMinutes(8), completed, proofCompleted));
    }
    [Fact]
    public void Cleanup_chronology_has_no_circular_timestamp_requirement()
    {
        CurrentCustomerSequenceClosedProofReader.RequireAbsenceChronology(Now.AddMinutes(4), Now.AddMinutes(2), Now.AddMinutes(3),
            Now, Now.AddMinutes(8), Now.AddMinutes(5), Now.AddMinutes(6));
        CurrentCustomerSequenceClosedProofReader.RequireAbsenceChronology(Now.AddMinutes(8), Now.AddMinutes(8), Now.AddMinutes(8),
            Now, Now.AddMinutes(8), Now.AddMinutes(8), Now.AddMinutes(8));
    }
    private const ulong GiB = 1024UL * 1024 * 1024;
    [Theory]
    [InlineData(true, (3UL * GiB) - 1, 0UL, "host_free_memory_admission_below_3GiB")]
    [InlineData(false, GiB - 1, 0UL, "host_free_memory_floor_below_1GiB")]
    [InlineData(false, GiB, (5UL * GiB) + 1, "owned_rss_above_5GiB")]
    public void Capacity_limits_reject_without_weakening_thresholds(bool admission, ulong available, ulong rss, string code)
    { Assert.Equal(code, Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceCapacity.RequireValues(available, rss, admission)).Code); }
    [Fact]
    public void Exact_capacity_boundaries_remain_admitted()
    { CurrentCustomerSequenceCapacity.RequireValues(3 * GiB, 5 * GiB, true); CurrentCustomerSequenceCapacity.RequireValues(GiB, 5 * GiB, false); }
    [Theory]
    [InlineData("persistent")]
    [InlineData("production")]
    [InlineData("unknown")]
    public void Typed_bootstrap_cannot_authorize_other_targets(string fault)
    {
        var scope = Scope() with { ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap };
        scope = fault switch
        {
            "persistent" => scope with { Target = new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/persistent-aaaaaaaaaaaa", new string('d', 64)) },
            "production" => scope with { Target = new(DeltaTargetAuthorityKind.ProductionCloudNativePg, "cnpg://maliev-legacy/legacy-postgres-main", new string('d', 64)) },
            _ => scope with { ProofAdmission = (CurrentCustomerSequenceProofAdmission)99 },
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.RequireProofAdmission(scope));
    }
    [Fact]
    public void Only_explicit_disposable_bootstrap_passes_mode_guard()
    { CurrentCustomerSequenceRepairPermit.RequireProofAdmission(Scope() with { ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap }); }
    [Theory]
    [InlineData("native")]
    [InlineData("native-component")]
    [InlineData("maintenance")]
    [InlineData("maintenance-component")]
    [InlineData("definition")]
    public void Genuine_distinct_signature_domain_roundtrips(string phase)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new ReceiptAttestationTrustStore([new("receipt", key.ExportSubjectPublicKeyInfo())]);
        Assert.True(trust.TryGetPublicKeyFingerprintSha256("receipt", out string fingerprint));
        var pins = new CurrentCustomerSequenceRepairSigningPins("review", new string('a', 64), "auth", new string('b', 64), "receipt", fingerprint);
        var scope = Scope() with { ProofAdmission = phase.EndsWith("-component", StringComparison.Ordinal) ? CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap : CurrentCustomerSequenceProofAdmission.PersistentWithClosedConsoleProof }; var proof = Proof(scope, phase);
        proof = proof with { Signature = Convert.ToBase64String(key.SignData(CurrentCustomerSequenceClosedProofReader.Payload(proof, phase), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
        CurrentCustomerSequenceClosedProofReader.RequireHeader(proof, phase, scope, trust, pins, Now, new string('1', 64), new string('2', 64));
        string other = phase == "definition" ? "native-component" : "definition";
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireHeader(proof, other, scope, trust, pins, Now, new string('1', 64), new string('2', 64)));
    }
    [Theory]
    [InlineData("target")]
    [InlineData("run")]
    [InlineData("native-before")]
    [InlineData("console")]
    [InlineData("core")]
    [InlineData("operation")]
    [InlineData("expired")]
    [InlineData("signature")]
    public void Signed_proof_subject_cannot_be_substituted(string fault)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var trust = new ReceiptAttestationTrustStore([new("receipt", key.ExportSubjectPublicKeyInfo())]);
        _ = trust.TryGetPublicKeyFingerprintSha256("receipt", out string fingerprint);
        var pins = new CurrentCustomerSequenceRepairSigningPins("review", new string('a', 64), "auth", new string('b', 64), "receipt", fingerprint);
        var scope = Scope() with { ProofAdmission = CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap }; var proof = Proof(scope, "native-component");
        proof = fault switch
        {
            "target" => proof with { IntendedTargetObservationSha256 = new string('f', 64) },
            "run" => proof with { IntendedRunBindingSha256 = new string('f', 64) },
            "native-before" => proof with { IntendedNativeBeforeStateSha256 = new string('f', 64) },
            "console" => proof with { ConsoleAssemblySha256 = new string('f', 64) },
            "core" => proof with { CoreAssemblySha256 = new string('f', 64) },
            "operation" => proof with { OperationSha256 = new string('f', 64) },
            "expired" => proof with { ExpiresAtUtc = Now },
            _ => proof,
        };
        proof = proof with { Signature = Convert.ToBase64String(key.SignData(CurrentCustomerSequenceClosedProofReader.Payload(proof, "native-component"), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation)) };
        if (fault == "signature") { proof = proof with { Signature = Convert.ToBase64String(new byte[64]) }; }
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireHeader(proof, "native-component", scope, trust, pins, Now, new string('1', 64), new string('2', 64)));
    }
    [Theory]
    [InlineData("prepared-publication")]
    [InlineData("commit-ack-lost")]
    [InlineData("terminal-publication")]
    [InlineData("final-fleet")]
    public void Empty_effects_cannot_prove_post_DDL_failure(string id)
    {
        var before = new Dictionary<string, string>(StringComparer.Ordinal) { ["Customer"] = new('a', 64), ["postgres"] = new('b', 64) };
        var scenario = Scenario(id);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireCaseEffects(id, scenario, [], before, before));
    }
    [Fact]
    public void Lost_ack_requires_authentic_prepared_after_and_uncertain_terminal()
    {
        var before = new Dictionary<string, string>(StringComparer.Ordinal) { ["Customer"] = new('a', 64), ["postgres"] = new('b', 64) };
        var after = new Dictionary<string, string>(before, StringComparer.Ordinal) { ["Customer"] = new('e', 64) };
        var receipts = new[] { Receipt(CurrentAppOwnedCommitClassification.Prepared), Receipt(CurrentAppOwnedCommitClassification.Uncertain) };
        CurrentCustomerSequenceClosedProofReader.RequireCaseEffects("commit-ack-lost", Scenario("commit-ack-lost"), receipts, before, after);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireCaseEffects("commit-ack-lost", Scenario("commit-ack-lost") with { CommitAcknowledged = true }, receipts, before, after));
        after["postgres"] = new string('c', 64);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireCaseEffects("commit-ack-lost", Scenario("commit-ack-lost"), receipts, before, after));
    }
    [Fact]
    public void Final_failure_requires_acknowledged_terminal_then_uncertain()
    {
        var before = new Dictionary<string, string>(StringComparer.Ordinal) { ["Customer"] = new('a', 64), ["postgres"] = new('b', 64) };
        var after = new Dictionary<string, string>(before, StringComparer.Ordinal) { ["Customer"] = new('e', 64) };
        var scenario = Scenario("final-fleet") with { Boundary = "final-fleet-after-terminal", CommitAcknowledged = true };
        var receipts = new[] { Receipt(CurrentAppOwnedCommitClassification.Prepared), Receipt(CurrentAppOwnedCommitClassification.CommittedAndReadback), Receipt(CurrentAppOwnedCommitClassification.Uncertain) };
        CurrentCustomerSequenceClosedProofReader.RequireCaseEffects("final-fleet", scenario, receipts, before, after);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireCaseEffects("final-fleet", scenario, receipts.Take(2).ToArray(), before, after));
    }
    [Theory]
    [InlineData(1)]
    [InlineData(9)]
    public void Definition_proof_preserves_genuine_operand_shape_and_requires_commit_readback(int ordinal)
    {
        var state = ApprovedCurrentCustomerSequenceDefinitionTests.State() with { LastValue = 69831, IsCalled = true, AttributeNumber = checked((short)ordinal) };
        var before = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(state);
        var after = ApprovedCurrentCustomerSequenceDefinitionTests.Observation(ApprovedCurrentCustomerSequenceDefinitionTests.Final(state));
        var scenario = Scenario("definition") with { Boundary = "definition-rollback-and-readback", RejectionCode = null, CommitAcknowledged = true };
        string id = "start-69831-true-" + ordinal.ToString(System.Globalization.CultureInfo.InvariantCulture);
        CurrentCustomerSequenceClosedProofReader.RequireDefinitionCase(id, before, after, scenario, []);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireDefinitionCase(id, before, after, scenario with { CommitAcknowledged = false }, []));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequireDefinitionCase(id, before, after with { State = after.State with { LastValue = 1 } }, scenario, []));
    }
    [Fact]
    public void Proof_case_operands_are_fixed_and_exports_cannot_mutate_them()
    {
        var cases = CurrentCustomerSequenceClosedProofReader.Cases("definition"); Assert.Equal(13, cases.Length); cases[0] = "unsafe";
        Assert.Equal("start-1-false-1", CurrentCustomerSequenceClosedProofReader.Cases("definition")[0]);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.Cases("arbitrary"));
    }
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Held_native_policy_rules_are_semantically_validated_not_hash_markers(bool unsafeHost)
    {
        var rules = new List<object>
        {
            Rule(1,"host","fixture_operator","127.0.0.1","255.255.255.255","scram-sha-256"),
            Rule(2,"host","fixture_operator","::1","ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff","scram-sha-256"),
        };
        if (unsafeHost) { rules.Add(Rule(3, "host", "unprobed_sdk", "127.0.0.1", "255.255.255.255", "trust")); }
        rules.Add(Rule(4, "local", "all", null, null, "reject"));
        rules.Add(Rule(5, "host", "all", "0.0.0.0", "0.0.0.0", "reject"));
        rules.Add(Rule(6, "host", "all", "::", "::", "reject"));
        byte[] raw = JsonSerializer.SerializeToUtf8Bytes(rules), hba = "pure fixture HBA bytes, never authority"u8.ToArray();
        var scope = Scope(); var hbaArtifact = new CurrentCustomerSequenceProofArtifact("hba", CurrentCustomerSequenceRepairPermit.Hash(hba));
        var rawArtifact = new CurrentCustomerSequenceProofArtifact("rules", CurrentCustomerSequenceRepairPermit.Hash(raw));
        scope = scope with { Maintenance = scope.Maintenance with { HbaSha256 = hbaArtifact.Sha256, HbaRulesSha256 = rawArtifact.Sha256 } };
        var policy = new CurrentCustomerSequenceProofPolicy(scope.Target.SystemIdentifierSha256, scope.Maintenance.Postmaster, scope.Maintenance.ConfigLoaded,
            scope.Maintenance.Role, scope.Maintenance.ExpiresAtUtc, scope.Maintenance.RoleComment, scope.Maintenance.HbaPath, hbaArtifact, rawArtifact,
            true, true, false, false, false, false, 0, true, 0, 0, 0, 0, true, Now);
        var scenario = Scenario("maintenance") with { InstalledSemanticPolicyAccepted = !unsafeHost };
        CurrentCustomerSequenceClosedProofReader.RequirePolicyEvidence(policy, scope, scenario, Read);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequirePolicyEvidence(policy, scope,
            scenario with { InstalledSemanticPolicyAccepted = unsafeHost }, Read));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceClosedProofReader.RequirePolicyEvidence(policy with { OtherClients = 1 }, scope, scenario, Read));
        byte[] Read(CurrentCustomerSequenceProofArtifact artifact)
        {
            return artifact.Path == "hba" ? hba : raw;
        }

        static object Rule(int number, string type, string user, string? address, string? netmask, string method)
        {
            return new
            { rule_number = number, type, database = new[] { "all" }, user_name = new[] { user }, address, netmask, auth_method = method, options = Array.Empty<string>(), error = (string?)null };
        }
    }

    private static DateTimeOffset Now => ApprovedCurrentCustomerSequenceDefinitionTests.Now;
    private static CurrentCustomerSequenceProofScenario Scenario(string boundary)
    {
        return new("current-customer-sequence-proof-scenario-v1", Guid.NewGuid(), new string('a', 64), boundary, "injected", Now, [], [], true, false, false);
    }

    private static CurrentCustomerSequenceRepairReceipt Receipt(CurrentAppOwnedCommitClassification value)
    {
        return new("component-only", Guid.NewGuid(), "Customer", new string('a', 64), new string('a', 64), new string('e', 64), new string('b', 64), new string('0', 64), value, Now, "not-authority", null);
    }

    private static CurrentCustomerSequenceRepairScope Scope()
    {
        var source = ApprovedCurrentCustomerSequenceDefinitionTests.Source(); var owner = ApprovedCurrentCustomerSequenceDefinitionTests.Owner();
        var map = new Dictionary<string, string>(StringComparer.Ordinal) { ["Customer"] = new('a', 64), ["postgres"] = new('b', 64) };
        return new(Guid.NewGuid(), CurrentCustomerSequenceRepairOperation.FixedStartDefinitionOnly, source.CommitSha, new string('c', 64), source.CatalogReportSha256, source, owner,
            new string('a', 64), new string('b', 64), new string('c', 64), new string('d', 64), CurrentCustomerSequenceRepairPermit.MaintenanceValidator,
            new(DeltaTargetAuthorityKind.LocalAspire, "aspire://legacy-postgres-main-local/disposable-aaaaaaaaaaaa", new string('d', 64)), "local-aspire", "legacy-postgres-main-local",
            "fixture", new string('e', 64), new string('a', 64), map, CurrentCustomerSequenceRepairPermit.FleetSha256(map), new string('1', 64), new string('2', 64), new string('3', 64),
            new("fixture_operator", "fixture", Now.AddMinutes(-1), Now.AddHours(1), Now.AddMinutes(-2), Now.AddMinutes(-2), new string('4', 64), new string('5', 64), "/fixture/pg_hba.conf"), new string('6', 64));
    }
    private static CurrentCustomerSequenceClosedProof Proof(CurrentCustomerSequenceRepairScope scope, string phase)
    {
        string kind = phase switch
        {
            "definition" => "current-customer-sequence-native-definition-proof-v1",
            "native" => "current-customer-sequence-native-console-proof-v1",
            "native-component" => "current-customer-sequence-native-provider-proof-v1",
            "maintenance" => "current-customer-sequence-maintenance-console-proof-v1",
            _ => "current-customer-sequence-maintenance-provider-proof-v1"
        };
        var artifact = new CurrentCustomerSequenceProofArtifact("component-only", new string('a', 64));
        return new(kind, scope.SourceCommitSha, scope.SourceSchemaPlanSha256, scope.CatalogReportSha256, scope.DefinitionSha256, scope.NativeBeforeStateSha256,
            phase == "definition" ? "definition-subject-excludes-proof-hash-v1" : scope.OperationSha256, scope.MaintenanceValidatorSha256, scope.TargetObservationSha256, scope.RunBindingSha256,
            new string('1', 64), new string('2', 64), Now.AddMinutes(-2), Now.AddMinutes(-1), Now.AddHours(1), artifact, [new(Guid.NewGuid(), "component-only", new string('a', 64), artifact, artifact, artifact)], [], "receipt", null);
    }
}
