using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class CurrentAuthArchiveRecoveryV2V1CompatibilityTests
{
    [Theory]
    [InlineData("first-only-decrypt-insert-readback")]
    [InlineData("second-only-decrypt-insert-readback")]
    public void V1_effect_reader_rejects_actual_setup_delete_journals_even_when_restore_returns_original_rows(string id)
    {
        var now = new DateTimeOffset(2026, 11, 24, 0, 0, 0, TimeSpan.Zero);
        var original = new CurrentAppOwnedDatabaseSnapshot("Auth", [], [new("public", "refresh_sessions", 1, new string('a', 64))], []);
        string hash = new('b', 64);
        var prepared = new CurrentAuthArchiveReceipt(Guid.NewGuid(), hash, new string('0', 64), original.Sha256,
            new string('c', 64), hash, CurrentAppOwnedCommitClassification.Prepared, now);
        var terminal = prepared with { Classification = CurrentAppOwnedCommitClassification.CommittedAndReadback, ObservedAtUtc = now.AddSeconds(1) };
        var scenario = new CurrentAuthArchiveProofScenario("decrypted-insert-independent-readback", null, true, true, true, true, now.AddSeconds(2));
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireEffects(id, scenario, [prepared, terminal], original, original));
    }
    [Fact]
    public void V1_reader_rejects_the_V2_recovery_candidate_wire_shape()
    {
        byte[] candidate = JsonSerializer.SerializeToUtf8Bytes(new
        {
            Kind = "current-auth-genuine-recovery-candidate-v2",
            Phase = "recovery",
            CaseId = "first-only-decrypt-insert-readback",
            OperationId = Guid.NewGuid(),
            ProviderProcessExitCode = (int?)null,
            CleanupVerified = true,
            PhaseProofComplete = false,
        });
        _ = Assert.Throws<JsonException>(() => MigrationConsole.DecodeAuthRepair<CurrentAuthArchiveExecutionProof>(candidate));
    }

    [Theory]
    [InlineData("current-auth-genuine-recovery-candidate-v2")]
    [InlineData("current-auth-session-archive-execution-proof-v2")]
    public void V1_proof_header_does_not_accept_a_new_kind_when_method_inventory_is_available(string kind)
    {
        DateTimeOffset now = new(2031, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var scope = CurrentAuthArchiveComponentBootstrapSubjectTests.SyntheticScope(now);
        var proof = new CurrentAuthArchiveExecutionProof(kind, CurrentAuthArchiveProofReader.Subject(scope),
            scope.LocalObservationPolicy.SourceCommitSha, new('a', 64), new('b', 64), now.AddMinutes(-1), now,
            now.AddMinutes(1), new("synthetic.trx", new('c', 64)), [], []);
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentAuthArchiveProofReader.RequireHeader(proof, scope, "recovery", new('a', 64), new('b', 64), now));
    }
}
