namespace Legacy.Maliev.DataMigration.Console;

internal enum IsoComponentProofPhase { Native = 1, Maintenance = 2 }
internal sealed record IsoComponentSlot(IsoDefinitionArtifact RetainedFile, IsoDefinitionArtifact AckObservation);
internal sealed record IsoComponentCase(string CaseId, string TestName, string TestId, string ExecutionId, Guid RunId,
    IsoDefinitionArtifact HostEntry, IsoDefinitionArtifact Entry, IsoDefinitionArtifact Invocation,
    IsoDefinitionArtifact Scope, IsoDefinitionArtifact Pins, IsoDefinitionArtifact PublicKeys,
    IsoDefinitionArtifact Source, IsoDefinitionArtifact Owners, IsoDefinitionArtifact Binding,
    IsoDefinitionArtifact FleetBefore, IsoDefinitionArtifact FleetAfter,
    IsoDefinitionArtifact CountryBefore, IsoDefinitionArtifact MaterialBefore,
    IsoDefinitionArtifact CountryAfter, IsoDefinitionArtifact MaterialAfter,
    IsoDefinitionArtifact InstalledPolicy, IsoDefinitionArtifact NativePolicy, IsoDefinitionArtifact? Review, IsoDefinitionArtifact? Authorization,
    IsoDefinitionArtifact? CountryCandidate, IsoDefinitionArtifact? MaterialCandidate,
    IReadOnlyList<IsoDefinitionArtifact> CandidateFleets, IReadOnlyList<IsoComponentSlot> Slots,
    IsoDefinitionArtifact? Reservation, IsoDefinitionArtifact? Fault, IsoDefinitionArtifact? Replay,
    IReadOnlyList<IsoDefinitionArtifact> OrdinaryProbes, IsoDefinitionArtifact? ProxyObserved,
    IsoDefinitionArtifact? ProxyDropped, IsoDefinitionArtifact? ProxyDisposed, IsoDefinitionRun Resource);
internal sealed record IsoComponentHostEvidence(string Nonce, IsoDefinitionArtifact Exit, IsoDefinitionArtifact Cleanup,
    IsoDefinitionArtifact PostExitAbsence, IsoDefinitionArtifact ChildConfiguration, IsoDefinitionArtifact RunSettings,
    IReadOnlyList<IsoDefinitionArtifact> JobFrames, IsoDefinitionArtifact Stdout, IsoDefinitionArtifact Stderr);
internal sealed record IsoComponentProof(string Kind, IsoComponentProofPhase Phase, IsoDefinitionSubject Subject,
    IsoDefinitionArtifact Definition, IsoDefinitionArtifact DefinitionBinding, IsoDefinitionArtifact DefinitionPublicKey, IsoDefinitionArtifact Trx, IsoDefinitionArtifact TestAssembly,
    string ExecutedTestAssemblyPath, IsoComponentHostEvidence Host, IReadOnlyList<IsoComponentCase> Cases,
    DateTimeOffset BeganAtUtc, DateTimeOffset CompletedAtUtc, DateTimeOffset ExpiresAtUtc, string KeyId, string? Signature);
internal sealed record IsoComponentInvocation(DateTimeOffset StartedAtUtc, DateTimeOffset ExitedAtUtc,
    bool Returned, string? ExceptionType, string? RejectionCode, int Reservations);
internal static class IsoComponentCases
{
    internal static readonly string[] Native = ["complete", "prepared-publication", "lost-commit-ack", "terminal-publication", "wrong-owner", "fleet-drift"];
    internal static readonly string[] Maintenance = ["unsafe-host", "local-trust", "ordinary-all26", "exclusive-policy"];
    internal static string[] Required(IsoComponentProofPhase phase)
    {
        return phase switch { IsoComponentProofPhase.Native => Native, IsoComponentProofPhase.Maintenance => Maintenance, _ => throw Invalid() };
    }

    internal static string Method(string id)
    {
        return id switch
        {
            "complete" => "Complete_26_database_fleet_is_preserved_after_Country_and_Material_commit",
            "prepared-publication" => "Prepared_receipt_publication_failure_rolls_back_without_commit",
            "lost-commit-ack" => "Dropped_commit_ack_stops_without_Material_apply",
            "terminal-publication" => "Terminal_publication_uncertainty_stops_without_Material_apply",
            "wrong-owner" => "Wrong_owner_rejected_before_DDL",
            "fleet-drift" => "Full_fleet_drift_after_Country_stops_Material",
            "unsafe-host" => "Unsafe_unprobed_host_rule_rejected",
            "local-trust" => "Local_trust_rejected",
            "ordinary-all26" => "Ordinary_client_rejected_in_all_26_databases",
            "exclusive-policy" => "Exact_installed_policy_accepts_only_maintenance_client",
            _ => throw Invalid()
        };
    }

    internal static MigrationExecutionException Invalid()
    {
        return new("iso_component_proof_invalid", "Actual completed disposable component evidence is required; this is not persistent authority.");
    }
}
