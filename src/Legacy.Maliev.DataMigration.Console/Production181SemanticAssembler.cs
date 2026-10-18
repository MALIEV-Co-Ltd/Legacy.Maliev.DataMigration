using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181SemanticAssembler
{
    // Inner component must already be genuinely assembled, independently validated and signed.
    // Every engine artifact is read from the actual original run ledger, never synthesized here.
    internal static Production181SemanticEnvelope Assemble(CurrentAppOwnedRepairCustody files, string phase,
        CustomerDefinitionSubject subject, CustomerDefinitionArtifact component, CustomerDefinitionArtifact hostExit, string originalLedgerRoot,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now)
    {
        byte[] bytes = files.Read(component.Path, sharedReader: true, maximumBytes: 8_000_000);
        if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != component.Sha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        Guid[] runs; DateTimeOffset began, completed, expires;
        if (phase == "definition")
        {
            var body = MigrationConsole.DecodeCustomerSequence<CustomerDefinitionProof>(bytes);
            Production181CustomerDefinitionReader.Require(files, body, subject, trust, keyId, fingerprint, now);
            runs = body.Runs.Select(x => x.RunId).ToArray(); began = body.BeganAtUtc; completed = body.CompletedAtUtc; expires = body.ExpiresAtUtc;
        }
        else if (phase is "provider" or "maintenance")
        {
            var body = MigrationConsole.DecodeCustomerSequence<Production181GuardedBootstrapProof>(bytes);
            Production181CustomerGuardedReader.Require(files, body, subject, trust, keyId, fingerprint, now);
            runs = body.Cases.Select(x => x.RunId).ToArray(); began = body.BeganAtUtc; completed = body.CompletedAtUtc; expires = body.ExpiresAtUtc;
        }
        else { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var envelope = new Production181SemanticEnvelope("current-production181-customer-semantic-component-v1", phase, subject, component, hostExit,
            runs.Select(run => new Production181SemanticRun(run, Artifact(run, "engine-raw", 32 * 1024 * 1024), Artifact(run, "engine-initializer", 2 * 1024 * 1024), Artifact(run, "engine-checksum", 2 * 1024 * 1024), Artifact(run, "host-entry", 65536))).ToArray(),
            began, completed, expires, keyId, null);
        Production181SemanticEnvelopeReader.RequireBody(files, envelope, subject, trust, keyId, fingerprint, now); return envelope;
        CustomerDefinitionArtifact Artifact(Guid run, string phaseName, int limit)
        {
            string path = Path.Combine(originalLedgerRoot, run.ToString("N") + "-" + phaseName + ".json");
            byte[] actual = files.Read(path, sharedReader: true, maximumBytes: limit);
            return new(path, CurrentCustomerSequenceRepairPermit.Hash(actual));
        }
    }
    internal static async Task<Production181ValidatedComponent> SignRetainAndReadbackAsync(CurrentAppOwnedRepairCustody files,
        Production181SemanticEnvelope unsigned, CustomerDefinitionSubject intended, P256MigrationEvidenceSigner signer,
        IReceiptAttestationTrustStore trust, string fingerprint, string newPath, DateTimeOffset now, CancellationToken ct)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        Production181SemanticEnvelopeReader.RequireBody(files, unsigned, intended, trust, signer.KeyId, fingerprint, now);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Production181SemanticEnvelopeReader.Payload(unsigned))) };
        _ = Production181SemanticEnvelopeReader.Require(files, signed, intended, trust, signer.KeyId, fingerprint, now);
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(signed); await files.WriteNewAsync(newPath, bytes, ct).ConfigureAwait(false);
        byte[] actual = files.Read(newPath, sharedReader: true, maximumBytes: 8_000_000);
        return !actual.AsSpan().SequenceEqual(bytes)
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : Production181SemanticEnvelopeReader.Require(files, MigrationConsole.DecodeCustomerSequence<Production181SemanticEnvelope>(actual), intended, trust, signer.KeyId, fingerprint, DateTimeOffset.UtcNow);
    }
}
