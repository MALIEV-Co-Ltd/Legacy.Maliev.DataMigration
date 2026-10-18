using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoNamedClosedProofAssembler
{
    // Imports happen under held original case custody. Secret files are never copied.
    // Every imported file retains its original SourcePath for configuration resolution.
    internal static async Task<IsoNamedClosedProof> AssembleAsync(CurrentAppOwnedRepairCustody files,
        IsoComponentProofPhase phase, IsoDefinitionSubject expected, IsoComponentHostEvidence host,
        string trxPath, string heldTestAssemblyPath, string executedTestAssemblyPath, string importedRoot,
        IReadOnlyDictionary<string, IsoDefinitionArtifact> imports, DateTimeOffset began, DateTimeOffset completed,
        DateTimeOffset expires, string keyId, CancellationToken ct)
    {
        using var xml = XmlReader.Create(new MemoryStream(files.Read(trxPath, sharedReader: true, maximumBytes: 8_000_000), false),
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var cases = new List<IsoNamedClosedCase>();
        foreach (string id in IsoComponentCases.Required(phase))
        {
            ct.ThrowIfCancellationRequested(); string method = IsoComponentCases.Method(id);
            var result = trx.Descendants(ns + "UnitTestResult").SingleOrDefault(x => (string?)x.Attribute("testName") == method) ?? throw Invalid();
            var entries = new List<(string Path, IsoNamedClosedHostEntry Value)>();
            foreach (string path in Directory.EnumerateFiles(importedRoot, "iso-closed-host-*-entry.json", SearchOption.TopDirectoryOnly))
            { var value = MigrationConsole.DecodeOwnerIso<IsoNamedClosedHostEntry>(files.Read(path, sharedReader: true, maximumBytes: 65536)); if (value.Host.CaseId == id) { entries.Add((path, value)); } }
            if (entries.Count != 1) { throw Invalid(); }
            var entry = entries[0].Value;
            var actualFiles = imports.Where(x => StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(x.Key)), entry.FixtureRoot)).Select(x => x.Value).ToArray();
            if (actualFiles.Length == 0 || actualFiles.Any(x => x.SourcePath is null || !IsNonSecretCaseArtifact(Path.GetFileName(x.SourcePath)))) { throw Invalid(); }
            string configuration = "iso-closed-case-" + entry.Host.RunId.ToString("N") + "-closed-configuration.json";
            cases.Add(new(id, method, (string?)result.Attribute("testId") ?? throw Invalid(), (string?)result.Attribute("executionId") ?? throw Invalid(),
                entry.Host.RunId, Artifact(entries[0].Path), actualFiles.Single(x => Path.GetFileName(x.SourcePath) == configuration), actualFiles));
        }
        var proof = new IsoNamedClosedProof("current-owner-iso-completed-named-console-v1", phase, expected, host, Artifact(trxPath),
            Artifact(heldTestAssemblyPath) with { SourcePath = executedTestAssemblyPath }, executedTestAssemblyPath, cases, began, completed, expires, keyId, null);
        await IsoNamedClosedProofReader.RequireBodyAsync(files, proof, expected, DateTimeOffset.UtcNow, ct).ConfigureAwait(false); return proof;
        IsoDefinitionArtifact Artifact(string path) { files.Require(); using var held = SecureLocalFile.OpenReadShared(path); return held.Length is < 1 or > 512L * 1024 * 1024 ? throw Invalid() : new(path, Convert.ToHexStringLower(SHA256.HashData(held))); }
    }
    internal static bool IsNonSecretCaseArtifact(string name)
    {
        return !string.IsNullOrEmpty(name) && !name.EndsWith(".private.pem", StringComparison.OrdinalIgnoreCase) && (!name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".public.txt", StringComparison.OrdinalIgnoreCase)) && (name.EndsWith(".json", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".public.txt", StringComparison.OrdinalIgnoreCase) || name.EndsWith("-maintenance-validator.cs", StringComparison.Ordinal));
    }
    internal static async Task<IsoNamedClosedProof> SignAfterActualReadbackAsync(CurrentAppOwnedRepairCustody files,
        IsoNamedClosedProof unsigned, IsoDefinitionSubject expected, P256MigrationEvidenceSigner signer, DateTimeOffset now, CancellationToken ct)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw Invalid(); }
        await IsoNamedClosedProofReader.RequireBodyAsync(files, unsigned, expected, now, ct).ConfigureAwait(false);
        return unsigned with { Signature = Convert.ToBase64String(signer.Sign(IsoNamedClosedProofReader.Payload(unsigned))) };
    }
    private static MigrationExecutionException Invalid()
    {
        return new("iso_named_closed_assembly_invalid", "Only actual imported non-secret observations from the exact named Console cases may be assembled.");
    }
}
