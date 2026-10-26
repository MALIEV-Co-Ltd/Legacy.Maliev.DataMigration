using System.Security.Cryptography;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoComponentProofAssembler
{
    // Source artifacts must already have been losslessly imported into held flat parent custody.
    // This assembles actual observations only; it launches no process and creates no result marker.
    internal static async Task<IsoComponentProof> AssembleAsync(CurrentAppOwnedRepairCustody files, IsoComponentProofPhase phase,
        IsoDefinitionSubject intended, IsoDefinitionArtifact definition, IsoDefinitionArtifact definitionBinding, IsoDefinitionArtifact definitionPublicKey,
        string trxPath, string heldTestAssemblyPath, string executedTestAssemblyPath, string importedRoot,
        IsoDefinitionArtifact caseBinding, IsoComponentHostEvidence host, IReceiptAttestationTrustStore definitionTrust,
        string definitionKeyId, string definitionFingerprint, DateTimeOffset began, DateTimeOffset completed, DateTimeOffset expires, string keyId, CancellationToken ct)
    {
        using var xml = XmlReader.Create(new MemoryStream(files.Read(trxPath, sharedReader: true, maximumBytes: 8_000_000), false),
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var cases = new List<IsoComponentCase>();
        foreach (string id in IsoComponentCases.Required(phase))
        {
            string method = IsoComponentCases.Method(id);
            var result = trx.Descendants(ns + "UnitTestResult").SingleOrDefault(x => (string?)x.Attribute("testName") == method) ?? throw Invalid();
            var entries = new List<(string Path, IsoActualCaseEntry Value)>();
            foreach (string path in Directory.EnumerateFiles(importedRoot, "iso-component-*-entry.json", SearchOption.TopDirectoryOnly))
            { var entry = MigrationConsole.DecodeOwnerIso<IsoActualCaseEntry>(files.Read(path, sharedReader: true, maximumBytes: 65536)); if (entry.CaseId == id) { entries.Add((path, entry)); } }
            if (entries.Count != 1) { throw Invalid(); }
            var actual = entries[0].Value; string prefix = Path.Combine(importedRoot, "iso-component-" + actual.RunId.ToString("N"));
            IsoDefinitionArtifact Slot(string name)
            {
                return Artifact(prefix + "-" + name + ".json");
            }

            IsoDefinitionArtifact? Optional(string name)
            {
                return File.Exists(prefix + "-" + name + ".json") ? Slot(name) : null;
            }

            var slotPaths = Directory.EnumerateFiles(importedRoot, "iso-component-" + actual.RunId.ToString("N") + "-slot-*.json", SearchOption.TopDirectoryOnly)
                .OrderBy(path => int.Parse(Path.GetFileNameWithoutExtension(path).Split('-').Last(), System.Globalization.CultureInfo.InvariantCulture)).ToArray();
            var slots = new List<IsoComponentSlot>();
            foreach (string ackPath in slotPaths)
            { var ack = MigrationConsole.DecodeOwnerIso<IsoActualReceiptSlot>(files.Read(ackPath, sharedReader: true, maximumBytes: 1_000_000)); slots.Add(new(Artifact(Path.Combine(importedRoot, ack.Name)), Artifact(ackPath))); }
            string[] actualOperationPaths = Directory.EnumerateFiles(importedRoot, actual.RunId.ToString("D") + "-*", SearchOption.TopDirectoryOnly).Select(Path.GetFileName).Select(x => x ?? throw Invalid()).Order(StringComparer.Ordinal).ToArray();
            string reservationName = actual.RunId.ToString("D") + "-iso-component-operation-start.json";
            var reservation = File.Exists(Path.Combine(importedRoot, reservationName)) ? Artifact(Path.Combine(importedRoot, reservationName)) : null;
            string[] declared = slots.Select(x => Path.GetFileName(x.RetainedFile.Path)).Concat(reservation is null ? [] : new[] { reservationName }).ToArray();
            if (!actualOperationPaths.SequenceEqual(declared.Order(StringComparer.Ordinal), StringComparer.Ordinal)) { throw Invalid(); }
            using var metadata = System.Text.Json.JsonDocument.Parse(files.Read(Slot("container").Path, sharedReader: true, maximumBytes: 65536)); var m = metadata.RootElement;
            int port = int.Parse(m.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString() ?? throw Invalid(), System.Globalization.CultureInfo.InvariantCulture);
            var run = new IsoDefinitionRun(actual.RunId, m.GetProperty("Id").GetString() ?? throw Invalid(), m.GetProperty("Name").GetString()!.TrimStart('/'), port, Slot("attempt"), Slot("container"), Slot("capacity"), Slot("disposed"), Slot("absence"));
            cases.Add(new(id, method, (string?)result.Attribute("testId") ?? throw Invalid(), (string?)result.Attribute("executionId") ?? throw Invalid(), actual.RunId,
                Slot("host-entry"), Artifact(entries[0].Path), Slot("provider-invocation"), Slot("scope"), Slot("pins"), Slot("public-keys"), Slot("case-source"), Slot("case-owners"), caseBinding,
                Slot("fleet-before"), Slot("fleet-after"), Slot("before-Country"), Slot("before-Material"), Slot("after-Country"), Slot("after-Material"), Slot("installed-policy"), Slot("native-policy"),
                Optional("review"), Optional("authorization"), Optional("candidate-Country"), Optional("candidate-Material"),
                Directory.EnumerateFiles(importedRoot, "iso-component-" + actual.RunId.ToString("N") + "-candidate-fleet-*.json", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal).Select(Artifact).ToArray(), slots, reservation, Optional("declared-fleet-fault"), Optional("replay-rejected"),
                Directory.EnumerateFiles(importedRoot, "iso-component-" + actual.RunId.ToString("N") + "-ordinary-rejections-*.json", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal).Select(Artifact).ToArray(), Optional("proxy-observed"), Optional("proxy-dropped"), Optional("proxy-disposed"), run));
        }
        var proof = new IsoComponentProof(phase == IsoComponentProofPhase.Native ? "current-owner-iso-completed-native-component-v1" : "current-owner-iso-completed-maintenance-component-v1", phase, intended, definition, definitionBinding, definitionPublicKey,
            Artifact(trxPath), Artifact(heldTestAssemblyPath) with { SourcePath = executedTestAssemblyPath }, executedTestAssemblyPath, host, cases, began, completed, expires, keyId, null);
        await IsoComponentProofReader.RequireBodyAsync(files, proof, intended, definitionTrust, definitionKeyId, definitionFingerprint, DateTimeOffset.UtcNow, ct); return proof;
        IsoDefinitionArtifact Artifact(string path) { files.Require(); using var held = SecureLocalFile.OpenReadShared(path); if (held.Length is < 1 or > 512L * 1024 * 1024) { throw Invalid(); } string digest = Convert.ToHexStringLower(SHA256.HashData(held)); files.Require(); return new(path, digest); }
    }
    internal static async Task<IsoComponentProof> SignAfterActualReadbackAsync(CurrentAppOwnedRepairCustody files, IsoComponentProof unsigned, IsoDefinitionSubject intended,
        IReceiptAttestationTrustStore definitionTrust, string definitionKeyId, string definitionFingerprint, P256MigrationEvidenceSigner signer, DateTimeOffset now, CancellationToken ct)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw Invalid(); }
        await IsoComponentProofReader.RequireBodyAsync(files, unsigned, intended, definitionTrust, definitionKeyId, definitionFingerprint, now, ct);
        return unsigned with { Signature = Convert.ToBase64String(signer.Sign(IsoComponentProofReader.Payload(unsigned))) };
    }
    private static MigrationExecutionException Invalid()
    {
        return IsoComponentCases.Invalid();
    }
}
