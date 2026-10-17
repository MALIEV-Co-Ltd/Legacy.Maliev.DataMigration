using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class CurrentCustomerClosedEightAssembler
{
    // Compare physical Windows paths without rewriting the authenticated binding
    // or any signed subject. Subsequent captures retain its exact canonical root.
    internal static string RequireCanonicalCaseRoot(string observedRoot, LocalExecutionBinding binding)
    {
        return !Path.IsPathFullyQualified(observedRoot) || !Path.IsPathFullyQualified(binding.ArtifactRootCanonicalPath) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.TrimEndingDirectorySeparator(Path.GetFullPath(observedRoot)),
                Path.TrimEndingDirectorySeparator(binding.ArtifactRootCanonicalPath))
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : binding.ArtifactRootCanonicalPath;
    }

    // Called after the real launcher has returned and its job/testhost, proxy,
    // exact container and volume cleanup observations have completed. No facts,
    // execution identifiers, captures or signatures are supplied by a callback.
    internal static async Task<CustomerClosedEightAcceptance> AssembleAfterActualRunAsync(
        CurrentAppOwnedRepairCustody destination, LocalExecutionBinding destinationBinding,
        CurrentAppOwnedRepairCustody host, LocalExecutionBinding hostBinding, CustomerNamedClosedHostResult result,
        CustomerClosedLaneInput input, IMigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust,
        CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true); destination.Require(); host.Require();
        DateTimeOffset now = DateTimeOffset.UtcNow;
        var subject = CustomerClosedCompletedReadback.Require(input, now);
        if (StringComparer.OrdinalIgnoreCase.Equals(hostBinding.ArtifactRootCanonicalPath, destinationBinding.ArtifactRootCanonicalPath) ||
            result.CompletedAtUtc > now || result.CompletedAtUtc < result.BeganAtUtc || result.CompletedAtUtc - result.BeganAtUtc > TimeSpan.FromMinutes(80) ||
            !trust.TryGetPublicKeyFingerprintSha256(signer.KeyId, out string fingerprint) || fingerprint != signer.PublicKeyFingerprintSha256)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var exited = CustomerClosedCompletedReadback.Decode<CustomerNamedClosedHostExit>(host.Read(result.HostExit.Path, sharedReader: true, maximumBytes: 65536));
        if (exited.RunIds.Count != 8 || !Guid.TryParseExact(exited.JobNonce, "N", out _)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string prefix = exited.JobNonce;
        async Task<CustomerDefinitionArtifact> HostImport(string path)
        {
            return await CurrentCustomerClosedArtifactImport.ImportAsync(destination, destinationBinding, host, hostBinding, path, prefix, ct).ConfigureAwait(false);
        }

        var trx = await HostImport(result.Trx.Path).ConfigureAwait(false);
        var hostExit = await HostImport(result.HostExit.Path).ConfigureAwait(false);
        var cleanup = await HostImport(Path.Combine(hostBinding.ArtifactRootCanonicalPath, "customer-host-" + prefix + "-cleanup.json")).ConfigureAwait(false);
        var absence = await HostImport(Path.Combine(hostBinding.ArtifactRootCanonicalPath, "customer-named-host-" + prefix + "-absence.json")).ConfigureAwait(false);
        var hostBaseline = await HostImport(Path.Combine(hostBinding.ArtifactRootCanonicalPath, "customer-host-" + prefix + "-docker-before.json")).ConfigureAwait(false);
        CustomerDefinitionArtifact image;
        var imageBinding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(input.TestBundleBindingPath, 65536);
        using (var imageAuthority = WindowsLocalRunAuthority.AcquireResume(imageBinding.ArtifactRootCanonicalPath, imageBinding))
        using (var imageFiles = new CurrentAppOwnedRepairCustody(imageAuthority))
        {
            CustomerClosedCompletedReadback.RequireExactBinding(imageFiles, input.TestBundleBindingPath, imageBinding);
            image = await CurrentCustomerClosedArtifactImport.ImportAsync(destination, destinationBinding, imageFiles, imageBinding, input.TestAssemblyPath, prefix, ct).ConfigureAwait(false);
            if (image.Sha256 != input.TestAssemblySha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        var stream = destination.BorrowReadStream(trx.Path, 32 * 1024 * 1024); stream.Position = 0;
        XDocument document;
        using (var xml = XmlReader.Create(stream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, CloseInput = false, MaxCharactersInDocument = 32 * 1024 * 1024 }))
        { document = XDocument.Load(xml); }
        XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var cases = new List<CustomerClosedEightCase>();
        foreach (Guid operation in exited.RunIds)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false); host.Require(); destination.Require();
            string root = Path.Combine(hostBinding.ArtifactRootCanonicalPath, "customer-closed-case-" + operation.ToString("N"));
            var binding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(Path.Combine(root, "fixture-binding.json"), 65536);
            root = RequireCanonicalCaseRoot(root, binding);
            using var authority = WindowsLocalRunAuthority.AcquireResume(root, binding); using var original = new CurrentAppOwnedRepairCustody(authority);
            CustomerClosedCompletedReadback.RequireExactBinding(original, Path.Combine(root, "fixture-binding.json"), binding);
            string[] paths = Directory.GetFiles(root, "*", SearchOption.TopDirectoryOnly).Order(StringComparer.Ordinal).ToArray();
            if (Directory.EnumerateDirectories(root).Any() || paths.Length is < 10 or > 256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var imported = new List<CustomerDefinitionArtifact>();
            foreach (string path in paths)
            {
                string name = Path.GetFileName(path);
                if (name == ".run.lock") { continue; }
                // Secrets must already have been deleted by same-handle owned
                // cleanup. Never import credentials or private keys as proof.
                if (name is "operator.txt" or "ordinary.txt" or "source-connection.txt" or "source-token.txt" || name.EndsWith(".private.pem", StringComparison.Ordinal))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                imported.Add(await CurrentCustomerClosedArtifactImport.ImportAsync(destination, destinationBinding, original, binding, path, operation.ToString("N"), ct).ConfigureAwait(false));
            }
            var facts = imported.Single(x => Path.GetFileName(x.SourcePath) == "customer-closed-actual-case.json");
            var actual = CustomerClosedCompletedReadback.Decode<CustomerClosedCase>(destination.Read(facts.Path, sharedReader: true, maximumBytes: 8_000_000));
            var resultXml = document.Descendants(ns + "UnitTestResult").Single(x => ((string?)x.Attribute("testName"))?.EndsWith("(caseId: \"" + actual.CaseId + "\")", StringComparison.Ordinal) == true);
            var entry = await HostImport(Path.Combine(hostBinding.ArtifactRootCanonicalPath, operation.ToString("N") + "-host-entry.json")).ConfigureAwait(false);
            cases.Add(new(actual.CaseId, operation, (string?)resultXml.Attribute("testName") ?? throw CurrentCustomerSequenceRepairPermit.Invalid(),
                (string?)resultXml.Attribute("testId") ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), (string?)resultXml.Attribute("executionId") ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), root, facts, entry, imported,
                DateTimeOffset.Parse((string?)resultXml.Attribute("startTime") ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime(),
                DateTimeOffset.Parse((string?)resultXml.Attribute("endTime") ?? throw CurrentCustomerSequenceRepairPermit.Invalid(), System.Globalization.CultureInfo.InvariantCulture).ToUniversalTime()));
            original.Require();
        }
        DateTimeOffset expires = result.BeganAtUtc.AddHours(12);
        DateTimeOffset precursorExpires = CustomerClosedCompletedReadback.MaximumExpires(input);
        if (precursorExpires < expires) { expires = precursorExpires; }
        if (expires <= DateTimeOffset.UtcNow) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var unsigned = new CustomerClosedEightReport("current-customer-sequence-closed-eight-console-proof-v1", "native", subject, input, trx, hostExit, cleanup, absence, hostBaseline, image,
            cases, result.BeganAtUtc, DateTimeOffset.UtcNow, expires, signer.KeyId, null);
        // Independent body validation happens before signing, and again after
        // durable readback. Any missing actual evidence prevents publication.
        await CurrentCustomerClosedEightReadback.RequireBodyAsync(destination, unsigned, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
        var outputs = new List<CustomerDefinitionArtifact>();
        foreach (string purpose in new[] { "native", "maintenance", "recovery", "role-transition" })
        {
            var report = unsigned with { Purpose = purpose };
            report = report with { Signature = Convert.ToBase64String(signer.Sign(CurrentCustomerClosedEightReadback.Payload(report))) };
            string path = Path.Combine(destinationBinding.ArtifactRootCanonicalPath, "customer-closed-eight-" + prefix + "-" + purpose + ".json");
            byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(report); await destination.WriteNewAsync(path, bytes, ct).ConfigureAwait(false);
            byte[] held = destination.Read(path, sharedReader: true, maximumBytes: 8_000_000);
            if (!held.AsSpan().SequenceEqual(bytes)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            var readback = CustomerClosedCompletedReadback.Decode<CustomerClosedEightReport>(held);
            CurrentCustomerClosedEightReadback.RequireHeader(readback, purpose, trust, signer.KeyId, fingerprint, DateTimeOffset.UtcNow);
            await CurrentCustomerClosedEightReadback.RequireBodyAsync(destination, readback, DateTimeOffset.UtcNow, ct).ConfigureAwait(false);
            outputs.Add(new(path, CurrentCustomerSequenceRepairPermit.Hash(held)));
        }
        if (outputs.Select(x => x.Sha256).Distinct(StringComparer.Ordinal).Count() != 4) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        destination.Require(); host.Require(); return new(outputs[0], outputs[1], outputs[2], outputs[3]);
    }
}
