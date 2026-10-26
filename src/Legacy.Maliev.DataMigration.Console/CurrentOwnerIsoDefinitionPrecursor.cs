using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoDefinitionPrecursor
{
    private const string Image = "postgres:18.4-bookworm@sha256:882236b897e39051d2368c5ccc6cda944904723506b2dfc97f2a8f5bc9afa382";
    internal static byte[] Payload(IsoDefinitionProof proof)
    {
        return [.. "Legacy.Maliev.OwnerIso.DefinitionPrecursor.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static void Require(CurrentAppOwnedRepairCustody files, IsoDefinitionProof proof,
        IsoDefinitionSubject intended, IReceiptAttestationTrustStore trust, string keyId,
        string fingerprint, DateTimeOffset now)
    {
        if (proof.KeyId != keyId || string.IsNullOrWhiteSpace(proof.Signature) ||
            !trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw Invalid(); }
        try { if (!trust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
        RequireBody(files, proof, intended, now);
    }

    internal static void RequireBody(CurrentAppOwnedRepairCustody files, IsoDefinitionProof proof,
        IsoDefinitionSubject intended, DateTimeOffset now)
    {
        if (proof.Kind != "current-owner-iso-definition-precursor-v1" ||
            JsonSerializer.Serialize(proof.Subject) != JsonSerializer.Serialize(intended) ||
            !HashFields(intended) || intended.ConsoleAssemblySha256 != AssemblyHash(typeof(MigrationConsole).Assembly.Location) ||
            intended.CoreAssemblySha256 != AssemblyHash(typeof(ApprovedCurrentOwnerIsoOverlay).Assembly.Location) ||
            proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now ||
            now - proof.BeganAtUtc > TimeSpan.FromHours(12) || proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(IsoDefinitionCases.Required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != 17 ||
            proof.Runs.Count != 16 || proof.Runs.Select(x => x.RunId).Distinct().Count() != 16 ||
            !proof.Cases.Where(x => x.RunId is not null).Select(x => x.RunId!.Value).Order().SequenceEqual(proof.Runs.Select(x => x.RunId).Order())) { throw Invalid(); }
        // The fixture profile is retained as genuine input, never presented as production source parity.
        var overlay = ApprovedCurrentOwnerIsoOverlay.Create(proof.FixtureSource, proof.FixtureSource.SourceCommitSha,
            CurrentOwnerIsoSelection.LiteralWidthV1, proof.FixtureOwners, proof.FixtureOwners.Max(x => x.ObservedAtUtc));
        var acceptedSource = Decode<FreshSchemaPlan>(Read(proof.AcceptedSource));
        var acceptedOwners = Decode<CurrentOwnerIsoSourceObservation[]>(Read(proof.AcceptedOwners));
        var acceptedOverlay = ApprovedCurrentOwnerIsoOverlay.Create(acceptedSource, intended.SourceCommitSha,
            CurrentOwnerIsoSelection.LiteralWidthV1, acceptedOwners, now);
        if (proof.AcceptedSource.Sha256 != intended.RawSourceFileSha256 ||
            SchemaPlanCanonicalizer.ComputeSha256(acceptedSource) != intended.SourceSchemaPlanSha256 || proof.AcceptedOwners.Sha256 != intended.OwnerSourcesSha256 ||
            proof.SourceCatalog.Sha256 != intended.SourceCatalogSha256 || acceptedOverlay.ComputeSha256() != intended.ContractSha256)
        { throw Invalid(); }
        _ = CurrentOwnerIsoRepairSourceObservation.ReadCatalog(Read(proof.SourceCatalog), acceptedSource,
            intended.SourceCatalogSha256, intended.SourceCommitSha, now);
        using var xml = XmlReader.Create(new MemoryStream(Read(proof.Trx), false),
            new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var results = trx.Descendants(ns + "UnitTestResult").ToArray();
        var counters = trx.Descendants(ns + "Counters").Single();
        if (results.Length != 17 || (string?)counters.Attribute("total") != "17" || (string?)counters.Attribute("passed") != "17" ||
            (string?)counters.Attribute("failed") != "0" || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var unit = trx.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId);
            var method = unit.Element(ns + "TestMethod") ?? throw Invalid();
            if ((string?)result.Attribute("testName") != item.TestName ||
                (string?)method.Attribute("name") != IsoDefinitionCases.Method(item.CaseId) ||
                (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentOwnerIsoNativePreservationTests" ||
                item.TestAssembly.Sha256 != intended.TestAssemblySha256) { throw Invalid(); }
            CurrentOwnerIsoClosedProofReader.RequireExecutedAssemblyPath(item.ExecutedTestAssemblyPath, item.TestAssembly.SourcePath ?? item.TestAssembly.Path,
                (string?)method.Attribute("codeBase"), (string?)unit.Attribute("storage"));
            _ = Read(item.TestAssembly);
            if (!string.Equals(Path.GetFileName(item.TestAssembly.Path), Path.GetFileName(item.ExecutedTestAssemblyPath), StringComparison.Ordinal)) { throw Invalid(); }
            var entry = Decode<IsoDefinitionEntry>(Read(item.Entered)); var exit = Decode<IsoDefinitionExit>(Read(item.Exited));
            if (entry.Kind != "iso-definition-entered-v1" || exit.Kind != "iso-definition-exited-v1" ||
                entry.CaseId != item.CaseId || exit.CaseId != item.CaseId || entry.RunId != item.RunId || exit.RunId != item.RunId ||
                entry.TestAssemblySha256 != intended.TestAssemblySha256 || entry.ObservedAtUtc < proof.BeganAtUtc ||
                entry.ObservedAtUtc.Offset != TimeSpan.Zero || exit.ObservedAtUtc.Offset != TimeSpan.Zero ||
                exit.ObservedAtUtc < entry.ObservedAtUtc || exit.ObservedAtUtc > proof.CompletedAtUtc) { throw Invalid(); }
            string stdout = (string?)result.Element(ns + "Output")?.Element(ns + "StdOut") ?? throw Invalid();
            string marker = "ISO_DEFINITION_CASE=" + item.CaseId;
            if (stdout.Split('\n').Count(x => x.Trim() == marker) != 1) { throw Invalid(); }
            if (item.CaseId.StartsWith("literal-", StringComparison.Ordinal))
            {
                var phases = item.Native ?? throw Invalid();
                var before = Decode<IsoCapturedNative>(Read(phases.Before)).Observe();
                var candidate = Decode<IsoCapturedNative>(Read(phases.Candidate)).Observe();
                var rolled = Decode<IsoCapturedNative>(Read(phases.RolledBack)).Observe();
                var committed = Decode<IsoCapturedNative>(Read(phases.CommitCandidate)).Observe();
                var after = Decode<IsoCapturedNative>(Read(phases.IndependentReadback)).Observe();
                if (before.Snapshot.Database != item.CaseId[8..] || item.Rejection is not null || item.Projections.Count != 0 || item.RejectedSnapshots.Count != 0 ||
                    before.LiteralRows.Rows != 8 || !before.LiteralRows.ExactWidths ||
                    before.Snapshot.Sha256 != rolled.Snapshot.Sha256 || before.LiteralRows != rolled.LiteralRows) { throw Invalid(); }
                CurrentOwnerIsoNativePreservation.RequireBefore(before, overlay);
                CurrentOwnerIsoNativePreservation.RequireBefore(rolled, overlay);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, candidate, overlay);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, committed, overlay);
                CurrentOwnerIsoNativePreservation.RequirePreserved(before, after, overlay);
                RequireCommittedReadback(committed, after);
            }
            else if (item.CaseId == "width")
            {
                if (item.Native is not null || item.Rejection is not null || item.Projections.Count != 10 || item.RejectedSnapshots.Count != 0) { throw Invalid(); }
                var projection = item.Projections.Select(x => Decode<IsoDefinitionProjection>(Read(x))).ToArray();
                foreach (string database in new[] { "iso_country_fixture", "iso_material_fixture" })
                {
                    var selected = projection.Where(x => x.Database == database).ToArray();
                    if (selected.Length != 5 || selected.Any(x => x != selected[0])) { throw Invalid(); }
                }
            }
            else if (item.CaseId == "pure-storage")
            {
                if (item.RunId is not null || item.Native is not null || item.Rejection is not null || item.Projections.Count != 0 || item.RejectedSnapshots.Count != 0 || entry.FaultSql is not null) { throw Invalid(); }
            }
            else
            {
                if (item.Native is not null || item.RunId is null || item.Projections.Count != 0 || entry.FaultSql is null ||
                    IsoDefinitionCases.Fault(entry.FaultSql, item.CaseId.StartsWith("candidate-", StringComparison.Ordinal)) != item.CaseId) { throw Invalid(); }
                var rejection = Decode<IsoDefinitionRejection>(Read(item.Rejection ?? throw Invalid()));
                if (item.RejectedSnapshots.Count != 2 ||
                    Decode<CurrentAppOwnedDatabaseSnapshot>(Read(item.RejectedSnapshots[0])).Sha256 !=
                    Decode<CurrentAppOwnedDatabaseSnapshot>(Read(item.RejectedSnapshots[1])).Sha256) { throw Invalid(); }
                if (rejection.Kind != "iso-definition-rejected-v1" || rejection.CaseId != item.CaseId || string.IsNullOrWhiteSpace(rejection.Code) ||
                    rejection.Boundary != (item.CaseId.StartsWith("candidate-", StringComparison.Ordinal) ? "candidate-before-effect" : "native-preimage") ||
                    rejection.ObservedAtUtc < entry.ObservedAtUtc || rejection.ObservedAtUtc > exit.ObservedAtUtc) { throw Invalid(); }
            }
        }
        foreach (var run in proof.Runs)
        {
            using var attempt = JsonDocument.Parse(Read(run.Attempt)); using var metadata = JsonDocument.Parse(Read(run.ContainerMetadata));
            using var disposed = JsonDocument.Parse(Read(run.Disposed)); using var capacity = JsonDocument.Parse(Read(run.Capacity));
            var a = attempt.RootElement; var c = metadata.RootElement; var d = disposed.RootElement;
            DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), lease = a.GetProperty("expires").GetDateTimeOffset();
            var entry = Decode<IsoDefinitionEntry>(Read(proof.Cases.Single(x => x.RunId == run.RunId).Entered));
            var exit = Decode<IsoDefinitionExit>(Read(proof.Cases.Single(x => x.RunId == run.RunId).Exited));
            var absent = Decode<IsoDefinitionAbsence>(Read(run.Absence));
            var config = c.GetProperty("Config"); var host = c.GetProperty("HostConfig");
            var ports = c.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            if (a.GetProperty("run").GetGuid() != run.RunId || a.GetProperty("persistent").GetBoolean() ||
                run.Name != "iso-native-proof-" + run.RunId.ToString("N") || c.GetProperty("Name").GetString() != "/" + run.Name ||
                run.ContainerId.Length != 64 || !run.ContainerId.All(char.IsAsciiHexDigitLower) || run.Port is < 1 or > 65535 ||
                c.GetProperty("Id").GetString() != run.ContainerId || config.GetProperty("Image").GetString() != Image ||
                config.GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
                config.GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != "current-owner-iso-native-proof" ||
                config.GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != run.RunId.ToString("D") ||
                !c.GetProperty("State").GetProperty("Running").GetBoolean() || c.GetProperty("Mounts").GetArrayLength() != 0 ||
                host.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || host.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                host.GetProperty("NanoCpus").GetInt64() != 750000000 ||
                !Empty(host, "Binds") || !Empty(host, "VolumesFrom") || !Empty(host, "Mounts") ||
                host.GetProperty("Tmpfs").EnumerateObject().Count() != 1 || host.GetProperty("Tmpfs").GetProperty("/var/lib/postgresql").GetString() != "rw,nosuid,size=384m" ||
                ports.Length != 1 || ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" ||
                ports[0].GetProperty("HostPort").GetString() != run.Port.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                capacity.RootElement.GetProperty("capacityBytes").GetInt64() != 384L * 1024 * 1024 ||
                began < proof.BeganAtUtc || lease - began != TimeSpan.FromMinutes(8) || entry.ObservedAtUtc < began || exit.ObservedAtUtc > lease ||
                d.GetProperty("run").GetGuid() != run.RunId || d.GetProperty("containerId").GetString() != run.ContainerId ||
                !d.GetProperty("removed").GetBoolean() || !d.GetProperty("disposed").GetBoolean() || d.GetProperty("cleanupFailed").GetBoolean()) { throw Invalid(); }
            DateTimeOffset removed = d.GetProperty("removedAtUtc").GetDateTimeOffset(), completed = d.GetProperty("completedAtUtc").GetDateTimeOffset();
            if (removed < exit.ObservedAtUtc || absent.ObservedAtUtc < removed || completed < absent.ObservedAtUtc || completed > lease.AddMinutes(1) ||
                completed > proof.CompletedAtUtc || absent.RunId != run.RunId || !absent.ContainerInventorySucceeded || !absent.VolumeInventorySucceeded ||
                !absent.ListenerInventorySucceeded || absent.ContainerIds.Contains(run.ContainerId, StringComparer.Ordinal) ||
                absent.ContainerNames.Any(x => x == run.Name || x == "/" + run.Name) || absent.ListeningPorts.Contains(run.Port)) { throw Invalid(); }
        }
        files.Require();
        byte[] Read(IsoDefinitionArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, maximumBytes: 8_000_000, sharedReader: true);
            return CurrentAppOwnedRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
        }
    }

    internal static IsoDefinitionProof SignAfterActualRun(CurrentAppOwnedRepairCustody files,
        IsoDefinitionProof unsigned, IsoDefinitionSubject intended, P256MigrationEvidenceSigner signer, DateTimeOffset now)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw Invalid(); }
        RequireBody(files, unsigned, intended, now);
        return unsigned with { Signature = Convert.ToBase64String(signer.Sign(Payload(unsigned))) };
    }
    private static bool HashFields(IsoDefinitionSubject x)
    {
        return new[] { x.SourceCatalogSha256, x.SourceSchemaPlanSha256, x.RawSourceFileSha256,
        x.OwnerSourcesSha256, x.ContractSha256, x.IntendedTargetObservationSha256, x.IntendedRunBindingSha256,
        x.ConsoleAssemblySha256, x.CoreAssemblySha256, x.TestAssemblySha256 }.All(CurrentAppOwnedRepairPermit.HashShape) &&
        x.SourceCommitSha.Length == 40 && x.SourceCommitSha.All(char.IsAsciiHexDigitLower);
    }

    private static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeOwnerIso<T>(bytes);
    }

    internal static void RequireCommittedReadback(CurrentOwnerIsoNativeObservation committed, CurrentOwnerIsoNativeObservation readback)
    {
        // Both transaction horizons remain retained. Only their independently observed SnapshotXmin may differ.
        if (!committed.Selected || !readback.Selected || committed.OverlaySha256 != readback.OverlaySha256 ||
            committed.Snapshot.Sha256 != readback.Snapshot.Sha256 || committed.LiteralRows != readback.LiteralRows ||
            !committed.CopyStorage().OrderBy(x => x.Key, StringComparer.Ordinal).SequenceEqual(readback.CopyStorage().OrderBy(x => x.Key, StringComparer.Ordinal)))
        { throw Invalid(); }
        var left = committed.CopyCatalog(); var right = readback.CopyCatalog();
        if (!left.Keys.Order(StringComparer.Ordinal).SequenceEqual(right.Keys.Order(StringComparer.Ordinal)) ||
            left.Any(x => !x.Value.SequenceEqual(right[x.Key], StringComparer.Ordinal))) { throw Invalid(); }
    }
    private static bool Empty(JsonElement value, string name)
    {
        return !value.TryGetProperty(name, out var item) ||
        item.ValueKind == JsonValueKind.Null || (item.ValueKind == JsonValueKind.Array && item.GetArrayLength() == 0);
    }

    private static string AssemblyHash(string path) { using var file = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(file)); }
    private static MigrationExecutionException Invalid()
    {
        return IsoDefinitionCases.Invalid();
    }
}
