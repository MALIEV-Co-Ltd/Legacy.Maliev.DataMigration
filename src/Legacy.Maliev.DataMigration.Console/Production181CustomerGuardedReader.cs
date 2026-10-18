using System.Globalization;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class Production181CustomerGuardedReader
{
    private const string PinnedImage = "ghcr.io/cloudnative-pg/postgresql:18.1-standard-bookworm@sha256:4d7755c0460bdac6143f49e5d16ba4865aeb61368fe773adfea8696380a69b7a";
    internal static byte[] Payload(Production181GuardedBootstrapProof proof)
    {
        return [.. "Legacy.Maliev.Production181.CustomerSequence.GuardedBootstrapProof.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static void Require(CurrentAppOwnedRepairCustody files, Production181GuardedBootstrapProof proof, CustomerDefinitionSubject intended,
        IReceiptAttestationTrustStore outerTrust, string keyId, string fingerprint, DateTimeOffset now)
    {
        if (proof.KeyId != keyId || proof.Signature is null || !outerTrust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint ||
            !outerTrust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); }
        RequireBody(files, proof, intended, outerTrust, proof.DefinitionKeyId, proof.DefinitionFingerprint, now);
    }
    internal static void RequireBody(CurrentAppOwnedRepairCustody files, Production181GuardedBootstrapProof proof, CustomerDefinitionSubject intended,
        IReceiptAttestationTrustStore definitionTrust, string definitionKeyId, string definitionFingerprint, DateTimeOffset now)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        string phase = proof.Kind switch
        {
            "current-production181-customer-native-bootstrap-precursor-v1" => "native-component",
            "current-production181-customer-maintenance-bootstrap-precursor-v1" => "maintenance-component",
            _ => throw Invalid()
        };
        string[] required = CurrentCustomerSequenceClosedProofReader.Cases(phase);
        if (JsonSerializer.Serialize(proof.IntendedSubject) != JsonSerializer.Serialize(intended) ||
            proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now ||
            proof.ExpiresAtUtc - proof.BeganAtUtc > TimeSpan.FromHours(12) || now - proof.BeganAtUtc > TimeSpan.FromHours(12) ||
            !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal)) ||
            proof.Cases.Select(x => x.RunId).Distinct().Count() != required.Length || proof.Cases.Select(x => x.ExecutionId).Distinct(StringComparer.Ordinal).Count() != required.Length) { throw Invalid(); }
        _ = Read(proof.DefinitionPrecursor);
        using var heldDefinition = Production181HeldDefinition.Open(proof.DefinitionPaths, intended, definitionTrust, definitionKeyId, definitionFingerprint);
        if (heldDefinition.DefinitionSha256 != proof.DefinitionPrecursor.Sha256) { throw Invalid(); }
        var definition = heldDefinition.Proof;
        var hostExit = Decode<CustomerGuardedBootstrapHostExit>(Read(proof.HostExit));
        RequireHostExit(hostExit, proof.BeganAtUtc, proof.CompletedAtUtc, proof.Cases.Select(x => x.RunId).ToArray());
        using var trxStream = new MemoryStream(Read(proof.Trx), false);
        using var xml = XmlReader.Create(trxStream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var counters = trx.Descendants(ns + "Counters").Single(); var results = trx.Descendants(ns + "UnitTestResult").ToArray();
        if ((string?)counters.Attribute("total") != required.Length.ToString(CultureInfo.InvariantCulture) ||
            (string?)counters.Attribute("passed") != required.Length.ToString(CultureInfo.InvariantCulture) || (string?)counters.Attribute("failed") != "0" ||
            results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            var result = results.Single(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            var unit = trx.Descendants(ns + "UnitTest").Single(x => (string?)x.Attribute("id") == item.TestId); var method = unit.Element(ns + "TestMethod") ?? throw Invalid();
            if ((string?)result.Attribute("testName") != item.TestName || (string?)method.Attribute("name") != "Customer_sequence_" + item.CaseId.Replace('-', '_') ||
                (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.Production181CustomerGuardedNativeTests" ||
                RequireReportedRun((string?)result.Element(ns + "Output")?.Element(ns + "StdOut") ?? throw Invalid()) != item.RunId) { throw Invalid(); }
            Production181CustomerDefinitionReader.RequireImageProvenance(item.ExecutedTestAssemblyPath, item.TestAssembly,
                (string?)method.Attribute("codeBase"), (string?)unit.Attribute("storage"));
            _ = Read(item.TestAssembly);
            using var hostEntry = JsonDocument.Parse(Read(item.HostEntry)); JsonElement host = hostEntry.RootElement;
            if (host.GetProperty("run").GetGuid() != item.RunId || host.GetProperty("processId").GetInt32() != hostExit.ProcessId ||
                host.GetProperty("processStartTimeUtc").GetDateTimeOffset() != hostExit.ProcessStartTimeUtc || host.GetProperty("executable").GetString() != hostExit.Executable ||
                host.GetProperty("executableSha256").GetString() != hostExit.ExecutableSha256 || host.GetProperty("testAssemblySha256").GetString() != hostExit.TestAssemblySha256 ||
                host.GetProperty("jobNonce").GetString() != hostExit.JobNonce || !host.GetProperty("nativeJobMembershipObserved").GetBoolean() ||
                hostExit.TestAssemblySha256 != item.TestAssembly.Sha256) { throw Invalid(); }
            var source = Decode<FreshSchemaPlan>(Read(item.FixtureSource)); var scope = Decode<CurrentCustomerSequenceRepairScope>(Read(item.Scope));
            var review = Decode<CurrentCustomerSequenceRepairSignedClaim>(Read(item.Review)); var authorization = Decode<CurrentCustomerSequenceRepairSignedClaim>(Read(item.Authorization));
            var pins = Decode<CurrentCustomerSequenceRepairSigningPins>(Read(item.SigningPins)); var keys = Decode<CustomerGuardedPublicKey[]>(Read(item.PublicKeys));
            var caseTrust = new ReceiptAttestationTrustStore(keys.Select(x => new TrustedAttestationKey(x.Id, Convert.FromBase64String(x.Spki))));
            if (scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap || scope.BootstrapSubject is not { } subject ||
                scope.SourceCommitSha != intended.Source.CommitSha || scope.CatalogReportSha256 != intended.Source.CatalogReportSha256 ||
                scope.DefinitionSha256 != intended.DefinitionSha256 || scope.DefinitionProofSha256 != proof.DefinitionPrecursor.Sha256 ||
                subject.ConsoleAssemblySha256 != intended.ConsoleAssemblySha256 || subject.CoreAssemblySha256 != intended.CoreAssemblySha256 ||
                subject.TestAssemblySha256 != item.TestAssembly.Sha256 || subject.TargetObservationSha256 != item.Resource.Container.Sha256 ||
                JsonSerializer.Serialize(review.Scope) != JsonSerializer.Serialize(scope)) { throw Invalid(); }
            using var entered = JsonDocument.Parse(Read(item.Entered)); using var exit = JsonDocument.Parse(Read(item.Exit));
            var begin = entered.RootElement.GetProperty("enteredAtUtc").GetDateTimeOffset(); var end = exit.RootElement.GetProperty("exitedAtUtc").GetDateTimeOffset();
            if (entered.RootElement.GetProperty("operation").GetGuid() != item.RunId || entered.RootElement.GetProperty("fault").GetString() != item.CaseId ||
                exit.RootElement.GetProperty("run").GetGuid() != item.RunId || begin < proof.BeganAtUtc || end < begin || end > proof.CompletedAtUtc) { throw Invalid(); }
            CurrentCustomerSequenceRepairPermit.ValidateClaims(review, authorization, source, caseTrust, pins, begin);
            if (phase == "native-component")
            {
                using var proxy = JsonDocument.Parse(Read(item.Proxy ?? throw Invalid())); using var proxyDisposed = JsonDocument.Parse(Read(item.ProxyDisposed ?? throw Invalid()));
                JsonElement p = proxy.RootElement, d = proxyDisposed.RootElement;
                if (p.GetProperty("operation").GetGuid() != item.RunId || d.GetProperty("operation").GetGuid() != item.RunId ||
                    p.GetProperty("processId").GetInt32() != hostExit.ProcessId || p.GetProperty("processStartTimeUtc").GetDateTimeOffset() != hostExit.ProcessStartTimeUtc ||
                    p.GetProperty("executable").GetString() != hostExit.Executable || p.GetProperty("persistent").GetBoolean() ||
                    !d.GetProperty("workerCompleted").GetBoolean() || d.GetProperty("port").GetInt32() != p.GetProperty("port").GetInt32() ||
                    d.GetProperty("completedAtUtc").GetDateTimeOffset() > end) { throw Invalid(); }
                var absence = Decode<CustomerDefinitionAbsence>(Read(item.Resource.Absence));
                if (absence.ListeningPorts.Contains(p.GetProperty("port").GetInt32())) { throw Invalid(); }
                if (item.CaseId == "commit-ack-lost")
                {
                    using var drop = JsonDocument.Parse(Read(item.CommitDrop ?? throw Invalid())); JsonElement observedDrop = drop.RootElement;
                    if (observedDrop.GetProperty("operation").GetGuid() != item.RunId || observedDrop.GetProperty("count").GetInt32() != 1 ||
                        observedDrop.GetProperty("frameTag").GetInt32() != (byte)'C' || observedDrop.GetProperty("payloadSha256").GetString() != CurrentCustomerSequenceRepairPermit.Hash("COMMIT\0"u8.ToArray()) ||
                        observedDrop.GetProperty("observedAtUtc").GetDateTimeOffset() < begin || observedDrop.GetProperty("observedAtUtc").GetDateTimeOffset() > end) { throw Invalid(); }
                }
                else if (item.CommitDrop is not null) { throw Invalid(); }
            }
            else if (item.Proxy is not null || item.ProxyDisposed is not null || item.CommitDrop is not null) { throw Invalid(); }
            var before = Decode<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.Before)); var after = Decode<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.After));
            RequireFleet(before, scope); RequireFleetNames(after, scope);
            var customerBefore = Decode<CurrentCustomerSequenceObservation>(Read(item.CustomerBefore)); var customerAfter = Decode<CurrentCustomerSequenceObservation>(Read(item.CustomerAfter));
            CurrentCustomerSequenceRepairPermit.RequireNativePreimage(customerBefore, scope, begin);
            if (customerBefore.Snapshot.Sha256 != before.Single(x => x.Database == "Customer").Sha256 || customerAfter.Snapshot.Sha256 != after.Single(x => x.Database == "Customer").Sha256) { throw Invalid(); }
            if (phase == "native-component" && item.CaseId != "prepared-publication") { ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(customerBefore, customerAfter, "legacy_local"); }
            else if (customerBefore.State != customerAfter.State || customerBefore.Snapshot.Sha256 != customerAfter.Snapshot.Sha256) { throw Invalid(); }
            using var scenario = JsonDocument.Parse(Read(item.Scenario)); JsonElement s = scenario.RootElement;
            DateTimeOffset observed = s.GetProperty("observedAtUtc").GetDateTimeOffset();
            if (s.GetProperty("operation").GetGuid() != scope.OperationId || observed < begin || observed > end || s.GetProperty("fault").GetString() != item.CaseId) { throw Invalid(); }
            string authorizationHash = CurrentAppOwnedSnapshotSerialization.Sha256(authorization), predecessor = new('0', 64);
            var acknowledged = new List<CurrentCustomerSequenceRepairReceipt>(); var slots = new List<(CurrentCustomerSequenceRepairReceipt Receipt, bool Acknowledged)>();
            RequireRetainedSlotInventory(s.GetProperty("retainedSlots"));
            foreach (var slot in s.GetProperty("retainedSlots").EnumerateArray())
            {
                string name = slot.GetProperty("name").GetString() ?? throw Invalid();
                string path = Path.Combine(Path.GetDirectoryName(item.Scenario.Path) ?? throw Invalid(), name);
                byte[] bytes = Read(new(path, slot.GetProperty("sha256").GetString() ?? throw Invalid())); var receipt = Decode<CurrentCustomerSequenceRepairReceipt>(bytes);
                if (Path.GetFileName(name) != name || receipt.ObservedAtUtc < begin || receipt.ObservedAtUtc > end ||
                    name != $"{scope.OperationId:D}-Customer-{CurrentCustomerSequenceRepairConsoleEnvironment.ReceiptSuffix(receipt.Classification)}.json") { throw Invalid(); }
                bool ack = slot.GetProperty("acknowledged").GetBoolean();
                if (ack) { PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt, scope, authorizationHash, caseTrust, pins, predecessor, end); predecessor = CurrentCustomerSequenceRepairPermit.Hash(bytes); acknowledged.Add(receipt); }
                else { PostgreSqlCurrentCustomerSequenceRepair.RequireReceipt(receipt, scope, authorizationHash, caseTrust, pins, receipt.PreviousReceiptSha256, end); }
                slots.Add((receipt, ack));
            }
            if (item.Candidate is not null)
            {
                var candidate = Decode<CurrentCustomerSequenceObservation>(Read(item.Candidate)); var candidateFleet = Decode<CurrentAppOwnedDatabaseSnapshot[]>(Read(item.CandidateFleet ?? throw Invalid()));
                ApprovedCurrentCustomerSequenceDefinition.RequirePreserved(customerBefore, candidate, "legacy_local"); RequireFleetNames(candidateFleet, scope);
                if (candidateFleet.Single(x => x.Database == "Customer").Sha256 != candidate.Snapshot.Sha256 ||
                    candidateFleet.Where(x => x.Database != "Customer").Any(x => x.Sha256 != scope.BeforeDatabaseSha256[x.Database]) ||
                    slots.Any(x => x.Receipt.AfterSha256 != candidate.Snapshot.Sha256)) { throw Invalid(); }
            }
            else if (phase == "native-component" || item.CandidateFleet is not null || slots.Count != 0) { throw Invalid(); }
            foreach (var (Receipt, Acknowledged) in slots.Where(x => !x.Acknowledged))
            {
                if (item.CaseId == "prepared-publication" && Receipt.Classification == CurrentAppOwnedCommitClassification.Prepared)
                { if (Receipt.PreviousReceiptSha256 != new string('0', 64) || acknowledged.Count != 1 || Receipt.AfterSha256 != acknowledged[0].AfterSha256) { throw Invalid(); } }
                else if (item.CaseId == "terminal-publication" && Receipt.Classification == CurrentAppOwnedCommitClassification.CommittedAndReadback)
                { var prepared = acknowledged.FirstOrDefault(x => x.Classification == CurrentAppOwnedCommitClassification.Prepared) ?? throw Invalid(); if (Receipt.PreviousReceiptSha256 != CurrentAppOwnedSnapshotSerialization.Sha256(prepared) || Receipt.AfterSha256 != prepared.AfterSha256) { throw Invalid(); } }
                else { throw Invalid(); }
            }
            string boundary = item.CaseId switch
            {
                "complete" => "complete",
                "replay" => "replay-blocked",
                "prepared-publication" => "prepared-publication-before-ack",
                "commit-ack-lost" => "commit-ack-lost",
                "terminal-publication" => "terminal-publication",
                "final-fleet" => "final-fleet-after-terminal",
                "unsafe-host" or "local-trust" => "maintenance-semantic",
                _ => "maintenance-probes"
            };
            var scenarioTyped = new CurrentCustomerSequenceProofScenario("current-customer-sequence-proof-scenario-v1", scope.OperationId, item.Scenario.Sha256, boundary,
                s.GetProperty("rejectionCode").GetString(), observed, [], Decode<string[]>(System.Text.Encoding.UTF8.GetBytes(s.GetProperty("ordinaryRejected").GetRawText())),
                s.GetProperty("installedSemanticPolicyAccepted").GetBoolean(), s.GetProperty("commitAcknowledged").GetBoolean(), s.GetProperty("replayRejected").GetBoolean());
            CurrentCustomerSequenceClosedProofReader.RequireCaseEffects(item.CaseId, scenarioTyped, acknowledged,
                before.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal), after.ToDictionary(x => x.Database, x => x.Sha256, StringComparer.Ordinal));
            RequirePolicy(item, scope, scenarioTyped.InstalledSemanticPolicyAccepted);
            RequireResource(item.Resource, item.Image, item.RunId, scope, begin, end, hostExit.ExitedAtUtc);
        }
        files.Require();
        byte[] Read(CustomerDefinitionArtifact artifact)
        {
            CurrentCustomerSequenceCapacity.Require(admission: false); byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000); return CurrentCustomerSequenceRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
        }
        void RequirePolicy(CustomerGuardedBootstrapCase item, CurrentCustomerSequenceRepairScope scope, bool accepted)
        {
            using var actual = JsonDocument.Parse(Read(item.InstalledPolicy)); JsonElement p = actual.RootElement.GetProperty("policy");
            using var hba = JsonDocument.Parse(Read(item.HbaFile)); using var rules = JsonDocument.Parse(Read(item.HbaRules));
            string h = hba.RootElement.GetProperty("text").GetString() ?? throw Invalid(), r = rules.RootElement.GetProperty("text").GetString() ?? throw Invalid();
            if (CurrentCustomerSequenceRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(h)) != scope.Maintenance.HbaSha256 || CurrentCustomerSequenceRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(r)) != scope.Maintenance.HbaRulesSha256 ||
                p.GetProperty("systemIdentifierSha256").GetString() != scope.Target.SystemIdentifierSha256 || p.GetProperty("role").GetString() != scope.Maintenance.Role ||
                p.GetProperty("postmaster").GetDateTimeOffset() != scope.Maintenance.Postmaster || p.GetProperty("configLoaded").GetDateTimeOffset() != scope.Maintenance.ConfigLoaded ||
                p.GetProperty("roleExpires").GetDateTimeOffset() != scope.Maintenance.ExpiresAtUtc || p.GetProperty("roleComment").GetString() != scope.Maintenance.RoleComment ||
                p.GetProperty("hbaPath").GetString() != scope.Maintenance.HbaPath ||
                !p.GetProperty("superuser").GetBoolean() || !p.GetProperty("login").GetBoolean() || p.GetProperty("createRole").GetBoolean() || p.GetProperty("createDatabase").GetBoolean() ||
                p.GetProperty("replication").GetBoolean() || p.GetProperty("bypassRls").GetBoolean() || p.GetProperty("memberships").GetInt64() != 0 ||
                !p.GetProperty("scram").GetBoolean() || p.GetProperty("defaultAcls").GetInt64() != 0 || p.GetProperty("otherClients").GetInt64() != 0 ||
                p.GetProperty("preparedTransactions").GetInt64() != 0 || p.GetProperty("eventTriggers").GetInt64() != 0 || !p.GetProperty("primary").GetBoolean()) { throw Invalid(); }
            using var raw = JsonDocument.Parse(r); var parsed = raw.RootElement.EnumerateArray().Select(x => new CurrentAppOwnedMaintenanceHbaRule(x.GetProperty("rule_number").GetInt32(),
                x.GetProperty("type").GetString()!, Strings(x, "database"), Strings(x, "user_name"), Text(x, "address"), Text(x, "netmask"), x.GetProperty("auth_method").GetString()!, Strings(x, "options"), Text(x, "error"))).ToArray();
            bool semantic = true; try { CurrentAppOwnedMaintenanceHba.Require(parsed, scope.Maintenance.Role, scope.Target.Kind); } catch (MigrationExecutionException failure) when (failure.Code == "current_app_owned_maintenance_hba_not_exclusive") { semantic = false; }
            if (semantic != accepted) { throw Invalid(); }
        }
        void RequireResource(CustomerDefinitionRun resource, CustomerDefinitionArtifact image, Guid run, CurrentCustomerSequenceRepairScope scope, DateTimeOffset begin, DateTimeOffset end, DateTimeOffset completed)
        {
            using var attempt = JsonDocument.Parse(Read(resource.Attempt)); using var container = JsonDocument.Parse(Read(resource.Container)); using var volume = JsonDocument.Parse(Read(resource.VolumeMetadata)); using var disposed = JsonDocument.Parse(Read(resource.Disposed));
            using var creation = JsonDocument.Parse(Read(resource.CreationAttempt));
            var absence = Decode<CustomerDefinitionAbsence>(Read(resource.Absence)); JsonElement a = attempt.RootElement, c = container.RootElement, v = volume.RootElement, d = disposed.RootElement;
            using var imageDocument = JsonDocument.Parse(Read(image)); JsonElement observedImage = imageDocument.RootElement;
            DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expires = a.GetProperty("expires").GetDateTimeOffset();
            DateTimeOffset attempted = creation.RootElement.GetProperty("attemptedAtUtc").GetDateTimeOffset();
            if (creation.RootElement.GetProperty("run").GetGuid() != run || creation.RootElement.GetProperty("name").GetString() != resource.Name ||
                creation.RootElement.GetProperty("expires").GetDateTimeOffset() != expires || attempted < began || attempted > begin ||
                Decode<string[]>(Read(resource.PreviousContainerNames)).Any(x => x == resource.Name || x == "/" + resource.Name)) { throw Invalid(); }
            if (resource.RunId != run || scope.OperationId != run || !LowerHex(resource.ContainerId) || resource.Volume != Production181EngineContract.Name(run) ||
                !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) || DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target) ||
                !scope.Target.AuthorityId.EndsWith(resource.ContainerId, StringComparison.Ordinal) || resource.Name != Production181EngineContract.Name(run) ||
                a.GetProperty("run").GetGuid() != run || a.GetProperty("persistent").GetBoolean() || a.GetProperty("name").GetString() != resource.Name ||
                c.GetProperty("Id").GetString() != resource.ContainerId || c.GetProperty("Name").GetString() != "/" + resource.Name ||
                c.GetProperty("Config").GetProperty("Labels").GetProperty("codex.repair.run").GetString() != run.ToString("D") ||
                c.GetProperty("Config").GetProperty("Labels").GetProperty("codex.repair.operation").GetString() != run.ToString("D") ||
                c.GetProperty("Config").GetProperty("Labels").GetProperty("codex.repair.purpose").GetString() != Production181EngineContract.Purpose ||
                c.GetProperty("Config").GetProperty("Image").GetString() != PinnedImage || c.GetProperty("Image").GetString() != observedImage.GetProperty("Id").GetString() ||
                !observedImage.GetProperty("RepoDigests").EnumerateArray().Any(x => x.GetString() == "ghcr.io/cloudnative-pg/postgresql@" + PinnedImage.Split('@')[1]) ||
                c.GetProperty("Config").GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
                c.GetProperty("HostConfig").GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || c.GetProperty("HostConfig").GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 ||
                c.GetProperty("HostConfig").GetProperty("NanoCpus").GetInt64() != 750000000 ||
                v.GetProperty("Name").GetString() != resource.Volume || v.GetProperty("Driver").GetString() != "local" || v.GetProperty("Scope").GetString() != "local" ||
                Decode<string[]>(Read(resource.PreviousVolumes)).Contains(resource.Volume, StringComparer.Ordinal) || !Decode<string[]>(Read(resource.VolumeConsumers)).SequenceEqual([resource.ContainerId], StringComparer.Ordinal) ||
                d.GetProperty("run").GetGuid() != run || d.GetProperty("containerId").GetString() != resource.ContainerId || d.GetProperty("volume").GetString() != resource.Volume ||
                !d.GetProperty("removed").GetBoolean() || !d.GetProperty("disposed").GetBoolean() || d.GetProperty("cleanupFailure").GetBoolean() ||
                began > begin || end > expires || expires - began != TimeSpan.FromMinutes(8) || d.GetProperty("completedAtUtc").GetDateTimeOffset() > completed) { throw Invalid(); }
            var mounts = c.GetProperty("Mounts").EnumerateArray().ToArray(); var ports = c.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            DateTimeOffset created = c.GetProperty("Created").GetDateTimeOffset(), started = c.GetProperty("State").GetProperty("StartedAt").GetDateTimeOffset();
            if (mounts.Length != 1 || mounts[0].GetProperty("Type").GetString() != "volume" || mounts[0].GetProperty("Name").GetString() != resource.Volume || mounts[0].GetProperty("Destination").GetString() != "/var/lib/postgresql" ||
                !mounts[0].GetProperty("RW").GetBoolean() || ports.Length != 1 || ports[0].GetProperty("HostIp").GetString() != "127.0.0.1" || ports[0].GetProperty("HostPort").GetString() != resource.Port.ToString(CultureInfo.InvariantCulture) ||
                created < attempted.AddSeconds(-1) || created > begin || started < created || started > begin || !c.GetProperty("State").GetProperty("Running").GetBoolean() ||
                !Empty(c.GetProperty("HostConfig"), "Binds") || !Empty(c.GetProperty("HostConfig"), "VolumesFrom") || !Production181SemanticResource.DeclaredMount(c.GetProperty("HostConfig"), resource.Volume) ||
                !Empty(c.GetProperty("HostConfig"), "Tmpfs") || !Empty(v, "Options") || !Production181SemanticResource.NamedLabels(v, run) ||
                !c.GetProperty("NetworkSettings").GetProperty("Ports").EnumerateObject().Where(x => x.Value.ValueKind != JsonValueKind.Null).Select(x => x.Name).SequenceEqual(["5432/tcp"], StringComparer.Ordinal) ||
                v.GetProperty("CreatedAt").GetDateTimeOffset() < began.AddSeconds(-1) || v.GetProperty("CreatedAt").GetDateTimeOffset() > expires) { throw Invalid(); }
            Production181CustomerDefinitionReader.RequireCleanup(end, d.GetProperty("removedAtUtc").GetDateTimeOffset(), absence.ObservedAtUtc, d.GetProperty("completedAtUtc").GetDateTimeOffset(), expires);
            if (absence.RunId != run || !absence.ContainersObserved || !absence.VolumesObserved || !absence.ListenersObserved || absence.ContainerIds.Contains(resource.ContainerId, StringComparer.Ordinal) ||
                absence.ContainerNames.Any(x => x == resource.Name || x == "/" + resource.Name) || absence.VolumeNames.Contains(resource.Volume, StringComparer.Ordinal) || absence.ListeningPorts.Contains(resource.Port)) { throw Invalid(); }
        }
    }
    internal static void RequireRetainedSlotInventory(JsonElement retained)
    {
        if (retained.ValueKind != JsonValueKind.Array || retained.GetArrayLength() > 3) { throw Invalid(); }
        var names = new HashSet<string>(StringComparer.Ordinal); var hashes = new HashSet<string>(StringComparer.Ordinal); int unacknowledged = 0;
        foreach (var slot in retained.EnumerateArray())
        {
            string name = slot.GetProperty("name").GetString() ?? throw Invalid(), hash = slot.GetProperty("sha256").GetString() ?? throw Invalid();
            if (string.IsNullOrWhiteSpace(name) || Path.GetFileName(name) != name || !names.Add(name) || !CurrentCustomerSequenceRepairPermit.HashShape(hash) || !hashes.Add(hash)) { throw Invalid(); }
            if (!slot.GetProperty("acknowledged").GetBoolean() && ++unacknowledged > 1) { throw Invalid(); }
        }
    }
    // Explicit component consumer. This route never accepts a persistent execution scope.
    internal static void RequireComponent(CurrentAppOwnedRepairCustody files, string phase, CurrentCustomerSequenceRepairScope scope,
        CustomerDefinitionArtifact artifact, CustomerDefinitionSubject intended, IReceiptAttestationTrustStore trust, string keyId, string fingerprint, DateTimeOffset now)
    {
        RequireComponentScope(phase, scope);
        string expected = phase == "native-component" ? scope.NativeProofSha256 : scope.MaintenanceProofSha256;
        if (artifact.Sha256 != expected) { throw Invalid(); }
        byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000);
        if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != expected) { throw Invalid(); }
        var proof = Decode<Production181GuardedBootstrapProof>(bytes);
        string kind = phase == "native-component" ? "current-production181-customer-native-bootstrap-precursor-v1" : "current-production181-customer-maintenance-bootstrap-precursor-v1";
        if (proof.Kind != kind || intended.Source.CommitSha != scope.SourceCommitSha || intended.Source.CatalogReportSha256 != scope.CatalogReportSha256 ||
            JsonSerializer.Serialize(intended.Source) != JsonSerializer.Serialize(scope.SourceObservation) || JsonSerializer.Serialize(intended.Owner) != JsonSerializer.Serialize(scope.OwnerObservation) ||
            intended.SourceSchemaPlanSha256 != scope.SourceSchemaPlanSha256 || intended.DefinitionSha256 != scope.DefinitionSha256 ||
            intended.IntendedNativeBeforeStateSha256 != scope.NativeBeforeStateSha256 || intended.IntendedTargetObservationSha256 != scope.TargetObservationSha256 ||
            intended.IntendedRunBindingSha256 != scope.RunBindingSha256 || proof.DefinitionPrecursor.Sha256 != scope.DefinitionProofSha256) { throw Invalid(); }
        Require(files, proof, intended, trust, keyId, fingerprint, now);
    }
    internal static void RequireComponentScope(string phase, CurrentCustomerSequenceRepairScope scope)
    {
        if (phase is not ("native-component" or "maintenance-component") || scope.ProofAdmission != CurrentCustomerSequenceProofAdmission.DisposableNativeBootstrap ||
            scope.BootstrapSubject is not null || scope.Target.Kind != DeltaTargetAuthorityKind.LocalAspire ||
            !DeltaSynchronizationPlanProducer.IsDisposableLocalAuthority(scope.Target) || DeltaSynchronizationPlanProducer.IsPersistentLocalAuthority(scope.Target)) { throw Invalid(); }
    }
    private static void RequireFleet(CurrentAppOwnedDatabaseSnapshot[] fleet, CurrentCustomerSequenceRepairScope scope)
    { RequireFleetNames(fleet, scope); if (fleet.Any(x => x.Sha256 != scope.BeforeDatabaseSha256[x.Database])) { throw Invalid(); } }
    private static void RequireFleetNames(CurrentAppOwnedDatabaseSnapshot[] fleet, CurrentCustomerSequenceRepairScope scope)
    { if (fleet.Length != 26 || fleet.Select(x => x.Database).Distinct(StringComparer.Ordinal).Count() != 26 || !fleet.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal))) { throw Invalid(); } }
    internal static Guid RequireReportedRun(string stdout)
    { var found = new HashSet<Guid>(); foreach (string line in stdout.Split('\n', StringSplitOptions.RemoveEmptyEntries)) { if (!line.TrimStart().StartsWith('{')) { continue; } using var json = JsonDocument.Parse(line.Trim()); if (json.RootElement.TryGetProperty("Purpose", out var p) && p.GetString() == Production181EngineContract.Purpose) { _ = found.Add(json.RootElement.GetProperty("run").GetGuid()); } } return found.Count == 1 ? found.Single() : throw Invalid(); }
    internal static void RequireHostExit(CustomerGuardedBootstrapHostExit host, DateTimeOffset began, DateTimeOffset completed, IReadOnlyList<Guid> runs)
    {
        if (host.Kind != "current-customer-sequence-actual-testhost-exit-v1" || !host.ProcessExitObserved || host.ProcessId <= 0 || host.ExitCode != 0 ||
            !Guid.TryParseExact(host.JobNonce, "N", out _) || !host.NativeMembershipObserved || !host.EmptyJobObservedAfterExit ||
            host.MembershipObservedAtUtc.Offset != TimeSpan.Zero || host.MembershipObservedAtUtc < host.ProcessStartTimeUtc || host.MembershipObservedAtUtc > host.ExitedAtUtc ||
            host.ExitedAtUtc.Offset != TimeSpan.Zero || host.ProcessStartTimeUtc.Offset != TimeSpan.Zero || host.ProcessStartTimeUtc > began ||
            host.ExitedAtUtc < began || host.ExitedAtUtc > completed || !host.RunIds.Order().SequenceEqual(runs.Order()) ||
            !CurrentCustomerSequenceRepairPermit.HashShape(host.ExecutableSha256) || !CurrentCustomerSequenceRepairPermit.HashShape(host.TestAssemblySha256) ||
            !Path.IsPathFullyQualified(host.Executable)) { throw Invalid(); }
    }
    private static string? Text(JsonElement value, string name)
    {
        return value.GetProperty(name).ValueKind == JsonValueKind.Null ? null : value.GetProperty(name).GetString();
    }

    private static bool LowerHex(string value)
    {
        return value.Length == 64 && value.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static bool Empty(JsonElement parent, string name)
    {
        return !parent.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null ||
        (value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0) || (value.ValueKind == JsonValueKind.Object && !value.EnumerateObject().Any());
    }

    private static string[] Strings(JsonElement value, string name)
    {
        return value.GetProperty(name).ValueKind == JsonValueKind.Null ? [] : [.. value.GetProperty(name).EnumerateArray().Select(x => x.GetString() ?? throw Invalid())];
    }

    private static T Decode<T>(byte[] bytes)
    {
        return MigrationConsole.DecodeCustomerSequence<T>(bytes);
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_guarded_bootstrap_proof_invalid", "Genuine disposable component evidence required; no persistent authority.");
    }
}

// Reads genuine completed runs only. No test outcome, receipt, host exit or native state is synthesized.
internal static class Production181CustomerGuardedAssembler
{
    // Acquire each actual source root separately; this copies bytes without relaxing custody paths.
    // Repeat for each case root, TRX root and executed-image root. The destination is immediate-root.
    internal static async Task<IReadOnlyDictionary<string, CustomerDefinitionArtifact>> ImportActualArtifactsAsync(
        CurrentAppOwnedRepairCustody sourceFiles, CurrentAppOwnedRepairCustody destinationFiles, IReadOnlyList<string> sourcePaths,
        string flatDestinationDirectory, CancellationToken ct)
    {
        var imported = new Dictionary<string, CustomerDefinitionArtifact>(StringComparer.Ordinal);
        RequireFlatImportPaths(sourcePaths, flatDestinationDirectory);
        foreach (string sourcePath in sourcePaths)
        {
            ct.ThrowIfCancellationRequested(); string name = Path.GetFileName(sourcePath);
            if (!Path.IsPathFullyQualified(sourcePath) || string.IsNullOrWhiteSpace(name) || imported.ContainsKey(name)) { throw Invalid(); }
            imported.Add(name, await Production181CustomerDefinitionAssembler.ImportActualAsync(sourceFiles, destinationFiles, sourcePath,
                Path.Combine(flatDestinationDirectory, name), ct).ConfigureAwait(false));
        }
        return new System.Collections.ObjectModel.ReadOnlyDictionary<string, CustomerDefinitionArtifact>(imported);
    }
    internal static void RequireFlatImportPaths(IReadOnlyList<string> sourcePaths, string flatDestinationDirectory)
    {
        if (!Path.IsPathFullyQualified(flatDestinationDirectory) || sourcePaths.Count == 0) { throw Invalid(); }
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (string path in sourcePaths)
        { string name = Path.GetFileName(path); if (!Path.IsPathFullyQualified(path) || string.IsNullOrWhiteSpace(name) || !names.Add(name)) { throw Invalid(); } }
    }
    internal static Production181GuardedBootstrapProof AssembleAfterActualRun(CurrentAppOwnedRepairCustody files, string phase, CustomerDefinitionSubject intended,
        CustomerDefinitionArtifact definition, Production181PrerequisitePaths definitionPaths, CustomerDefinitionArtifact trxArtifact, CustomerDefinitionArtifact hostExit, string ledgerDirectory,
        string testAssemblyPath, DateTimeOffset began, DateTimeOffset completed, DateTimeOffset expires, string definitionKeyId, string definitionFingerprint,
        string keyId, IReceiptAttestationTrustStore definitionTrust, DateTimeOffset now, string executedTestAssemblyPath)
    {
        if (phase is not ("native-component" or "maintenance-component") || !Path.IsPathFullyQualified(executedTestAssemblyPath)) { throw Invalid(); }
        using var trxStream = new MemoryStream(Read(trxArtifact), false);
        using var xml = XmlReader.Create(trxStream, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"; var cases = new List<CustomerGuardedBootstrapCase>();
        CustomerDefinitionArtifact testAssembly = Artifact(testAssemblyPath) with { SourcePath = Path.GetFullPath(executedTestAssemblyPath) };
        foreach (var result in trx.Descendants(ns + "UnitTestResult"))
        {
            Guid run = Production181CustomerGuardedReader.RequireReportedRun((string?)result.Element(ns + "Output")?.Element(ns + "StdOut") ?? throw Invalid());
            string prefix = Path.Combine(ledgerDirectory, run.ToString("N"));
            using var entered = JsonDocument.Parse(Read(Phase("case-entered"))); string id = entered.RootElement.GetProperty("fault").GetString() ?? throw Invalid();
            using var container = JsonDocument.Parse(Read(Phase("proof-container"))); using var disposed = JsonDocument.Parse(Read(Phase("disposed")));
            JsonElement c = container.RootElement, d = disposed.RootElement; var ports = c.GetProperty("NetworkSettings").GetProperty("Ports").GetProperty("5432/tcp").EnumerateArray().ToArray();
            if (ports.Length != 1 || !int.TryParse(ports[0].GetProperty("HostPort").GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out int port)) { throw Invalid(); }
            var resource = new CustomerDefinitionRun(run, c.GetProperty("Id").GetString() ?? throw Invalid(), (c.GetProperty("Name").GetString() ?? throw Invalid()).TrimStart('/'),
                d.GetProperty("volume").GetString() ?? throw Invalid(), port, Phase("attempt"), Phase("proof-container"), Phase("proof-volume-metadata"), Phase("disposed"),
                Phase("proof-absence"), Phase("proof-previous-volumes"), Phase("proof-volume-consumers"), Phase("creation-attempt"), Phase("proof-previous-container-names"));
            cases.Add(new CustomerGuardedBootstrapCase(id, Required(result, "testName"), Required(result, "testId"), Required(result, "executionId"), run,
                Phase("source-schema"), Phase("scope"), Phase("review"), Phase("authorization"), Phase("public-keys"), Phase("signing-pins"), Phase("fleet-before"), Phase("fleet-after"),
                Phase("customer-before"), Phase("customer-after"), phase == "native-component" ? Phase("customer-candidate") : null, phase == "native-component" ? Phase("fleet-candidate") : null,
                Phase("scenario"), Phase("installed-policy"), Phase("hba-file"), Phase("hba-rules"), Phase("case-entered"), Phase("guarded-invocation-exited"), resource, Phase("proof-image"),
                Phase("host-entry"), testAssembly, Path.GetFullPath(executedTestAssemblyPath), phase == "native-component" ? Phase("proxy") : null,
                phase == "native-component" ? Phase("proxy-disposed") : null, id == "commit-ack-lost" ? Phase("commit-ack-observed-drop") : null));
            CustomerDefinitionArtifact Phase(string name)
            {
                return Artifact(prefix + "-" + name + ".json");
            }
        }
        var unsigned = new Production181GuardedBootstrapProof(phase == "native-component" ? "current-production181-customer-native-bootstrap-precursor-v1" : "current-production181-customer-maintenance-bootstrap-precursor-v1",
            intended, definition, definitionPaths, trxArtifact, hostExit, cases, began, completed, expires, definitionKeyId, definitionFingerprint, keyId, null);
        Production181CustomerGuardedReader.RequireBody(files, unsigned, intended, definitionTrust, definitionKeyId, definitionFingerprint, now); return unsigned;
        CustomerDefinitionArtifact Artifact(string path)
        { byte[] bytes = files.Read(path, sharedReader: true, maximumBytes: 8_000_000); return new(path, CurrentCustomerSequenceRepairPermit.Hash(bytes)); }
        byte[] Read(CustomerDefinitionArtifact artifact)
        {
            byte[] bytes = files.Read(artifact.Path, sharedReader: true, maximumBytes: 8_000_000); return CurrentCustomerSequenceRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes;
        }
    }
    internal static Production181GuardedBootstrapProof SignAfterActualReadback(CurrentAppOwnedRepairCustody files, Production181GuardedBootstrapProof unsigned,
        CustomerDefinitionSubject intended, P256MigrationEvidenceSigner signer, IReceiptAttestationTrustStore trust, string fingerprint, DateTimeOffset now)
    {
        if (unsigned.Signature is not null || unsigned.KeyId != signer.KeyId) { throw Invalid(); }
        Production181CustomerGuardedReader.RequireBody(files, unsigned, intended, trust, unsigned.DefinitionKeyId, unsigned.DefinitionFingerprint, now);
        var signed = unsigned with { Signature = Convert.ToBase64String(signer.Sign(Production181CustomerGuardedReader.Payload(unsigned))) };
        Production181CustomerGuardedReader.Require(files, signed, intended, trust, signer.KeyId, fingerprint, now); return signed;
    }
    private static string Required(XElement element, string name)
    {
        return (string?)element.Attribute(name) ?? throw Invalid();
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_guarded_bootstrap_proof_invalid", "Actual completed native artifacts required before assembly/signing.");
    }
}
