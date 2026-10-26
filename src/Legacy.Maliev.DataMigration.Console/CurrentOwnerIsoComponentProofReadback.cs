using System.Security.Cryptography;
using System.Text.Json;
using System.Xml;
using System.Xml.Linq;

namespace Legacy.Maliev.DataMigration.Console;

internal static class IsoComponentProofReader
{
    internal static byte[] Payload(IsoComponentProof proof)
    {
        return [.. "Legacy.Maliev.OwnerIso.CompletedComponent.v1\0"u8, .. JsonSerializer.SerializeToUtf8Bytes(proof with { Signature = null })];
    }

    internal static async Task RequireAsync(CurrentAppOwnedRepairCustody files, IsoComponentProof proof, IsoDefinitionSubject intended,
        IReceiptAttestationTrustStore trust, string keyId, string fingerprint, string definitionKeyId, string definitionFingerprint, DateTimeOffset now, CancellationToken ct)
    {
        if (proof.KeyId != keyId || string.IsNullOrWhiteSpace(proof.Signature) || !trust.TryGetPublicKeyFingerprintSha256(keyId, out string actual) || actual != fingerprint) { throw Invalid(); }
        try { if (!trust.Verify(keyId, Payload(proof), Convert.FromBase64String(proof.Signature))) { throw Invalid(); } }
        catch (FormatException) { throw Invalid(); }
        await RequireBodyAsync(files, proof, intended, trust, definitionKeyId, definitionFingerprint, now, ct);
    }
    internal static async Task RequireBodyAsync(CurrentAppOwnedRepairCustody files, IsoComponentProof proof, IsoDefinitionSubject intended, IReceiptAttestationTrustStore definitionTrust, string definitionKeyId, string definitionFingerprint, DateTimeOffset now, CancellationToken ct)
    {
        files.Require(); string[] required = IsoComponentCases.Required(proof.Phase);
        if (proof.Kind != (proof.Phase == IsoComponentProofPhase.Native ? "current-owner-iso-completed-native-component-v1" : "current-owner-iso-completed-maintenance-component-v1") ||
            JsonSerializer.Serialize(proof.Subject) != JsonSerializer.Serialize(intended) || proof.BeganAtUtc.Offset != TimeSpan.Zero || proof.CompletedAtUtc.Offset != TimeSpan.Zero || proof.ExpiresAtUtc.Offset != TimeSpan.Zero ||
            proof.BeganAtUtc > proof.CompletedAtUtc || proof.CompletedAtUtc > now || proof.ExpiresAtUtc <= now || proof.ExpiresAtUtc - proof.CompletedAtUtc > TimeSpan.FromHours(4) ||
            proof.Cases.Count != required.Length || !proof.Cases.Select(x => x.CaseId).Order(StringComparer.Ordinal).SequenceEqual(required.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            proof.Cases.Select(x => x.RunId).Distinct().Count() != required.Length || proof.TestAssembly.Sha256 != intended.TestAssemblySha256) { throw Invalid(); }
        Digest(proof.TestAssembly); Digest(proof.Definition);
        var definitionBinding = Read<LocalExecutionBinding>(proof.DefinitionBinding);
        var publicTrust = new ReceiptAttestationTrustStore([new(definitionKeyId, Bytes(proof.DefinitionPublicKey))]);
        if (!publicTrust.TryGetPublicKeyFingerprintSha256(definitionKeyId, out string actualDefinitionFingerprint) || actualDefinitionFingerprint != definitionFingerprint ||
            !definitionTrust.TryGetPublicKeyFingerprintSha256(definitionKeyId, out string expectedDefinitionFingerprint) || expectedDefinitionFingerprint != definitionFingerprint) { throw Invalid(); }
        if (StringComparer.OrdinalIgnoreCase.Equals(definitionBinding.ArtifactRootCanonicalPath, Path.GetDirectoryName(proof.Host.Exit.Path))) { throw Invalid(); }
        using (var definitionAuthority = WindowsLocalRunAuthority.AcquireResume(definitionBinding.ArtifactRootCanonicalPath, definitionBinding))
        using (var definitionFiles = new CurrentAppOwnedRepairCustody(definitionAuthority))
        {
            byte[] sourceProof = definitionFiles.Read(proof.Definition.SourcePath ?? proof.Definition.Path, maximumBytes: 8_000_000, sharedReader: true);
            if (CurrentAppOwnedRepairPermit.Hash(sourceProof) != proof.Definition.Sha256) { throw Invalid(); }
            IsoDefinitionPrecursor.Require(definitionFiles, MigrationConsole.DecodeOwnerIso<IsoDefinitionProof>(sourceProof), intended, publicTrust, definitionKeyId, definitionFingerprint, now);
        }
        var host = Read<OwnerIsoGuardedBootstrapHostExit>(proof.Host.Exit);
        if (host.Kind != "current-owner-iso-actual-testhost-exit-v1" || host.ExitCode != 0 || !host.ProcessExitObserved || !host.NativeMembershipObserved || !host.EmptyJobObservedAfterExit ||
            host.JobNonce != proof.Host.Nonce || host.TestAssemblySha256 != intended.TestAssemblySha256 || host.ProcessId <= 0 || host.ExitedAtUtc > proof.CompletedAtUtc ||
            !host.RunIds.Order().SequenceEqual(proof.Cases.Select(x => x.RunId).Order()) || !Guid.TryParseExact(host.JobNonce, "N", out _)) { throw Invalid(); }
        using var cleanup = JsonDocument.Parse(Bytes(proof.Host.Cleanup)); var clean = cleanup.RootElement;
        DateTimeOffset cleaned = clean.GetProperty("completedAtUtc").GetDateTimeOffset();
        if (clean.GetProperty("nonce").GetString() != host.JobNonce || !clean.GetProperty("allMemberExitObserved").GetBoolean() || !clean.GetProperty("waitingChildExited").GetBoolean() ||
            !clean.GetProperty("streamsSettled").GetBoolean() || clean.GetProperty("cleanupFailure").GetBoolean() || cleaned < host.ExitedAtUtc || cleaned > proof.CompletedAtUtc) { throw Invalid(); }
        using var hostAbsence = JsonDocument.Parse(Bytes(proof.Host.PostExitAbsence)); var absent = hostAbsence.RootElement;
        DateTimeOffset absenceAt = absent.GetProperty("observedAtUtc").GetDateTimeOffset();
        if (absent.GetProperty("nonce").GetString() != host.JobNonce || !absent.GetProperty("containerInventorySucceeded").GetBoolean() || !absent.GetProperty("volumeInventorySucceeded").GetBoolean() ||
            !absent.GetProperty("listenerInventorySucceeded").GetBoolean() || absenceAt < host.ExitedAtUtc || absenceAt > cleaned) { throw Invalid(); }
        if (proof.Host.JobFrames.Count == 0) { throw Invalid(); }
        bool actualHostMember = false;
        foreach (var frame in proof.Host.JobFrames)
        {
            using var item = JsonDocument.Parse(Bytes(frame)); var f = item.RootElement;
            if (f.GetProperty("nonce").GetString() != host.JobNonce) { throw Invalid(); }
            var capacity = f.GetProperty("Capacity"); CurrentOwnerIsoCapacity.RequireValues(capacity.GetProperty("AvailablePhysicalBytes").GetUInt64(), capacity.GetProperty("OwnedRssBytes").GetUInt64(), admission: false);
            foreach (var member in f.GetProperty("Processes").EnumerateArray())
            { if (member.GetProperty("ProcessId").GetInt32() == host.ProcessId && member.GetProperty("StartTimeUtc").GetDateTimeOffset() == host.ProcessStartTimeUtc && member.GetProperty("ExecutableSha256").GetString() == host.ExecutableSha256) { actualHostMember = true; } }
        }
        if (!actualHostMember) { throw Invalid(); }
        using var child = JsonDocument.Parse(Bytes(proof.Host.ChildConfiguration));
        var configuration = child.RootElement.GetProperty("Configuration");
        if (child.RootElement.GetProperty("Nonce").GetString() != host.JobNonce || configuration.GetProperty("TestAssemblySha256").GetString() != intended.TestAssemblySha256 ||
            configuration.GetProperty("ConsoleAssemblySha256").GetString() != intended.ConsoleAssemblySha256 || configuration.GetProperty("CoreAssemblySha256").GetString() != intended.CoreAssemblySha256 ||
            configuration.GetProperty("Group").GetString() != (proof.Phase == IsoComponentProofPhase.Native ? "native-component" : "maintenance-component")) { throw Invalid(); }
        if (!Bytes(proof.Host.RunSettings).AsSpan().SequenceEqual("<RunSettings><RunConfiguration><MaxCpuCount>1</MaxCpuCount></RunConfiguration></RunSettings>"u8)) { throw Invalid(); }
        Digest(proof.Host.Stdout); Digest(proof.Host.Stderr);
        using var xml = XmlReader.Create(new MemoryStream(Bytes(proof.Trx), false), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 8_000_000 });
        var trx = XDocument.Load(xml); XNamespace ns = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010";
        var results = trx.Descendants(ns + "UnitTestResult").ToArray();
        if (results.Length != required.Length || results.Any(x => (string?)x.Attribute("outcome") != "Passed")) { throw Invalid(); }
        foreach (var item in proof.Cases)
        {
            ct.ThrowIfCancellationRequested();
            if (item.RunId == Guid.Empty || item.TestName != IsoComponentCases.Method(item.CaseId)) { throw Invalid(); }
            var result = results.SingleOrDefault(x => (string?)x.Attribute("testId") == item.TestId && (string?)x.Attribute("executionId") == item.ExecutionId);
            if (result is null || (string?)result.Attribute("testName") != item.TestName) { throw Invalid(); }
            var definition = trx.Descendants(ns + "UnitTest").SingleOrDefault(x => (string?)x.Attribute("id") == item.TestId);
            var method = definition?.Element(ns + "TestMethod");
            if (method is null || (string?)method.Attribute("className") != "Legacy.Maliev.DataMigration.Tests.CurrentOwnerIsoGuardedNativeExecutionTests" || (string?)method.Attribute("name") != item.TestName ||
                (string?)definition?.Element(ns + "Execution")?.Attribute("id") != item.ExecutionId || !Path.IsPathFullyQualified(proof.ExecutedTestAssemblyPath)) { throw Invalid(); }
            foreach (string? path in new[] { (string?)method.Attribute("codeBase"), (string?)definition?.Attribute("storage"), proof.TestAssembly.SourcePath ?? proof.TestAssembly.Path })
            { if (!StringComparer.OrdinalIgnoreCase.Equals(path, proof.ExecutedTestAssemblyPath)) { throw Invalid(); } }
            var entry = Read<IsoActualCaseEntry>(item.Entry); var hostEntry = Read<IsoActualHostEntry>(item.HostEntry); var invocation = Read<IsoComponentInvocation>(item.Invocation);
            var scope = Read<CurrentOwnerIsoRepairScope>(item.Scope); var source = Read<FreshSchemaPlan>(item.Source); var owners = Read<CurrentOwnerIsoSourceObservation[]>(item.Owners);
            var pins = Read<CurrentOwnerIsoRepairSigningPins>(item.Pins); var keys = Read<IsoCasePublicKey[]>(item.PublicKeys);
            if (keys.Length != 4 || keys.Select(x => x.KeyId).Distinct(StringComparer.Ordinal).Count() != 4) { throw Invalid(); }
            var caseTrust = new ReceiptAttestationTrustStore(keys.Select(x => new TrustedAttestationKey(x.KeyId, Convert.FromBase64String(x.PublicKeyBase64))));
            CurrentOwnerIsoRepairPermit.ValidateComponentScope(scope, source, owners, caseTrust, pins, invocation.StartedAtUtc);
            var bootstrapSubject = scope.BootstrapSubject ?? throw Invalid();
            IsoMaintenanceNativeObserver.Require(Read<IsoMaintenanceNativeObservation>(item.NativePolicy), scope);
            if (scope.OperationId != item.RunId || bootstrapSubject.CaseId != item.CaseId || bootstrapSubject.Claim.Subject.DefinitionPrecursorSha256 != proof.Definition.Sha256 ||
                scope.SourceCommitSha != intended.SourceCommitSha || scope.BeforeSchemaPlanSha256 != intended.SourceSchemaPlanSha256 || scope.SourceCatalogSha256 != intended.SourceCatalogSha256 ||
                scope.OwnerSourcesSha256 != intended.OwnerSourcesSha256 || scope.ContractSha256 != intended.ContractSha256 || scope.TargetObservationSha256 != item.Resource.ContainerMetadata.Sha256 ||
                scope.Target.AuthorityId != "aspire://legacy-postgres-main-local/disposable-" + item.Resource.ContainerId ||
                bootstrapSubject.Claim.Subject.ConsoleAssemblySha256 != intended.ConsoleAssemblySha256 || bootstrapSubject.Claim.Subject.CoreAssemblySha256 != intended.CoreAssemblySha256 ||
                bootstrapSubject.Claim.Subject.TestAssemblySha256 != intended.TestAssemblySha256 ||
                hostEntry.RunId != item.RunId || hostEntry.CaseId != item.CaseId || hostEntry.JobNonce != host.JobNonce || !hostEntry.NativeJobMembershipObserved ||
                hostEntry.ProcessId != host.ProcessId || hostEntry.ProcessStartTimeUtc != host.ProcessStartTimeUtc || hostEntry.ExecutableSha256 != host.ExecutableSha256 || hostEntry.TestAssemblySha256 != intended.TestAssemblySha256 ||
                entry.RunId != item.RunId || entry.CaseId != item.CaseId || entry.ProcessId != host.ProcessId || entry.ProcessStartTimeUtc != host.ProcessStartTimeUtc ||
                entry.ExecutableSha256 != host.ExecutableSha256 || entry.TestAssemblySha256 != intended.TestAssemblySha256 ||
                !StringComparer.OrdinalIgnoreCase.Equals(entry.TestAssemblyPath, proof.ExecutedTestAssemblyPath) || hostEntry.ObservedAtUtc > entry.BeganAtUtc ||
                invocation.StartedAtUtc < entry.BeganAtUtc || invocation.ExitedAtUtc < invocation.StartedAtUtc || invocation.ExitedAtUtc > host.ExitedAtUtc) { throw Invalid(); }
            var binding = Read<LocalExecutionBinding>(item.Binding);
            if (binding.ComputeSha256() != scope.RunBindingSha256) { throw Invalid(); }
            var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, scope.SourceCommitSha, scope.Operation, owners, invocation.StartedAtUtc);
            var before = await Fleet(item.FleetBefore); var after = await Fleet(item.FleetAfter);
            if (before.Length != 26 || !before.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(scope.BeforeDatabaseSha256.Keys.Order(StringComparer.Ordinal)) ||
                before.Any(x => x.Sha256 != scope.BeforeDatabaseSha256[x.Database]) || CurrentAppOwnedSnapshotSerialization.Sha256(before) != scope.GlobalPreservationSha256 ||
                after.Length != 26 || !after.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal))) { throw Invalid(); }
            var countryBefore = Read<IsoCapturedNative>(item.CountryBefore).Observe(); var materialBefore = Read<IsoCapturedNative>(item.MaterialBefore).Observe();
            var countryAfter = Read<IsoCapturedNative>(item.CountryAfter).Observe(); var materialAfter = Read<IsoCapturedNative>(item.MaterialAfter).Observe();
            CurrentOwnerIsoNativePreservation.RequireBefore(countryBefore, contract); CurrentOwnerIsoNativePreservation.RequireBefore(materialBefore, contract);
            if (countryBefore.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Country"] || materialBefore.Snapshot.Sha256 != scope.BeforeDatabaseSha256["Material"] ||
                countryAfter.Snapshot.Sha256 != after.Single(x => x.Database == "Country").Sha256 || materialAfter.Snapshot.Sha256 != after.Single(x => x.Database == "Material").Sha256) { throw Invalid(); }
            using var installedPolicy = JsonDocument.Parse(Bytes(item.InstalledPolicy));
            var policyPin = MigrationConsole.DecodeOwnerIso<CurrentAppOwnedMaintenancePin>(System.Text.Encoding.UTF8.GetBytes(installedPolicy.RootElement.GetProperty("Pin").GetRawText()));
            if (installedPolicy.RootElement.GetProperty("Identity").GetString() != scope.Target.SystemIdentifierSha256) { throw Invalid(); }
            string rawHba = installedPolicy.RootElement.GetProperty("rawHba").GetString() ?? throw Invalid();
            string rawRules = installedPolicy.RootElement.GetProperty("rawRules").GetString() ?? throw Invalid();
            if (CurrentAppOwnedSnapshotSerialization.Sha256(policyPin) != CurrentAppOwnedSnapshotSerialization.Sha256(scope.Maintenance) ||
                CurrentAppOwnedRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(rawHba)) != scope.Maintenance.HbaSha256 ||
                CurrentAppOwnedRepairPermit.Hash(System.Text.Encoding.UTF8.GetBytes(rawRules)) != scope.Maintenance.HbaRulesSha256) { throw Invalid(); }
            var rules = ParseRules(rawRules);
            if (item.CaseId is "unsafe-host" or "local-trust")
            {
                bool rejectedPolicy = false;
                try { CurrentAppOwnedMaintenanceHba.Require(rules, scope.Maintenance.Role, scope.Target.Kind); }
                catch (MigrationExecutionException error) when (error.Code == "current_app_owned_maintenance_hba_not_exclusive") { rejectedPolicy = true; }
                if (!rejectedPolicy) { throw Invalid(); }
            }
            else { CurrentAppOwnedMaintenanceHba.Require(rules, scope.Maintenance.Role, scope.Target.Kind); }
            bool rejected = item.CaseId is "wrong-owner" or "unsafe-host" or "local-trust";
            bool expectedFailure = rejected || (item.CaseId is "prepared-publication" or "lost-commit-ack" or "terminal-publication" or "fleet-drift");
            if (invocation.Returned == expectedFailure || (expectedFailure && string.IsNullOrWhiteSpace(invocation.ExceptionType))) { throw Invalid(); }
            bool executed = item.CaseId is "complete" or "prepared-publication" or "lost-commit-ack" or "terminal-publication" or "fleet-drift";
            if (rejected)
            {
                if (item.Review is not null || item.Authorization is not null || item.Reservation is not null || item.Slots.Count != 0 || invocation.Reservations != 0 || invocation.Returned ||
                    invocation.RejectionCode != (item.CaseId == "wrong-owner" ? "current_owner_iso_admission_invalid" : "current_app_owned_maintenance_hba_not_exclusive")) { throw Invalid(); }
            }
            else
            {
                var review = Read<CurrentOwnerIsoRepairSignedClaim>(item.Review ?? throw Invalid());
                CurrentOwnerIsoRepairPermit.ValidateReview(review, source, owners, caseTrust, pins, invocation.StartedAtUtc);
                if (CurrentAppOwnedSnapshotSerialization.Sha256(review.Scope) != CurrentAppOwnedSnapshotSerialization.Sha256(scope)) { throw Invalid(); }
                if (executed)
                {
                    var authorization = Read<CurrentOwnerIsoRepairSignedClaim>(item.Authorization ?? throw Invalid());
                    CurrentOwnerIsoRepairPermit.ValidateClaims(review, authorization, source, owners, caseTrust, pins, invocation.StartedAtUtc);
                    if (CurrentAppOwnedSnapshotSerialization.Sha256(authorization.Scope) != CurrentAppOwnedSnapshotSerialization.Sha256(scope) || invocation.Reservations != 1 || item.Reservation is null || item.Replay is null) { throw Invalid(); }
                    using var reservation = JsonDocument.Parse(Bytes(item.Reservation));
                    if (reservation.RootElement.GetProperty("kind").GetString() != "current-owner-iso-component-operation-start-v1" || reservation.RootElement.GetProperty("OperationId").GetGuid() != item.RunId ||
                        reservation.RootElement.GetProperty("authorizationSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(authorization) || reservation.RootElement.GetProperty("scopeSha256").GetString() != CurrentAppOwnedSnapshotSerialization.Sha256(scope)) { throw Invalid(); }
                    RequireSlots(item, scope, authorization, caseTrust, pins, countryBefore, countryAfter, materialBefore, materialAfter, contract);
                }
                else if (item.Authorization is not null || item.Reservation is not null || item.Slots.Count != 0 || item.CountryCandidate is not null || item.MaterialCandidate is not null || invocation.Reservations != 0 || !invocation.Returned) { throw Invalid(); }
            }
            bool countrySelected = item.CaseId is "complete" or "lost-commit-ack" or "terminal-publication" or "fleet-drift";
            bool materialSelected = item.CaseId == "complete";
            RequirePhase(countryBefore, countryAfter, item.CountryCandidate, countrySelected, contract);
            RequirePhase(materialBefore, materialAfter, item.MaterialCandidate, materialSelected, contract);
            int expectedCandidates = item.CaseId == "complete" ? 2 : executed ? 1 : 0;
            if (item.CandidateFleets.Count != expectedCandidates) { throw Invalid(); }
            for (int phase = 0; phase < item.CandidateFleets.Count; phase++)
            {
                var candidateFleet = await Fleet(item.CandidateFleets[phase]); string selected = phase == 0 ? "Country" : "Material";
                if (candidateFleet.Length != 26 || !candidateFleet.Select(x => x.Database).Order(StringComparer.Ordinal).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal))) { throw Invalid(); }
                foreach (var actual in candidateFleet)
                {
                    string expected = actual.Database == selected ? Read<IsoCapturedNative>((selected == "Country" ? item.CountryCandidate : item.MaterialCandidate) ?? throw Invalid()).Snapshot.Sha256 :
                        phase == 1 && actual.Database == "Country" ? countryAfter.Snapshot.Sha256 : before.Single(x => x.Database == actual.Database).Sha256;
                    if (actual.Sha256 != expected) { throw Invalid(); }
                }
            }
            foreach (var actual in after.Where(x => x.Database is not ("Country" or "Material")))
            {
                var original = before.Single(x => x.Database == actual.Database);
                if (item.CaseId == "fleet-drift" && actual.Database == "Upload")
                {
                    if (item.Fault is null || !original.Catalog.SequenceEqual(actual.Catalog) || !original.Sequences.SequenceEqual(actual.Sequences) || original.Relations.Count != actual.Relations.Count) { throw Invalid(); }
                    foreach (var relation in original.Relations)
                    {
                        var observed = actual.Relations.Single(x => x.Schema == relation.Schema && x.Name == relation.Name);
                        if (relation.Schema == "iso_proof_private" && relation.Name == "journal") { if (observed.Rows != relation.Rows || observed.RowSha256 == relation.RowSha256) { throw Invalid(); } }
                        else if (observed != relation) { throw Invalid(); }
                    }
                    using var fault = JsonDocument.Parse(Bytes(item.Fault)); if (fault.RootElement.GetProperty("database").GetString() != "Upload" || fault.RootElement.GetProperty("schema").GetString() != "iso_proof_private" || fault.RootElement.GetProperty("table").GetString() != "journal" || fault.RootElement.GetProperty("key").GetInt32() != 1) { throw Invalid(); }
                }
                else if (actual.Sha256 != original.Sha256) { throw Invalid(); }
            }
            if (!rejected)
            {
                if (item.OrdinaryProbes.Count == 0) { throw Invalid(); }
                foreach (var probe in item.OrdinaryProbes) { using var json = JsonDocument.Parse(Bytes(probe)); if (!json.RootElement.GetProperty("databases").EnumerateArray().Select(x => x.GetString()).SequenceEqual(before.Select(x => x.Database).Order(StringComparer.Ordinal))) { throw Invalid(); } }
            }
            RequireResource(item, invocation, proof, absent);
        }
        files.Require();

        void RequirePhase(CurrentOwnerIsoNativeObservation original, CurrentOwnerIsoNativeObservation after, IsoDefinitionArtifact? candidate, bool selected, ApprovedCurrentOwnerIsoOverlay contract)
        {
            if (candidate is not null) { CurrentOwnerIsoNativePreservation.RequirePreserved(original, Read<IsoCapturedNative>(candidate).Observe(), contract); }
            if (selected) { CurrentOwnerIsoNativePreservation.RequirePreserved(original, after, contract); IsoDefinitionPrecursor.RequireCommittedReadback(Read<IsoCapturedNative>(candidate ?? throw Invalid()).Observe(), after); }
            else if (after.Selected || after.Snapshot.Sha256 != original.Snapshot.Sha256) { throw Invalid(); }
        }
        void RequireSlots(IsoComponentCase item, CurrentOwnerIsoRepairScope scope, CurrentOwnerIsoRepairSignedClaim authorization, IReceiptAttestationTrustStore trust,
            CurrentOwnerIsoRepairSigningPins pins, CurrentOwnerIsoNativeObservation cb, CurrentOwnerIsoNativeObservation ca, CurrentOwnerIsoNativeObservation mb, CurrentOwnerIsoNativeObservation ma, ApprovedCurrentOwnerIsoOverlay contract)
        {
            if (item.Slots.Select(x => x.RetainedFile.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != item.Slots.Count || item.Slots.Select(x => x.AckObservation.Path).Distinct(StringComparer.OrdinalIgnoreCase).Count() != item.Slots.Count) { throw Invalid(); }
            string previous = new('0', 64); DateTimeOffset last = scope.Maintenance.IssuedAtUtc, lastObserved = last, lastPublished = last; var receipts = new List<(CurrentOwnerIsoRepairReceipt Receipt, bool Ack)>();
            foreach (var slot in item.Slots)
            {
                byte[] payload = Bytes(slot.RetainedFile); var ack = Read<IsoActualReceiptSlot>(slot.AckObservation);
                var receipt = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(payload);
                if (!Convert.FromBase64String(ack.PayloadBase64).AsSpan().SequenceEqual(payload) || Path.GetFileName(slot.RetainedFile.SourcePath ?? slot.RetainedFile.Path) != ack.Name ||
                    receipt.PreviousReceiptSha256 != previous || receipt.ObservedAtUtc < lastObserved || ack.ObservedAtUtc < lastPublished || receipt.ObservedAtUtc > scope.Maintenance.ExpiresAtUtc || ack.ObservedAtUtc < receipt.ObservedAtUtc) { throw Invalid(); }
                PostgreSqlCurrentOwnerIsoRepair.RequireReceipt(receipt, scope, CurrentAppOwnedSnapshotSerialization.Sha256(authorization), trust, pins);
                if (receipt.AfterSha256 is not null && receipt.AfterSha256 != Read<IsoCapturedNative>((receipt.Database == "Country" ? item.CountryCandidate : item.MaterialCandidate) ?? throw Invalid()).Snapshot.Sha256) { throw Invalid(); }
                lastObserved = receipt.ObservedAtUtc; lastPublished = ack.ObservedAtUtc;
                receipts.Add((receipt, ack.Acknowledged)); if (ack.Acknowledged) { previous = CurrentAppOwnedSnapshotSerialization.Sha256(receipt); last = receipt.ObservedAtUtc; }
            }
            RequireScenarioSlots(item.CaseId, receipts.Select(x => (x.Receipt.Database, x.Receipt.Classification, x.Ack)).ToArray());
            using var replay = JsonDocument.Parse(Bytes(item.Replay ?? throw Invalid())); if (replay.RootElement.GetProperty("reservations").GetInt32() != 1 || replay.RootElement.GetProperty("unchangedSlots").GetInt32() != receipts.Count + 1) { throw Invalid(); }
        }
        void RequireResource(IsoComponentCase item, IsoComponentInvocation invocation, IsoComponentProof proof, JsonElement hostAbsence)
        {
            var resource = item.Resource; using var attempt = JsonDocument.Parse(Bytes(resource.Attempt)); using var metadata = JsonDocument.Parse(Bytes(resource.ContainerMetadata)); using var disposed = JsonDocument.Parse(Bytes(resource.Disposed));
            var absence = Read<IsoDefinitionAbsence>(resource.Absence); var a = attempt.RootElement; var m = metadata.RootElement; var d = disposed.RootElement;
            DateTimeOffset began = a.GetProperty("began").GetDateTimeOffset(), expires = a.GetProperty("expires").GetDateTimeOffset(), removed = d.GetProperty("removedAtUtc").GetDateTimeOffset(), completed = d.GetProperty("completedAtUtc").GetDateTimeOffset();
            DateTimeOffset created = m.GetProperty("Created").GetDateTimeOffset();
            if (created < began.AddSeconds(-1) || created > expires || resource.ContainerId.Length != 64 || !resource.ContainerId.All(char.IsAsciiHexDigitLower)) { throw Invalid(); }
            var config = m.GetProperty("Config"); var labels = config.GetProperty("Labels"); var hostConfig = m.GetProperty("HostConfig"); var ports = m.GetProperty("NetworkSettings").GetProperty("Ports");
            if (resource.RunId != item.RunId || resource.ContainerId != m.GetProperty("Id").GetString() || resource.Name != "iso-component-" + item.RunId.ToString("N") || m.GetProperty("Name").GetString() != "/" + resource.Name ||
                config.GetProperty("Image").GetString() != CurrentOwnerIsoBootstrapSubjectValidator.Image || config.GetProperty("PgData").GetString() != "/var/lib/postgresql/18/docker" ||
                labels.GetProperty("codex.repair.purpose").GetString() != "current-owner-iso-guarded-component" || labels.GetProperty("codex.repair.run").GetString() != item.RunId.ToString("D") || labels.GetProperty("codex.repair.operation").GetString() != item.RunId.ToString("D") ||
                m.GetProperty("Mounts").GetArrayLength() != 0 || !m.GetProperty("State").GetProperty("Running").GetBoolean() || hostConfig.GetProperty("Memory").GetInt64() != 512L * 1024 * 1024 || hostConfig.GetProperty("MemorySwap").GetInt64() != 512L * 1024 * 1024 || hostConfig.GetProperty("NanoCpus").GetInt64() != 750000000 ||
                !Empty(hostConfig, "Binds") || !Empty(hostConfig, "Mounts") || !Empty(hostConfig, "VolumesFrom") || hostConfig.GetProperty("Tmpfs").EnumerateObject().Count() != 1 || hostConfig.GetProperty("Tmpfs").GetProperty("/var/lib/postgresql").GetString() != "rw,nosuid,size=384m" ||
                ports.EnumerateObject().Count() != 1 || ports.GetProperty("5432/tcp").GetArrayLength() != 1 || ports.GetProperty("5432/tcp")[0].GetProperty("HostIp").GetString() != "127.0.0.1" || ports.GetProperty("5432/tcp")[0].GetProperty("HostPort").GetString() != resource.Port.ToString(System.Globalization.CultureInfo.InvariantCulture) ||
                a.GetProperty("run").GetGuid() != item.RunId || a.GetProperty("name").GetString() != resource.Name || a.GetProperty("persistent").GetBoolean() || expires - began != TimeSpan.FromMinutes(8) || began < proof.BeganAtUtc || invocation.ExitedAtUtc > expires ||
                !d.GetProperty("removed").GetBoolean() || !d.GetProperty("disposed").GetBoolean() || d.GetProperty("cleanupFailed").GetBoolean() || removed < invocation.ExitedAtUtc || absence.ObservedAtUtc < removed || completed < absence.ObservedAtUtc || completed > proof.CompletedAtUtc ||
                absence.RunId != item.RunId || !absence.ContainerInventorySucceeded || !absence.VolumeInventorySucceeded || !absence.ListenerInventorySucceeded || absence.ContainerIds.Contains(resource.ContainerId, StringComparer.Ordinal) || absence.ContainerNames.Any(x => x == resource.Name || x == "/" + resource.Name) || absence.ListeningPorts.Contains(resource.Port) ||
                hostAbsence.GetProperty("containerIds").EnumerateArray().Any(x => x.GetString() == resource.ContainerId) || hostAbsence.GetProperty("containerNames").EnumerateArray().Any(x => x.GetString() == resource.Name || x.GetString() == "/" + resource.Name) || hostAbsence.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == resource.Port)) { throw Invalid(); }
            using var capacity = JsonDocument.Parse(Bytes(resource.Capacity)); if (capacity.RootElement.GetProperty("run").GetGuid() != item.RunId || capacity.RootElement.GetProperty("containerId").GetString() != resource.ContainerId || capacity.RootElement.GetProperty("capacityBytes").GetInt64() != 384L * 1024 * 1024) { throw Invalid(); }
            if (item.CaseId == "lost-commit-ack")
            {
                using var observed = JsonDocument.Parse(Bytes(item.ProxyObserved ?? throw Invalid())); using var dropped = JsonDocument.Parse(Bytes(item.ProxyDropped ?? throw Invalid())); using var finished = JsonDocument.Parse(Bytes(item.ProxyDisposed ?? throw Invalid()));
                int port = observed.RootElement.GetProperty("port").GetInt32(); if (observed.RootElement.GetProperty("RunId").GetGuid() != item.RunId || dropped.RootElement.GetProperty("actualTag").GetString() != "COMMIT\0" || dropped.RootElement.GetProperty("port").GetInt32() != port ||
                    !finished.RootElement.GetProperty("workerExited").GetBoolean() || !finished.RootElement.GetProperty("listenerAbsent").GetBoolean() || finished.RootElement.GetProperty("cleanupFailed").GetBoolean() || finished.RootElement.GetProperty("droppedCommits").GetInt32() != 1 || hostAbsence.GetProperty("listeningPorts").EnumerateArray().Any(x => x.GetInt32() == port)) { throw Invalid(); }
            }
            else if (item.ProxyObserved is not null || item.ProxyDropped is not null || item.ProxyDisposed is not null) { throw Invalid(); }
        }
        async Task<CurrentAppOwnedDatabaseSnapshot[]> Fleet(IsoDefinitionArtifact artifact)
        { Digest(artifact); return await files.ReadBaselineAsync(artifact.Path, ct); }
        T Read<T>(IsoDefinitionArtifact artifact)
        {
            return MigrationConsole.DecodeOwnerIso<T>(Bytes(artifact));
        }

        byte[] Bytes(IsoDefinitionArtifact artifact) { byte[] bytes = files.Read(artifact.Path, maximumBytes: 8_000_000, sharedReader: true); return CurrentAppOwnedRepairPermit.Hash(bytes) != artifact.Sha256 ? throw Invalid() : bytes; }
        void Digest(IsoDefinitionArtifact artifact) { files.Require(); using var held = SecureLocalFile.OpenReadShared(artifact.Path); if (held.Length is < 1 or > 512L * 1024 * 1024 || Convert.ToHexStringLower(SHA256.HashData(held)) != artifact.Sha256) { throw Invalid(); } files.Require(); }
    }
    internal static void RequireScenarioSlots(string id, IReadOnlyList<(string Db, CurrentAppOwnedCommitClassification Class, bool Ack)> actual)
    {
        (string Db, CurrentAppOwnedCommitClassification Class, bool Ack)[] expected = id switch
        {
            "complete" => [("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, true), ("Material", CurrentAppOwnedCommitClassification.Prepared, true), ("Material", CurrentAppOwnedCommitClassification.CommittedAndReadback, true)],
            "prepared-publication" => [("Country", CurrentAppOwnedCommitClassification.Prepared, false), ("Country", CurrentAppOwnedCommitClassification.RolledBackBeforeCommit, true)],
            "lost-commit-ack" => [("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.Uncertain, true)],
            "terminal-publication" => [("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, false), ("Country", CurrentAppOwnedCommitClassification.Uncertain, true)],
            "fleet-drift" => [("Country", CurrentAppOwnedCommitClassification.Prepared, true), ("Country", CurrentAppOwnedCommitClassification.CommittedAndReadback, true), ("Country", CurrentAppOwnedCommitClassification.Uncertain, true)],
            _ => throw Invalid()
        };
        if (!actual.SequenceEqual(expected)) { throw Invalid(); }
    }
    private static CurrentAppOwnedMaintenanceHbaRule[] ParseRules(string raw)
    {
        using var document = JsonDocument.Parse(raw);
        return document.RootElement.ValueKind != JsonValueKind.Array
            ? throw Invalid()
            : document.RootElement.EnumerateArray().Select(x => new CurrentAppOwnedMaintenanceHbaRule(
            x.GetProperty("rule_number").GetInt32(), x.GetProperty("type").GetString() ?? string.Empty,
            Strings(x.GetProperty("database")), Strings(x.GetProperty("user_name")), Nullable(x.GetProperty("address")), Nullable(x.GetProperty("netmask")),
            x.GetProperty("auth_method").GetString() ?? string.Empty, Strings(x.GetProperty("options")), Nullable(x.GetProperty("error")))).ToArray();

        static string? Nullable(JsonElement value)
        {
            return value.ValueKind == JsonValueKind.Null ? null : value.GetString();
        }

        static string[] Strings(JsonElement value)
        {
            return value.ValueKind == JsonValueKind.Null ? [] : value.EnumerateArray().Select(x => x.GetString() ?? throw Invalid()).ToArray();
        }
    }
    private static bool Empty(JsonElement value, string name)
    {
        return !value.TryGetProperty(name, out var field) || field.ValueKind == JsonValueKind.Null || field.GetArrayLength() == 0;
    }

    private static MigrationExecutionException Invalid()
    {
        return IsoComponentCases.Invalid();
    }
}
