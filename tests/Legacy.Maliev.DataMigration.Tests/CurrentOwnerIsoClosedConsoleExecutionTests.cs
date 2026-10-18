using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;
using Xunit.Abstractions;
using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentOwnerIsoNativeProofGroup.Name)]
public sealed class CurrentOwnerIsoClosedConsoleExecutionTests(ITestOutputHelper output)
{
    [WindowsLocalRunFact]
    public Task Complete_26_database_fleet_is_preserved_after_Country_and_Material_commit()
    {
        return RunAsync("complete");
    }

    [WindowsLocalRunFact]
    public Task Prepared_receipt_publication_failure_rolls_back_without_commit()
    {
        return RunAsync("prepared-publication");
    }

    [WindowsLocalRunFact]
    public Task Dropped_commit_ack_stops_without_Material_apply()
    {
        return RunAsync("lost-commit-ack");
    }

    [WindowsLocalRunFact]
    public Task Terminal_publication_uncertainty_stops_without_Material_apply()
    {
        return RunAsync("terminal-publication");
    }

    [WindowsLocalRunFact]
    public Task Wrong_owner_rejected_before_DDL()
    {
        return RunAsync("wrong-owner");
    }

    [WindowsLocalRunFact]
    public Task Full_fleet_drift_after_Country_stops_Material()
    {
        return RunAsync("fleet-drift");
    }

    [WindowsLocalRunFact]
    public Task Unsafe_unprobed_host_rule_rejected()
    {
        return RunAsync("unsafe-host");
    }

    [WindowsLocalRunFact]
    public Task Local_trust_rejected()
    {
        return RunAsync("local-trust");
    }

    [WindowsLocalRunFact]
    public Task Ordinary_client_rejected_in_all_26_databases()
    {
        return RunAsync("ordinary-all26");
    }

    [WindowsLocalRunFact]
    public Task Exact_installed_policy_accepts_only_maintenance_client()
    {
        return RunAsync("exclusive-policy");
    }

    private async Task RunAsync(string caseId)
    {
        string path = Environment.GetEnvironmentVariable("MALIEV_ISO_NAMED_CLOSED_INPUTS") ?? throw new InvalidOperationException("iso_named_closed_input_required");
        var input = MigrationConsole.DecodeOwnerIso<IsoNamedClosedLaneInputs>(Read(path, 65536));
        var binding = MigrationConsole.DecodeOwnerIso<LocalExecutionBinding>(Read(input.ParentRunBindingPath, 65536));
        string root = binding.ArtifactRootCanonicalPath;
        if (binding.ComputeSha256() != input.ParentRunBindingSha256 || !StringComparer.OrdinalIgnoreCase.Equals(Path.GetDirectoryName(Path.GetFullPath(path)), root) ||
            !StringComparer.OrdinalIgnoreCase.Equals(Path.GetFullPath(typeof(CurrentOwnerIsoClosedConsoleExecutionTests).Assembly.Location), Path.GetFullPath(input.TestAssemblyPath)) ||
            HashFile(input.TestAssemblyPath) != input.TestAssemblySha256 || HashFile(typeof(MigrationConsole).Assembly.Location) != input.ConsoleAssemblySha256 ||
            HashFile(typeof(CurrentOwnerIsoRepairPermit).Assembly.Location) != input.CoreAssemblySha256) { throw Invalid(); }
        FreshSchemaPlan source; CurrentOwnerIsoSourceObservation[] owners;
        using (var authority = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            if (!files.Read(path, sharedReader: true, maximumBytes: 65536).AsSpan().SequenceEqual(Read(path, 65536))) { throw Invalid(); }
            source = MigrationConsole.DecodeOwnerIso<FreshSchemaPlan>(files.Read(input.SourcePath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            owners = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoSourceObservation[]>(files.Read(input.OwnersPath, sharedReader: true, maximumBytes: 8_000_000));
        }
        await using var fixture = await CurrentOwnerIsoNamedClosedFixture.CreateAsync(binding, caseId, CancellationToken.None).ConfigureAwait(false);
        // The named job is observed before schema/role setup. A naked testhost cannot satisfy this fixture.
        string nonce = Environment.GetEnvironmentVariable("MALIEV_ISO_COMPONENT_JOB_NONCE") ?? throw Invalid();
        using (var process = System.Diagnostics.Process.GetCurrentProcess())
        {
            string executable = process.MainModule?.FileName ?? throw Invalid();
            OwnerIsoGuardedBootstrapHostObservation.RequireCurrentMembership(nonce);
            await fixture.RecordAsync("host-entry", new
            {
                fixture.Operation,
                caseId,
                processId = process.Id,
                startTimeUtc = new DateTimeOffset(process.StartTime.ToUniversalTime()),
                executable,
                executableSha256 = HashFile(executable),
                input.TestAssemblyPath,
                input.TestAssemblySha256,
                jobNonce = nonce,
                jobMembershipObservedAtUtc = DateTimeOffset.UtcNow
            }, fixture.Token).ConfigureAwait(false);
        }
        CurrentOwnerIsoRepairSourceInputs copied; string helper;
        using (var parent = WindowsLocalRunAuthority.AcquireResume(root, binding))
        using (var parentFiles = new CurrentAppOwnedRepairCustody(parent))
        using (var actual = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(actual))
        {
            async Task<string> Copy(string from, string name, int maximum = 8_000_000)
            { string to = Path.Combine(fixture.Root, name); await files.WriteNewAsync(to, parentFiles.Read(from, sharedReader: true, maximumBytes: maximum), fixture.Token).ConfigureAwait(false); return to; }
            string report = await Copy(input.SourceInputs.AcceptedCatalogReportPath, "iso-closed-case-" + fixture.Operation.ToString("N") + "-source-catalog.json").ConfigureAwait(false);
            string connection = await Copy(input.SourceInputs.SourceConnectionPath, "source-connection.txt", 65536).ConfigureAwait(false);
            string token = await Copy(input.SourceInputs.SourceCloudOptions.ServiceAccountTokenFile, "source-service-token.txt", 65536).ConfigureAwait(false);
            string ca = await Copy(input.SourceInputs.SourceCloudOptions.ServiceAccountCaFile, "source-service-ca.pem", 65536).ConfigureAwait(false);
            helper = await Copy(input.MaintenanceValidatorSourcePath, "iso-closed-case-" + fixture.Operation.ToString("N") + "-maintenance-validator.cs").ConfigureAwait(false);
            copied = new(report, connection, input.SourceInputs.SourceCloudOptions with { ServiceAccountTokenFile = token, ServiceAccountCaFile = ca });
        }
        IsoNamedClosedPreparation preparation = await CurrentOwnerIsoNamedClosedConfiguration.PrepareAsync(fixture, source, owners, copied, input.Precursors, input.PrecursorPins,
            input.NativeComponentSha256, input.MaintenanceComponentSha256, helper, input.TestAssemblyPath, caseId, fixture.Token).ConfigureAwait(false);
        if (caseId == "unsafe-host")
        {
            await using var probe = new NpgsqlConnection(new NpgsqlConnectionStringBuilder(fixture.AdminConnection) { Username = "iso_unprobed_sdk", Password = string.Empty, Pooling = false }.ConnectionString); await probe.OpenAsync(fixture.Token).ConfigureAwait(false);
            await using var query = new NpgsqlCommand("SELECT current_user;", probe); Assert.Equal("iso_unprobed_sdk", await query.ExecuteScalarAsync(fixture.Token).ConfigureAwait(false));
            await fixture.RecordAsync("unprobed-sdk-allowed", new { role = "iso_unprobed_sdk", observedAtUtc = DateTimeOffset.UtcNow }, fixture.Token).ConfigureAwait(false);
        }
        if (caseId == "local-trust")
        {
            string observed = await CurrentAppOwnedRepairDockerProcess.RunDockerAsync(["--host", "npipe:////./pipe/docker_engine", "exec", fixture.ContainerId, "env", "LC_ALL=C", "psql", "-X", "-w", "-h", "/var/run/postgresql", "-U", "postgres", "-d", "postgres", "-At", "-c", "SELECT current_user;"], fixture.Token, value => fixture.RecordAsync("docker-local-probe", value, CancellationToken.None)).ConfigureAwait(false);
            Assert.Equal("postgres", observed.Trim()); await fixture.RecordAsync("local-client-allowed", new { role = "postgres", transport = "unix", observedAtUtc = DateTimeOffset.UtcNow }, fixture.Token).ConfigureAwait(false);
        }
        var calls = new List<IsoNamedClosedInvocation>(); bool rejectReview = caseId is "wrong-owner" or "unsafe-host" or "local-trust";
        Assert.Equal(rejectReview ? 1 : 0, await Invoke("review-current-owner-iso-repair").ConfigureAwait(false));
        if (rejectReview)
        {
            Assert.False(File.Exists(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-review.json"))); Assert.False(File.Exists(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-authorization.json")));
            Assert.Empty(Directory.GetFiles(fixture.Root, fixture.Operation.ToString("D") + "-*.json"));
        }
        else if (caseId is not ("ordinary-all26" or "exclusive-policy"))
        {
            Assert.Equal(0, await Invoke("authorize-current-owner-iso-repair").ConfigureAwait(false));
            Assert.Equal(0, await Invoke("verify-current-owner-iso-repair").ConfigureAwait(false));
            Assert.Equal(caseId == "complete" ? 0 : 1, await Invoke("apply-current-owner-iso-repair").ConfigureAwait(false));
        }
        var contract = ApprovedCurrentOwnerIsoOverlay.Create(source, source.SourceCommitSha, CurrentOwnerIsoSelection.LiteralWidthV1, owners, DateTimeOffset.UtcNow);
        var after = new List<CurrentAppOwnedDatabaseSnapshot>();
        foreach (string database in IsoGuardedFleetFixture.Names.Order(StringComparer.Ordinal))
        {
            bool selected = (database == "Country" && (caseId is "complete" or "lost-commit-ack" or "terminal-publication" or "fleet-drift")) || (database == "Material" && caseId == "complete");
            var snapshot = await IsoGuardedFleetFixture.CaptureAsync(preparation.Endpoint, database, fixture.Token).ConfigureAwait(false); after.Add(snapshot);
            if (database is "Country" or "Material")
            {
                var native = await IsoGuardedFleetFixture.NativeAsync(preparation.Endpoint, database, contract, selected, fixture.Token).ConfigureAwait(false);
                var before = preparation.BeforeNative[database].Observe();
                if (selected)
                {
                    var prepared = MigrationConsole.DecodeOwnerIso<CurrentOwnerIsoRepairReceipt>(Read(Path.Combine(fixture.Root, $"{fixture.Operation:D}-{database}-prepared.json"), 65536));
                    Assert.Equal(prepared.AfterSha256, native.Snapshot.Sha256); CurrentOwnerIsoNativePreservation.RequirePreserved(before, native, contract);
                }
                else { Assert.Equal(before.Snapshot.Sha256, native.Snapshot.Sha256); CurrentOwnerIsoNativePreservation.RequireBefore(native, contract); }
                await fixture.RecordAsync("after-native-" + database, IsoCapturedNative.Capture(native), fixture.Token).ConfigureAwait(false);
            }
            if (!selected && !(caseId == "fleet-drift" && database == "Upload")) { Assert.Equal(preparation.Baseline.Single(x => x.Database == database).Sha256, snapshot.Sha256); }
            if (caseId == "fleet-drift" && database == "Upload") { Assert.NotEqual(preparation.Baseline.Single(x => x.Database == database).Sha256, snapshot.Sha256); }
        }
        using (var actual = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(actual))
        {
            await files.WriteBaselineNewAsync(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-fleet-after.json"), after.ToArray(), fixture.Token).ConfigureAwait(false);
            await files.WriteNewAsync(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-invocations.json"), JsonSerializer.SerializeToUtf8Bytes(calls), fixture.Token).ConfigureAwait(false);
        }
        if (!rejectReview && caseId is not ("ordinary-all26" or "exclusive-policy"))
        {
            var saved = Slots(); Assert.Equal(1, await Invoke("apply-current-owner-iso-repair").ConfigureAwait(false)); Assert.Equal(saved, Slots());
            await fixture.RecordAsync("replay-rejected", new { fixture.Operation, reservations = 1, unchangedSlots = saved.Length, observedAtUtc = DateTimeOffset.UtcNow }, fixture.Token).ConfigureAwait(false);
        }
        using (var finalAuthority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var finalFiles = new CurrentAppOwnedRepairCustody(finalAuthority))
        { await finalFiles.WriteNewAsync(Path.Combine(fixture.Root, "iso-closed-case-" + fixture.Operation.ToString("N") + "-closed-invocations-final.json"), JsonSerializer.SerializeToUtf8Bytes(calls), fixture.Token).ConfigureAwait(false); }
        await fixture.RecordAsync("case-returned", new
        {
            fixture.Operation,
            caseId,
            returnedAtUtc = DateTimeOffset.UtcNow,
            configurationSha256 = CurrentAppOwnedRepairPermit.Hash(Read(preparation.ConfigurationPath, 8_000_000)),
            actualCalls = calls.Count,
            retainedSlots = Slots()
        }, fixture.Token).ConfigureAwait(false);
        output.WriteLine("Actual named Console observations retained; no signed completion is inferred from stdout.");
        async Task<int> Invoke(string command)
        {
            DateTimeOffset began = DateTimeOffset.UtcNow; using var stdout = new StringWriter(); using var stderr = new StringWriter();
            int result = await MigrationConsole.RunAsync([command, "--config", preparation.ConfigurationPath], stdout, stderr, Environment.GetEnvironmentVariable, fixture.Token).ConfigureAwait(false);
            calls.Add(new(command, fixture.Operation, began, DateTimeOffset.UtcNow, result, CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stdout.ToString())), CurrentAppOwnedRepairPermit.Hash(Encoding.UTF8.GetBytes(stderr.ToString())))); return result;
        }
        string[] Slots()
        {
            return Directory.GetFiles(fixture.Root, fixture.Operation.ToString("D") + "-*.json").Order(StringComparer.Ordinal).Select(x => Path.GetFileName(x) + ":" + CurrentAppOwnedRepairPermit.Hash(Read(x, 65536))).ToArray();
        }
    }
    private static byte[] Read(string path, int maximum) { using var held = SecureLocalFile.OpenReadShared(path); if (held.Length is < 1 || held.Length > maximum) { throw Invalid(); } byte[] bytes = new byte[(int)held.Length]; held.ReadExactly(bytes); return bytes; }
    private static string HashFile(string path) { using var held = SecureLocalFile.OpenReadShared(path); return Convert.ToHexStringLower(SHA256.HashData(held)); }
    private static MigrationExecutionException Invalid()
    {
        return CurrentOwnerIsoRepairPermit.Invalid();
    }
}
