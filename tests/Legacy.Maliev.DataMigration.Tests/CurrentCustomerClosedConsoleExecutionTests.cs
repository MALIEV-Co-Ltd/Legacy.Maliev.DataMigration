using System.Diagnostics;
using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(CurrentCustomerGuardedProofGroup.Name)]
public sealed class CurrentCustomerClosedConsoleExecutionTests
{
    [WindowsLocalRunTheory]
    [InlineData("success")]
    [InlineData("prepared-publication")]
    [InlineData("lost-commit-ack")]
    [InlineData("terminal-publication")]
    [InlineData("host-unprobed-sdk")]
    [InlineData("local-ordinary-trust")]
    [InlineData("final-fleet")]
    [InlineData("replay")]
    public async Task Genuine_named_closed_customer_console(string caseId)
    {
        CurrentCustomerSequenceCapacity.Require(admission: true);
        string parent = Environment.GetEnvironmentVariable("MALIEV_CUSTOMER_CLOSED_PARENT_ROOT") ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        string inputPath = Environment.GetEnvironmentVariable("MALIEV_CUSTOMER_CLOSED_LANE_INPUT") ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        string nonce = Environment.GetEnvironmentVariable("MALIEV_CUSTOMER_GUARDED_JOB_NONCE") ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
        CustomerNamedClosedHostObservation.RequireCurrentMembership(nonce);
        if (!Path.IsPathFullyQualified(parent) || Path.GetDirectoryName(Path.GetFullPath(inputPath)) != parent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var input = CustomerClosedCompletedReadback.ReadProtected<CustomerClosedLaneInput>(inputPath, 65536);
        _ = CustomerClosedCompletedReadback.Require(input, DateTimeOffset.UtcNow);
        if (Path.GetFullPath(typeof(CurrentCustomerClosedConsoleExecutionTests).Assembly.Location) != Path.GetFullPath(input.TestAssemblyPath))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        FreshSchemaPlan source;
        var inputBinding = CustomerClosedCompletedReadback.ReadProtected<LocalExecutionBinding>(input.InputBindingPath, 65536);
        if (inputBinding.ComputeSha256() != input.InputBindingSha256 || inputBinding.ArtifactRootCanonicalPath == parent) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        using (var authority = WindowsLocalRunAuthority.AcquireResume(inputBinding.ArtifactRootCanonicalPath, inputBinding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            CustomerClosedCompletedReadback.RequireExactBinding(files, input.InputBindingPath, inputBinding);
            source = CustomerClosedCompletedReadback.Decode<FreshSchemaPlan>(files.Read(input.SourceSchemaPath, sharedReader: true, maximumBytes: 32 * 1024 * 1024));
            if (SchemaPlanCanonicalizer.ComputeSha256(source) != input.SourceSchemaSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        Guid operation = Guid.NewGuid(); DateTimeOffset began = DateTimeOffset.UtcNow;
        using (var process = Process.GetCurrentProcess())
        {
            string executable = Environment.ProcessPath ?? throw CurrentCustomerSequenceRepairPermit.Invalid();
            byte[] entry = JsonSerializer.SerializeToUtf8Bytes(new
            {
                run = operation,
                caseId,
                processId = process.Id,
                processStartTimeUtc = process.StartTime.ToUniversalTime(),
                executable,
                executableSha256 = CustomerClosedCompletedReadback.Image(executable),
                testAssemblySha256 = input.TestAssemblySha256,
                jobNonce = nonce,
                nativeJobMembershipObserved = true,
                beganAtUtc = began
            });
            WriteParent(Path.Combine(parent, operation.ToString("N") + "-host-entry.json"), entry);
        }
        await using var fixture = await CurrentCustomerNamedClosedFixture.CreateAsync(parent, operation, CancellationToken.None);
        (string Path, CurrentCustomerSequenceRepairConfiguration Configuration, CurrentCustomerSequenceRepairScope Scope) configured;
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            var state = await CurrentCustomerClosedTemplate.PrepareAsync(files, fixture.Binding, operation, fixture.ContainerId, source, fixture.AdminConnection, fixture.Token);
            await CurrentCustomerClosedRows.PopulateBeforeCaptureAsync(state, source, fixture.AdminConnection, fixture.Token);
            await CurrentCustomerClosedTemplate.InstallPolicyAsync(files, fixture.Binding, state, fixture.AdminConnection, caseId, fixture.Token);
            var capture = await CurrentCustomerClosedTemplate.CaptureAsync(files, fixture.Binding, state, source, caseId is "host-unprobed-sdk" or "local-ordinary-trust", fixture.Token);
            configured = await CurrentCustomerClosedConfiguration.WriteAsync(files, fixture.Binding, capture, source, input, caseId, fixture.Token);
        }
        await CurrentCustomerClosedPolicyEvidence.CaptureAsync(fixture.Binding, configured.Configuration, configured.Scope, fixture.Token);
        // Explicit persistent control uses no persistent endpoint or volume. Its
        // typed seed cannot satisfy the public pure admission before observers.
        var persistent = configured.Scope with
        {
            Target = configured.Scope.Target with
            { AuthorityId = "aspire://legacy-postgres-main-local/persistent-" + fixture.ContainerId[..12] }
        };
        _ = Assert.Throws<MigrationExecutionException>(() => CurrentCustomerSequenceRepairPermit.RequireProofAdmission(persistent));
        string controlScope = Path.Combine(fixture.Root, "persistent-control-scope.json"), controlConfig = Path.Combine(fixture.Root, "persistent-control-config.json");
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await files.WriteNewAsync(controlScope, JsonSerializer.SerializeToUtf8Bytes(persistent), fixture.Token);
            await files.WriteNewAsync(controlConfig, JsonSerializer.SerializeToUtf8Bytes(configured.Configuration with { ScopePath = controlScope }), fixture.Token);
        }
        using (var stdout = new StringWriter())
        using (var stderr = new StringWriter())
        {
            int exit = await MigrationConsole.RunAsync(["review-current-customer-sequence-repair", "--config", controlConfig], stdout, stderr, Environment.GetEnvironmentVariable, fixture.Token);
            Assert.Equal(1, exit);
            await fixture.RecordAsync("persistent-control-rejected", new
            {
                operation,
                exit,
                observedAtUtc = DateTimeOffset.UtcNow,
                scopePath = controlScope,
                configurationPath = controlConfig,
                typedAdmissionRejected = true
            }, fixture.Token);
        }
        CustomerClosedCase actual = await CurrentCustomerClosedConsoleCase.RunAsync(fixture.Binding, configured.Configuration, configured.Scope, configured.Path, fixture.Token);
        using (var authority = WindowsLocalRunAuthority.AcquireResume(fixture.Root, fixture.Binding))
        using (var files = new CurrentAppOwnedRepairCustody(authority))
        {
            await CurrentCustomerClosedEightReadback.RequireEffectsAsync(files, actual, configured.Scope, configured.Configuration, source, DateTimeOffset.UtcNow, fixture.Token);
        }
        // await using releases exact owned container/volume and secrets even on
        // any assertion/cancellation. Parent independently verifies post-host exit.
    }
    private static void WriteParent(string path, byte[] bytes)
    {
        using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 4096, FileOptions.WriteThrough);
        if (!SecureLocalFile.IsOwnerOnlyFile(new FileInfo(path)) || !SecureLocalFile.HandleResolvesToApprovedPath(stream, path)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        stream.Write(bytes); stream.Flush(flushToDisk: true);
    }
}
