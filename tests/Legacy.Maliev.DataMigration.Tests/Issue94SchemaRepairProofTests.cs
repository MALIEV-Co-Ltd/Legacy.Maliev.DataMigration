using System.Diagnostics;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class Issue94SchemaRepairProofFactAttribute : FactAttribute
{
    public Issue94SchemaRepairProofFactAttribute()
    {
        if (Environment.GetEnvironmentVariable("LEGACY_RUN_ISSUE94_SCHEMA_PROOF") != "1")
        {
            Skip = "Requires the owner-protected exact-23 production restore and reviewed repair inputs.";
        }
    }
}

public sealed class Issue94SchemaRepairProofTests
{
    [Issue94SchemaRepairProofFact]
    public async Task RepairedDisposableIdentityAndQuotation_ReplayWithoutSchemaMutation()
    {
        string run = Environment.GetEnvironmentVariable("LEGACY_ISSUE94_SCHEMA_PROOF_DIRECTORY") ??
            throw new InvalidOperationException("The owner-protected proof directory is required.");
        string repo = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        string tool = Path.Combine(repo, "tools", "Issue94SchemaRepair", "bin", "Release", "net10.0",
            "Issue94SchemaRepair.dll");
        Assert.True(File.Exists(tool));
        Assert.True(File.Exists(Path.Combine(run, "source-schema-plan-v2.json")));
        foreach (string database in new[] { "CustomerIdentity", "Quotation" })
        {
            using var process = new Process
            {
                StartInfo = new ProcessStartInfo("dotnet")
                {
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                },
            };
            process.StartInfo.ArgumentList.Add(tool);
            process.StartInfo.ArgumentList.Add(run);
            process.StartInfo.ArgumentList.Add("local");
            process.StartInfo.ArgumentList.Add(database);
            Assert.True(process.Start());
            using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
            await process.WaitForExitAsync(timeout.Token);
            string output = await process.StandardOutput.ReadToEndAsync(timeout.Token);
            string error = await process.StandardError.ReadToEndAsync(timeout.Token);
            Assert.True(process.ExitCode == 0, error);
            Assert.Contains($"repair_complete:local:{database}:already_current=True", output,
                StringComparison.Ordinal);
        }
    }
}
