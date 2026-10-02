using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Console;

/// <summary>Read-only protected-main and actual frozen-bundle admission. No configured bypass.</summary>
internal static class SourceBackedLocalRepairSourceAcceptance
{
    private const string Repository = "MALIEV-Co-Ltd/Legacy.Maliev.DataMigration";
    private const string Checkout = @"B:\maliev-legacy\Legacy.Maliev.DataMigration";
    private const string RequiredContext = "validate / validate";

    internal static async Task<string> RequireAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows() || !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GH_DEBUG")) ||
            !string.IsNullOrEmpty(Environment.GetEnvironmentVariable("GH_HOST"))) { throw Invalid(); }
        string head = (await RunAsync("git", ["-C", Checkout, "rev-parse", "HEAD"], cancellationToken).ConfigureAwait(false)).Trim();
        if (!Sha(head) || CompiledSha(typeof(MigrationConsole).Assembly) != head ||
            CompiledSha(typeof(DeltaExecutionCoordinator).Assembly) != head ||
            !string.IsNullOrWhiteSpace(await RunAsync("git", ["-C", Checkout, "status", "--porcelain", "--untracked-files=all"],
                cancellationToken).ConfigureAwait(false))) { throw Invalid(); }
        await RequireMainCheckoutAsync(head, cancellationToken).ConfigureAwait(false);
        string remote = (await RunAsync("git", ["-C", Checkout, "remote", "get-url", "origin"], cancellationToken).ConfigureAwait(false)).Trim();
        if (remote is not ("https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration.git" or
            "https://github.com/MALIEV-Co-Ltd/Legacy.Maliev.DataMigration" or
            "git@github.com:MALIEV-Co-Ltd/Legacy.Maliev.DataMigration.git")) { throw Invalid(); }
        using JsonDocument branch = await ApiAsync("branches/main", cancellationToken).ConfigureAwait(false);
        if (!branch.RootElement.GetProperty("protected").GetBoolean() ||
            branch.RootElement.GetProperty("commit").GetProperty("sha").GetString() != head) { throw Invalid(); }
        using JsonDocument protection = await ApiAsync("branches/main/protection", cancellationToken).ConfigureAwait(false);
        if (!protection.RootElement.GetProperty("enforce_admins").GetProperty("enabled").GetBoolean() ||
            !protection.RootElement.GetProperty("required_status_checks").GetProperty("contexts").EnumerateArray()
                .Select(item => item.GetString()).SequenceEqual([RequiredContext], StringComparer.Ordinal)) { throw Invalid(); }
        using JsonDocument runs = await ApiAsync("actions/workflows/ci-main.yml/runs?branch=main&head_sha=" + head + "&per_page=100",
            cancellationToken).ConfigureAwait(false);
        using JsonDocument checks = await ApiAsync("commits/" + head + "/check-runs?filter=latest&per_page=100",
            cancellationToken).ConfigureAwait(false);
        RequireCi(runs.RootElement, checks.RootElement, head);
        await RequireBundleAsync(cancellationToken).ConfigureAwait(false);
        // Close changes during the independent API/bundle checks.
        if ((await RunAsync("git", ["-C", Checkout, "rev-parse", "HEAD"], cancellationToken).ConfigureAwait(false)).Trim() != head ||
            !string.IsNullOrWhiteSpace(await RunAsync("git", ["-C", Checkout, "status", "--porcelain", "--untracked-files=all"],
                cancellationToken).ConfigureAwait(false))) { throw Invalid(); }
        await RequireMainCheckoutAsync(head, cancellationToken).ConfigureAwait(false);
        using JsonDocument final = await ApiAsync("branches/main", cancellationToken).ConfigureAwait(false);
        if (!final.RootElement.GetProperty("protected").GetBoolean() ||
            final.RootElement.GetProperty("commit").GetProperty("sha").GetString() != head) { throw Invalid(); }
        return head;
    }

    private static async Task RequireMainCheckoutAsync(string head, CancellationToken cancellationToken)
    {
        if ((await RunAsync("git", ["-C", Checkout, "symbolic-ref", "--short", "HEAD"], cancellationToken).ConfigureAwait(false)).Trim() != "main" ||
            (await RunAsync("git", ["-C", Checkout, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}"], cancellationToken).ConfigureAwait(false)).Trim() != "origin/main" ||
            (await RunAsync("git", ["-C", Checkout, "rev-parse", "origin/main"], cancellationToken).ConfigureAwait(false)).Trim() != head)
        { throw Invalid(); }
    }

    private static async Task RequireBundleAsync(CancellationToken cancellationToken)
    {
        string accepted = Path.Combine(Checkout, "src", "Legacy.Maliev.DataMigration.Console", "bin", "Release", "net10.0");
        string running = Path.GetFullPath(AppContext.BaseDirectory).TrimEnd(Path.DirectorySeparatorChar);
        if (string.Equals(accepted, running, StringComparison.OrdinalIgnoreCase) || !Directory.Exists(accepted)) { throw Invalid(); }
        string[] expected = Directory.GetFiles(accepted, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(accepted, path)).Order(StringComparer.Ordinal).ToArray();
        string[] actual = Directory.GetFiles(running, "*", SearchOption.AllDirectories)
            .Select(path => Path.GetRelativePath(running, path)).Order(StringComparer.Ordinal).ToArray();
        if (expected.Length == 0 || !expected.SequenceEqual(actual, StringComparer.Ordinal)) { throw Invalid(); }
        foreach (string relative in expected)
        {
            await using FileStream left = File.OpenRead(Path.Combine(accepted, relative));
            await using FileStream right = OwnerProtectedFilePolicy.OpenRead(Path.Combine(running, relative), "delta_source_repair_build_unprotected");
            byte[] acceptedHash = await SHA256.HashDataAsync(left, cancellationToken).ConfigureAwait(false);
            byte[] runningHash = await SHA256.HashDataAsync(right, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(acceptedHash, runningHash)) { throw Invalid(); }
        }
    }

    internal static void RequireCi(JsonElement runs, JsonElement checks, string head)
    {
        JsonElement latest = runs.GetProperty("workflow_runs").EnumerateArray().Where(run =>
            run.GetProperty("head_sha").GetString() == head && run.GetProperty("head_branch").GetString() == "main" &&
            run.GetProperty("path").GetString() == ".github/workflows/ci-main.yml" && run.GetProperty("name").GetString() == "CI - Main")
            .OrderByDescending(run => run.GetProperty("updated_at").GetDateTimeOffset()).FirstOrDefault();
        if (latest.ValueKind == JsonValueKind.Undefined || latest.GetProperty("status").GetString() != "completed" ||
            latest.GetProperty("conclusion").GetString() != "success" ||
            latest.GetProperty("event").GetString() is not ("push" or "workflow_dispatch")) { throw Invalid(); }
        long suite = latest.GetProperty("check_suite_id").GetInt64();
        JsonElement[] required = checks.GetProperty("check_runs").EnumerateArray().Where(check =>
            check.GetProperty("head_sha").GetString() == head && check.GetProperty("name").GetString() == RequiredContext &&
            check.GetProperty("check_suite").GetProperty("id").GetInt64() == suite &&
            check.GetProperty("app").GetProperty("slug").GetString() == "github-actions").ToArray();
        if (suite <= 0 || required.Length == 0 || required.Any(check =>
            check.GetProperty("status").GetString() != "completed" || check.GetProperty("conclusion").GetString() != "success"))
        { throw Invalid(); }
    }

    private static string CompiledSha(Assembly assembly)
    {
        string version = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "";
        return RequireCompiledSourceRevision(version);
    }

    internal static string RequireCompiledSourceRevision(string informationalVersion)
    {
        string[] parts = informationalVersion.Split('+');
        return parts.Length == 2 && Sha(parts[1]) ? parts[1] : throw Invalid();
    }

    private static bool Sha(string value) => value is { Length: 40 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));

    private static async Task<JsonDocument> ApiAsync(string path, CancellationToken cancellationToken)
    {
        return JsonDocument.Parse(await RunAsync("gh", ["api", "--hostname", "github.com", "repos/" + Repository + "/" + path], cancellationToken).ConfigureAwait(false));
    }

    private static async Task<string> RunAsync(string executable, IReadOnlyList<string> arguments, CancellationToken cancellationToken)
    {
        var start = new ProcessStartInfo(executable)
        { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        BackupProcessResult result = await ReadOnlyDockerProcess.ExecuteAsync(start, deadline.Token).ConfigureAwait(false);
        return result.ExitCode == 0 ? result.StandardOutput : throw Invalid();
    }

    private static MigrationConsoleException Invalid() => new("delta_source_repair_source_unaccepted",
        "Source repair requires the protected exact main commit, its required successful CI and an identical protected frozen build.");
}

internal sealed class ProtectedMainSourceRepairAcceptance : ISourceBackedLocalRepairSourceAcceptance
{
    public async Task RequireAsync(string sourceCommitSha, CancellationToken cancellationToken)
    {
        string accepted = await SourceBackedLocalRepairSourceAcceptance.RequireAsync(cancellationToken).ConfigureAwait(false);
        if (sourceCommitSha != accepted)
        {
            throw new MigrationConsoleException("delta_source_repair_source_unaccepted",
            "The signed plan and schema source must match the actual accepted compiled main commit.");
        }
    }
}
