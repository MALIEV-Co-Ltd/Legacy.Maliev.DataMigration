using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

internal sealed partial class CurrentAuthArchiveFixtureTarget
{
    internal async Task<JsonElement> ObservePreflightCustodyAsync(WindowsLocalRunAuthority authority, CancellationToken ct)
    {
        await RequireHealthyHeldAsync(authority, ct);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, Token); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        var actual = await _docker.Containers.InspectContainerAsync(ContainerId, deadline.Token); RequireContainer(actual);
        var volume = await _docker.Volumes.InspectAsync(Name, deadline.Token);
        var container = JsonSerializer.SerializeToNode(actual)!.AsObject();
        var config = container["Config"]?.AsObject() ?? throw CurrentAuthArchiveGenuinePreflight.Invalid();
        if (!config.Remove("Env")) { throw CurrentAuthArchiveGenuinePreflight.Invalid(); }
        await RequireHealthyHeldAsync(authority, deadline.Token);
        return JsonSerializer.SerializeToElement(new { Operation, Comparison, RunBindingSha256 = Binding.ComputeSha256(), Container = container, Volume = volume, ObservedAtUtc = DateTimeOffset.UtcNow });
    }
    // Fixed read-only client inside this exact owned container. No caller executable, SQL, role or password is accepted.
    internal async Task<CurrentAuthArchiveGenuinePreflightProbe> ProbeLocalPreflightRoleAsync(WindowsLocalRunAuthority authority, CancellationToken ct)
    {
        await RequireHealthyHeldAsync(authority, ct);
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(ct, Token); deadline.CancelAfter(TimeSpan.FromSeconds(10));
        string role = "archive_denied_" + Operation.ToString("N"); DateTimeOffset began = DateTimeOffset.UtcNow;
        const string executable = "/usr/lib/postgresql/18/bin/psql";
        var result = await _container.ExecAsync([executable, "-X", "-w", "-h", "/var/run/postgresql", "-U", role, "-d", "Auth", "-A", "-t", "-c", "SELECT current_user;"], deadline.Token);
        if (result.Stdout.Length > 4096 || result.Stderr.Length > 4096) { throw CurrentAuthArchiveGenuinePreflight.Invalid(); }
        await RequireHealthyHeldAsync(authority, deadline.Token);
        bool connected = result.ExitCode == 0;
        bool invalidProbe = connected ? result.Stdout.Trim() != role : result.ExitCode != 2 || !result.Stderr.Contains("pg_hba.conf rejects connection", StringComparison.Ordinal);
        return invalidProbe
            ? throw CurrentAuthArchiveGenuinePreflight.Invalid()
            : new CurrentAuthArchiveGenuinePreflightProbe(role, "unix-socket", connected, connected ? result.Stdout.Trim() : null, null,
            result.ExitCode, executable, result.Stdout, result.Stderr, began, DateTimeOffset.UtcNow);
    }
}
