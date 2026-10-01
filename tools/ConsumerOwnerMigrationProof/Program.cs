using System.Text.Json;
using Legacy.Maliev.AccountingService.Data;
using Legacy.Maliev.AuthService.Infrastructure;
using Microsoft.EntityFrameworkCore;
using Npgsql;

// Test-only subprocess. No public application/CLI references this executable.
using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(90));
try
{
    if (Environment.GetEnvironmentVariable("LEGACY_DEPLOY_ENABLED") != "false") { throw new InvalidOperationException(); }
    var buffer = new char[8193];
    int length = 0;
    while (length < buffer.Length)
    {
        int count = await Console.In.ReadAsync(buffer.AsMemory(length, 1), deadline.Token);
        if (count == 0 || buffer[length] == '\n') { break; }
        length++;
    }
    if (length == buffer.Length) { throw new InvalidOperationException(); }
    var input = JsonSerializer.Deserialize<ProofRequest>(buffer.AsSpan(0, length)) ?? throw new InvalidOperationException();
    var settings = new NpgsqlConnectionStringBuilder(input.ConnectionString);
    if (!Guid.TryParseExact(input.RunId, "N", out _) || input.Database != "owner_ef_proof_" + input.RunId ||
        settings.Database != input.Database || settings.Host is not ("127.0.0.1" or "localhost" or "::1") ||
        settings.Port is < 1 or > 65535 || input.Context is not ("Invoice" or "CustomerIdentity" or "EmployeeIdentity"))
    { throw new InvalidOperationException(); }
    settings.Pooling = false;
    settings.Timeout = 5;
    settings.CommandTimeout = 60;
    await using (var admission = new NpgsqlConnection(settings.ConnectionString))
    {
        await admission.OpenAsync(deadline.Token);
        await using var command = new NpgsqlCommand("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database() AND current_setting('server_version_num')::integer BETWEEN 180000 AND 189999;", admission);
        if (await command.ExecuteScalarAsync(deadline.Token) is not string marker || marker != "owner-ef-proof:" + input.RunId)
        { throw new InvalidOperationException(); }
    }
    await using DbContext context = input.Context switch
    {
        "Invoice" => new InvoiceDbContext(new DbContextOptionsBuilder<InvoiceDbContext>().UseNpgsql(settings.ConnectionString).Options),
        "CustomerIdentity" => new CustomerIdentityDbContext(new DbContextOptionsBuilder<CustomerIdentityDbContext>().UseNpgsql(settings.ConnectionString).Options),
        "EmployeeIdentity" => new EmployeeIdentityDbContext(new DbContextOptionsBuilder<EmployeeIdentityDbContext>().UseNpgsql(settings.ConnectionString).Options),
        _ => throw new InvalidOperationException(),
    };
    await context.Database.MigrateAsync(deadline.Token);
    string[] migrations = [.. await context.Database.GetAppliedMigrationsAsync(deadline.Token)];
    Console.WriteLine(JsonSerializer.Serialize(migrations));
    return 0;
}
catch (Exception)
{
    // Fixed diagnostics deliberately omit exception messages, connections and row values.
    Console.Error.WriteLine("owner_migration_proof_failed");
    return 1;
}

internal sealed record ProofRequest(string Context, string ConnectionString, string Database, string RunId);
