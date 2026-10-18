using System.Diagnostics;
using System.Globalization;
using System.Data;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.SqlClient;

namespace Legacy.Maliev.DataMigration.Console;

internal sealed record CurrentCustomerSequenceRepairSourceInputs(string AcceptedCatalogReportPath, string SourceConnectionPath,
    CloudNativePgTargetObserverOptions SourceCloudOptions);

/// <summary>Actual fixed source service/SQL snapshot metadata and independently observed exact clean owner checkout.</summary>
internal sealed class CurrentCustomerSequenceRepairSourceObservation : IDisposable
{
    private const string SchemaQuery = """
        SELECT (SELECT 'schema' AS kind,DB_NAME() AS [database],s.name AS [schema],t.name AS [table],
        JSON_QUERY((SELECT c.column_id AS ordinal,c.name,ty.name AS type,c.max_length AS maxLength,c.precision,c.scale,c.is_nullable AS nullable,c.collation_name AS collationName,c.is_identity AS isIdentity,c.is_computed AS isComputed,CONVERT(varchar(64),HASHBYTES('SHA2_256',dc.definition),2) AS defaultDefinitionSha256 FROM sys.columns c JOIN sys.types ty ON ty.user_type_id=c.user_type_id LEFT JOIN sys.default_constraints dc ON dc.object_id=c.default_object_id WHERE c.object_id=t.object_id ORDER BY c.column_id FOR JSON PATH)) AS columns,
        JSON_QUERY((SELECT i.name,i.is_unique AS isUnique,i.is_primary_key AS isPrimaryKey,i.has_filter AS hasFilter,i.filter_definition AS filterDefinition,JSON_QUERY((SELECT c.name,ic.key_ordinal AS ordinal,ic.is_descending_key AS descendingKey,ic.is_included_column AS included FROM sys.index_columns ic JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id WHERE ic.object_id=t.object_id AND ic.index_id=i.index_id ORDER BY ic.index_column_id FOR JSON PATH)) AS columns FROM sys.indexes i WHERE i.object_id=t.object_id AND i.index_id>0 ORDER BY i.index_id FOR JSON PATH)) AS indexes,
        JSON_QUERY((SELECT f.name,f.is_disabled AS disabled,f.is_not_trusted AS notTrusted,OBJECT_SCHEMA_NAME(f.referenced_object_id) AS referencedSchema,OBJECT_NAME(f.referenced_object_id) AS referencedTable,JSON_QUERY((SELECT COL_NAME(fc.parent_object_id,fc.parent_column_id) AS [column],COL_NAME(fc.referenced_object_id,fc.referenced_column_id) AS referencedColumn FROM sys.foreign_key_columns fc WHERE fc.constraint_object_id=f.object_id ORDER BY fc.constraint_column_id FOR JSON PATH)) AS columns FROM sys.foreign_keys f WHERE f.parent_object_id=t.object_id ORDER BY f.name FOR JSON PATH)) AS foreignKeys
        FOR JSON PATH,WITHOUT_ARRAY_WRAPPER)
        FROM sys.tables t JOIN sys.schemas s ON s.schema_id=t.schema_id WHERE t.is_ms_shipped=0 ORDER BY s.name,t.name;
        """;
    private const string ServiceUid = "71cf80cc-ec33-11e8-8f70-42010a8000ce";
    private readonly CurrentAppOwnedRepairCustody _files;
    private readonly CurrentCustomerSequenceRepairScope _scope;
    private readonly CurrentCustomerSequenceRepairSourceInputs _inputs;
    private readonly FreshSchemaPlan _schema;
    private readonly Func<CurrentAppOwnedDockerResource, Task> _ledger;
    private readonly HttpClient _kubernetes;
    private readonly string _token;
    private readonly byte[] _reportBytes;
    internal CurrentCustomerSequenceRepairSourceObservation(CurrentAppOwnedRepairCustody files, CurrentCustomerSequenceRepairScope scope,
        CurrentCustomerSequenceRepairSourceInputs inputs, FreshSchemaPlan schema, Func<CurrentAppOwnedDockerResource, Task> ledger)
    {
        _files = files; _scope = scope; _inputs = inputs; _schema = schema; _ledger = ledger;
        _reportBytes = files.Read(inputs.AcceptedCatalogReportPath, sharedReader: true, maximumBytes: 8_000_000);
        if (CurrentCustomerSequenceRepairPermit.Hash(_reportBytes) != scope.CatalogReportSha256) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        _ = files.Read(inputs.SourceCloudOptions.ServiceAccountCaFile, sharedReader: true);
        _token = Encoding.UTF8.GetString(files.Read(inputs.SourceCloudOptions.ServiceAccountTokenFile, sharedReader: true)).Trim();
        if (string.IsNullOrWhiteSpace(_token)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var options = inputs.SourceCloudOptions;
        HttpMessageHandler handler = options.ApiServer.HostNameType == UriHostNameType.IPv4
            ? HostRuntimeTrust.CreateRepairKubernetesIpv4Handler(options.ApiServer, options.ServiceAccountTokenFile, options.ServiceAccountCaFile)
            : HostRuntimeTrust.CreateKubernetesHandler(options.ApiServer, options.ServiceAccountTokenFile, options.ServiceAccountCaFile);
        _kubernetes = new(handler) { BaseAddress = options.ApiServer, Timeout = TimeSpan.FromSeconds(20) };
    }
    internal async Task<CurrentCustomerSequenceSource> ObserveCatalogAsync(string acceptedSha, CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        _files.Require();
        if (acceptedSha != _scope.SourceCommitSha || acceptedSha != _schema.SourceCommitSha) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var evidence = ReadCatalog(_reportBytes, _schema, _scope.CatalogReportSha256, acceptedSha, DateTimeOffset.UtcNow);
        await RequireServiceAsync(ct).ConfigureAwait(false);
        var settings = new SqlConnectionStringBuilder(Encoding.UTF8.GetString(_files.Read(_inputs.SourceConnectionPath, sharedReader: true)).Trim())
        { InitialCatalog = "master", ApplicationIntent = ApplicationIntent.ReadOnly, Pooling = false, ConnectTimeout = 5 };
        if (!settings.DataSource.StartsWith("tcp:127.0.0.1,", StringComparison.Ordinal) || settings.UserID != "KubernetesAccess" ||
            settings.IntegratedSecurity || string.IsNullOrWhiteSpace(settings.Password) ||
            !int.TryParse(settings.DataSource[14..], out int port) || port is < 1 or > 65535)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        try
        {
            await using var connection = new SqlConnection(settings.ConnectionString);
            await connection.OpenAsync(ct).ConfigureAwait(false);
            await using (var identity = new SqlCommand("SELECT LOWER(CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(nvarchar(4000),SERVERPROPERTY('ServerName'))),2)),CONVERT(nvarchar(128),SERVERPROPERTY('ProductVersion')),SYSTEM_USER; SELECT (SELECT 'catalog' AS kind,name,state_desc AS state,snapshot_isolation_state AS snapshotState FROM sys.databases WHERE database_id>4 ORDER BY name FOR JSON PATH);", connection) { CommandTimeout = 30 })
            await using (var reader = await identity.ExecuteReaderAsync(ct).ConfigureAwait(false))
            {
                if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetString(0) != evidence.ServerNameSha256 ||
                    reader.GetString(1) != evidence.ProductVersion || reader.GetString(2) != "KubernetesAccess" || await reader.ReadAsync(ct).ConfigureAwait(false))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                if (!await reader.NextResultAsync(ct).ConfigureAwait(false) || !await reader.ReadAsync(ct).ConfigureAwait(false))
                { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                var actualCatalog = MigrationConsole.DecodeCustomerSequence<JsonElement>(Encoding.UTF8.GetBytes(reader.GetString(0)));
                using var report = JsonDocument.Parse(_reportBytes);
                JsonElement[] heldCatalog = [..report.RootElement.GetProperty("facts").EnumerateArray()
                    .SelectMany(x=>x.ValueKind==JsonValueKind.Array?x.EnumerateArray().ToArray():[x])
                    .Where(x=>x.GetProperty("kind").GetString()=="catalog")];
                if (heldCatalog.Length == 0 || JsonSerializer.Serialize(actualCatalog) != JsonSerializer.Serialize(heldCatalog) ||
                    await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            foreach (var database in _schema.Databases)
            {
                CurrentCustomerSequenceCapacity.Require(admission: false);
                await connection.ChangeDatabaseAsync(database.Database, ct).ConfigureAwait(false);
                await using (var fence = new SqlCommand("SET LOCK_TIMEOUT 5000; IF (SELECT snapshot_isolation_state FROM sys.databases WHERE name=DB_NAME())<>1 THROW 50000,'snapshot_required',1;", connection) { CommandTimeout = 30 })
                { _ = await fence.ExecuteNonQueryAsync(ct).ConfigureAwait(false); }
                await using var tx = (SqlTransaction)await connection.BeginTransactionAsync(IsolationLevel.Snapshot, ct).ConfigureAwait(false);
                DateTimeOffset begin = DateTimeOffset.UtcNow;
                await using (var command = new SqlCommand(SchemaQuery, connection, tx) { CommandTimeout = 30 })
                await using (var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false))
                {
                    var actual = new Dictionary<string, string>(StringComparer.Ordinal);
                    while (await reader.ReadAsync(ct).ConfigureAwait(false))
                    {
                        var item = MigrationConsole.DecodeCustomerSequence<JsonElement>(Encoding.UTF8.GetBytes(reader.GetString(0)));
                        string key = item.GetProperty("schema").GetString() + "/" + item.GetProperty("table").GetString();
                        if (!actual.TryAdd(key, JsonSerializer.Serialize(item))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                    }
                    using var report = JsonDocument.Parse(_reportBytes);
                    var expected = report.RootElement.GetProperty("facts").EnumerateArray()
                        .Where(x => x.ValueKind == JsonValueKind.Object && x.GetProperty("kind").GetString() == "schema" && x.GetProperty("database").GetString() == database.Database)
                        .ToDictionary(x => x.GetProperty("schema").GetString() + "/" + x.GetProperty("table").GetString(), x => JsonSerializer.Serialize(x), StringComparer.Ordinal);
                    if (actual.Count != expected.Count || actual.Any(x => !expected.TryGetValue(x.Key, out string? held) || held != x.Value))
                    { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                }
                if (database.Database == "Customer")
                {
                    await using var command = new SqlCommand("SELECT CONVERT(bigint,ic.seed_value),CONVERT(bigint,ic.increment_value),CONVERT(bigint,ic.last_value),ic.is_not_for_replication,ty.name,c.is_identity FROM sys.identity_columns ic JOIN sys.columns c ON c.object_id=ic.object_id AND c.column_id=ic.column_id JOIN sys.tables t ON t.object_id=ic.object_id JOIN sys.schemas s ON s.schema_id=t.schema_id JOIN sys.types ty ON ty.user_type_id=c.user_type_id WHERE s.name='dbo' AND t.name='Customer' AND c.name='ID';", connection, tx) { CommandTimeout = 30 };
                    await using var reader = await command.ExecuteReaderAsync(ct).ConfigureAwait(false);
                    if (!await reader.ReadAsync(ct).ConfigureAwait(false) || reader.GetInt64(0) != evidence.Source.Seed || reader.GetInt64(1) != evidence.Source.Increment ||
                        reader.IsDBNull(2) || reader.GetInt64(2) != evidence.Source.CurrentValue || reader.GetBoolean(3) || reader.GetString(4) != "int" || !reader.GetBoolean(5) ||
                        await reader.ReadAsync(ct).ConfigureAwait(false)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
                }
                await tx.RollbackAsync(ct).ConfigureAwait(false);
                if (begin > DateTimeOffset.UtcNow || DateTimeOffset.UtcNow - begin > TimeSpan.FromMinutes(2)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
            }
            await RequireServiceAsync(ct).ConfigureAwait(false); CurrentCustomerSequenceCapacity.Require(admission: false); _files.Require();
            return evidence.Source with { ObservedAtUtc = DateTimeOffset.UtcNow };
        }
        catch (SqlException) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    private async Task RequireServiceAsync(CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/v1/namespaces/maliev/services/maliev-mssql");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
        using var response = await _kubernetes.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        _ = response.EnsureSuccessStatusCode();
        await response.Content.LoadIntoBufferAsync(65536, ct).ConfigureAwait(false);
        await using var stream = await response.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
        using var json = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
        var root = json.RootElement; var metadata = root.GetProperty("metadata"); var spec = root.GetProperty("spec");
        if (metadata.GetProperty("uid").GetString() != ServiceUid || metadata.GetProperty("namespace").GetString() != "maliev" ||
            metadata.GetProperty("name").GetString() != "maliev-mssql" ||
            !spec.GetProperty("ports").EnumerateArray().Any(x => x.GetProperty("port").GetInt32() == 1433 && x.GetProperty("targetPort").GetInt32() == 1433))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
    }
    internal sealed record CatalogEvidence(CurrentCustomerSequenceSource Source, string ServerNameSha256, string ProductVersion);
    internal static CatalogEvidence ReadCatalog(byte[] bytes, FreshSchemaPlan schema, string independentlyHeldSha, string acceptedSha, DateTimeOffset now)
    {
        if (CurrentCustomerSequenceRepairPermit.Hash(bytes) != independentlyHeldSha || schema.SourceCommitSha != acceptedSha)
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        JsonElement report = MigrationConsole.DecodeCustomerSequence<JsonElement>(bytes);
        DateTimeOffset observed = report.GetProperty("observedAtUtc").GetDateTimeOffset();
        if (report.GetProperty("kind").GetString() != "fresh-readonly-source-catalog-and-counts" || report.GetProperty("serviceUid").GetString() != ServiceUid ||
            report.GetProperty("databaseWrites").GetBoolean() || report.GetProperty("atomicAcrossDatabases").GetBoolean() ||
            observed.Offset != TimeSpan.Zero || observed > now || now - observed > TimeSpan.FromHours(12)) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        JsonElement[] facts = [.. report.GetProperty("facts").EnumerateArray().SelectMany(x => x.ValueKind == JsonValueKind.Array ? x.EnumerateArray().ToArray() : [x])];
        JsonElement[] selected(string kind)
        {
            return [.. facts.Where(x => x.ValueKind == JsonValueKind.Object && x.GetProperty("kind").GetString() == kind)];
        }

        JsonElement[] begins = selected("begin"), ends = selected("end"), tables = selected("schema"), identities = selected("identity-definition"), source = selected("source");
        if (begins.Length != 23 || ends.Length != 23 || tables.Length != 100 || source.Length != 1 ||
            !begins.Select(x => x.GetProperty("database").GetString()).Order(StringComparer.Ordinal).SequenceEqual(DatabaseInventory.ActiveDatabases.Order(StringComparer.Ordinal)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        foreach (var database in schema.Databases)
        {
            var startText = begins.Single(x => x.GetProperty("database").GetString() == database.Database).GetProperty("capturedUtc").GetString();
            var endText = ends.Single(x => x.GetProperty("database").GetString() == database.Database).GetProperty("capturedUtc").GetString();
            DateTimeOffset start = DateTimeOffset.Parse(startText!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            DateTimeOffset end = DateTimeOffset.Parse(endText!, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
            if (start.Offset != TimeSpan.Zero || end.Offset != TimeSpan.Zero || start > end || end > observed || now - start > TimeSpan.FromHours(12) || end - start > TimeSpan.FromMinutes(5) ||
                !tables.Where(x => x.GetProperty("database").GetString() == database.Database)
                    .Select(x => x.GetProperty("schema").GetString() + "/" + x.GetProperty("table").GetString()).Order(StringComparer.Ordinal)
                    .SequenceEqual(database.Tables.Select(x => x.SourceSchema + "/" + x.SourceTable).Order(StringComparer.Ordinal))) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        }
        var identity = identities.Single(x => x.GetProperty("database").GetString() == "Customer" && x.GetProperty("schema").GetString() == "dbo" &&
            x.GetProperty("table").GetString() == "Customer" && x.GetProperty("column").GetString() == "ID");
        if (identity.GetProperty("notForReplication").GetBoolean()) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        var observation = new CurrentCustomerSequenceSource(acceptedSha, independentlyHeldSha, observed, identity.GetProperty("seed").GetInt64(),
            identity.GetProperty("increment").GetInt64(), identity.GetProperty("currentValue").GetInt64());
        string serverHash = source[0].GetProperty("serverNameSha256").GetString()!.ToLowerInvariant();
        string version = source[0].GetProperty("productVersion").GetString()!;
        return observation.Seed != 1000 || observation.Increment != 1 || observation.CurrentValue < 999 || observation.CurrentValue > int.MaxValue ||
            !CurrentCustomerSequenceRepairPermit.HashShape(serverHash) || string.IsNullOrWhiteSpace(version) ||
            source[0].GetProperty("loginName").GetString() != "KubernetesAccess"
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : new(observation, serverHash, version);
    }
    internal async Task<CurrentCustomerSequenceOwner> ObserveOwnerAsync(CancellationToken ct)
    {
        CurrentCustomerSequenceCapacity.Require(admission: false);
        string head = (await CurrentCustomerSequenceOwnerProcess.RunGitAsync("head", _ledger, ct).ConfigureAwait(false)).Trim();
        if (!string.IsNullOrWhiteSpace(await CurrentCustomerSequenceOwnerProcess.RunGitAsync("status", _ledger, ct).ConfigureAwait(false)))
        { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        const string root = @"B:\maliev-legacy\Legacy.Maliev.CustomerService";
        using var context = new FileStream(Path.Combine(root, @"Legacy.Maliev.CustomerService.Data\CustomerDbContext.cs"), FileMode.Open, FileAccess.Read, FileShare.Read);
        using var snapshot = new FileStream(Path.Combine(root, @"Legacy.Maliev.CustomerService.Data\Migrations\CustomerDbContextModelSnapshot.cs"), FileMode.Open, FileAccess.Read, FileShare.Read);
        string c = Convert.ToHexStringLower(SHA256.HashData(context)), s = Convert.ToHexStringLower(SHA256.HashData(snapshot));
        return (await CurrentCustomerSequenceOwnerProcess.RunGitAsync("head", _ledger, ct).ConfigureAwait(false)).Trim() != head ||
            !string.IsNullOrWhiteSpace(await CurrentCustomerSequenceOwnerProcess.RunGitAsync("status", _ledger, ct).ConfigureAwait(false))
            ? throw CurrentCustomerSequenceRepairPermit.Invalid()
            : new(head, true, DateTimeOffset.UtcNow, c, s);
    }
    public void Dispose()
    {
        _kubernetes.Dispose();
    }
}

internal static class CurrentCustomerSequenceOwnerProcess
{
    private static readonly TimeSpan Lifetime = TimeSpan.FromSeconds(20), Cleanup = TimeSpan.FromSeconds(5);
    private const int OutputLimit = 2_000_000;
    internal static Task<string> RunGitAsync(string query, Func<CurrentAppOwnedDockerResource, Task> observe, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows() || query is not ("head" or "status")) { throw CurrentCustomerSequenceRepairPermit.Invalid(); }
        string executable = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Git", "cmd", "git.exe");
        string[] operation = query == "head" ? ["rev-parse", "HEAD"] : ["status", "--porcelain", "--untracked-files=all"];
        return RunOwnedAsync(executable, ["--no-optional-locks", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", "-C", @"B:\maliev-legacy\Legacy.Maliev.CustomerService", .. operation], Lifetime, OutputLimit, observe, ct);
    }
    private static async Task<string> RunOwnedAsync(string executable, IReadOnlyList<string> arguments,
        TimeSpan lifetime, int maximumCharacters, Func<CurrentAppOwnedDockerResource, Task>? observe, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (!Path.IsPathFullyQualified(executable) || lifetime <= TimeSpan.Zero || lifetime > Lifetime ||
            maximumCharacters is < 1 or > OutputLimit || arguments.Any(x => x is null || x.Contains('\0')))
        { throw Failure("input"); }
        executable = Path.GetFullPath(executable);
        // Hold the executable against writes/deletion while its identity is captured and launched.
        using var image = new FileStream(executable, FileMode.Open, FileAccess.Read, FileShare.Read);
        string imageSha = Convert.ToHexStringLower(SHA256.HashData(image));
        var start = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };
        // Do not inherit tokens, credential overrides, debug switches or caller script variables.
        // Docker's built-in default context uses the same Windows user profile; no shell is used.
        start.Environment.Clear();
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        start.Environment["SystemRoot"] = windows;
        start.Environment["WINDIR"] = windows;
        start.Environment["USERPROFILE"] = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        start.Environment["TEMP"] = Path.GetTempPath();
        start.Environment["TMP"] = Path.GetTempPath();
        foreach (string argument in arguments) { start.ArgumentList.Add(argument); }
        using var process = new Process { StartInfo = start };
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(lifetime);
        using var readers = new CancellationTokenSource();
        CurrentAppOwnedDockerResource resource = new(Guid.NewGuid(), executable, imageSha, null, null,
            DateTimeOffset.UtcNow.Add(lifetime + Cleanup + Cleanup), false, false, false);
        Task<string>? stdout = null;
        Task<string>? stderr = null;
        bool started = false;
        try
        {
            ct.ThrowIfCancellationRequested();
            if (!process.Start()) { throw Failure("start"); }
            started = true;
            // Opening/retaining the kernel process handle protects cleanup against PID reuse.
            _ = process.SafeHandle;
            resource = resource with { ProcessId = process.Id };
            resource = resource with { StartUtcTicks = process.StartTime.ToUniversalTime().Ticks };
            if (observe is not null) { await observe(resource).ConfigureAwait(false); }
            process.StandardInput.Close();
            stdout = ReadBoundedAsync(process.StandardOutput, maximumCharacters, readers.Token);
            stderr = ReadBoundedAsync(process.StandardError, maximumCharacters, readers.Token);
            Task exited = process.WaitForExitAsync(timeout.Token);
            // Continue observing both readers even if one stream reaches EOF before child exit.
            var pending = new List<Task> { exited, stdout, stderr };
            while (pending.Count != 0)
            {
                Task finished = await Task.WhenAny(pending).WaitAsync(timeout.Token).ConfigureAwait(false);
                _ = pending.Remove(finished);
                await finished.ConfigureAwait(false);
            }
            string content = await stdout.ConfigureAwait(false);
            return process.ExitCode != 0 ? throw Failure("child") : content;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        { throw Failure("timeout"); }
        finally
        {
            await CompleteCleanupAsync().ConfigureAwait(false);
        }

        async Task CompleteCleanupAsync()
        {
            Exception? cleanupFailure = null;
            if (started)
            {
                try
                {
                    process.Refresh();
                    if ((resource.ProcessId is { } pid && process.Id != pid) ||
                        (resource.StartUtcTicks is { } ticks && process.StartTime.ToUniversalTime().Ticks != ticks))
                    { throw Failure("identity"); }
                    if (!process.HasExited)
                    {
                        // Uses the retained exact process handle. Never kill descendants or enumerate a tree.
                        try { process.Kill(); }
                        catch (InvalidOperationException) when (process.HasExited) { }
                    }
                    await process.WaitForExitAsync(CancellationToken.None).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false);
                    if (!process.HasExited) { throw Failure("exit"); }
                    resource = resource with { Exited = true };
                }
                catch (Exception failure) when (failure is InvalidOperationException or System.ComponentModel.Win32Exception or
                    TimeoutException or MigrationConsoleException)
                { cleanupFailure = failure; }
            }
            await readers.CancelAsync().ConfigureAwait(false);
            // Close the parent's pipe ends even if another process inherited a writer. No tree termination.
            if (started)
            {
                try { process.StandardOutput.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
                try { process.StandardError.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
                try { process.StandardInput.Dispose(); }
                catch (IOException failure) { cleanupFailure ??= failure; }
            }
            try
            {
                await SettleAsync(stdout, stderr).WaitAsync(Cleanup, CancellationToken.None).ConfigureAwait(false);
                resource = resource with { ReadersSettled = true };
            }
            catch (TimeoutException failure) { cleanupFailure ??= failure; }
            resource = resource with { CleanupFailed = cleanupFailure is not null };
            // Test evidence is PII-free: no arguments, output, environment values or credentials.
            if (observe is not null) { await observe(resource).ConfigureAwait(false); }
            if (cleanupFailure is not null) { throw Failure("cleanup"); }
        }
    }

    private static async Task<string> ReadBoundedAsync(StreamReader stream, int maximum, CancellationToken ct)
    {
        var text = new StringBuilder(Math.Min(maximum, 4096));
        char[] buffer = new char[4096];
        while (true)
        {
            int count = await stream.ReadAsync(buffer.AsMemory(), ct).ConfigureAwait(false);
            if (count == 0) { return text.ToString(); }
            if (count > maximum - text.Length) { throw Failure("output"); }
            _ = text.Append(buffer, 0, count);
        }
    }

    private static async Task SettleAsync(Task<string>? stdout, Task<string>? stderr)
    {
        foreach (Task<string>? task in new[] { stdout, stderr })
        {
            if (task is null) { continue; }
            try { _ = await task.ConfigureAwait(false); }
            catch (Exception failure) when (failure is OperationCanceledException or IOException or ObjectDisposedException or
                InvalidOperationException or MigrationConsoleException)
            { }
        }
    }

    private static MigrationConsoleException Failure(string category)
    {
        return new("current_customer_sequence_owner_" + category + "_failed", "The bounded exact Customer owner observer failed without exposing child output.");
    }
}
