using System.Data;
using System.Net;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.Json;
using Docker.DotNet;
using Legacy.Maliev.DataMigration.SourceUnicodeWitness;
using Microsoft.Data.SqlClient;
using Testcontainers.MsSql;
using Xunit.Abstractions;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(SqlServerAdapterTestGroup.Name)]
public sealed class SourceUnicodeProviderQualificationTests(ITestOutputHelper output)
{
    private const string Image = "mcr.microsoft.com/mssql/server:2022-CU20-ubuntu-22.04";
    private const string OwnerLabel = "com.maliev.source-unicode-witness";
    private readonly string evidenceDirectory = Path.Combine(AppContext.BaseDirectory, "source-unicode-evidence", Guid.NewGuid().ToString("N"));

    [SqlServerIntegrationFact]
    public async Task CurrentSourceEfAndExplicitSqlParameterMatricesRetainIndependentReceipts()
    {
        Assert.True(OperatingSystem.IsLinux(), "The bounded witness uses the existing Linux hosted SQL adapter lane.");
        var available = long.Parse(File.ReadLines("/proc/meminfo").Single(line => line.StartsWith("MemAvailable:", StringComparison.Ordinal))
            .Split(' ', StringSplitOptions.RemoveEmptyEntries)[1], System.Globalization.CultureInfo.InvariantCulture) * 1024;
        Assert.True(available >= 4L * 1024 * 1024 * 1024, "SQL witness admission requires at least 4 GiB available; do not lower this guard.");
        var owner = Guid.NewGuid().ToString("N");
        var name = "source-unicode-" + owner;
        using var lifetime = new CancellationTokenSource(TimeSpan.FromMinutes(10));
        using var docker = new DockerClientBuilder().WithEndpoint(new Uri("unix:///var/run/docker.sock")).Build();
        var container = new MsSqlBuilder(Image)
            .WithDockerEndpoint("unix:///var/run/docker.sock")
            .WithName(name)
            .WithLabel(OwnerLabel, owner)
            .WithLabel("com.maliev.expires-utc", DateTime.UtcNow.AddMinutes(12).ToString("o"))
            .WithEnvironment("MSSQL_MEMORY_LIMIT_MB", "2560")
            .WithCreateParameterModifier(parameters =>
            {
                var host = parameters.HostConfig ?? throw new InvalidOperationException("Container host configuration is required.");
                host.Memory = 3L * 1024 * 1024 * 1024;
                host.MemorySwap = host.Memory;
                host.NanoCPUs = 2_000_000_000;
                foreach (var bindings in host.PortBindings.Values)
                {
                    foreach (var binding in bindings)
                    {
                        binding.HostIP = "127.0.0.1";
                    }
                }
            }).Build();
        string? id = null;
        Exception? primaryFailure = null;
        Exception? cleanupFailure = null;
        try
        {
            WriteEvidence("planned", new { Stage = "planned", Owner = owner, Name = name, Image, Persistent = false });
            using var sourceBindings = JsonDocument.Parse(File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "SourceUnicodeWitness", "source-bindings.json")));
            WriteEvidence("source-bindings", sourceBindings.RootElement);
            await container.StartAsync(lifetime.Token);
            var inspected = await docker.Containers.InspectContainerAsync(container.Id, lifetime.Token);
            id = inspected.ID;
            var inspectedConfig = inspected.Config ?? throw new InvalidOperationException("Owned container configuration is missing.");
            var inspectedHost = inspected.HostConfig ?? throw new InvalidOperationException("Owned container limits are missing.");
            var inspectedNetwork = inspected.NetworkSettings ?? throw new InvalidOperationException("Owned container bindings are missing.");
            Assert.Equal(owner, inspectedConfig.Labels[OwnerLabel]);
            Assert.Equal("/" + name, inspected.Name);
            Assert.Empty(inspected.Mounts);
            Assert.Equal(3L * 1024 * 1024 * 1024, inspectedHost.Memory);
            Assert.Equal(inspectedHost.Memory, inspectedHost.MemorySwap);
            Assert.Equal(2_000_000_000, inspectedHost.NanoCPUs);
            Assert.All(inspectedNetwork.Ports.Values.SelectMany(value => value), binding => Assert.Equal("127.0.0.1", binding.HostIP));
            WriteEvidence("running", new
            {
                Stage = "running",
                Owner = owner,
                Id = id,
                inspected.Created,
                inspected.Image,
                inspectedHost.Memory,
                inspectedHost.MemorySwap,
                inspectedHost.NanoCPUs,
                inspectedNetwork.Ports,
                Persistent = false,
            });
            var connection = new SqlConnectionStringBuilder(container.GetConnectionString())
            {
                DataSource = $"127.0.0.1,{container.GetMappedPublicPort(1433)}",
                Pooling = false,
                ConnectTimeout = 15,
            };
            await CreateDatabaseAsync(connection.ConnectionString, "EfSourceWitness", lifetime.Token);
            await CreateDatabaseAsync(connection.ConnectionString, "RawParameterControl", lifetime.Token);
            connection.InitialCatalog = "EfSourceWitness";
            var ef = await RunIsolatedEfAsync(connection.ConnectionString, lifetime.Token);
            WriteEvidence("ef-8.0.28", ef);
            Assert.Equal("EF8.0.28", ef.Provider);
            Assert.Contains(ef.Assemblies, value => value.Name == "Microsoft.EntityFrameworkCore" && value.InformationalVersion!.StartsWith("8.0.28", StringComparison.Ordinal));
            Assert.Contains(ef.Assemblies, value => value.Name == "Microsoft.EntityFrameworkCore.Relational" && value.InformationalVersion!.StartsWith("8.0.28", StringComparison.Ordinal));
            Assert.Contains(ef.Assemblies, value => value.Name == "Microsoft.EntityFrameworkCore.SqlServer" && value.InformationalVersion!.StartsWith("8.0.28", StringComparison.Ordinal));
            Assert.Contains(ef.Assemblies, value => value.Name == "Microsoft.Data.SqlClient" && value.InformationalVersion!.StartsWith("5.1.7", StringComparison.Ordinal));
            Assert.All(ef.Assemblies, value => Assert.Equal("source-ef-8.0.28", value.LoadContext));
            Assert.All(ef.Assemblies, value => Assert.StartsWith("source-ef-8.0.28" + Path.DirectorySeparatorChar, value.RelativePath, StringComparison.Ordinal));
            Assert.Equal(432, ef.Observations.Length);
            VerifyObservations(ef.Observations, false);
            connection.InitialCatalog = "RawParameterControl";
            var raw = await RunRawAsync(connection.ConnectionString, lifetime.Token);
            WriteEvidence("raw-sqlclient-7.1", raw);
            Assert.Equal(864, raw.Observations.Length);
            Assert.Contains(raw.Assemblies, value => value.Name == "Microsoft.Data.SqlClient" && value.InformationalVersion!.StartsWith("7.1.0", StringComparison.Ordinal));
            VerifyObservations(raw.Observations, true);
        }
        catch (Exception error)
        {
            primaryFailure = error;
            WriteEvidence("failure", new { Stage = "failed", ExceptionType = error.GetType().FullName });
        }
        finally
        {
            using var cleanup = new CancellationTokenSource(TimeSpan.FromSeconds(60));
            try
            {
                try
                {
                    // Name lookup covers a failed StartAsync after creation but before its handle was returned.
                    var owned = await docker.Containers.InspectContainerAsync(id ?? name, cleanup.Token);
                    var ownedConfig = owned.Config;
                    Assert.NotNull(ownedConfig);
                    Assert.Equal(owner, ownedConfig.Labels[OwnerLabel]);
                    Assert.Equal("/" + name, owned.Name);
                    id = owned.ID;
                    await container.StopAsync(cleanup.Token);
                    await container.DisposeAsync().AsTask().WaitAsync(cleanup.Token);
                    var absent = await Assert.ThrowsAsync<DockerContainerNotFoundException>(() => docker.Containers.InspectContainerAsync(id, cleanup.Token));
                    Assert.Equal(HttpStatusCode.NotFound, absent.StatusCode);
                    WriteEvidence("cleanup", new { Stage = "removed", Owner = owner, Id = id, Absent = true });
                }
                catch (DockerApiException missing) when (missing.StatusCode == HttpStatusCode.NotFound && id is null)
                {
                    await container.DisposeAsync().AsTask().WaitAsync(cleanup.Token);
                    WriteEvidence("cleanup", new { Stage = "not-created", Owner = owner, Name = name, Absent = true });
                }
            }
            catch (Exception error)
            {
                cleanupFailure = error;
            }
        }
        if (primaryFailure is not null && cleanupFailure is not null)
        {
            throw new AggregateException("Synthetic provider validation and owned cleanup both failed.", primaryFailure, cleanupFailure);
        }

        if (primaryFailure is not null)
        {
            ExceptionDispatchInfo.Capture(primaryFailure).Throw();
        }

        if (cleanupFailure is not null)
        {
            ExceptionDispatchInfo.Capture(cleanupFailure).Throw();
        }
    }

    private void WriteEvidence(string name, object value)
    {
        _ = Directory.CreateDirectory(evidenceDirectory);
        var json = JsonSerializer.Serialize(value);
        File.WriteAllText(Path.Combine(evidenceDirectory, name + ".json"), json);
        output.WriteLine(json);
    }

    [Fact]
    public void WitnessFieldRosterRetainsAcceptedFieldsAndAddsNullableCatalogBoundaries()
    {
        Assert.Equal(
            new[]
            {
                ("Order.TrackingNumber", "TrackingNumber", 250, false, (string?)null),
                ("Order.Name", "Name", 100, false, "unnamed"),
                ("Order.Description", "Description", 250, false, null),
                ("Company.Name", "Name", 256, true, null),
                ("Company.Registrar", "Registrar", 256, false, null),
                ("Company.TaxNumber", "TaxNumber", 256, false, null),
                ("Category.Name", "Name", 50, false, null),
                ("FileFormat.Name", "Name", 50, false, null),
                ("FileFormat.Extension", "Extension", 50, false, null),
            },
            FieldCase.All.Select(field => (field.Name, field.Column, field.Capacity, field.Required, field.InsertDefault)));
    }

    [Fact]
    public void ReceiptHashPreservesUtf16CodeUnitsIncludingUnpairedSurrogates()
    {
        Assert.NotEqual(ValueEvidence.From("\ud800"), ValueEvidence.From("\ufffd"));
        Assert.Equal(2, ValueEvidence.From("😀").Utf16Units);
        Assert.NotEqual(ValueEvidence.From(null), ValueEvidence.From(""));
    }

    private static async Task<ProviderReceipt> RunIsolatedEfAsync(string connectionString, CancellationToken token)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "source-ef-8.0.28", "SourceUnicodeProviderWitness.dll");
        var context = new WitnessLoadContext(path);
        try
        {
            var assembly = context.LoadFromAssemblyPath(path);
            var method = assembly.GetType("Legacy.Maliev.DataMigration.SourceUnicodeWitness.ProviderWitness", true)!
                .GetMethod("RunAsync", BindingFlags.Public | BindingFlags.Static)!;
            var pending = (Task<string>)method.Invoke(null, [connectionString, token])!;
            // The helper shares this finite token and must finish its connection scopes before container cleanup.
            var json = await pending;
            return JsonSerializer.Deserialize<ProviderReceipt>(json) ?? throw new InvalidOperationException("Missing EF receipt.");
        }
        finally
        {
            context.Unload();
        }
    }

    private sealed class WitnessLoadContext(string path) : AssemblyLoadContext("source-ef-8.0.28", isCollectible: true)
    {
        private readonly AssemblyDependencyResolver resolver = new(path);
        private readonly string root = Path.GetDirectoryName(Path.GetFullPath(path)) + Path.DirectorySeparatorChar;
        protected override Assembly? Load(AssemblyName assemblyName)
        {
            var resolved = resolver.ResolveAssemblyToPath(assemblyName);
            return resolved is not null
                ? !Path.GetFullPath(resolved).StartsWith(root, StringComparison.Ordinal)
                    ? throw new FileNotFoundException("An isolated dependency resolved outside the witness directory.")
                    : LoadFromAssemblyPath(resolved)
                : assemblyName.Name!.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.Ordinal) ||
                assemblyName.Name.StartsWith("Microsoft.Data.", StringComparison.Ordinal) ||
                assemblyName.Name.StartsWith("Microsoft.Extensions.", StringComparison.Ordinal) ||
                assemblyName.Name.StartsWith("Microsoft.Identity", StringComparison.Ordinal) ||
                assemblyName.Name.StartsWith("Azure.", StringComparison.Ordinal) ||
                assemblyName.Name.StartsWith("Microsoft.SqlServer.", StringComparison.Ordinal)
                ? throw new FileNotFoundException("The isolated source provider dependency must not fall back to the host.")
                : null;
        }
        protected override nint LoadUnmanagedDll(string unmanagedDllName)
        {
            var resolved = resolver.ResolveUnmanagedDllToPath(unmanagedDllName);
            return resolved is not null && !Path.GetFullPath(resolved).StartsWith(root, StringComparison.Ordinal)
                ? throw new FileNotFoundException("An isolated native dependency resolved outside the witness directory.")
                : resolved is null ? nint.Zero : LoadUnmanagedDllFromPath(resolved);
        }
    }

    private static void VerifyObservations(Observation[] observations, bool raw)
    {
        Assert.Equal(observations.Length, observations.Select(value => (value.Field, value.Vector, value.Update, value.AnsiWarnings, value.ExplicitParameterSize)).Distinct().Count());
        var expected = new HashSet<(string Field, string Vector, bool Update, bool AnsiWarnings, int? ExplicitParameterSize)>();
        foreach (var field in FieldCase.All)
        {
            foreach (var vector in field.Vectors())
            {
                foreach (var update in new[] { false, true })
                {
                    foreach (var ansi in new[] { true, false })
                    {
                        foreach (var size in raw ? new int?[] { field.Capacity, 4000 } : new int?[] { null })
                        {
                            Assert.True(expected.Add((field.Name, vector.Name, update, ansi, size)), "Witness matrix identity is duplicated.");
                        }
                    }
                }
            }
        }
        Assert.True(expected.SetEquals(observations.Select(value => (value.Field, value.Vector, value.Update, value.AnsiWarnings, value.ExplicitParameterSize))),
            "Every declared field/vector/operation/session/parameter-size identity must be observed exactly once.");
        foreach (var row in observations)
        {
            var field = Assert.Single(FieldCase.All, value => value.Name == row.Field);
            Assert.Equal(row.AnsiWarnings ? 1 : 0, row.ActualAnsiWarnings);
            Assert.True(row.OtherFieldsRetained);
            var expectedImmediate = !raw && !row.Update && row.Input.IsNull && field.InsertDefault is not null && row.Succeeded
                ? ValueEvidence.From(field.InsertDefault) : row.Input;
            if (raw || row.Input.IsNull || row.Input.Utf16Units <= field.Capacity)
            {
                Assert.Equal(expectedImmediate, row.ImmediateEntity);
            }

            Assert.Equal(row.Succeeded && !row.Update ? 1 : 0, row.RowCountDelta);
            Assert.NotEmpty(row.Parameters);
            Assert.Contains(row.Parameters, value => value.Type == "NVarChar");
            if (!raw && !row.Update && row.Input.IsNull && field.InsertDefault is not null)
            {
                Assert.DoesNotContain(row.Parameters, value => value.IsSelectedField);
            }
            else
            {
                var selected = Assert.Single(row.Parameters, value => value.IsSelectedField);
                Assert.Equal("NVarChar", selected.Type);
                Assert.Equal(row.Input.Utf16Units, selected.InputUtf16Units);
                Assert.Equal(row.Input.IsNull, selected.ValueIsNull);
            }
            if (raw)
            {
                Assert.Contains(row.Parameters, value => value.Size == row.ExplicitParameterSize);
            }

            if (row.Input.IsNull && field.Required)
            {
                Assert.False(row.Succeeded);
                Assert.Contains(515, row.SqlErrorNumbers);
            }
            else if (row.Input.IsNull || row.Input.Utf16Units <= field.Capacity)
            {
                Assert.True(row.Succeeded);
                var expectedStored = !raw && !row.Update && row.Input.IsNull && field.InsertDefault is not null
                    ? ValueEvidence.From(field.InsertDefault) : row.Input;
                Assert.Equal(expectedStored, row.FreshRead);
                Assert.Equal(expectedStored.Utf16LittleEndianSha256, row.StoredSha256);
            }
            if (row.Succeeded)
            {
                Assert.Empty(row.SqlErrorNumbers);
                Assert.True(row.StoredBytes is null || row.StoredBytes <= field.Capacity * 2);
            }
            else
            {
                Assert.NotEmpty(row.SqlErrorNumbers);
                if (row.Input.IsNull && field.Required)
                {
                    Assert.All(row.SqlErrorNumbers, number => Assert.True(number is 515 or 3621));
                }
                else
                {
                    Assert.True(row.Input.Utf16Units > field.Capacity);
                    Assert.Contains(row.SqlErrorNumbers, number => number is 8152 or 2628);
                    Assert.All(row.SqlErrorNumbers, number => Assert.True(number is 8152 or 2628 or 3621));
                }
                Assert.Equal(ValueEvidence.From(row.Update ? "before" : null), row.FreshRead);
            }
        }
    }

    private static async Task CreateDatabaseAsync(string connectionString, string database, CancellationToken token)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(token);
        await ExecuteAsync(connection, $"CREATE DATABASE [{database}];", token);
    }

    private static async Task<ProviderReceipt> RunRawAsync(string connectionString, CancellationToken token)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(token);
        await ExecuteAsync(connection, "CREATE TABLE Orders (ID int IDENTITY PRIMARY KEY, Name nvarchar(100) NULL DEFAULT(N'unnamed'), Description nvarchar(250) NULL, TrackingNumber nvarchar(250) NULL); CREATE TABLE Company (ID int IDENTITY PRIMARY KEY, Name nvarchar(256) NOT NULL, Registrar nvarchar(256) NULL, TaxNumber nvarchar(256) NULL); CREATE TABLE Category (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL); CREATE TABLE FileFormat (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL, Extension nvarchar(50) NULL);", token);
        var observations = new List<Observation>();
        foreach (var field in FieldCase.All)
        {
            foreach (var size in new[] { field.Capacity, 4000 })
            {
                foreach (var ansi in new[] { true, false })
                {
                    foreach (var update in new[] { false, true })
                    {
                        foreach (var (Name, Value) in field.Vectors())
                        {
                            observations.Add(await ObserveRawAsync(connection, field, size, ansi, update, Name, Value, token));
                        }
                    }
                }
            }
        }

        return new("ExplicitSqlClient7.1", RuntimeInformation.FrameworkDescription, connection.ServerVersion,
            [AssemblyEvidence.From(typeof(SqlConnection).Assembly)], observations.ToArray());
    }

    private static async Task<Observation> ObserveRawAsync(SqlConnection connection, FieldCase field, int size,
        bool ansi, bool update, string vector, string? input, CancellationToken token)
    {
        await ExecuteAsync(connection, $"SET ANSI_WARNINGS {(ansi ? "ON" : "OFF")};", token);
        var actualAnsi = Convert.ToInt32(await ScalarAsync(connection, "SELECT SESSIONPROPERTY('ANSI_WARNINGS');", token), System.Globalization.CultureInfo.InvariantCulture);
        var columns = field.Columns;
        var id = 0;
        if (update)
        {
            id = Convert.ToInt32(await ScalarAsync(connection,
                $"INSERT [{field.Table}] ({string.Join(',', columns)}) OUTPUT INSERTED.ID VALUES ({string.Join(',', columns.Select(_ => "N'before'"))});", token), System.Globalization.CultureInfo.InvariantCulture);
        }

        var before = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        var insert = $"INSERT [{field.Table}] ({string.Join(',', columns)}) OUTPUT INSERTED.ID VALUES ({string.Join(',', columns.Select(column => column == field.Column ? "@value" : "N'before'"))});";
        await using var command = new SqlCommand(update
            ? $"UPDATE [{field.Table}] SET [{field.Column}]=@value OUTPUT INSERTED.ID WHERE ID=@id;" : insert, connection)
        { CommandTimeout = 30 };
        var parameter = command.Parameters.Add("@value", SqlDbType.NVarChar, size);
        parameter.Value = (object?)input ?? DBNull.Value;
        _ = command.Parameters.AddWithValue("@id", id);
        var errors = Array.Empty<int>();
        var succeeded = false;
        try
        {
            id = Convert.ToInt32(await command.ExecuteScalarAsync(token), System.Globalization.CultureInfo.InvariantCulture);
            succeeded = true;
        }
        catch (SqlException error)
        {
            errors = error.Errors.Cast<SqlError>().Select(value => value.Number).Distinct().Order().ToArray();
        }
        var after = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        await using var read = new SqlCommand($"SELECT [{field.Column}],DATALENGTH([{field.Column}]),CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varbinary(max),[{field.Column}])),2),{string.Join(',', columns)} FROM [{field.Table}] WHERE ID=@id;", connection) { CommandTimeout = 30 };
        _ = read.Parameters.AddWithValue("@id", id);
        await using var reader = await read.ExecuteReaderAsync(token);
        string? stored = null;
        int? bytes = null;
        string? hash = null;
        var otherFields = true;
        if (await reader.ReadAsync(token))
        {
            stored = reader.IsDBNull(0) ? null : reader.GetString(0);
            bytes = reader.IsDBNull(1) ? null : reader.GetInt32(1);
            hash = reader.IsDBNull(2) ? null : reader.GetString(2);
            for (var index = 0; index < columns.Length; index++)
            {
                if (columns[index] != field.Column)
                {
                    otherFields &= reader.GetString(index + 3) == "before";
                }
            }
        }
        return new("ExplicitSqlClient7.1", field.Name, vector, update, ansi, actualAnsi, size, succeeded, errors,
            ValueEvidence.From(input), ValueEvidence.From(input), ValueEvidence.From(stored), bytes, hash,
            after - before, otherFields,
            [new(parameter.ParameterName, parameter.SqlDbType.ToString(), parameter.Size, parameter.IsNullable,
                input?.Length, true, input is null)]);
    }

    private static async Task ExecuteAsync(SqlConnection connection, string text, CancellationToken token)
    {
        await using var command = new SqlCommand(text, connection) { CommandTimeout = 30 };
        _ = await command.ExecuteNonQueryAsync(token);
    }

    private static async Task<object?> ScalarAsync(SqlConnection connection, string text, CancellationToken token)
    {
        await using var command = new SqlCommand(text, connection) { CommandTimeout = 30 };
        return await command.ExecuteScalarAsync(token);
    }
}
