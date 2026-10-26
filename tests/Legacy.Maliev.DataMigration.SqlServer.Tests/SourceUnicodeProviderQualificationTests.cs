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
            Assert.Equal(624, ef.Observations.Length);
            VerifyObservations(ef.Observations, false);
            VerifyObjectNameCompanions(ef, false);
            connection.InitialCatalog = "RawParameterControl";
            var raw = await RunRawAsync(connection.ConnectionString, lifetime.Token);
            WriteEvidence("raw-sqlclient-7.1", raw);
            Assert.Equal(1248, raw.Observations.Length);
            Assert.Contains(raw.Assemblies, value => value.Name == "Microsoft.Data.SqlClient" && value.InformationalVersion!.StartsWith("7.1.1", StringComparison.Ordinal));
            VerifyObservations(raw.Observations, true);
            VerifyObjectNameCompanions(raw, true);
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
        Assert.Equal<(string Name, string Column, int Capacity, bool Required, string? InsertDefault)>(
            [
                ("Order.TrackingNumber", "TrackingNumber", 250, false, null),
                ("Order.Name", "Name", 100, false, "unnamed"),
                ("Order.Description", "Description", 250, false, null),
                ("Company.Name", "Name", 256, true, null),
                ("Company.Registrar", "Registrar", 256, false, null),
                ("Company.TaxNumber", "TaxNumber", 256, false, null),
                ("Category.Name", "Name", 50, false, null),
                ("FileFormat.Name", "Name", 50, false, null),
                ("FileFormat.Extension", "Extension", 50, false, null),
                ("Process.Name", "Name", 50, true, null),
                ("OrderStatus.Name", "Name", 50, true, null),
                ("OrderStatus.Description", "Description", 100, false, null),
                ("OrderFile.Bucket", "Bucket", 50, true, null),
            ],
            FieldCase.All.Select(field => (field.Name, field.Column, field.Capacity, field.Required, field.InsertDefault)));
    }

    [Fact]
    public void ProcessAndStatusExpansionRetainsNineFieldMatricesAndRequiredNullMetadata()
    {
        string[] retained = ["Order.TrackingNumber", "Order.Name", "Order.Description", "Company.Name", "Company.Registrar", "Company.TaxNumber", "Category.Name", "FileFormat.Name", "FileFormat.Extension"];
        Assert.Equal(retained, FieldCase.All.Take(retained.Length).Select(value => value.Name));
        Assert.Equal(["Company.Name", "Process.Name", "OrderStatus.Name", "OrderFile.Bucket"], FieldCase.All.Where(value => value.Required).Select(value => value.Name));
        var description = Assert.Single(FieldCase.All, value => value.Name == "OrderStatus.Description");
        Assert.False(description.Required);
        Assert.Null(description.InsertDefault);
        Assert.Equal(100, description.Capacity);
        foreach (var raw in new[] { false, true })
        {
            var identities = new HashSet<(string Field, string Vector, bool Update, bool Ansi, int? Size)>();
            foreach (var field in FieldCase.All)
            {
                int?[] sizes = raw ? [field.Capacity, 4000] : [null];
                Assert.Equal(12, field.Vectors().Count());
                foreach (var (vector, _) in field.Vectors())
                {
                    foreach (var update in new[] { false, true })
                    {
                        foreach (var ansi in new[] { true, false })
                        {
                            foreach (var size in sizes)
                            {
                                Assert.True(identities.Add((field.Name, vector, update, ansi, size)));
                            }
                        }
                    }
                }
            }
            Assert.Equal(raw ? 1248 : 624, identities.Count);
            Assert.Equal(raw ? 864 : 432, identities.Count(value => retained.Contains(value.Field, StringComparer.Ordinal)));
        }
    }

    [Fact]
    public void BucketExpansionRetainsTwelveFieldsAndNamesTheActualRequiredNullColumn()
    {
        string[] retained = ["Order.TrackingNumber", "Order.Name", "Order.Description", "Company.Name", "Company.Registrar", "Company.TaxNumber", "Category.Name", "FileFormat.Name", "FileFormat.Extension", "Process.Name", "OrderStatus.Name", "OrderStatus.Description"];
        Assert.Equal(retained, FieldCase.All.Take(retained.Length).Select(value => value.Name));
        var bucket = Assert.Single(FieldCase.All, value => value.Name == "OrderFile.Bucket");
        Assert.Equal(("Bucket", 50, true), (bucket.Column, bucket.Capacity, bucket.Required));
        Assert.Null(bucket.InsertDefault);
        Assert.Equal(["Bucket", "ObjectName"], bucket.Columns);
        Assert.Equal(13, FieldCase.All.Length);
        Assert.Equal(12, bucket.Vectors().Count());
        Assert.True(FieldCase.ObjectNameCompanion.Length > 4000);
        Assert.Contains("ก", FieldCase.ObjectNameCompanion, StringComparison.Ordinal);
        Assert.Contains("😀", FieldCase.ObjectNameCompanion, StringComparison.Ordinal);
        Assert.StartsWith("  ", FieldCase.ObjectNameCompanion, StringComparison.Ordinal);
        Assert.EndsWith("  ", FieldCase.ObjectNameCompanion, StringComparison.Ordinal);
        Assert.True(SqlNullFailureEvidence.NamesSelectedColumn([(515, "Cannot insert the value NULL into column 'Bucket'."), (3621, "The statement has been terminated.")], "Bucket"));
        Assert.False(SqlNullFailureEvidence.NamesSelectedColumn([(515, "Cannot insert the value NULL into column 'ObjectName'.")], "Bucket"));
        Assert.False(SqlNullFailureEvidence.NamesSelectedColumn([(515, "Cannot insert the value NULL into column 'Bucket'."), (515, "Cannot insert the value NULL into column 'ObjectName'.")], "Bucket"));
        Assert.False(SqlNullFailureEvidence.NamesSelectedColumn([(2628, "String data would be truncated.")], "Bucket"));
        foreach (var raw in new[] { false, true })
        {
            Assert.Equal(raw ? 1152 : 576, FieldCase.All.Where(value => retained.Contains(value.Name, StringComparer.Ordinal)).Sum(value => value.Vectors().Count() * 2 * 2 * (raw ? 2 : 1)));
            Assert.Equal(raw ? 96 : 48, bucket.Vectors().Count() * 2 * 2 * (raw ? 2 : 1));
        }
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
            int?[] sizes = raw ? [field.Capacity, 4000] : [null];
            foreach (var (vectorName, _) in field.Vectors())
            {
                foreach (var update in new[] { false, true })
                {
                    foreach (var ansi in new[] { true, false })
                    {
                        foreach (var size in sizes)
                        {
                            Assert.True(expected.Add((field.Name, vectorName, update, ansi, size)), "Witness matrix identity is duplicated.");
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

    private static void VerifyObjectNameCompanions(ProviderReceipt receipt, bool raw)
    {
        var observations = receipt.Observations.Where(value => value.Field == "OrderFile.Bucket").ToArray();
        Assert.Equal(raw ? 96 : 48, observations.Length);
        Assert.NotNull(receipt.Companions);
        Assert.Equal(observations.Length, receipt.Companions.Length);
        Assert.Equal(receipt.Companions.Length, receipt.Companions.Select(value => (value.Field, value.Vector, value.Update, value.AnsiWarnings, value.ExplicitParameterSize)).Distinct().Count());
        var input = ValueEvidence.From(FieldCase.ObjectNameCompanion);
        foreach (var row in receipt.Companions)
        {
            var observed = Assert.Single(observations, value => (value.Field, value.Vector, value.Update, value.AnsiWarnings, value.ExplicitParameterSize)
                == (row.Field, row.Vector, row.Update, row.AnsiWarnings, row.ExplicitParameterSize));
            Assert.Equal(receipt.Provider, row.Provider);
            Assert.Equal(input, row.Input);
            Assert.Equal(input, row.ParameterValue);
            Assert.Equal(input, row.ImmediateEntity);
            Assert.Equal(row.Update, row.ParameterFromSeed);
            Assert.Equal("NVarChar", row.Parameter.Type);
            Assert.True(row.Parameter.IsSelectedField);
            Assert.False(row.Parameter.ValueIsNull);
            Assert.Equal(input.Utf16Units, row.Parameter.InputUtf16Units);
            Assert.True(row.Parameter.Size == -1 || row.Parameter.Size >= input.Utf16Units);
            Assert.Equal(observed.Succeeded || row.Update, row.Physical.RowExists);
            Assert.Equal(row.Physical.RowExists ? input : ValueEvidence.From(null), row.FreshRead);
            Assert.Equal(row.FreshRead, row.Physical.Value);
            Assert.Equal(row.FreshRead.Utf16LittleEndianSha256, row.Physical.Sha256);
            Assert.Equal(row.Physical.RowExists ? input.Utf16Units * 2L : null, row.Physical.Bytes);
            Assert.Equal(new CompanionSchemaEvidence(true, null, "nvarchar(max)", false), row.Physical.Schema);
            if (raw)
            {
                Assert.Null(row.Model);
            }
            else
            {
                Assert.Equal(new CompanionSchemaEvidence(true, null, "nvarchar(max)", false), row.Model);
            }
            Assert.Equal(observed.Input.IsNull, row.NullFailureNamesSelectedColumn);
        }
        Assert.NotNull(receipt.RequiredColumnControls);
        Assert.Equal(4, receipt.RequiredColumnControls.Length);
        Assert.Equal(4, receipt.RequiredColumnControls.Select(value => (value.Update, value.AnsiWarnings)).Distinct().Count());
        foreach (var control in receipt.RequiredColumnControls)
        {
            Assert.Equal(receipt.Provider, control.Provider);
            Assert.Equal(control.AnsiWarnings ? 1 : 0, control.ActualAnsiWarnings);
            Assert.False(control.Succeeded);
            Assert.Contains(515, control.SqlErrorNumbers);
            Assert.All(control.SqlErrorNumbers, value => Assert.True(value is 515 or 3621));
            Assert.False(control.NamesBucketColumn);
            Assert.True(control.NamesObjectNameColumn);
            Assert.Equal(0, control.RowCountDelta);
            Assert.Equal(ValueEvidence.From(control.Update ? "before" : null), control.FreshBucket);
            Assert.Equal(control.Update, control.Physical.RowExists);
            Assert.Equal(control.Update ? input : ValueEvidence.From(null), control.Physical.Value);
            Assert.Equal(control.Physical.Value.Utf16LittleEndianSha256, control.Physical.Sha256);
            Assert.Equal(control.Update ? input.Utf16Units * 2L : null, control.Physical.Bytes);
            Assert.Equal(new CompanionSchemaEvidence(true, null, "nvarchar(max)", false), control.Physical.Schema);
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
        await ExecuteAsync(connection, "CREATE TABLE Orders (ID int IDENTITY PRIMARY KEY, Name nvarchar(100) NULL DEFAULT(N'unnamed'), Description nvarchar(250) NULL, TrackingNumber nvarchar(250) NULL); CREATE TABLE Company (ID int IDENTITY PRIMARY KEY, Name nvarchar(256) NOT NULL, Registrar nvarchar(256) NULL, TaxNumber nvarchar(256) NULL); CREATE TABLE Category (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL); CREATE TABLE FileFormat (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL, Extension nvarchar(50) NULL); CREATE TABLE Process (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NOT NULL); CREATE TABLE OrderStatus (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NOT NULL, Description nvarchar(100) NULL); CREATE TABLE OrderFile (ID int IDENTITY PRIMARY KEY, Bucket nvarchar(50) NOT NULL, ObjectName nvarchar(max) NOT NULL);", token);
        var observations = new List<Observation>();
        var companions = new List<CompanionObservation>();
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
                            observations.Add(await ObserveRawAsync(connection, field, size, ansi, update, Name, Value, companions, token));
                        }
                    }
                }
            }
        }

        var controls = new List<RequiredColumnControl>();
        foreach (var ansi in new[] { true, false })
        {
            foreach (var update in new[] { false, true })
            {
                controls.Add(await ObserveRawObjectNameRequiredAsync(connection, update, ansi, token));
            }
        }
        return new("ExplicitSqlClient7.1", RuntimeInformation.FrameworkDescription, connection.ServerVersion,
            [AssemblyEvidence.From(typeof(SqlConnection).Assembly)], observations.ToArray(), companions.ToArray(), controls.ToArray());
    }

    private static async Task<Observation> ObserveRawAsync(SqlConnection connection, FieldCase field, int size,
        bool ansi, bool update, string vector, string? input, List<CompanionObservation> companions, CancellationToken token)
    {
        await ExecuteAsync(connection, $"SET ANSI_WARNINGS {(ansi ? "ON" : "OFF")};", token);
        var actualAnsi = Convert.ToInt32(await ScalarAsync(connection, "SELECT SESSIONPROPERTY('ANSI_WARNINGS');", token), System.Globalization.CultureInfo.InvariantCulture);
        var columns = field.Columns;
        var id = 0;
        (ParameterEvidence Parameter, ValueEvidence Value)? companionCapture = null;
        if (update)
        {
            if (field.Table == "OrderFile")
            {
                await using var seed = new SqlCommand("INSERT [OrderFile] (Bucket,ObjectName) OUTPUT INSERTED.ID VALUES (N'before',@companion);", connection) { CommandTimeout = 30 };
                var companionParameter = seed.Parameters.Add("@companion", SqlDbType.NVarChar, -1);
                companionParameter.Value = FieldCase.ObjectNameCompanion;
                companionCapture = CaptureObjectNameParameter(companionParameter);
                id = Convert.ToInt32(await seed.ExecuteScalarAsync(token), System.Globalization.CultureInfo.InvariantCulture);
            }
            else
            {
                id = Convert.ToInt32(await ScalarAsync(connection,
                    $"INSERT [{field.Table}] ({string.Join(',', columns)}) OUTPUT INSERTED.ID VALUES ({string.Join(',', columns.Select(_ => "N'before'"))});", token), System.Globalization.CultureInfo.InvariantCulture);
            }
        }

        var before = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        var insert = $"INSERT [{field.Table}] ({string.Join(',', columns)}) OUTPUT INSERTED.ID VALUES ({string.Join(',', columns.Select(column => column == field.Column ? "@value" : field.Table == "OrderFile" && column == "ObjectName" ? "@companion" : "N'before'"))});";
        await using var command = new SqlCommand(update
            ? $"UPDATE [{field.Table}] SET [{field.Column}]=@value OUTPUT INSERTED.ID WHERE ID=@id;" : insert, connection)
        { CommandTimeout = 30 };
        var parameter = command.Parameters.Add("@value", SqlDbType.NVarChar, size);
        parameter.Value = (object?)input ?? DBNull.Value;
        _ = command.Parameters.AddWithValue("@id", id);
        if (field.Table == "OrderFile" && !update)
        {
            var companionParameter = command.Parameters.Add("@companion", SqlDbType.NVarChar, -1);
            companionParameter.Value = FieldCase.ObjectNameCompanion;
            companionCapture = CaptureObjectNameParameter(companionParameter);
        }
        var errors = Array.Empty<int>();
        var namesSelectedNullColumn = false;
        var succeeded = false;
        try
        {
            id = Convert.ToInt32(await command.ExecuteScalarAsync(token), System.Globalization.CultureInfo.InvariantCulture);
            succeeded = true;
        }
        catch (SqlException error)
        {
            errors = error.Errors.Cast<SqlError>().Select(value => value.Number).Distinct().Order().ToArray();
            if (field.Table == "OrderFile")
            {
                namesSelectedNullColumn = SqlNullFailureEvidence.NamesSelectedColumn(error.Errors.Cast<SqlError>().Select(value => (value.Number, value.Message)), "Bucket");
            }
        }
        var after = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        var companionPhysical = field.Table == "OrderFile" ? await ObjectNameEvidence.ReadAsync(connection, id, token) : null;
        await using var read = new SqlCommand($"SELECT [{field.Column}],DATALENGTH([{field.Column}]),CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varbinary(max),[{field.Column}])),2),{string.Join(',', columns)} FROM [{field.Table}] WHERE ID=@id;", connection) { CommandTimeout = 30 };
        _ = read.Parameters.AddWithValue("@id", id);
        await using var reader = await read.ExecuteReaderAsync(token);
        string? stored = null;
        int? bytes = null;
        string? hash = null;
        var otherFields = true;
        string? storedCompanion = null;
        if (await reader.ReadAsync(token))
        {
            stored = reader.IsDBNull(0) ? null : reader.GetString(0);
            bytes = reader.IsDBNull(1) ? null : reader.GetInt32(1);
            hash = reader.IsDBNull(2) ? null : reader.GetString(2);
            for (var index = 0; index < columns.Length; index++)
            {
                if (columns[index] != field.Column)
                {
                    otherFields &= reader.GetString(index + 3) == (field.Table == "OrderFile" && columns[index] == "ObjectName" ? FieldCase.ObjectNameCompanion : "before");
                    if (field.Table == "OrderFile" && columns[index] == "ObjectName")
                    {
                        storedCompanion = reader.GetString(index + 3);
                    }
                }
            }
        }
        if (field.Table == "OrderFile")
        {
            if (companionCapture is not { } captured || companionPhysical is null)
            {
                throw new InvalidOperationException("Missing ObjectName parameter/physical observation.");
            }
            companions.Add(new("ExplicitSqlClient7.1", field.Name, vector, update, ansi, size,
                ValueEvidence.From(FieldCase.ObjectNameCompanion), captured.Value, captured.Parameter, update,
                captured.Value, ValueEvidence.From(storedCompanion), companionPhysical, null, namesSelectedNullColumn));
        }
        return new("ExplicitSqlClient7.1", field.Name, vector, update, ansi, actualAnsi, size, succeeded, errors,
            ValueEvidence.From(input), ValueEvidence.From(input), ValueEvidence.From(stored), bytes, hash,
            after - before, otherFields,
            [new(parameter.ParameterName, parameter.SqlDbType.ToString(), parameter.Size, parameter.IsNullable,
                input?.Length, true, input is null)]);
    }

    private static (ParameterEvidence Parameter, ValueEvidence Value) CaptureObjectNameParameter(SqlParameter parameter)
    {
        var value = parameter.Value as string;
        return (new(parameter.ParameterName, parameter.SqlDbType.ToString(), parameter.Size, parameter.IsNullable,
            value?.Length, true, parameter.Value is null or DBNull), ValueEvidence.From(value));
    }

    private static async Task<RequiredColumnControl> ObserveRawObjectNameRequiredAsync(SqlConnection connection, bool update, bool ansi, CancellationToken token)
    {
        await ExecuteAsync(connection, $"SET ANSI_WARNINGS {(ansi ? "ON" : "OFF")};", token);
        var actualAnsi = Convert.ToInt32(await ScalarAsync(connection, "SELECT SESSIONPROPERTY('ANSI_WARNINGS');", token), System.Globalization.CultureInfo.InvariantCulture);
        var id = 0;
        if (update)
        {
            await using var seed = new SqlCommand("INSERT [OrderFile] (Bucket,ObjectName) OUTPUT INSERTED.ID VALUES (N'before',@companion);", connection) { CommandTimeout = 30 };
            _ = seed.Parameters.Add("@companion", SqlDbType.NVarChar, -1);
            seed.Parameters["@companion"].Value = FieldCase.ObjectNameCompanion;
            id = Convert.ToInt32(await seed.ExecuteScalarAsync(token), System.Globalization.CultureInfo.InvariantCulture);
        }
        var before = Convert.ToInt32(await ScalarAsync(connection, "SELECT COUNT(*) FROM OrderFile;", token), System.Globalization.CultureInfo.InvariantCulture);
        await using var command = new SqlCommand(update
            ? "UPDATE [OrderFile] SET ObjectName=@value OUTPUT INSERTED.ID WHERE ID=@id;"
            : "INSERT [OrderFile] (Bucket,ObjectName) OUTPUT INSERTED.ID VALUES (N'before',@value);", connection)
        { CommandTimeout = 30 };
        _ = command.Parameters.Add("@value", SqlDbType.NVarChar, -1);
        command.Parameters["@value"].Value = DBNull.Value;
        _ = command.Parameters.AddWithValue("@id", id);
        SqlError[] errors = [];
        var succeeded = false;
        try
        {
            id = Convert.ToInt32(await command.ExecuteScalarAsync(token), System.Globalization.CultureInfo.InvariantCulture);
            succeeded = true;
        }
        catch (SqlException error)
        {
            errors = error.Errors.Cast<SqlError>().ToArray();
        }
        var after = Convert.ToInt32(await ScalarAsync(connection, "SELECT COUNT(*) FROM OrderFile;", token), System.Globalization.CultureInfo.InvariantCulture);
        var bucket = await ScalarAsync(connection, $"SELECT Bucket FROM OrderFile WHERE ID={id};", token);
        return new("ExplicitSqlClient7.1", update, ansi, actualAnsi, succeeded,
            errors.Select(value => value.Number).Distinct().Order().ToArray(),
            SqlNullFailureEvidence.NamesSelectedColumn(errors.Select(value => (value.Number, value.Message)), "Bucket"),
            SqlNullFailureEvidence.NamesSelectedColumn(errors.Select(value => (value.Number, value.Message)), "ObjectName"),
            after - before, ValueEvidence.From(bucket as string), await ObjectNameEvidence.ReadAsync(connection, id, token));
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
