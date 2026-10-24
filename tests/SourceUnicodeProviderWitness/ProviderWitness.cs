using System.Data.Common;
using System.Runtime.InteropServices;
using System.Runtime.Loader;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Legacy.Maliev.DataMigration.SourceUnicodeWitness;

public static class ProviderWitness
{
    public static async Task<string> RunAsync(string connectionString, CancellationToken cancellationToken)
    {
        await using var connection = new SqlConnection(connectionString);
        await connection.OpenAsync(cancellationToken);
        await ExecuteAsync(connection, "CREATE TABLE Orders (ID int IDENTITY PRIMARY KEY, Name nvarchar(100) NULL DEFAULT(N'unnamed'), Description nvarchar(250) NULL, TrackingNumber nvarchar(250) NULL); CREATE TABLE Company (ID int IDENTITY PRIMARY KEY, Name nvarchar(256) NOT NULL, Registrar nvarchar(256) NULL, TaxNumber nvarchar(256) NULL); CREATE TABLE Category (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL); CREATE TABLE FileFormat (ID int IDENTITY PRIMARY KEY, Name nvarchar(50) NULL, Extension nvarchar(50) NULL);", cancellationToken);
        var observations = new List<Observation>();
        foreach (var field in FieldCase.All)
        {
            foreach (var ansi in new[] { true, false })
            {
                foreach (var update in new[] { false, true })
                {
                    foreach (var (name, value) in field.Vectors())
                    {
                        observations.Add(await ObserveAsync(connection, field, name, value, update, ansi, cancellationToken));
                    }
                }
            }
        }
        var receipt = new ProviderReceipt("EF8.0.28", RuntimeInformation.FrameworkDescription,
            connection.ServerVersion,
            AssemblyLoadContext.GetLoadContext(typeof(ProviderWitness).Assembly)!.Assemblies
                .OrderBy(assembly => assembly.GetName().Name, StringComparer.Ordinal)
                .Select(AssemblyEvidence.From).ToArray(),
            observations.ToArray());
        return JsonSerializer.Serialize(receipt);
    }

    private static async Task<Observation> ObserveAsync(SqlConnection connection, FieldCase field, string vector,
        string? input, bool update, bool ansi, CancellationToken token)
    {
        await ExecuteAsync(connection, $"SET ANSI_WARNINGS {(ansi ? "ON" : "OFF")};", token);
        var actualAnsi = Convert.ToInt32(await ScalarAsync(connection, "SELECT SESSIONPROPERTY('ANSI_WARNINGS');", token), System.Globalization.CultureInfo.InvariantCulture);
        var capture = new ParameterCapture(field.Column);
        await using var context = new WitnessContext(connection, capture);
        var order = new Order { Name = "before", Description = "before", TrackingNumber = "before" };
        var company = new Company { Name = "before", Registrar = "before", TaxNumber = "before" };
        var category = new Category { Name = "before" };
        var fileFormat = new FileFormat { Name = "before", Extension = "before" };
        object entity = field.Table switch
        {
            "Orders" => order,
            "Company" => company,
            "Category" => category,
            "FileFormat" => fileFormat,
            _ => throw new InvalidOperationException("Unknown synthetic table."),
        };
        if (update)
        {
            _ = context.Add(entity);
            _ = await context.SaveChangesAsync(token);
        }
        var before = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        Set(entity, field, input);
        if (!update)
        {
            _ = context.Add(entity);
        }
        capture.Enabled = true;
        var errors = Array.Empty<int>();
        var succeeded = false;
        try
        {
            _ = await context.SaveChangesAsync(token);
            succeeded = true;
        }
        catch (DbUpdateException error) when (error.InnerException is SqlException sql)
        {
            errors = sql.Errors.Cast<SqlError>().Select(value => value.Number).Distinct().Order().ToArray();
        }
        finally
        {
            capture.Enabled = false;
        }
        // Original controllers return the tracked entity after SaveChanges for POST; PUT returns 204.
        var immediate = Get(entity, field);
        var id = entity switch
        {
            Order value => value.Id,
            Company value => value.Id,
            Category value => value.Id,
            FileFormat value => value.Id,
            _ => throw new InvalidOperationException("Unknown synthetic entity."),
        };
        await using var fresh = new WitnessContext(connection, new ParameterCapture(field.Column));
        object? read = field.Table switch
        {
            "Orders" => await fresh.Orders.AsNoTracking().SingleOrDefaultAsync(value => value.Id == id, token),
            "Company" => await fresh.Companies.AsNoTracking().SingleOrDefaultAsync(value => value.Id == id, token),
            "Category" => await fresh.Categories.AsNoTracking().SingleOrDefaultAsync(value => value.Id == id, token),
            "FileFormat" => await fresh.FileFormats.AsNoTracking().SingleOrDefaultAsync(value => value.Id == id, token),
            _ => throw new InvalidOperationException("Unknown synthetic table."),
        };
        var stored = read is null ? null : Get(read, field);
        var after = Convert.ToInt32(await ScalarAsync(connection, $"SELECT COUNT(*) FROM [{field.Table}];", token), System.Globalization.CultureInfo.InvariantCulture);
        await using var physical = new SqlCommand($"SELECT DATALENGTH([{field.Column}]), CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varbinary(max),[{field.Column}])),2) FROM [{field.Table}] WHERE ID=@id;", connection) { CommandTimeout = 30 };
        _ = physical.Parameters.AddWithValue("@id", id);
        await using var reader = await physical.ExecuteReaderAsync(token);
        int? bytes = null;
        string? hash = null;
        if (await reader.ReadAsync(token))
        {
            bytes = reader.IsDBNull(0) ? null : reader.GetInt32(0);
            hash = reader.IsDBNull(1) ? null : reader.GetString(1);
        }
        var otherFields = read is null || field.Columns.All(column => column == field.Column || Get(read, field with { Column = column }) == "before");
        return new("EF8.0.28", field.Name, vector, update, ansi, actualAnsi, null, succeeded, errors,
            ValueEvidence.From(input), ValueEvidence.From(immediate), ValueEvidence.From(stored),
            bytes, hash, after - before, otherFields, capture.Parameters.ToArray());
    }

    private static string? Get(object entity, FieldCase field)
    {
        return entity is Category category
            ? field.Column == "Name" ? category.Name : throw new InvalidOperationException("Unknown synthetic field.")
            : entity is FileFormat fileFormat
            ? field.Column switch
            {
                "Name" => fileFormat.Name,
                "Extension" => fileFormat.Extension,
                _ => throw new InvalidOperationException("Unknown synthetic field."),
            } : entity is Order order
                ? field.Column switch
                {
                    "Name" => order.Name,
                    "Description" => order.Description,
                    "TrackingNumber" => order.TrackingNumber,
                    _ => throw new InvalidOperationException("Unknown synthetic field."),
                } : field.Column switch
                {
                    "Name" => ((Company)entity).Name,
                    "Registrar" => ((Company)entity).Registrar,
                    "TaxNumber" => ((Company)entity).TaxNumber,
                    _ => throw new InvalidOperationException("Unknown synthetic field."),
                };
    }

    private static void Set(object entity, FieldCase field, string? value)
    {
        if (entity is Category category)
        {
            category.Name = field.Column == "Name" ? value : throw new InvalidOperationException("Unknown synthetic field.");
        }
        else if (entity is FileFormat fileFormat)
        {
            if (field.Column == "Name")
            {
                fileFormat.Name = value;
            }
            else
            {
                fileFormat.Extension = field.Column == "Extension" ? value : throw new InvalidOperationException("Unknown synthetic field.");
            }
        }
        else if (entity is Order order)
        {
            if (field.Column == "Name")
            {
                order.Name = value;
            }
            else if (field.Column == "Description")
            {
                order.Description = value;
            }
            else
            {
                order.TrackingNumber = field.Column == "TrackingNumber" ? value : throw new InvalidOperationException("Unknown synthetic field.");
            }
        }
        else if (field.Column == "Name")
        {
            ((Company)entity).Name = value;
        }
        else if (field.Column == "Registrar")
        {
            ((Company)entity).Registrar = value;
        }
        else
        {
            ((Company)entity).TaxNumber = field.Column == "TaxNumber" ? value : throw new InvalidOperationException("Unknown synthetic field.");
        }
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

    private sealed class ParameterCapture(string selectedColumn) : DbCommandInterceptor
    {
        internal bool Enabled { get; set; }
        internal List<ParameterEvidence> Parameters { get; } = [];
        private void Capture(DbCommand command)
        {
            if (!Enabled)
            {
                return;
            }
            if (command.CommandText.Length > 16_384)
            {
                throw new InvalidOperationException("Synthetic command exceeded its bound.");
            }
            var selectedParameter = SelectedParameter(command.CommandText, selectedColumn);
            Parameters.AddRange(command.Parameters.Cast<SqlParameter>().Select(parameter => new ParameterEvidence(
                parameter.ParameterName, parameter.SqlDbType.ToString(), parameter.Size, parameter.IsNullable,
                parameter.Value is string text ? text.Length : null,
                parameter.ParameterName == selectedParameter, parameter.Value is null or DBNull)));
        }

        private static string? SelectedParameter(string command, string column)
        {
            var update = Regex.Match(command, @"\[" + Regex.Escape(column) + @"\]\s*=\s*(?<parameter>@\w+)",
                RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            if (update.Success)
            {
                return update.Groups["parameter"].Value;
            }
            var insert = Regex.Match(command,
                @"INSERT\s+INTO\s+\[(?:Orders|Company|Category|FileFormat)\]\s*\((?<columns>[^)]*)\).*?VALUES\s*\((?<values>[^)]*)\)",
                RegexOptions.Singleline | RegexOptions.CultureInvariant, TimeSpan.FromSeconds(1));
            if (!insert.Success)
            {
                throw new InvalidOperationException("Unexpected synthetic EF command shape.");
            }
            var columns = insert.Groups["columns"].Value.Split(',').Select(value => value.Trim().Trim('[', ']')).ToArray();
            var values = insert.Groups["values"].Value.Split(',').Select(value => value.Trim()).ToArray();
            if (columns.Length != values.Length)
            {
                throw new InvalidOperationException("Unpaired synthetic command columns.");
            }
            var index = Array.IndexOf(columns, column);
            return index < 0 ? null : values[index];
        }
        public override ValueTask<InterceptionResult<DbDataReader>> ReaderExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<DbDataReader> result, CancellationToken cancellationToken = default)
        {
            Capture(command);
            return ValueTask.FromResult(result);
        }
        public override ValueTask<InterceptionResult<int>> NonQueryExecutingAsync(DbCommand command,
            CommandEventData eventData, InterceptionResult<int> result, CancellationToken cancellationToken = default)
        {
            Capture(command);
            return ValueTask.FromResult(result);
        }
    }

    private sealed class WitnessContext(SqlConnection connection, ParameterCapture capture) : DbContext
    {
        internal DbSet<Order> Orders => Set<Order>();
        internal DbSet<Company> Companies => Set<Company>();
        internal DbSet<Category> Categories => Set<Category>();
        internal DbSet<FileFormat> FileFormats => Set<FileFormat>();
        protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
        {
            _ = optionsBuilder.UseSqlServer(connection, options => options.CommandTimeout(30)).AddInterceptors(capture);
        }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            _ = modelBuilder.Entity<Order>(entity =>
            {
                _ = entity.ToTable("Orders");
                _ = entity.Property(value => value.Id).HasColumnName("ID");
                _ = entity.Property(value => value.Name).HasMaxLength(100).HasDefaultValueSql("(N'unnamed')");
                _ = entity.Property(value => value.Description).HasMaxLength(250);
                _ = entity.Property(value => value.TrackingNumber).HasMaxLength(250);
            });
            _ = modelBuilder.Entity<Company>(entity =>
            {
                _ = entity.ToTable("Company");
                _ = entity.Property(value => value.Id).HasColumnName("ID");
                _ = entity.Property(value => value.Name).IsRequired().HasMaxLength(256);
                _ = entity.Property(value => value.Registrar).HasMaxLength(256);
                _ = entity.Property(value => value.TaxNumber).HasMaxLength(256);
            });
            _ = modelBuilder.Entity<Category>(entity =>
            {
                _ = entity.ToTable("Category");
                _ = entity.Property(value => value.Id).HasColumnName("ID");
                _ = entity.Property(value => value.Name).HasMaxLength(50);
            });
            _ = modelBuilder.Entity<FileFormat>(entity =>
            {
                _ = entity.ToTable("FileFormat");
                _ = entity.Property(value => value.Id).HasColumnName("ID");
                _ = entity.Property(value => value.Name).HasMaxLength(50);
                _ = entity.Property(value => value.Extension).HasMaxLength(50);
            });
        }
    }

    private sealed class Order
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Description { get; set; }
        public string? TrackingNumber { get; set; }
    }

    private sealed class Company
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Registrar { get; set; }
        public string? TaxNumber { get; set; }
    }

    private sealed class Category
    {
        public int Id { get; set; }
        public string? Name { get; set; }
    }

    private sealed class FileFormat
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public string? Extension { get; set; }
    }
}
