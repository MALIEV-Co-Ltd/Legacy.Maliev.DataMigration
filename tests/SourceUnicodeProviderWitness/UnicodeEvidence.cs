using System.Buffers.Binary;
using System.Data;
using System.Data.Common;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;

namespace Legacy.Maliev.DataMigration.SourceUnicodeWitness;

public sealed record ValueEvidence(bool IsNull, int? Utf16Units, string? Utf16LittleEndianSha256)
{
    public static ValueEvidence From(string? value)
    {
        if (value is null)
        {
            return new(true, null, null);
        }
        var bytes = new byte[value.Length * 2];
        for (var index = 0; index < value.Length; index++)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(bytes.AsSpan(index * 2, 2), value[index]);
        }
        return new(false, value.Length, Convert.ToHexString(SHA256.HashData(bytes)));
    }
}

public sealed record AssemblyEvidence(string Name, string? Version, string? InformationalVersion, string Sha256, string? LoadContext, string RelativePath)
{
    public static AssemblyEvidence From(Assembly assembly)
    {
        return new(
            assembly.GetName().Name!, assembly.GetName().Version?.ToString(),
            assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion,
            Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(assembly.Location))),
            AssemblyLoadContext.GetLoadContext(assembly)?.Name, Path.GetRelativePath(AppContext.BaseDirectory, assembly.Location));
    }
}

public sealed record ParameterEvidence(string Name, string Type, int Size, bool IsNullable, int? InputUtf16Units,
    bool IsSelectedField, bool ValueIsNull);
public sealed record Observation(string Provider, string Field, string Vector, bool Update, bool AnsiWarnings,
    int ActualAnsiWarnings, int? ExplicitParameterSize, bool Succeeded, int[] SqlErrorNumbers,
    ValueEvidence Input, ValueEvidence ImmediateEntity, ValueEvidence FreshRead,
    int? StoredBytes, string? StoredSha256, int RowCountDelta, bool OtherFieldsRetained,
    ParameterEvidence[] Parameters);
public sealed record ProviderReceipt(string Provider, string Runtime, string SqlServerVersion,
    AssemblyEvidence[] Assemblies, Observation[] Observations, CompanionObservation[]? Companions = null,
    RequiredColumnControl[]? RequiredColumnControls = null);

public sealed record CompanionSchemaEvidence(bool Required, int? MaxLength, string StoreType, bool HasDefault);
public sealed record CompanionPhysicalRead(bool RowExists, ValueEvidence Value, long? Bytes, string? Sha256,
    CompanionSchemaEvidence Schema);
public sealed record CompanionObservation(string Provider, string Field, string Vector, bool Update, bool AnsiWarnings,
    int? ExplicitParameterSize, ValueEvidence Input, ValueEvidence ParameterValue, ParameterEvidence Parameter,
    bool ParameterFromSeed, ValueEvidence ImmediateEntity, ValueEvidence FreshRead, CompanionPhysicalRead Physical,
    CompanionSchemaEvidence? Model, bool NullFailureNamesSelectedColumn);
public sealed record RequiredColumnControl(string Provider, bool Update, bool AnsiWarnings, int ActualAnsiWarnings,
    bool Succeeded, int[] SqlErrorNumbers, bool NamesBucketColumn, bool NamesObjectNameColumn, int RowCountDelta,
    ValueEvidence FreshBucket, CompanionPhysicalRead Physical);

public static class SqlNullFailureEvidence
{
    public static bool NamesSelectedColumn(IEnumerable<(int Number, string Message)> errors, string column)
    {
        if (column is not ("Bucket" or "ObjectName"))
        {
            throw new InvalidOperationException("Unknown required-column control.");
        }
        var failures = errors.Where(value => value.Number == 515).ToArray();
        return failures.Length != 0 && failures.All(value => value.Message.Contains("column '" + column + "'", StringComparison.Ordinal));
    }
}

public static class ObjectNameEvidence
{
    public static async Task<CompanionPhysicalRead> ReadAsync(DbConnection connection, int id, CancellationToken token)
    {
        await using var command = connection.CreateCommand();
        command.CommandTimeout = 30;
        command.CommandText = """
            SELECT f.ID,f.ObjectName,DATALENGTH(f.ObjectName),CONVERT(varchar(64),HASHBYTES('SHA2_256',CONVERT(varbinary(max),f.ObjectName)),2),
                c.is_nullable,c.max_length,t.name,c.default_object_id
            FROM sys.columns c JOIN sys.types t ON t.user_type_id=c.user_type_id
            LEFT JOIN dbo.OrderFile f ON f.ID=@id
            WHERE c.object_id=OBJECT_ID(N'dbo.OrderFile') AND c.name=N'ObjectName';
            """;
        var parameter = command.CreateParameter();
        parameter.ParameterName = "@id";
        parameter.DbType = DbType.Int32;
        parameter.Value = id;
        _ = command.Parameters.Add(parameter);
        await using var reader = await command.ExecuteReaderAsync(token);
        if (!await reader.ReadAsync(token))
        {
            throw new InvalidOperationException("Missing synthetic ObjectName metadata.");
        }
        var bytes = reader.GetInt16(5);
        var type = reader.GetString(6);
        var schema = new CompanionSchemaEvidence(!reader.GetBoolean(4), bytes == -1 ? null : bytes / 2,
            type + (bytes == -1 ? "(max)" : "(" + (bytes / 2).ToString(System.Globalization.CultureInfo.InvariantCulture) + ")"),
            reader.GetInt32(7) != 0);
        return new(!reader.IsDBNull(0), ValueEvidence.From(reader.IsDBNull(1) ? null : reader.GetString(1)),
            reader.IsDBNull(2) ? null : reader.GetInt64(2), reader.IsDBNull(3) ? null : reader.GetString(3), schema);
    }
}

public sealed record FieldCase(string Name, string Column, int Capacity, bool Required, string? InsertDefault = null)
{
    public string Table => Name[..Name.IndexOf('.')] switch
    {
        "Order" => "Orders",
        "Company" => "Company",
        "Category" => "Category",
        "FileFormat" => "FileFormat",
        "Process" => "Process",
        "OrderStatus" => "OrderStatus",
        "OrderFile" => "OrderFile",
        _ => throw new InvalidOperationException("Unknown synthetic table."),
    };
    public string[] Columns => Table switch
    {
        "Orders" => ["Name", "Description", "TrackingNumber"],
        "Company" => ["Name", "Registrar", "TaxNumber"],
        "Category" => ["Name"],
        "FileFormat" => ["Name", "Extension"],
        "Process" => ["Name"],
        "OrderStatus" => ["Name", "Description"],
        "OrderFile" => ["Bucket", "ObjectName"],
        _ => throw new InvalidOperationException("Unknown synthetic table."),
    };
    public static readonly FieldCase[] All =
    [
        new("Order.TrackingNumber", "TrackingNumber", 250, false),
        new("Order.Name", "Name", 100, false, "unnamed"),
        new("Order.Description", "Description", 250, false),
        new("Company.Name", "Name", 256, true),
        new("Company.Registrar", "Registrar", 256, false),
        new("Company.TaxNumber", "TaxNumber", 256, false),
        new("Category.Name", "Name", 50, false),
        new("FileFormat.Name", "Name", 50, false),
        new("FileFormat.Extension", "Extension", 50, false),
        new("Process.Name", "Name", 50, true),
        new("OrderStatus.Name", "Name", 50, true),
        new("OrderStatus.Description", "Description", 100, false),
        new("OrderFile.Bucket", "Bucket", 50, true),
    ];

    public static string ObjectNameCompanion { get; } = "  drawings/" + new string('ก', 2048)
        + string.Concat(Enumerable.Repeat("😀", 2048)) + ".step  ";

    public IEnumerable<(string Name, string? Value)> Vectors()
    {
        yield return ("null", null);
        yield return ("empty", "");
        yield return ("thai-literal", " ไทย A ");
        yield return ("ascii-limit", new string('A', Capacity));
        yield return ("ascii-overflow", new string('A', Capacity + 1));
        yield return ("ascii-limit-space", new string('A', Capacity) + " ");
        yield return ("ascii-limit-nonbreaking-space", new string('A', Capacity) + "\u00a0");
        yield return ("ascii-limit-tab", new string('A', Capacity) + "\t");
        yield return ("supplementary-limit", string.Concat(Enumerable.Repeat("😀", Capacity / 2)));
        yield return ("supplementary-overflow", string.Concat(Enumerable.Repeat("😀", (Capacity / 2) + 1)));
        yield return ("supplementary-limit-space", string.Concat(Enumerable.Repeat("😀", Capacity / 2)) + " ");
        yield return ("mixed-overflow-spaces", string.Concat(Enumerable.Repeat("😀", (Capacity / 2) - 1)) + "   ");
    }
}
