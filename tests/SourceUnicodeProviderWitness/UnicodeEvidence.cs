using System.Buffers.Binary;
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
    AssemblyEvidence[] Assemblies, Observation[] Observations);

public sealed record FieldCase(string Name, string Column, int Capacity, bool Required, string? InsertDefault = null)
{
    public string Table => Name[..Name.IndexOf('.')] switch
    {
        "Order" => "Orders",
        "Company" => "Company",
        "Category" => "Category",
        "FileFormat" => "FileFormat",
        _ => throw new InvalidOperationException("Unknown synthetic table."),
    };
    public string[] Columns => Table switch
    {
        "Orders" => ["Name", "Description", "TrackingNumber"],
        "Company" => ["Name", "Registrar", "TaxNumber"],
        "Category" => ["Name"],
        "FileFormat" => ["Name", "Extension"],
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
    ];

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
