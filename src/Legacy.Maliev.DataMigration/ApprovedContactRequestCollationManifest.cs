using System.Text.Json.Serialization;

namespace Legacy.Maliev.DataMigration;

/// <summary>Explicit producer selection for the reviewed ContactRequest mapped text columns.</summary>
[JsonConverter(typeof(JsonStringEnumConverter<ContactRequestCollationProfile>))]
public enum ContactRequestCollationProfile
{
    LegacyInherited = 0,
    ExplicitC = 1,
}

/// <summary>Changes only target column collations; never changes source projection or applies existing-target DDL.</summary>
internal static class ApprovedContactRequestCollationManifest
{
    internal const string Collation = "C";
    private static readonly string[] OrderedColumns =
        ["ID", "FirstName", "LastName", "Email", "Company", "Telephone", "MessageContent", "Country", "CreatedDate", "ModifiedDate"];
    private static readonly string[] TextColumns =
        ["FirstName", "LastName", "Email", "Company", "Telephone", "MessageContent", "Country"];
    private static readonly string[] NullableColumns = ["Company", "Telephone", "CreatedDate", "ModifiedDate"];
    private const string UtcDefault = "(timezone('UTC'::text, CURRENT_TIMESTAMP))";

    internal static void ValidateProfile(ContactRequestCollationProfile profile)
    {
        if (!Enum.IsDefined(profile))
        {
            throw Invalid();
        }
    }

    internal static DatabaseSchemaPlan Apply(DatabaseSchemaPlan draft, ContactRequestCollationProfile profile)
    {
        ValidateProfile(profile);
        if (profile == ContactRequestCollationProfile.LegacyInherited || draft.Database != "ContactRequest")
        {
            return draft;
        }
        TableCopyPlan[] messages = [.. draft.Tables.Where(table => table.SourceSchema == "dbo" && table.SourceTable == "Message")];
        if (draft.TargetSchemaVersion != "1.0" || messages.Length != 1 ||
            draft.TargetExtensionProfile is not null || draft.SourceDispositionProfile is not null ||
            draft.SourceTableDispositions.Count != 0)
        {
            throw Invalid();
        }
        TableCopyPlan message = messages[0];
        if (message.TargetSchema != "public" || message.TargetTable != "Message" ||
            !message.OrderedColumns.SequenceEqual(OrderedColumns, StringComparer.Ordinal) ||
            !message.OrderByColumns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            message.ColumnTypes.Count != OrderedColumns.Length || message.SourceColumnTypes.Count != OrderedColumns.Length ||
            !message.SourceColumns.Select(column => column.Column).SequenceEqual(OrderedColumns, StringComparer.Ordinal) ||
            !message.NullableColumns.Order(StringComparer.Ordinal).SequenceEqual(NullableColumns.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            !message.IdentityColumns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            message.Identities.Count != 1 || message.Identities[0] is not { Column: "ID", SeedValue: 1, IncrementValue: 1 } ||
            message.PrimaryKey is not { Name: "PK_Message" } ||
            !message.PrimaryKey.Columns.SequenceEqual(["ID"], StringComparer.Ordinal) ||
            message.UniqueConstraints.Count != 0 || message.Indexes.Count != 0 || message.ForeignKeys.Count != 0 ||
            message.CheckConstraints.Count != 0 || message.GeneratedColumns.Count != 0 || message.Collations.Count != 0 ||
            message.DefaultExpressions.Count != 2 ||
            message.DefaultExpressions.GetValueOrDefault("CreatedDate") != UtcDefault ||
            message.DefaultExpressions.GetValueOrDefault("ModifiedDate") != UtcDefault ||
            draft.Tables.Any(table => table.ForeignKeys.Any(foreignKey =>
                (foreignKey.ReferencedSchema == "public" && foreignKey.ReferencedTable == "Message") ||
                (foreignKey.SourceReferencedSchema == "dbo" && foreignKey.SourceReferencedTable == "Message"))) ||
            draft.Tables.Any(table => !ReferenceEquals(table, message) &&
                table.TargetSchema == "public" && table.TargetTable == "Message"))
        {
            throw Invalid();
        }
        foreach (string column in OrderedColumns)
        {
            string targetType = column switch
            {
                "ID" => "integer",
                "MessageContent" => "text",
                "CreatedDate" or "ModifiedDate" => "timestamp without time zone",
                _ => "character varying(50)",
            };
            string sourceType = column switch
            {
                "ID" => "int",
                "MessageContent" => "nvarchar(max)",
                "CreatedDate" or "ModifiedDate" => "datetime",
                _ => "nvarchar(50)",
            };
            if (message.ColumnTypes.GetValueOrDefault(column) != targetType ||
                message.SourceColumnTypes.GetValueOrDefault(column) != sourceType ||
                message.SourceColumns.Single(source => source.Column == column).DeclaredType != sourceType)
            {
                throw Invalid();
            }
        }
        TableCopyPlan selected = message with
        {
            Collations = TextColumns.ToDictionary(column => column, _ => Collation, StringComparer.Ordinal),
        };
        return draft with { Tables = [.. draft.Tables.Select(table => ReferenceEquals(table, message) ? selected : table)] };
    }

    private static MigrationExecutionException Invalid()
    {
        return new("contact_request_collation_profile_invalid",
        "The explicit C profile requires the exact reviewed ContactRequest source shape and dependency inventory.");
    }
}
