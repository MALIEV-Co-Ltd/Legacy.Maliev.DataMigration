using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

/// <summary>Reads retained pre-recovery documents without reserializing their signed original text.</summary>
public static class OriginalMigrationDocumentReader
{
    // Existing publishers use Web camelCase and existing readers accept case-insensitive names.
    // Keep PascalCase originals compatible, but reject duplicate mapped properties (including aliases).
    // Do not apply Web number coercion or change the strict new recovery-envelope options.
    private static readonly JsonSerializerOptions Options = new(RecoveryContractEncoding.Options)
    {
        PropertyNameCaseInsensitive = true,
    };

    /// <summary>Preserves the required/null/unmapped/duplicate/size/depth guards for original evidence.</summary>
    public static T Read<T>(string exactJson)
    {
        return RecoveryContractEncoding.Parse<T>(exactJson, Options);
    }
}
