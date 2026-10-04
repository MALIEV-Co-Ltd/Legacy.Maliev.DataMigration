namespace Legacy.Maliev.DataMigration;

/// <summary>Reviewed target-only consumer columns selected during genuine source schema generation.</summary>
[System.Text.Json.Serialization.JsonConverter(typeof(System.Text.Json.Serialization.JsonStringEnumConverter<ConsumerOverlaySelection>))]
public enum ConsumerOverlaySelection
{
    /// <summary>Retains the historical producer profiles and fingerprints.</summary>
    HistoricalDefaults = 0,
    /// <summary>Adds the reviewed Customer password lifecycle and Quotation decision version columns.</summary>
    CurrentConsumerColumnsV1 = 1,
}

internal static class ApprovedConsumerOverlaySelection
{
    internal static string? ProfileForDatabase(string database, ConsumerOverlaySelection selection)
    {
        return selection switch
        {
            ConsumerOverlaySelection.HistoricalDefaults => ApprovedTargetExtensionManifest.ProfileForDatabase(database),
            ConsumerOverlaySelection.CurrentConsumerColumnsV1 => database switch
            {
                "CustomerIdentity" => ApprovedConsumerColumnOverlayManifest.CustomerV2,
                "Quotation" => ApprovedConsumerColumnOverlayManifest.QuotationV1,
                _ => ApprovedTargetExtensionManifest.ProfileForDatabase(database),
            },
            _ => throw ApprovedConsumerColumnOverlayManifest.Invalid("consumer_overlay_selection_invalid"),
        };
    }

    internal static bool IsCurrent(FreshSchemaPlan schema)
    {
        return schema.Databases.Any(database =>
        database.TargetExtensionProfile is ApprovedConsumerColumnOverlayManifest.CustomerV2 or
            ApprovedConsumerColumnOverlayManifest.QuotationV1);
    }

    internal static bool IsApproved(FreshSchemaPlan schema)
    {
        ConsumerOverlaySelection selection = IsCurrent(schema)
            ? ConsumerOverlaySelection.CurrentConsumerColumnsV1 : ConsumerOverlaySelection.HistoricalDefaults;
        return schema.Databases.Select(database => database.Database)
                .SequenceEqual(DatabaseInventory.ActiveDatabases, StringComparer.Ordinal) &&
            schema.Databases.All(database => database.TargetExtensionProfile == ProfileForDatabase(database.Database, selection));
    }
}
