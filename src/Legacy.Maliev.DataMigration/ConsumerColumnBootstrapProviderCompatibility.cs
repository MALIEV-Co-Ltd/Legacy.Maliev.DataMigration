namespace Legacy.Maliev.DataMigration;

internal sealed record ConsumerColumnBootstrapProviderObservation(int EngineVersion, long CatalogVersion,
    string Encoding, int BlockSize, string CompositeDefense, string BuiltinTypeSemanticsSha256,
    string LocaleAndIcuProvenanceSha256, string DatabaseSettingsSha256);

/// <summary>Operation-specific compatibility; proof container images are not persistent target identities.</summary>
internal static class ConsumerColumnBootstrapProviderCompatibility
{
    internal static void RequireCompatible(ConsumerColumnBootstrapProviderObservation disposable,
        ConsumerColumnBootstrapProviderObservation intended)
    {
        RequireObservation(disposable); RequireObservation(intended);
        if (disposable.EngineVersion != intended.EngineVersion || disposable.CatalogVersion != intended.CatalogVersion ||
            disposable.Encoding != intended.Encoding || disposable.BlockSize != intended.BlockSize ||
            disposable.CompositeDefense != intended.CompositeDefense || disposable.BuiltinTypeSemanticsSha256 != intended.BuiltinTypeSemanticsSha256)
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
        // Locale/ICU and settings remain actual target provenance and part of that target's
        // reviewed preimage. They are not substituted with disposable values. The only two
        // statements append collation-free boolean DEFAULT false and nullable timestamp;
        // neither coerces source values nor evaluates a locale-dependent expression.
    }

    internal static void RequireObservation(ConsumerColumnBootstrapProviderObservation value)
    {
        if (value.EngineVersion is not (180004 or 180007) || value.CatalogVersion <= 0 || value.Encoding != "UTF8" || value.BlockSize != 8192 ||
            value.CompositeDefense != (value.EngineVersion == 180007 ? "error" : string.Empty) ||
            !ConsumerColumnBootstrapOperationalContract.IsHash(value.BuiltinTypeSemanticsSha256) ||
            !ConsumerColumnBootstrapOperationalContract.IsHash(value.LocaleAndIcuProvenanceSha256) ||
            !ConsumerColumnBootstrapOperationalContract.IsHash(value.DatabaseSettingsSha256))
        { throw ConsumerColumnBootstrapOperationalContract.Invalid(); }
    }
}
