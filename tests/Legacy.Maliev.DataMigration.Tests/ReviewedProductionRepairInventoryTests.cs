using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ReviewedProductionRepairInventoryTests
{
    private const string OriginalCatalogJson = """
        [
          {
            "name": "Auth",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "ContactRequest",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Country",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Currency",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Customer",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "CustomerIdentity",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "DataProtectionKeys",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "DataProtectionKeysEmployee",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Employee",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "EmployeeIdentity",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Invoice",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "JobOffers",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "LocationData",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Material",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Message",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Order",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "OrderStatus",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Payment",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "PurchaseOrder",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Quotation",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "QuotationRequest",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Receipt",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Supplier",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "Upload",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_migration_control",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_contact_4939d015_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_country_aff64e4f_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_currenc_466e5b9c_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_custome_8e752dc3_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_custome_b6c45863_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_datapro_31b72101_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_datapro_35b21653_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_employe_2fdc0177_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_employe_97429b04_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_invoice_52d6e3de_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_joboffe_ad34aeba_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_locatio_9b00942f_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_materia_40b30b4e_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_message_ab530a13_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_order_3eeb7e96_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_orderst_28340f2b_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_payment_040ffd59_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_purchas_32b703ee_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_quotati_d5e44483_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_quotati_fcd9bd43_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_receipt_6f328609_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_supplie_955ed10b_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "legacy_shadow_upload_ff4085ad_99dd9a9f4e6149c7ad64d6cd9ccc302e",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "postgres",
            "template": false,
            "allowConnections": true
          },
          {
            "name": "template0",
            "template": true,
            "allowConnections": false
          },
          {
            "name": "template1",
            "template": true,
            "allowConnections": true
          }
        ]
        """;

    private static ReviewedRepairDatabaseFlag[] Original()
    {
        using var document = JsonDocument.Parse(OriginalCatalogJson);
        return document.RootElement.EnumerateArray().Select(x => new ReviewedRepairDatabaseFlag(
            x.GetProperty("name").GetString() ?? throw new InvalidOperationException(),
            x.GetProperty("template").GetBoolean(), x.GetProperty("allowConnections").GetBoolean())).ToArray();
    }

    [Fact]
    public void Genuine_discovery_has_exact49_including_all_shadows_control_and_two_templates()
    {
        var actual = Original();
        var names = actual.Where(x => !x.IsTemplate).Select(x => x.Name).ToArray();
        Assert.Equal(51, actual.Length);
        Assert.Equal(49, names.Length);
        Assert.Equal(23, names.Count(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal)));
        Assert.Contains("legacy_migration_control", names);
        Assert.Contains("Auth", names);
        Assert.Contains("postgres", names);
        ReviewedProductionRepairInventory.RequireComplete(DeltaTargetAuthorityKind.ProductionCloudNativePg, actual, names);
        Assert.Equal(names.Order(StringComparer.Ordinal), ReviewedProductionRepairInventory.ExportProductionNames().Order(StringComparer.Ordinal));
    }

    [Theory]
    [InlineData("missing-control")]
    [InlineData("missing-shadow")]
    [InlineData("substitute-shadow")]
    [InlineData("extra")]
    [InlineData("case-alias")]
    [InlineData("duplicate")]
    [InlineData("template-in-map")]
    public void Baseline_keys_cannot_drop_substitute_add_or_alias(string fault)
    {
        var flags = Original();
        var keys = flags.Where(x => !x.IsTemplate).Select(x => x.Name).ToList();
        string shadow = keys.First(x => x.StartsWith("legacy_shadow_", StringComparison.Ordinal));
        switch (fault)
        {
            case "missing-control": _ = keys.Remove("legacy_migration_control"); break;
            case "missing-shadow": _ = keys.Remove(shadow); break;
            case "substitute-shadow": keys[keys.IndexOf(shadow)] = shadow + "x"; break;
            case "extra": keys.Add("unreviewed"); break;
            case "case-alias": keys[keys.IndexOf("Auth")] = "auth"; break;
            case "duplicate": keys.Add("Auth"); break;
            case "template-in-map": keys.Add("template1"); break;
            default: throw new InvalidOperationException();
        }
        Assert.False(ReviewedProductionRepairInventory.MatchesKeys(DeltaTargetAuthorityKind.ProductionCloudNativePg, keys));
        _ = Assert.Throws<MigrationExecutionException>(() => ReviewedProductionRepairInventory.RequireComplete(
            DeltaTargetAuthorityKind.ProductionCloudNativePg, flags, keys));
    }

    [Theory]
    [InlineData("disabled")]
    [InlineData("app-template")]
    [InlineData("missing-template")]
    [InlineData("template0-connectable")]
    [InlineData("duplicate-template")]
    [InlineData("extra-disabled")]
    [InlineData("case-alias")]
    public void Complete_catalog_flag_mutations_cannot_be_filtered_out(string fault)
    {
        var flags = Original().ToList();
        var keys = flags.Where(x => !x.IsTemplate).Select(x => x.Name).ToArray();
        switch (fault)
        {
            case "case-alias": flags[0] = flags[0] with { Name = flags[0].Name.ToLowerInvariant() }; break;
            case "disabled": flags[0] = flags[0] with { AllowsConnections = false }; break;
            case "app-template": flags[0] = flags[0] with { IsTemplate = true }; break;
            case "missing-template": _ = flags.RemoveAll(x => x.Name == "template0"); break;
            case "template0-connectable":
                int i = flags.FindIndex(x => x.Name == "template0");
                flags[i] = flags[i] with { AllowsConnections = true };
                break;
            case "duplicate-template": flags.Add(new("template1", true, true)); break;
            case "extra-disabled": flags.Add(new("hidden_unreviewed", false, false)); break;
            default: throw new InvalidOperationException();
        }
        _ = Assert.Throws<MigrationExecutionException>(() => ReviewedProductionRepairInventory.RequireComplete(
            DeltaTargetAuthorityKind.ProductionCloudNativePg, flags, keys));
    }

    [Fact]
    public void Local_exact26_remains_separate_and_exports_cannot_mutate_profile()
    {
        var names = DatabaseInventory.ActiveDatabases.Concat(["Auth", "postgres", "legacy_local"]).ToArray();
        var flags = names.Select(x => new ReviewedRepairDatabaseFlag(x, false, true))
            .Concat([new("template0", true, false), new("template1", true, true)]).ToArray();
        ReviewedProductionRepairInventory.RequireComplete(DeltaTargetAuthorityKind.LocalAspire, flags, names);
        Assert.False(ReviewedProductionRepairInventory.MatchesKeys(DeltaTargetAuthorityKind.ProductionCloudNativePg, names));
        var exported = (IList<string>)ReviewedProductionRepairInventory.ExportProductionNames();
        _ = Assert.Throws<NotSupportedException>(() => exported[0] = "changed");
        Assert.Equal("Auth", ReviewedProductionRepairInventory.ExportProductionNames()[0]);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Actual_system_binding_and_read_only_are_required(bool sameSystem, bool readOnly)
    {
        _ = Assert.Throws<MigrationExecutionException>(() => ReviewedProductionRepairInventoryObservation.RequireSystemBinding(
            new('a', 64), new(sameSystem ? 'a' : 'b', 64), readOnly));
        ReviewedProductionRepairInventoryObservation.RequireSystemBinding(new('a', 64), new('a', 64), true);
    }

    [Fact]
    public void Unknown_target_kind_and_blank_keys_are_rejected()
    {
        Assert.False(ReviewedProductionRepairInventory.MatchesKeys("unknown", ReviewedProductionRepairInventory.ExportProductionNames()));
        var keys = ReviewedProductionRepairInventory.ExportProductionNames().ToArray();
        keys[0] = " ";
        Assert.False(ReviewedProductionRepairInventory.MatchesKeys(DeltaTargetAuthorityKind.ProductionCloudNativePg, keys));
    }
}
