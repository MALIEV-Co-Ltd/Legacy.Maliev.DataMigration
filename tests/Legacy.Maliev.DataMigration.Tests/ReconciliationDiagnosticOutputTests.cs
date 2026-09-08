using System.Text.Json;
using Legacy.Maliev.DataMigration.Console;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ReconciliationDiagnosticOutputTests
{
    [Fact]
    public async Task WriteSafeReconciliationDiagnosticAsync_ValidDiagnostic_EmitsOnlyAllowlistedEvidence()
    {
        using var error = new StringWriter();
        var diagnostic = new ReconciliationDiagnostic(
            "Customer",
            "public.Customers",
            "row-count",
            "3058",
            "3057")
        {
            Field = "Id",
        };

        await MigrationConsole.WriteSafeReconciliationDiagnosticAsync(error, diagnostic);

        using JsonDocument document = JsonDocument.Parse(error.ToString());
        JsonElement root = document.RootElement;
        Assert.Equal("Customer", root.GetProperty("database").GetString());
        Assert.Equal("public.Customers", root.GetProperty("table").GetString());
        Assert.Equal("row-count", root.GetProperty("check").GetString());
        Assert.Equal("Id", root.GetProperty("field").GetString());
        Assert.Equal("3058", root.GetProperty("expected").GetString());
        Assert.Equal("3057", root.GetProperty("observed").GetString());
    }

    [Fact]
    public async Task WriteSafeReconciliationDiagnosticAsync_UntrustedValues_RedactsThem()
    {
        using var error = new StringWriter();
        var diagnostic = new ReconciliationDiagnostic(
            "NotInInventory",
            "public.Customers;select secret",
            "row-count\nsecret",
            "customer@example.com",
            "not-a-count")
        {
            Field = "field with spaces",
        };

        await MigrationConsole.WriteSafeReconciliationDiagnosticAsync(error, diagnostic);

        using JsonDocument document = JsonDocument.Parse(error.ToString());
        JsonElement root = document.RootElement;
        Assert.Equal(JsonValueKind.Null, root.GetProperty("database").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("table").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("check").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("field").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("expected").ValueKind);
        Assert.Equal(JsonValueKind.Null, root.GetProperty("observed").ValueKind);
        Assert.DoesNotContain("customer@example.com", error.ToString(), StringComparison.Ordinal);
        Assert.DoesNotContain("secret", error.ToString(), StringComparison.Ordinal);
    }
}
