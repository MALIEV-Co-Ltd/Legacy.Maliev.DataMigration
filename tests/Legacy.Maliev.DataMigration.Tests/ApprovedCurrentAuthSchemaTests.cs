using System.Text.Json;

namespace Legacy.Maliev.DataMigration.Tests;

public sealed class ApprovedCurrentAuthSchemaTests
{
    private static readonly DateTimeOffset Now = new(2026, 10, 12, 16, 30, 0, TimeSpan.Zero);
    private static readonly string[] AffectedIndexNames =
    [
        "IX_google_identity_nonces_NonceHash",
        "IX_identity_action_tokens_IdentityId_Purpose_TokenHash",
        "IX_identity_action_tokens_OriginalTokenSha256_Purpose",
        "IX_refresh_sessions_TokenHash",
        "PK___EFMigrationsHistory",
    ];

    [Fact]
    public void Fixed_shape_retains_all_columns_constraints_and_native_nullable_uniqueness()
    {
        CurrentAuthPhysicalShape before = ApprovedCurrentAuthSchema.PhysicalShape(false);
        CurrentAuthPhysicalShape after = ApprovedCurrentAuthSchema.PhysicalShape(true);
        Assert.Equal(4, before.Tables.Count);
        Assert.Equal(34, before.Columns.Count);
        Assert.Equal(4, before.Constraints.Count(constraint => constraint.Kind == 'p'));
        Assert.Equal(2, before.Constraints.Count(constraint => constraint.Kind == 'c'));
        Assert.Equal(8, before.Indexes.Count);
        Assert.Empty(before.ForeignKeys);
        Assert.Equal(16, ApprovedCurrentAuthSchema.CollationOperands().Length);
        Assert.Equal(5, ApprovedCurrentAuthSchema.AffectedIndices().Length);
        Assert.Equal(AffectedIndexNames, ApprovedCurrentAuthSchema.AffectedIndices().Select(index => index.Name).Order(StringComparer.Ordinal));
        Assert.Equal(23, DatabaseInventory.ActiveDatabases.Count);
        Assert.DoesNotContain("Auth", DatabaseInventory.ActiveDatabases);
        Assert.All(before.Columns, column => Assert.Equal(string.Empty, column.Collation));
        Assert.Equal(16, after.Columns.Count(column => column.Collation == "C"));
        Assert.All(after.Indexes, index => Assert.False(index.NullsNotDistinct));
        _ = Assert.Single(after.Columns, column => column.Table == "identity_action_tokens" &&
            column.Column == "OriginalTokenSha256" && column.Nullable);
        Assert.Equal(JsonSerializer.Serialize(before.Constraints.Where(constraint => constraint.Name != "CK_identity_action_tokens_employee_binding")),
            JsonSerializer.Serialize(after.Constraints.Where(constraint => constraint.Name != "CK_identity_action_tokens_employee_binding")));
        PostgreSqlSchemaFingerprint.ConstraintShape originalCheck = before.Constraints.Single(constraint => constraint.Name == "CK_identity_action_tokens_employee_binding");
        PostgreSqlSchemaFingerprint.ConstraintShape rebuiltCheck = after.Constraints.Single(constraint => constraint.Name == originalCheck.Name);
        Assert.Equal(JsonSerializer.Serialize(originalCheck with { Expression = rebuiltCheck.Expression }), JsonSerializer.Serialize(rebuiltCheck));
        Assert.Equal(originalCheck.Expression.Replace(
            "((ARRAY['employee-password-reset'::character varying, 'employee-email-confirmation'::character varying])::text[])",
            "(ARRAY[('employee-password-reset'::character varying)::text, ('employee-email-confirmation'::character varying)::text])", StringComparison.Ordinal),
            rebuiltCheck.Expression);
        Assert.NotEqual(originalCheck.Expression, rebuiltCheck.Expression);
        Assert.Equal(JsonSerializer.Serialize(before.Indexes), JsonSerializer.Serialize(after.Indexes));
        Assert.All(before.Columns, column =>
        {
            Assert.Empty(column.DefaultExpression);
            Assert.Empty(column.GeneratedExpression);
            Assert.False(column.Identity);
        });
        ApprovedCurrentAuthSchema.RequirePhysicalShape(before, false);
        ApprovedCurrentAuthSchema.RequirePhysicalShape(after, true);
        Assert.NotEqual(ApprovedCurrentAuthSchema.PhysicalSha256(false), ApprovedCurrentAuthSchema.PhysicalSha256(true));
        // Historical SQL Server nullable uniqueness remains unchanged and is distinct from this native Auth model.
        Assert.NotEqual(ApprovedCurrentAuthSchema.PhysicalSha256(false),
            PostgreSqlSchemaFingerprint.ComputeExpectedTables(ApprovedCurrentAuthSchema.Tables(false)));
    }

    [Fact]
    public void Exact_thirteen_pins_require_fresh_clean_current_owner_head()
    {
        CurrentAuthSourcePin[] pins = ApprovedCurrentAuthSchema.SourcePins();
        Assert.Equal(13, pins.Length);
        Assert.Equal("222d3a5e28af5c92da613bd2b17256bc6684c6670a07e925f19aa525a48dfbd2",
            pins.Single(pin => pin.RelativePath.EndsWith("/ServiceCollectionExtensions.cs", StringComparison.Ordinal)).Sha256);
        RequireSource(pins);
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, "5a81aba3d85c2a22cf999d7f02cdcd7f7fa38198"));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, clean: false));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, captured: Now.AddHours(-13)));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, captured: Now.AddTicks(1)));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, captured: Now.ToOffset(TimeSpan.FromHours(7))));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource([.. pins.Skip(1)]));
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource([.. pins, pins[0]]));
        CurrentAuthSourcePin[] changedPath = [.. pins];
        changedPath[0] = changedPath[0] with { RelativePath = "unknown" };
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(changedPath));
        pins[0] = pins[0] with { Sha256 = new string('a', 64) };
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins));
        RequireSource(ApprovedCurrentAuthSchema.SourcePins());
    }

    [Theory]
    [InlineData("head")]
    [InlineData("service-pin")]
    [InlineData("entity-pin")]
    public void Prior_owner_head_and_source_pins_cannot_be_used_as_current_observations(string fault)
    {
        CurrentAuthSourcePin[] pins = ApprovedCurrentAuthSchema.SourcePins();
        string head = ApprovedCurrentAuthSchema.AuthServiceCommit;
        if (fault == "head") { head = "f7079f133b1e607b8909636a5114ebccc73b27bc"; }
        if (fault == "service-pin")
        {
            int index = Array.FindIndex(pins, pin => pin.RelativePath.EndsWith("/ServiceCollectionExtensions.cs", StringComparison.Ordinal));
            pins[index] = pins[index] with { Sha256 = "ac3e31768341be0ac982fb515680ed7caf915e0f5de769a49d6ede8567a6c087" };
        }
        if (fault == "entity-pin")
        {
            int index = Array.FindIndex(pins, pin => pin.RelativePath.EndsWith("/IdentityActionToken.cs", StringComparison.Ordinal));
            pins[index] = pins[index] with { Sha256 = "71fe26148fc57e74d7c6cab8ddbd4c9643f16ba2e515e8b6929c765bd582ff56" };
        }
        _ = Assert.Throws<InvalidOperationException>(() => RequireSource(pins, head));
    }

    [Fact]
    public void Complete_physical_guard_rejects_unknown_or_mixed_catalog_shapes()
    {
        CurrentAuthPhysicalShape before = ApprovedCurrentAuthSchema.PhysicalShape(false);
        CurrentAuthPhysicalShape after = ApprovedCurrentAuthSchema.PhysicalShape(true);
        Reject(before, true);
        Reject(after, false);
        Reject(before with { Tables = [.. before.Tables, new("public", "unknown")] });
        Reject(before with { Columns = [.. before.Columns.Skip(1)] });
        Reject(before with { Columns = [.. before.Columns, before.Columns[0]] });
        foreach (PostgreSqlSchemaFingerprint.ColumnShape changed in new[]
        {
            before.Columns[0] with { Type = "text" },
            before.Columns[0] with { Nullable = true },
            before.Columns[0] with { DefaultExpression = "'unexpected'" },
            before.Columns[0] with { Identity = true },
            before.Columns[0] with { GeneratedExpression = "1" },
            before.Columns[0] with { Ordinal = 3 },
            before.Columns[0] with { Collation = "C" },
        })
        {
            Reject(before with { Columns = [changed, .. before.Columns.Skip(1)] });
        }
        Reject(before with { Constraints = [.. before.Constraints.Skip(1)] });
        PostgreSqlSchemaFingerprint.ConstraintShape check = before.Constraints.First(constraint => constraint.Kind == 'c');
        Reject(before with
        {
            Constraints = [.. before.Constraints.Select(constraint =>
            constraint == check ? constraint with { Expression = "true" } : constraint)]
        });
        Reject(before with { Indexes = [.. before.Indexes.Skip(1)] });
        PostgreSqlSchemaFingerprint.IndexShape nullable = before.Indexes.Single(index =>
            index.Name == "IX_identity_action_tokens_OriginalTokenSha256_Purpose");
        foreach (PostgreSqlSchemaFingerprint.IndexShape changed in new[]
        {
            nullable with { NullsNotDistinct = true },
            nullable with { Unique = false },
            nullable with { Columns = ["Purpose", "OriginalTokenSha256"] },
            nullable with { IncludedColumns = ["Id"] },
            nullable with { DescendingOrdinals = [1] },
            nullable with { FilterPredicate = "\"OriginalTokenSha256\" IS NOT NULL" },
        })
        {
            Reject(before with { Indexes = [.. before.Indexes.Select(index => index == nullable ? changed : index)] });
        }
        Reject(before with
        {
            ForeignKeys = [new("public", "refresh_sessions", "unexpected", ["Id"],
            "public", "refresh_sessions", ["Id"], ReferentialAction.NoAction, ReferentialAction.NoAction, true)]
        });
    }

    [Fact]
    public void Table_exports_are_defensive_and_cannot_change_digest_or_add_catalog_features()
    {
        string digest = ApprovedCurrentAuthSchema.ClosureSha256;
        TableCopyPlan table = ApprovedCurrentAuthSchema.Tables(false)[0];
        ApprovedCurrentAuthSchema.RequireTableContract(table, false);
        _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequireTableContract(
            table with { Indexes = [new("unknown", ["MigrationId"], true)] }, false));
        ((Dictionary<string, string>)table.ColumnTypes)["MigrationId"] = "text";
        _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequireTableContract(table, false));
        CurrentAuthPhysicalShape shape = ApprovedCurrentAuthSchema.PhysicalShape(false);
        if (shape.Columns is IList<PostgreSqlSchemaFingerprint.ColumnShape> exportedColumns)
        {
            if (exportedColumns.IsReadOnly)
            {
                _ = Assert.Throws<NotSupportedException>(() => exportedColumns[0] = shape.Columns[0] with { Type = "text" });
            }
            else
            {
                exportedColumns[0] = shape.Columns[0] with { Type = "text" };
            }
        }
        ApprovedCurrentAuthSchema.SourcePins()[0] = new("unknown", new string('b', 64));
        Assert.Equal(digest, ApprovedCurrentAuthSchema.ClosureSha256);
        Assert.Equal("character varying(150)", ApprovedCurrentAuthSchema.Tables(false)[0].ColumnTypes["MigrationId"]);
    }

    [Fact]
    public void Histories_are_preserved_independently_with_target_specific_fresh_artifacts()
    {
        CurrentAuthHistoryObservation production = History('a', "10.0.12");
        CurrentAuthHistoryObservation local = History('b', "10.0.10");
        ApprovedCurrentAuthSchema.RequireHistoryPreserved(production, production with { CapturedAtUtc = Now }, Now, TimeSpan.FromMinutes(15));
        ApprovedCurrentAuthSchema.RequireHistoryPreserved(local, local with { CapturedAtUtc = Now }, Now, TimeSpan.FromMinutes(15));
        _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequireHistoryPreserved(local, production, Now, TimeSpan.FromMinutes(15)));
        _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequireHistoryPreserved(local,
            local with { Rows = production.Rows }, Now, TimeSpan.FromMinutes(15)));
        foreach (CurrentAuthHistoryObservation changed in new[]
        {
            production with { RetainedArtifactSha256 = "missing" },
            production with { TargetBindingSha256 = "missing" },
            production with { Rows = [.. production.Rows.Skip(1)] },
            production with { Rows = [.. production.Rows, production.Rows[0]] },
            production with { CapturedAtUtc = Now.AddMinutes(-16) },
            production with { CapturedAtUtc = Now.AddTicks(1) },
        })
        {
            _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequireHistory(changed, Now, TimeSpan.FromMinutes(15)));
        }
    }

    private static void RequireSource(CurrentAuthSourcePin[] pins, string? head = null, bool clean = true, DateTimeOffset? captured = null)
    {
        ApprovedCurrentAuthSchema.RequireSourceObservation(head ?? ApprovedCurrentAuthSchema.AuthServiceCommit, clean, pins,
            captured ?? Now, Now, TimeSpan.FromHours(12));
    }

    private static void Reject(CurrentAuthPhysicalShape shape, bool explicitC = false)
    {
        _ = Assert.Throws<InvalidOperationException>(() => ApprovedCurrentAuthSchema.RequirePhysicalShape(shape, explicitC));
    }

    private static CurrentAuthHistoryObservation History(char target, string productVersion)
    {
        return new(new string(target, 64),
        new string('c', 64), Now.AddMinutes(-1),
        [.. ApprovedCurrentAuthSchema.SourcePins().Where(pin => pin.RelativePath.Contains("/Migrations/", StringComparison.Ordinal) &&
                !pin.RelativePath.EndsWith("ModelSnapshot.cs", StringComparison.Ordinal))
            .Select(pin => new CurrentAuthHistoryRow(Path.GetFileNameWithoutExtension(pin.RelativePath), productVersion))]);
    }
}
