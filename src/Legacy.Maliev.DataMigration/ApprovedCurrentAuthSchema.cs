using System.Security.Cryptography;
using System.Text.Json;

namespace Legacy.Maliev.DataMigration;

internal sealed record CurrentAuthSourcePin(string RelativePath, string Sha256);
internal sealed record CurrentAuthCollationOperand(string Table, string Column, string PostgreSqlType, bool Nullable);
internal sealed record CurrentAuthAffectedIndex(string Table, string Name, bool PrimaryKey, IReadOnlyList<string> Columns);
internal sealed record CurrentAuthPhysicalShape(
    IReadOnlyList<PostgreSqlSchemaFingerprint.TableShape> Tables,
    IReadOnlyList<PostgreSqlSchemaFingerprint.ColumnShape> Columns,
    IReadOnlyList<PostgreSqlSchemaFingerprint.ConstraintShape> Constraints,
    IReadOnlyList<PostgreSqlSchemaFingerprint.IndexShape> Indexes,
    IReadOnlyList<PostgreSqlSchemaFingerprint.ForeignKeyShape> ForeignKeys);
internal sealed record CurrentAuthHistoryRow(string MigrationId, string ProductVersion);
internal sealed record CurrentAuthHistoryObservation(
    string TargetBindingSha256, string RetainedArtifactSha256, DateTimeOffset CapturedAtUtc,
    IReadOnlyList<CurrentAuthHistoryRow> Rows);

/// <summary>Pure closed Auth preparation contract. No execution or source-acceptance authority.</summary>
internal static class ApprovedCurrentAuthSchema
{
    private const string OwnerCommit = "d05c1ed990303beb2fba630b49c78adca9d0b610";
    internal const string AuthServiceCommit = OwnerCommit;
    private const string Domain = "Legacy.Maliev.CurrentAuthClosure.v1";
    private static readonly CurrentAuthSourcePin[] Pins =
    [
        new("Legacy.Maliev.AuthService.Infrastructure/RefreshSessionDbContext.cs", "2c0233b91a1698135a07ca4d472dd57c5167e6b4bcd9bf6dd1c0eb2daba63f4f"),
        new("Legacy.Maliev.AuthService.Infrastructure/PostgresRefreshSessionStore.cs", "d1dc74fff3cdcabfb5bfcb51844f9808da865f3568542909e0e665ccc603d1e6"),
        new("Legacy.Maliev.AuthService.Infrastructure/GoogleIdentityNonceService.cs", "4159ba3fad180cccb5e68fe6f05df04e5f6aa2c9913ca3560974c35ba86b2006"),
        new("Legacy.Maliev.AuthService.Infrastructure/ServiceCollectionExtensions.cs", "222d3a5e28af5c92da613bd2b17256bc6684c6670a07e925f19aa525a48dfbd2"),
        new("Legacy.Maliev.AuthService.Infrastructure/Migrations/RefreshSessionDbContextModelSnapshot.cs", "2f6e883920112ec63d13cbe8026cbaf07ce3080f3f3101f57ef3dffcafdbc1ad"),
        new("Legacy.Maliev.AuthService.Domain/RefreshSession.cs", "00ed65f2619b356d64851e25109ef31c87e9bef3f8ba3c59383e4dd31b97107b"),
        new(RelativePath: "Legacy.Maliev.AuthService.Domain/IdentityActionToken.cs", Sha256: "ed03a9730d27dd6e81b986d5e78b9b673da699e5e6d2b3bf17c83ca20a168018"),
        new("Legacy.Maliev.AuthService.Domain/GoogleIdentityNonce.cs", "d9a8cbb4930b668f099776a47f2945f07f06f42cd2dfaf21653f977cb720d566"),
        new("Legacy.Maliev.AuthService.Infrastructure/Migrations/20260715104357_InitialRefreshSessions.cs", "60656d8afd6ec7f7400aec07a13957495e8ae293a8358ee985d73638765cb47c"),
        new(RelativePath: "Legacy.Maliev.AuthService.Infrastructure/Migrations/20260715140429_AddIdentityActionTokens.cs", Sha256: "e4a2a7ba883e98cef0dca189ba6ce073d7e6418a887551a356a2aba586f59a9b"),
        new("Legacy.Maliev.AuthService.Infrastructure/Migrations/20260726184305_AddGoogleIdentityNonces.cs", "b01161df1308f54a44d9af6ad5178d6182af7ed811acf906f477a45796e08e51"),
        new(RelativePath: "Legacy.Maliev.AuthService.Infrastructure/Migrations/20260727193121_AddIdentityActionTokenTargetEmail.cs", Sha256: "7d68b8c4296bc367b0bc7a412cb232bbc05201e753e5565df32e060180541360"),
        new("Legacy.Maliev.AuthService.Infrastructure/Migrations/20260930125706_AddEmployeeRecoveryBinding.cs", "371d99e97e26a46c93c38b9020cc9ff1153681526bc5ebad429d288613600624"),
    ];

    private static readonly string[] MigrationIds =
    [
        "20260715104357_InitialRefreshSessions",
        "20260715140429_AddIdentityActionTokens",
        "20260726184305_AddGoogleIdentityNonces",
        "20260727193121_AddIdentityActionTokenTargetEmail",
        "20260930125706_AddEmployeeRecoveryBinding",
    ];

    internal static CurrentAuthSourcePin[] SourcePins()
    {
        return [.. Pins];
    }

    internal static void RequireSourceObservation(string repositoryHead, bool workingTreeClean,
        IReadOnlyList<CurrentAuthSourcePin> observed, DateTimeOffset capturedAtUtc,
        DateTimeOffset nowUtc, TimeSpan maximumAge)
    {
        RequireFresh(capturedAtUtc, nowUtc, maximumAge);
        if (!workingTreeClean || repositoryHead != AuthServiceCommit || observed.Count != Pins.Length ||
            !observed.OrderBy(pin => pin.RelativePath, StringComparer.Ordinal)
                .SequenceEqual(Pins.OrderBy(pin => pin.RelativePath, StringComparer.Ordinal)))
        {
            throw Invalid();
        }
    }

    internal static TableCopyPlan[] Tables(bool explicitC)
    {
        TableCopyPlan[] tables = DefaultTables();
        return explicitC
            ? [.. tables.Select(table => table with
            {
                Collations = table.ColumnTypes.Where(pair => IsText(pair.Value))
                    .ToDictionary(pair => pair.Key, _ => "C", StringComparer.Ordinal),
                // PG18.4 reparses this exact fixed varchar-array coercion when
                // rebuilding the CHECK after COLLATE C. Keep its native physical
                // representation explicit; the native comparator also binds the
                // full typed expression and every original constant datum.
                CheckConstraints = [.. table.CheckConstraints.Select(check => check.Name == "CK_identity_action_tokens_employee_binding"
                    ? check with { Expression = check.Expression.Replace(
                        "((ARRAY['employee-password-reset'::character varying, 'employee-email-confirmation'::character varying])::text[])",
                        "(ARRAY[('employee-password-reset'::character varying)::text, ('employee-email-confirmation'::character varying)::text])",
                        StringComparison.Ordinal) }
                    : check)],
            })]
            : tables;
    }

    internal static CurrentAuthCollationOperand[] CollationOperands()
    {
        return [.. DefaultTables().SelectMany(table => table.OrderedColumns.Where(column => IsText(table.ColumnTypes[column]))
            .Select(column => new CurrentAuthCollationOperand(table.TargetTable, column, table.ColumnTypes[column],
                table.NullableColumns.Contains(column, StringComparer.Ordinal))))];
    }

    internal static CurrentAuthAffectedIndex[] AffectedIndices()
    {
        return [.. DefaultTables().SelectMany(table =>
            (table.PrimaryKey is { } key && key.Columns.Any(column => IsText(table.ColumnTypes[column]))
                ? new[] { new CurrentAuthAffectedIndex(table.TargetTable, key.Name, true, [.. key.Columns]) }
                : [])
            .Concat(table.Indexes.Where(index => index.Columns.Any(column => IsText(table.ColumnTypes[column])))
                .Select(index => new CurrentAuthAffectedIndex(table.TargetTable, index.Name, false, [.. index.Columns]))))];
    }

    internal static CurrentAuthPhysicalShape PhysicalShape(bool explicitC)
    {
        TableCopyPlan[] tables = Tables(explicitC);
        return new(
            [.. tables.Select(table => new PostgreSqlSchemaFingerprint.TableShape(table.TargetSchema, table.TargetTable))],
            [.. tables.SelectMany(table => table.OrderedColumns.Select((column, ordinal) =>
                PostgreSqlSchemaFingerprint.ExpectedColumn(table, column, ordinal + 1)))],
            [.. tables.SelectMany(table =>
                new[] { new PostgreSqlSchemaFingerprint.ConstraintShape(table.TargetSchema, table.TargetTable,
                    table.PrimaryKey!.Name, 'p', [.. table.PrimaryKey.Columns], string.Empty) }
                .Concat(table.CheckConstraints.Select(check => new PostgreSqlSchemaFingerprint.ConstraintShape(
                    table.TargetSchema, table.TargetTable, check.Name, 'c', [.. check.Columns], check.Expression))))],
            // These service-owned PostgreSQL indices all use native NULLS DISTINCT.
            // Do not use the SQL Server nullable-unique mapping for this independent physical contract.
            [.. tables.SelectMany(table => table.Indexes.Select(index => new PostgreSqlSchemaFingerprint.IndexShape(
                table.TargetSchema, table.TargetTable, index.Name, index.Unique, [.. index.Columns], [], [], string.Empty)
                { NullsNotDistinct = false }))],
            []);
    }

    internal static string PhysicalSha256(bool explicitC)
    {
        CurrentAuthPhysicalShape shape = PhysicalShape(explicitC);
        return PostgreSqlSchemaFingerprint.Compute(shape.Tables, shape.Columns, shape.Constraints, shape.Indexes, shape.ForeignKeys);
    }

    internal static void RequirePhysicalShape(CurrentAuthPhysicalShape observed, bool explicitC)
    {
        ArgumentNullException.ThrowIfNull(observed);
        if (ShapePayload(observed) != ShapePayload(PhysicalShape(explicitC)))
        {
            throw Invalid();
        }
    }

    internal static void RequireTableContract(TableCopyPlan observed, bool explicitC)
    {
        TableCopyPlan? expected = Tables(explicitC).SingleOrDefault(table =>
            table.TargetSchema == observed.TargetSchema && table.TargetTable == observed.TargetTable);
        if (expected is null || JsonSerializer.Serialize(observed) != JsonSerializer.Serialize(expected))
        {
            throw Invalid();
        }
    }

    internal static string ClosureSha256 => Hash(new
    {
        Domain,
        AuthServiceCommit,
        Sources = SourcePins(),
        Before = ShapePayload(PhysicalShape(false)),
        After = ShapePayload(PhysicalShape(true)),
        Operands = CollationOperands(),
        Indices = AffectedIndices(),
        HistoryPolicy = "retain independently per exact target binding; never require cross-target row equality",
        FleetPolicy = "complete target-specific fleet/global baseline; exact23 SQL source inventory unchanged",
    });

    internal static void RequireHistoryPreserved(CurrentAuthHistoryObservation before, CurrentAuthHistoryObservation after,
        DateTimeOffset nowUtc, TimeSpan maximumAge)
    {
        RequireHistory(before, nowUtc, maximumAge);
        RequireHistory(after, nowUtc, maximumAge);
        if (before.TargetBindingSha256 != after.TargetBindingSha256 || after.CapturedAtUtc < before.CapturedAtUtc ||
            !before.Rows.OrderBy(row => row.MigrationId, StringComparer.Ordinal)
                .SequenceEqual(after.Rows.OrderBy(row => row.MigrationId, StringComparer.Ordinal)))
        {
            throw Invalid();
        }
    }

    internal static void RequireHistory(CurrentAuthHistoryObservation observation, DateTimeOffset nowUtc, TimeSpan maximumAge)
    {
        RequireFresh(observation.CapturedAtUtc, nowUtc, maximumAge);
        if (!IsSha256(observation.TargetBindingSha256) || !IsSha256(observation.RetainedArtifactSha256) ||
            !observation.Rows.Select(row => row.MigrationId).Order(StringComparer.Ordinal).SequenceEqual(MigrationIds, StringComparer.Ordinal) ||
            observation.Rows.Any(row => string.IsNullOrEmpty(row.ProductVersion) || row.ProductVersion.Length > 32 ||
                row.ProductVersion.Any(character => !char.IsAsciiDigit(character) && character != '.')))
        {
            throw Invalid();
        }
    }

    private static string ShapePayload(CurrentAuthPhysicalShape shape)
    {
        return JsonSerializer.Serialize(new
        {
            Tables = shape.Tables.OrderBy(table => table.Schema, StringComparer.Ordinal).ThenBy(table => table.Table, StringComparer.Ordinal),
            Columns = shape.Columns.OrderBy(column => column.Schema, StringComparer.Ordinal).ThenBy(column => column.Table, StringComparer.Ordinal)
            .ThenBy(column => column.Ordinal),
            Constraints = shape.Constraints.OrderBy(constraint => constraint.Schema, StringComparer.Ordinal)
            .ThenBy(constraint => constraint.Table, StringComparer.Ordinal).ThenBy(constraint => constraint.Name, StringComparer.Ordinal),
            Indices = shape.Indexes.OrderBy(index => index.Schema, StringComparer.Ordinal).ThenBy(index => index.Table, StringComparer.Ordinal)
            .ThenBy(index => index.Name, StringComparer.Ordinal),
            ForeignKeys = shape.ForeignKeys.OrderBy(key => key.Schema, StringComparer.Ordinal).ThenBy(key => key.Table, StringComparer.Ordinal)
            .ThenBy(key => key.Name, StringComparer.Ordinal),
        });
    }

    private static void RequireFresh(DateTimeOffset capturedAtUtc, DateTimeOffset nowUtc, TimeSpan maximumAge)
    {
        if (capturedAtUtc.Offset != TimeSpan.Zero || nowUtc.Offset != TimeSpan.Zero || maximumAge <= TimeSpan.Zero ||
            maximumAge > TimeSpan.FromHours(12) || capturedAtUtc > nowUtc || nowUtc - capturedAtUtc > maximumAge)
        {
            throw Invalid();
        }
    }

    private static bool IsSha256(string value)
    {
        return value.Length == 64 && value.All(character =>
        char.IsAsciiDigit(character) || character is >= 'a' and <= 'f');
    }

    private static bool IsText(string type)
    {
        return type == "text" || type.StartsWith("character varying(", StringComparison.Ordinal);
    }

    private static string Hash<T>(T value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));
    }

    private static InvalidOperationException Invalid()
    {
        return new("The fixed current Auth preparation contract does not match.");
    }

    private static TableCopyPlan[] DefaultTables()
    {
        TableCopyPlan[] tables =
                [
                    new("public", "__EFMigrationsHistory", "public", "__EFMigrationsHistory", ["MigrationId", "ProductVersion"], ["MigrationId"])
            {
                ColumnTypes = new Dictionary<string,string>(StringComparer.Ordinal) { ["MigrationId"] = "character varying(150)", ["ProductVersion"] = "character varying(32)" },
                NullableColumns = [],
                PrimaryKey = new("PK___EFMigrationsHistory", ["MigrationId"]),
                Indexes = [],
                CheckConstraints = [],
            },
            new("public", "refresh_sessions", "public", "refresh_sessions", ["Id", "FamilyId", "IdentityId", "IdentityKind", "SecurityStamp", "TokenHash", "CreatedAt", "ExpiresAt", "RotatedAt", "RevokedAt", "ReplacedById"], ["Id"])
            {
                ColumnTypes = new Dictionary<string,string>(StringComparer.Ordinal) { ["Id"] = "uuid", ["FamilyId"] = "uuid", ["IdentityId"] = "character varying(450)", ["IdentityKind"] = "integer", ["SecurityStamp"] = "text", ["TokenHash"] = "character varying(64)", ["CreatedAt"] = "timestamp with time zone", ["ExpiresAt"] = "timestamp with time zone", ["RotatedAt"] = "timestamp with time zone", ["RevokedAt"] = "timestamp with time zone", ["ReplacedById"] = "uuid" },
                NullableColumns = ["SecurityStamp", "RotatedAt", "RevokedAt", "ReplacedById"],
                PrimaryKey = new("PK_refresh_sessions", ["Id"]),
                Indexes = [new("IX_refresh_sessions_ExpiresAt", ["ExpiresAt"], false), new("IX_refresh_sessions_FamilyId", ["FamilyId"], false), new("IX_refresh_sessions_TokenHash", ["TokenHash"], true)],
                CheckConstraints = [],
            },
            new("public", "google_identity_nonces", "public", "google_identity_nonces", ["Id", "NonceHash", "ServiceName", "Application", "CreatedAt", "ExpiresAt"], ["Id"])
            {
                ColumnTypes = new Dictionary<string,string>(StringComparer.Ordinal) { ["Id"] = "uuid", ["NonceHash"] = "character varying(64)", ["ServiceName"] = "character varying(128)", ["Application"] = "character varying(64)", ["CreatedAt"] = "timestamp with time zone", ["ExpiresAt"] = "timestamp with time zone" },
                NullableColumns = [],
                PrimaryKey = new("PK_google_identity_nonces", ["Id"]),
                Indexes = [new("IX_google_identity_nonces_ExpiresAt", ["ExpiresAt"], false), new("IX_google_identity_nonces_NonceHash", ["NonceHash"], true)],
                CheckConstraints = [],
            },
            new("public", "identity_action_tokens", "public", "identity_action_tokens", ["Id", "IdentityId", "TokenHash", "Purpose", "CreatedAt", "ExpiresAt", "ConsumedAt", "TargetEmail", "BoundNormalizedEmail", "BoundSecurityStamp", "EffectActionId", "FinalizedAt", "OriginalTokenSha256", "OwnerSubject", "RecoveryVersion"], ["Id"])
            {
                ColumnTypes = new Dictionary<string,string>(StringComparer.Ordinal) { ["Id"] = "uuid", ["IdentityId"] = "character varying(450)", ["TokenHash"] = "character varying(64)", ["Purpose"] = "character varying(32)", ["CreatedAt"] = "timestamp with time zone", ["ExpiresAt"] = "timestamp with time zone", ["ConsumedAt"] = "timestamp with time zone", ["TargetEmail"] = "character varying(320)", ["BoundNormalizedEmail"] = "character varying(256)", ["BoundSecurityStamp"] = "text", ["EffectActionId"] = "uuid", ["FinalizedAt"] = "timestamp with time zone", ["OriginalTokenSha256"] = "character varying(64)", ["OwnerSubject"] = "character varying(256)", ["RecoveryVersion"] = "integer" },
                NullableColumns = ["ConsumedAt", "TargetEmail", "BoundNormalizedEmail", "BoundSecurityStamp", "EffectActionId", "FinalizedAt", "OriginalTokenSha256", "OwnerSubject", "RecoveryVersion"],
                PrimaryKey = new("PK_identity_action_tokens", ["Id"]),
                Indexes = [new("IX_identity_action_tokens_ExpiresAt", ["ExpiresAt"], false), new("IX_identity_action_tokens_IdentityId_Purpose_TokenHash", ["IdentityId", "Purpose", "TokenHash"], true), new("IX_identity_action_tokens_OriginalTokenSha256_Purpose", ["OriginalTokenSha256", "Purpose"], true)],
                // Fixed PG18 deparser spellings: genuine current-owner native verification remains required.
                CheckConstraints = [
                    new("CK_identity_action_tokens_employee_binding", "((\"RecoveryVersion\" IS NULL) OR ((\"RecoveryVersion\" = 1) AND ((\"Purpose\")::text = ANY ((ARRAY['employee-password-reset'::character varying, 'employee-email-confirmation'::character varying])::text[])) AND (\"OriginalTokenSha256\" IS NOT NULL) AND (length((\"OriginalTokenSha256\")::text) = 64) AND (\"OwnerSubject\" IS NOT NULL) AND (length((\"OwnerSubject\")::text) > 0) AND (\"BoundNormalizedEmail\" IS NOT NULL) AND (length((\"BoundNormalizedEmail\")::text) > 0) AND (\"BoundSecurityStamp\" IS NOT NULL) AND (length(\"BoundSecurityStamp\") > 0)))") { Columns = ["RecoveryVersion", "Purpose", "OriginalTokenSha256", "OwnerSubject", "BoundNormalizedEmail", "BoundSecurityStamp"] },
                    new("CK_identity_action_tokens_employee_finalization", "(((\"FinalizedAt\" IS NULL) AND (\"EffectActionId\" IS NULL)) OR ((\"RecoveryVersion\" IS NOT NULL) AND (\"RecoveryVersion\" = 1) AND (\"FinalizedAt\" IS NOT NULL) AND (\"ConsumedAt\" IS NOT NULL) AND (\"EffectActionId\" IS NOT NULL) AND (\"EffectActionId\" = \"Id\")))") { Columns = ["FinalizedAt", "EffectActionId", "RecoveryVersion", "ConsumedAt", "Id"] },
                ],
            },
        ];
        return tables;
    }
}
