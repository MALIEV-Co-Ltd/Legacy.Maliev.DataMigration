using System.Security.Cryptography;
using System.Text.Json;
using Npgsql;

namespace Legacy.Maliev.DataMigration;

internal enum CurrentRepairOperandOwnerPurpose { AuthCollation16 = 1, CustomerSequenceStart = 2, CountryIsoLiteral = 3, MaterialCountryIsoLiteral = 4 }

/// <summary>Fixed operand owners, separately bound to actual target identity and trusted native preimages.</summary>
internal static class CurrentRepairOperandOwnerProfile
{
    private static readonly string[] AuthTables = ["__EFMigrationsHistory", "google_identity_nonces", "identity_action_tokens", "refresh_sessions"];
    private static readonly string[] CustomerTables = ["Customer"];

    internal static string ExpectedOwnerName(CurrentRepairOperandOwnerPurpose purpose, DeltaTargetAuthority target)
    {
        return !Enum.IsDefined(purpose) || !HashShape(target.SystemIdentifierSha256)
            ? throw Invalid()
            : target.Kind switch
            {
                DeltaTargetAuthorityKind.LocalAspire => "legacy_local",
                DeltaTargetAuthorityKind.ProductionCloudNativePg => purpose switch
                {
                    CurrentRepairOperandOwnerPurpose.AuthCollation16 => "legacy_auth_refresh",
                    CurrentRepairOperandOwnerPurpose.CustomerSequenceStart => "legacy_customer_owner",
                    CurrentRepairOperandOwnerPurpose.CountryIsoLiteral => "legacy_country_owner",
                    CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral => "legacy_material_owner",
                    _ => throw Invalid(),
                },
                _ => throw Invalid(),
            };
    }

    internal static string PolicySha256(CurrentRepairOperandOwnerPurpose purpose, DeltaTargetAuthority target)
    {
        return Digest(new
        {
            Domain = "Legacy.Maliev.CurrentRepairOperandOwners.v1",
            Purpose = purpose,
            TargetKind = target.Kind,
            target.SystemIdentifierSha256,
            Owner = ExpectedOwnerName(purpose, target),
            ProductionFlags = target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg ? new RoleFlags(false, true, false, false, true, false, false, 4) : null,
            OriginalBindings = "exact native pg_class/pg_index/pg_depend/pg_authid tuples in target-specific signed full baseline"
        });
    }

    internal static async Task<string> RequireNativeAsync(NpgsqlConnection connection, NpgsqlTransaction transaction,
        CurrentRepairOperandOwnerPurpose purpose, DeltaTargetAuthority target,
        CurrentAppOwnedDatabaseSnapshot snapshot, CancellationToken cancellationToken)
    {
        string owner = ExpectedOwnerName(purpose, target);
        bool iso = purpose is CurrentRepairOperandOwnerPurpose.CountryIsoLiteral or CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral;
        string database = purpose switch
        {
            CurrentRepairOperandOwnerPurpose.AuthCollation16 => "Auth",
            CurrentRepairOperandOwnerPurpose.CustomerSequenceStart => "Customer",
            CurrentRepairOperandOwnerPurpose.CountryIsoLiteral => "Country",
            CurrentRepairOperandOwnerPurpose.MaterialCountryIsoLiteral => "Material",
            _ => throw Invalid(),
        };
        if (connection.Database != database || snapshot.Database != database || transaction.Connection != connection ||
            transaction.IsolationLevel is not (System.Data.IsolationLevel.RepeatableRead or System.Data.IsolationLevel.Serializable)) { throw Invalid(); }
        string[] tables = iso ? ["Country"] : purpose == CurrentRepairOperandOwnerPurpose.AuthCollation16 ? AuthTables : CustomerTables;
        var rows = new List<OwnerRow>();
        const string sql = """
            WITH tables AS (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
              WHERE n.nspname='public' AND c.relkind='r' AND c.relname=ANY($1)), selected AS (
              SELECT c.oid,c.oid parent,NULL::text binding_hash FROM pg_class c JOIN tables t ON t.oid=c.oid
              UNION ALL
              SELECT c.oid,i.indrelid,encode(sha256(convert_to(to_jsonb(i)::text,'UTF8')),'hex')
                FROM pg_index i JOIN tables t ON t.oid=i.indrelid JOIN pg_class c ON c.oid=i.indexrelid
                WHERE $2
              UNION ALL
              SELECT s.oid,t.oid,encode(sha256(convert_to(to_jsonb(d)::text,'UTF8')),'hex')
                FROM tables t JOIN pg_class s ON s.relname=$4 AND s.relkind='S'
                JOIN pg_namespace n ON n.oid=s.relnamespace AND n.nspname='public'
                JOIN pg_attribute a ON a.attrelid=t.oid AND a.attname='ID' AND a.attnum>0 AND NOT a.attisdropped
                  AND a.attidentity='d' AND a.atttypid='integer'::regtype
                JOIN pg_depend d ON d.classid='pg_class'::regclass AND d.objid=s.oid AND d.objsubid=0
                  AND d.refclassid='pg_class'::regclass AND d.refobjid=t.oid AND d.refobjsubid=a.attnum AND d.deptype='i'
                WHERE NOT $2 OR $3)
            SELECT c.oid,c.relname,c.relkind::text,x.parent,c.relowner,r.rolname::text,
              r.rolsuper,r.rolinherit,r.rolcreaterole,r.rolcreatedb,r.rolcanlogin,r.rolreplication,r.rolbypassrls,r.rolconnlimit,
              encode(sha256(convert_to(to_jsonb(c)::text,'UTF8')),'hex'),
              (SELECT encode(sha256(convert_to(to_jsonb(secret_role)::text,'UTF8')),'hex') FROM pg_authid secret_role WHERE secret_role.oid=r.oid),
              x.binding_hash,encode(sha256(convert_to(system_identifier::text,'UTF8')),'hex')
            FROM selected x JOIN pg_class c ON c.oid=x.oid JOIN pg_roles r ON r.oid=c.relowner,pg_control_system()
            ORDER BY c.relname COLLATE "C",c.oid;
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = command.Parameters.AddWithValue(tables);
        _ = command.Parameters.AddWithValue(purpose == CurrentRepairOperandOwnerPurpose.AuthCollation16 || iso);
        _ = command.Parameters.AddWithValue(iso);
        _ = command.Parameters.AddWithValue(iso ? "Country_ID_seq" : "Customer_ID_seq");
        await using NpgsqlDataReader reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            uint oid = reader.GetFieldValue<uint>(0), roleOid = reader.GetFieldValue<uint>(4);
            string kind = reader.GetString(2), name = reader.GetString(1), role = reader.GetString(5);
            var flags = new RoleFlags(reader.GetBoolean(6), reader.GetBoolean(7), reader.GetBoolean(8), reader.GetBoolean(9),
                reader.GetBoolean(10), reader.GetBoolean(11), reader.GetBoolean(12), reader.GetInt32(13));
            if (role != owner || reader.GetString(17) != target.SystemIdentifierSha256 || oid == 0 || roleOid == 0 ||
                (target.Kind == DeltaTargetAuthorityKind.ProductionCloudNativePg &&
                 (flags.Superuser || !flags.Inherit || flags.CreateRole || flags.CreateDatabase || !flags.CanLogin || flags.Replication || flags.BypassRls || flags.ConnectionLimit != 4)))
            { throw Invalid(); }
            RequireFact(snapshot, "pg_class", oid, reader.GetString(14));
            RequireFact(snapshot, "pg_authid", roleOid, reader.GetString(15));
            if (kind is "i" or "I" or "S")
            {
                string bindingCatalog = kind == "S" ? "pg_depend" : "pg_index";
                if (reader.IsDBNull(16) || snapshot.Catalog.Count(x => x.Catalog == bindingCatalog &&
                    x.ObjectId == oid.ToString(System.Globalization.CultureInfo.InvariantCulture) && x.Sha256 == reader.GetString(16)) != 1) { throw Invalid(); }
            }
            rows.Add(new(oid, name, kind, reader.GetFieldValue<uint>(3), roleOid, role, flags));
        }
        OwnerRow[] tableRows = [.. rows.Where(x => x.Kind == "r")];
        if (!tableRows.Select(x => x.Name).Order(StringComparer.Ordinal).SequenceEqual(tables.Order(StringComparer.Ordinal), StringComparer.Ordinal) ||
            rows.Select(x => x.Oid).Distinct().Count() != rows.Count || rows.Select(x => x.RoleOid).Distinct().Count() != 1 ||
            rows.Any(x => !tableRows.Any(t => t.Oid == x.Parent))) { throw Invalid(); }
        if (purpose == CurrentRepairOperandOwnerPurpose.CustomerSequenceStart &&
            (rows.Count != 2 || rows.Count(x => x.Kind == "S" && x.Name == "Customer_ID_seq") != 1)) { throw Invalid(); }
        if (iso && rows.Count(x => x.Kind == "S" && x.Name == "Country_ID_seq") != 1) { throw Invalid(); }
        // Auth/ISO indexes may be legitimately rebuilt; their CURRENT OIDs/raw bindings above remain exact.
        // The returned semantic ownership digest retains index name, role and parent, not a stale index allocation.
        return Digest(new
        {
            Policy = PolicySha256(purpose, target),
            Rows = rows.Select(x => new
            { Oid = x.Kind is "i" or "I" ? 0u : x.Oid, x.Name, x.Kind, x.Parent, x.RoleOid, x.Role, x.Flags }).ToArray()
        });
    }

    private static void RequireFact(CurrentAppOwnedDatabaseSnapshot snapshot, string catalog, uint oid, string digest)
    {
        if (snapshot.Catalog.Count(x => x.Catalog == catalog && x.Key == oid.ToString(System.Globalization.CultureInfo.InvariantCulture) && x.Sha256 == digest) != 1) { throw Invalid(); }
    }
    private static bool HashShape(string value)
    {
        return value.Length == 64 && value.All(x => x is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
    }

    private static string Digest<T>(T value)
    {
        return Convert.ToHexStringLower(SHA256.HashData(JsonSerializer.SerializeToUtf8Bytes(value)));
    }

    private sealed record RoleFlags(bool Superuser, bool Inherit, bool CreateRole, bool CreateDatabase,
        bool CanLogin, bool Replication, bool BypassRls, int ConnectionLimit);
    private sealed record OwnerRow(uint Oid, string Name, string Kind, uint Parent, uint RoleOid, string Role, RoleFlags Flags);
    private static MigrationExecutionException Invalid()
    {
        return new("current_repair_operand_owner_invalid", "The fixed target operand owner binding failed.");
    }
}
