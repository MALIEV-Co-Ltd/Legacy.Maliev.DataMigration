using Npgsql;

namespace Legacy.Maliev.DataMigration;

/// <summary>Opt-in physical Company contract at the immutable reviewed Customer owner; grants no repair authority.</summary>
internal static class CustomerCompanyStorageManifest
{
    internal const string Profile = "customer-company-source-storage-439f34c15b5535df0554618b3ef7bdc9deae491b";
    internal static readonly string[] Columns = ["Name", "TaxNumber", "Registrar"];

    internal const string TriggerBody = """
        DECLARE field_values text[] := ARRAY[NEW."Name", NEW."TaxNumber", NEW."Registrar"];
            field_index integer; units integer; character_index integer; width integer; scalar text;
        BEGIN
            FOR field_index IN 1..3 LOOP
                IF field_values[field_index] IS NULL OR
                    char_length(field_values[field_index]) + char_length(regexp_replace(field_values[field_index] COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256 THEN
                    CONTINUE;
                END IF;
                units := 0; character_index := 0;
                WHILE units < 256 LOOP
                    scalar := substr(field_values[field_index], character_index + 1, 1);
                    IF scalar = '' THEN EXIT; END IF;
                    width := CASE WHEN octet_length(scalar) = 4 THEN 2 ELSE 1 END;
                    IF units + width > 256 THEN EXIT; END IF;
                    units := units + width;
                    character_index := character_index + 1;
                END LOOP;
                IF btrim(substr(field_values[field_index], character_index + 1), ' ') = '' THEN
                    field_values[field_index] := substr(field_values[field_index], 1, character_index);
                END IF;
            END LOOP;
            NEW."Name" := field_values[1];
            NEW."TaxNumber" := field_values[2];
            NEW."Registrar" := field_values[3];
            RETURN NEW;
        END;
        """;


    internal static bool IsProfile(string? profile)
    {
        return profile == Profile;
    }

    internal static DatabaseSchemaPlan BasePlan(DatabaseSchemaPlan plan)
    {
        return plan.Database != "Customer" || !IsProfile(plan.TargetExtensionProfile)
            ? throw Invalid()
            : plan with { TargetExtensionProfile = ApprovedCurrentConsumerSchemaManifest.Customer };
    }

    internal static IReadOnlyList<TableCopyPlan> Apply(IReadOnlyList<TableCopyPlan> physical)
    {
        TableCopyPlan[] roots = [.. physical.Where(x => x.TargetSchema == "public" && x.TargetTable == "Company")];
        if (roots.Length != 1) { throw Invalid(); }
        TableCopyPlan root = roots[0];
        return root.SourceSchema != "dbo" || root.SourceTable != "Company" ||
            Columns.Any(column => root.ColumnTypes.GetValueOrDefault(column) != "character varying(256)" ||
                root.NullableColumns.Contains(column, StringComparer.Ordinal) != (column != "Name") ||
                root.DefaultExpressions.ContainsKey(column) ||
                root.OrderedColumns.Count(x => x == column) != 1 ||
                root.GeneratedColumns.Any(x => x.Column == column)) ||
            root.CheckConstraints.Any(x => Columns.Any(column => x.Name == $"CK_Company_{column}_SourceLength"))
            ? throw Invalid()
            : [.. physical.Select(table => ReferenceEquals(table, root) ? table with
        {
            ColumnTypes = table.ColumnTypes.ToDictionary(x => x.Key,
                x => Columns.Contains(x.Key, StringComparer.Ordinal) ? "text" : x.Value, StringComparer.Ordinal),
            CheckConstraints = [.. table.CheckConstraints, .. Columns.Select(column =>
                new CheckConstraintCopyPlan($"CK_Company_{column}_SourceLength", CheckExpression(column)) { Columns = [column] })],
        } : table)];
    }

    // Exact PostgreSQL deparser form keeps the existing fingerprint format unchanged.
    internal static string CheckExpression(string column)
    {
        return $"((char_length(\"{column}\") + char_length(regexp_replace((\"{column}\" COLLATE \"C\"), '[\u0001-\uffff]'::text, ''::text, 'g'::text))) <= 256)";
    }

    internal static string CreateNormalizerSql => """
        CREATE FUNCTION public."NormalizeCompanySource"() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $source$
        """ + TriggerBody + """
        $source$;
        CREATE TRIGGER "NormalizeCompanySource" BEFORE INSERT OR UPDATE OF "Name","TaxNumber","Registrar" ON public."Company"
            FOR EACH ROW EXECUTE FUNCTION public."NormalizeCompanySource"();
        """;

    internal static async Task RequireNormalizerAsync(DatabaseSchemaPlan plan, NpgsqlConnection connection,
        NpgsqlTransaction transaction, CancellationToken ct)
    {
        if (!IsProfile(plan.TargetExtensionProfile)) { return; }
        _ = BasePlan(plan);
        const string sql = """
            SELECT current_setting('server_encoding') = 'UTF8'
              AND (SELECT count(*) FROM pg_proc WHERE pronamespace='public'::regnamespace AND proname='NormalizeCompanySource')=1
              AND EXISTS (SELECT 1 FROM pg_proc WHERE oid=to_regprocedure('public."NormalizeCompanySource"()')
                AND prorettype='trigger'::regtype AND prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
                AND NOT prosecdef AND NOT proisstrict AND NOT proleakproof AND prokind='f' AND proparallel='u' AND provolatile='v'
                AND proconfig=ARRAY['search_path=pg_catalog'] AND replace(prosrc,chr(13)||chr(10),chr(10))=$1)
              AND (SELECT count(*) FROM pg_trigger WHERE tgrelid='public."Company"'::regclass AND NOT tgisinternal)=1
              AND EXISTS (SELECT 1 FROM pg_trigger WHERE tgrelid='public."Company"'::regclass
                AND tgname='NormalizeCompanySource' AND tgfoid=to_regprocedure('public."NormalizeCompanySource"()')
                AND tgtype=23 AND tgenabled='O' AND NOT tgisinternal AND tgconstraint=0 AND tgqual IS NULL
                AND tgnargs=0 AND octet_length(tgargs)=0
                AND tgattr::text=(SELECT string_agg(attnum::text,' ' ORDER BY array_position(ARRAY['Name','TaxNumber','Registrar'],attname::text))
                  FROM pg_attribute WHERE attrelid='public."Company"'::regclass AND attname IN ('Name','TaxNumber','Registrar') AND NOT attisdropped));
            """;
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = command.Parameters.AddWithValue(TriggerBody.Replace("\r\n", "\n", StringComparison.Ordinal));
        if (await command.ExecuteScalarAsync(ct).ConfigureAwait(false) is not true) { throw Invalid(); }
    }

    private static MigrationExecutionException Invalid()
    {
        return new("customer_company_storage_profile_invalid",
            "The reviewed Company source storage contract is invalid.");
    }
}
