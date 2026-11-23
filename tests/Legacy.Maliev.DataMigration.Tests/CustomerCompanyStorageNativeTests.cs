using Npgsql;

namespace Legacy.Maliev.DataMigration.Tests;

[Collection(PostgreSqlAdapterTestGroup.Name)]
public sealed class CustomerCompanyStorageNativeTests(PostgreSqlAdapterFixture fixture)
{
    [Fact]
    public async Task Ordinary_shadow_seed_and_catalog_inspection_require_exact_normalizer_and_capacity()
    {
        PostgreSqlShadowTarget target = fixture.CreateShadowTarget();
        ShadowDatabase shadow = await target.CreateUniqueEmptyShadowAsync("Customer",
            $"legacy_shadow_company_{Guid.NewGuid():N}", Guid.NewGuid().ToString("D"), default);
        DatabaseSchemaPlan plan = CustomerCompanyStorageProfileTests.Select(CustomerCompanyStorageProfileTests.Before());
        string connectionString = new NpgsqlConnectionStringBuilder(fixture.ShadowAdminConnectionString) { Database = shadow.Name }.ConnectionString;
        try
        {
            await using var connection = new NpgsqlConnection(connectionString);
            await connection.OpenAsync();
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await using var seed = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                await seed.ApplySchemaAsync(plan, default);
                await seed.FinalizeSchemaAsync(plan, default);
                Assert.Equal(plan.TargetSchemaSha256, await seed.InspectSchemaAsync(plan, default));
                await transaction.CommitAsync();
            }
            // Reinstall the owner migration's literal SQL, rather than proving only our own seeder round trip.
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await ExecuteAsync(connection, transaction, """DROP TRIGGER "NormalizeCompanySource" ON public."Company"; DROP FUNCTION public."NormalizeCompanySource"();""");
                await ExecuteAsync(connection, transaction, ReviewedOwnerNormalizerSql);
                await ExecuteAsync(connection, transaction, """
                    ALTER TABLE public."Company" DROP CONSTRAINT "CK_Company_Name_SourceLength",
                        DROP CONSTRAINT "CK_Company_TaxNumber_SourceLength", DROP CONSTRAINT "CK_Company_Registrar_SourceLength";
                    ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_Name_SourceLength" CHECK
                        (char_length("Name") + char_length(regexp_replace("Name" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256);
                    ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_TaxNumber_SourceLength" CHECK
                        (char_length("TaxNumber") + char_length(regexp_replace("TaxNumber" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256);
                    ALTER TABLE public."Company" ADD CONSTRAINT "CK_Company_Registrar_SourceLength" CHECK
                        (char_length("Registrar") + char_length(regexp_replace("Registrar" COLLATE "C", U&'[\0001-\FFFF]', '', 'g')) <= 256);
                    """);
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(plan.TargetSchemaSha256, await inspection.InspectSchemaAsync(plan, default));
                await transaction.CommitAsync();
            }
            foreach (string lineEnding in new[] { "\n", "\r\n" })
            {
                await using var transaction = await connection.BeginTransactionAsync();
                string ownerSql = ReviewedOwnerNormalizerSql.Replace("\r\n", "\n", StringComparison.Ordinal)
                    .Replace("\n", lineEnding, StringComparison.Ordinal);
                await ExecuteAsync(connection, transaction, """DROP TRIGGER "NormalizeCompanySource" ON public."Company"; DROP FUNCTION public."NormalizeCompanySource"();""");
                await ExecuteAsync(connection, transaction, ownerSql);
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(plan.TargetSchemaSha256, await inspection.InspectSchemaAsync(plan, default));
                await transaction.RollbackAsync();
            }
            foreach (string mutation in Mutations)
            {
                await using var transaction = await connection.BeginTransactionAsync();
                await ExecuteAsync(connection, transaction, mutation);
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal("customer_company_storage_profile_invalid",
                    (await Assert.ThrowsAsync<MigrationExecutionException>(() => inspection.InspectSchemaAsync(plan, default))).Code);
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await ExecuteAsync(connection, transaction, """ALTER TABLE public."Company" DROP CONSTRAINT "CK_Company_Name_SourceLength";""");
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.NotEqual(plan.TargetSchemaSha256, await inspection.InspectSchemaAsync(plan, default));
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await using var command = new NpgsqlCommand("""
                    INSERT INTO public."Company" ("ID","Name","TaxNumber","Registrar")
                    VALUES (1,$1,$2,NULL);
                    """, connection, transaction);
                _ = command.Parameters.AddWithValue(new string('a', 256) + "   ");
                _ = command.Parameters.AddWithValue(string.Concat(Enumerable.Repeat("😀", 128)));
                _ = await command.ExecuteNonQueryAsync();
                await using var readback = new NpgsqlCommand("""SELECT "Name","TaxNumber","Registrar" FROM public."Company" WHERE "ID"=1;""", connection, transaction);
                await using (NpgsqlDataReader reader = await readback.ExecuteReaderAsync())
                {
                    Assert.True(await reader.ReadAsync());
                    Assert.Equal(new string('a', 256), reader.GetString(0));
                    Assert.Equal(string.Concat(Enumerable.Repeat("😀", 128)), reader.GetString(1));
                    Assert.True(reader.IsDBNull(2));
                }
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await using var command = new NpgsqlCommand("""
                    INSERT INTO public."Company" ("ID","Name") VALUES (1,$1);
                    """, connection, transaction);
                _ = command.Parameters.AddWithValue(string.Concat(Enumerable.Repeat("😀", 129)));
                PostgresException error = await Assert.ThrowsAsync<PostgresException>(command.ExecuteNonQueryAsync);
                Assert.Equal(PostgresErrorCodes.CheckViolation, error.SqlState);
                await transaction.RollbackAsync();
            }
            await using (var transaction = await connection.BeginTransactionAsync())
            {
                await using var inspection = new PostgreSqlWholeDatabaseTransaction(connection, transaction, ownsResources: false);
                Assert.Equal(plan.TargetSchemaSha256, await inspection.InspectSchemaAsync(plan, default));
                await transaction.RollbackAsync();
            }
        }
        finally { await target.DeleteRunOwnedShadowAsync(shadow, default); }
    }

    private static readonly string[] Mutations =
    [
        """DROP TRIGGER "NormalizeCompanySource" ON public."Company";""",
        """DROP TRIGGER "NormalizeCompanySource" ON public."Company"; DROP FUNCTION public."NormalizeCompanySource"();""",
        """ALTER FUNCTION public."NormalizeCompanySource"() SECURITY DEFINER;""",
        """ALTER FUNCTION public."NormalizeCompanySource"() SET search_path = public;""",
        """ALTER TABLE public."Company" DISABLE TRIGGER "NormalizeCompanySource";""",
        """CREATE OR REPLACE FUNCTION public."NormalizeCompanySource"() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$BEGIN RETURN NEW; END;$$;""",
        """DROP TRIGGER "NormalizeCompanySource" ON public."Company"; CREATE TRIGGER "NormalizeCompanySource" BEFORE INSERT OR UPDATE OF "Name" ON public."Company" FOR EACH ROW EXECUTE FUNCTION public."NormalizeCompanySource"();""",
        """CREATE TRIGGER "UnexpectedNormalizer" BEFORE INSERT ON public."Company" FOR EACH ROW EXECUTE FUNCTION public."NormalizeCompanySource"();""",
        """CREATE FUNCTION public."NormalizeCompanySource"(integer) RETURNS integer LANGUAGE sql AS 'SELECT $1';""",
    ];

    // Literal SQL result of the reviewed owner migration raw-string concatenation, independently retained from its fixture seeder.
    private const string ReviewedOwnerNormalizerSql = """
        CREATE FUNCTION public."NormalizeCompanySource"() RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog AS $source$DECLARE field_values text[] := ARRAY[NEW."Name", NEW."TaxNumber", NEW."Registrar"];
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
        END;$source$;
        CREATE TRIGGER "NormalizeCompanySource" BEFORE INSERT OR UPDATE OF "Name","TaxNumber","Registrar" ON public."Company"
            FOR EACH ROW EXECUTE FUNCTION public."NormalizeCompanySource"();
        """;

    private static async Task ExecuteAsync(NpgsqlConnection connection, NpgsqlTransaction transaction, string sql)
    {
        await using var command = new NpgsqlCommand(sql, connection, transaction);
        _ = await command.ExecuteNonQueryAsync();
    }
}
